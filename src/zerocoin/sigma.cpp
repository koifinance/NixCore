// Copyright (c) 2019 The NIX Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <zerocoin/sigma.h>
#include <zerocoin/zerocoin.h>
#include <timedata.h>
#include <util.h>
#include <base58.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <atomic>
#include <sstream>
#include <chrono>
#include <net_processing.h>
#include <utilstrencodings.h>

sigma::Params* SParams = sigma::Params::get_default();

static CSigmaState sigmaState;

uint256 GetSerialHash(const Scalar& bnSerial)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnSerial;
    return Hash(ss.begin(), ss.end());
}

uint256 GetPubCoinValueHash(const GroupElement& bnValue)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << bnValue;
    return Hash(ss.begin(), ss.end());
}


static bool CheckSigmaSpendSerial(
        CValidationState &state,
        CSigmaTxInfo *sigmaTxInfo,
        const Scalar &serial,
        int nHeight,
        bool fConnectTip) {
    // check for sigma transaction in this block as well
    if (sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete &&
            sigmaTxInfo->spentSerials.find(serial) != sigmaTxInfo->spentSerials.end())
        return state.DoS(0, error("CTransaction::CheckSigmaSpendSerial() : two or more spends with same serial in the same block"));

    // check for used serials in sigmaState
    if (sigmaState.IsUsedCoinSerial(serial)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckSigmaSpendSerial() : The  CoinSpend serial has been used"));
        }
    }
    return true;
}

bool IsSigmaAllowed(int height)
{
    return height >= Params().GetConsensus().nSigmaStartBlock;
}

bool IsSigmaAllowed()
{
    LOCK(cs_main);
    return IsSigmaAllowed(chainActive.Height());
}

secp_primitives::GroupElement ParseSigmaMintScript(const CScript& script)
{
    if (script.size() < 1) {
        throw std::invalid_argument("Script is not a valid Sigma mint");
    }

    std::vector<unsigned char> serialized(script.begin() + 1, script.end());

    secp_primitives::GroupElement pub;
    pub.deserialize(serialized.data());

    return pub;
}

std::pair<std::unique_ptr<sigma::CoinSpend>, uint32_t> ParseSigmaSpend(const CTxIn& in)
{
    uint32_t groupId = in.prevout.n;

    if (groupId < 1 || groupId >= INT_MAX || in.scriptSig.size() < 1) {
        throw CBadTxIn();
    }

    CDataStream serialized(
        std::vector<unsigned char>(in.scriptSig.begin() + 1, in.scriptSig.end()),
        SER_NETWORK,
        PROTOCOL_VERSION
    );

    std::unique_ptr<sigma::CoinSpend> spend(new sigma::CoinSpend(SParams, serialized));

    return std::make_pair(std::move(spend), groupId);
}

bool CheckSigmaSpendTransaction(
        const CTransaction &tx,
        const vector<sigma::CoinDenomination>& targetDenominations,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        CSigmaTxInfo *sigmaTxInfo) {

    bool hasSigmaSpendInputs = false, hasNonSigmaInputs = false;
    int vinIndex = -1;
    std::unordered_set<Scalar, sigma::CScalarHash> spendSerials;

    for (const CTxIn &txin : tx.vin)
    {
        std::unique_ptr<sigma::CoinSpend> spend;
        uint32_t pubcoinId;

        vinIndex++;
        if (txin.scriptSig.IsSigmaSpend())
            hasSigmaSpendInputs = true;
        else
            hasNonSigmaInputs = true;

        try {
            std::tie(spend, pubcoinId) = ParseSigmaSpend(txin);
        } catch (CBadTxIn&) {
            return state.DoS(100,
                false,
                REJECT_MALFORMED,
                "CheckSigmaSpendTransaction: invalid spend transaction");
        }

        if (spend->getVersion() != sigma::SIGMA_VERSION_1) {
            return state.DoS(100,
                             false,
                             NSEQUENCE_INCORRECT,
                             "CTransaction::CheckTransaction() : Error: incorrect spend transaction verion");
        }

        uint256 txHashForMetadata;

        // Obtain the hash of the transaction sans the sigma part
        CMutableTransaction txTemp = tx;
        for(CTxIn &txTempIn: txTemp.vin) {
            if (txTempIn.scriptSig.IsSigmaSpend()) {
                txTempIn.scriptSig.clear();
            }
        }
        txHashForMetadata = txTemp.GetHash();

        LogPrintf("CheckSigmaSpendTransaction: tx version=%d, tx metadata hash=%s, serial=%s\n",
                spend->getVersion(), txHashForMetadata.ToString(),
                spend->getCoinSerialNumber().tostring());

        CSigmaState::CoinGroupInfo coinGroup;
        if (!sigmaState.GetCoinGroupInfo(targetDenominations[vinIndex], pubcoinId, coinGroup))
            return state.DoS(100, false, NO_MINT_ZEROCOIN,
                    "CheckSigmaSpendTransaction: Error: no coins were minted with such parameters");

        bool passVerify = false;
        CBlockIndex *index = coinGroup.lastBlock;
        pair<sigma::CoinDenomination, int> denominationAndId = std::make_pair(
            targetDenominations[vinIndex], pubcoinId);

        uint256 accumulatorBlockHash = spend->getAccumulatorBlockHash();

        // We use incomplete transaction hash as metadata.
        sigma::SpendMetaData newMetaData(
            pubcoinId,
            accumulatorBlockHash,
            txHashForMetadata);

        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != accumulatorBlockHash)
            index = index->pprev;

        // Build a vector with all the public coins with given denomination and accumulator id before
        // the block on which the spend occured.
        // This list of public coins is required by function "Verify" of CoinSpend.
        std::vector<sigma::PublicCoin> anonymity_set;
        while(true) {
            for(const sigma::PublicCoin& pubCoinValue: index->mintedPubCoinsV2[denominationAndId]) {
                anonymity_set.push_back(pubCoinValue);
            }
            if (index == coinGroup.firstBlock)
                break;
            index = index->pprev;
        }

        passVerify = spend->Verify(anonymity_set, newMetaData);
        if (passVerify) {
            Scalar serial = spend->getCoinSerialNumber();
            // do not check for duplicates in case we've seen exact copy of this tx in this block before
            if (!(sigmaTxInfo && sigmaTxInfo->sTransactions.count(hashTx) > 0)) {
                if (!CheckSigmaSpendSerial(
                            state, sigmaTxInfo, serial, nHeight, false))
                    return false;
            }

            if (!spendSerials.insert(serial).second) {
                return state.DoS(100,
                    error("CheckSpendSigmaTansaction: two or more spends with same serial in the same transaction"));
            }

            if(!isVerifyDB && !isCheckWallet) {
                if (sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete) {
                    // add spend information to the index
                    sigmaTxInfo->spentSerials.insert(std::make_pair(
                                serial, (int)spend->getDenomination()));
                    sigmaTxInfo->sTransactions.insert(hashTx);
                }
            }
        }
        else {
            LogPrintf("CheckSigmaSpendTransaction: verification failed at block %d\n", nHeight);
            return false;
        }
    }

    if(!isVerifyDB && !isCheckWallet) {
        if (sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete) {
            sigmaTxInfo->sTransactions.insert(hashTx);
        }
    }

    if (hasSigmaSpendInputs) {
        if (hasNonSigmaInputs) {
            // mixing sigma spend input with non-sigma inputs is prohibited
            return state.DoS(100, false,
                             REJECT_MALFORMED,
                             "CheckSigmaSpendTransaction: can't mix sigma spend input with regular ones");
        }
    }


    return true;
}

bool CheckSigmaMintTransaction(
        const CTxOut &txout,
        CValidationState &state,
        uint256 hashTx,
        CSigmaTxInfo *sigmaTxInfo) {
    secp_primitives::GroupElement pubCoinValue;

    try {
        pubCoinValue = ParseSigmaMintScript(txout.scriptPubKey);
    } catch (std::invalid_argument&) {
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : PubCoin validation failed");
    }

    sigma::CoinDenomination denomination;
    if (!sigma::IntegerToDenomination(txout.nValue, denomination, state)) {
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CTransaction::CheckSigmaMintTransaction() : "
                "PubCoin validation failed, unknown denomination");
    }
    sigma::PublicCoin pubCoin(pubCoinValue, denomination);
    bool hasCoin = sigmaState.HasCoin(pubCoin);

    if (!hasCoin && sigmaTxInfo && !sigmaTxInfo->fInfoIsComplete) {
        for(const sigma::PublicCoin& mint: sigmaTxInfo->mints) {
            if (mint == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    /*
    if (hasCoin) {
        LogPrintf("CheckSigmaMintTransaction(): double mint, tx=%s\n",
                txout.GetHash().ToString());
    }
    */

    if (!pubCoin.validate())
        return state.DoS(100,
                false,
                PUBCOIN_NOT_VALIDATE,
                "CheckSigmaTransaction : PubCoin validation failed");

    if (sigmaTxInfo != NULL && !sigmaTxInfo->fInfoIsComplete) {
        // Update public coin list in the info
        sigmaTxInfo->mints.push_back(pubCoin);
        sigmaTxInfo->sTransactions.insert(hashTx);
    }

    return true;
}

bool CheckSigmaTransaction(
        const CTransaction &tx,
        CValidationState &state,
        uint256 hashTx,
        bool isVerifyDB,
        int nHeight,
        bool isCheckWallet,
        CSigmaTxInfo *sigmaTxInfo)
{

    bool sigmaIsEnabled = false;;

    {
        LOCK(cs_main);
        if(nHeight == INT_MAX)
            sigmaIsEnabled = (chainActive.Height() >= Params().GetConsensus().nSigmaStartBlock);
        else
            sigmaIsEnabled = nHeight >= Params().GetConsensus().nSigmaStartBlock;
    }

    // Check Mint Sigma Transaction
    if (sigmaIsEnabled) {
        for (const CTxOut &txout : tx.vout) {
            if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsSigmaMint()) {
                if (!CheckSigmaMintTransaction(txout, state, hashTx, sigmaTxInfo))
                    return false;
            }
        }
    }

    // Check Spend Sigma Transaction
    if(tx.IsSigmaSpend()) {
        vector<sigma::CoinDenomination> denominations;
        uint64_t totalValue = 0;
        for(const CTxIn &txin: tx.vin){
            if(!txin.scriptSig.IsSigmaSpend()) {
                return state.DoS(100, false,
                                 REJECT_MALFORMED,
                                 "CheckSigmaSpendTransaction: can't mix sigma spend input with regular ones");
            }
            // Get the CoinDenomination value of each vin for the CheckSigmaSpendTransaction function
            uint32_t pubcoinId = txin.prevout.n;
            if (pubcoinId < 1 || pubcoinId >= INT_MAX) {
                // coin id should be positive integer
                return false;
            }

            CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 1),
                                            (const char *)&*txin.scriptSig.end(),
                                            SER_NETWORK, PROTOCOL_VERSION);
            sigma::CoinSpend newSpend(SParams, serializedCoinSpend);
            uint64_t denom = newSpend.getIntDenomination();
            totalValue += denom;
            sigma::CoinDenomination denomination;
            if (!sigma::IntegerToDenomination(denom, denomination, state))
                return false;
            denominations.push_back(denomination);
        }

        // Check vOut
        // Only one loop, we checked on the format before entering this case
        if (!isVerifyDB) {
            if (!CheckSigmaSpendTransaction(
                tx, denominations, state, hashTx, isVerifyDB, nHeight,
                isCheckWallet, sigmaTxInfo)) {
                    return false;
            }
        }
    }

    return true;
}

void DisconnectTipSigma(CBlock & /*block*/, CBlockIndex *pindexDelete) {
    sigmaState.RemoveBlock(pindexDelete);
}

Scalar SigmaGetSpendSerialNumber(const CTransaction &tx, const CTxIn &txin) {
    if (!tx.IsSigmaSpend())
        return Scalar(uint64_t(0));

    try {
        CDataStream serializedCoinSpend(
                (const char *)&*(txin.scriptSig.begin() + 1),
                (const char *)&*txin.scriptSig.end(),
                SER_NETWORK, PROTOCOL_VERSION);
        sigma::CoinSpend spend(SParams, serializedCoinSpend);
        return spend.getCoinSerialNumber();
    }
    catch (const std::ios_base::failure &) {
        return Scalar(uint64_t(0));
    }
}

CAmount GetSpendTransactionInput(const CTransaction &tx) {
    if (!tx.IsSigmaSpend())
        return CAmount(0);

    try {
        CAmount sum(0);
        for(const CTxIn& txin: tx.vin){
            CDataStream serializedCoinSpend(
                    (const char *)&*(txin.scriptSig.begin() + 1),
                    (const char *)&*txin.scriptSig.end(),
                    SER_NETWORK, PROTOCOL_VERSION);
            sigma::CoinSpend spend(SParams, serializedCoinSpend);
            sum += spend.getIntDenomination();
        }
        return sum;
    }
    catch (const std::runtime_error &) {
        return CAmount(0);
    }
}


/**
 * Connect a new sigma block to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockSigma(
        CValidationState &state,
        const CChainParams &chainparams,
        CBlockIndex *pindexNew,
        const CBlock *pblock,
        bool fJustCheck) {
    // Add sigma transaction information to index
    if (pblock && pblock->sigmaTxInfo) {
        
        if (!fJustCheck)
            pindexNew->spentSerials.clear();
        
        for(auto& serial: pblock->sigmaTxInfo->spentSerials) {
            if (!CheckSigmaSpendSerial(state, pblock->sigmaTxInfo.get(), serial.first,
                                       pindexNew->nHeight, true /* fConnectTip */)) {
                return false;
            }
            
            if (!fJustCheck) {
                pindexNew->spentSerialsV2.insert(serial.first);
                sigmaState.AddSpend(serial.first);
            }
        }

        if (!(pindexNew->nHeight >= Params().GetConsensus().nSigmaStartBlock) && !pblock->sigmaTxInfo->mints.empty())
            return state.DoS(0, error("ConnectBlockSigma :  sigma mints not allowed until a given block"));
        if (fJustCheck)
            return true;
        
        // Update pindexNew.mintedPubCoins
        for(const sigma::PublicCoin& mint: pblock->sigmaTxInfo->mints) {
            sigma::CoinDenomination denomination = mint.getDenomination();
            int mintId = sigmaState.AddMint(pindexNew,	mint);
            
            //LogPrintf("ConnectTipSigma: mint added denomination=%d, id=%d\n", denomination, mintId);
            pair<sigma::CoinDenomination, int> denomAndId = make_pair(denomination, mintId);
            pindexNew->mintedPubCoinsV2[denomAndId].push_back(mint);
        }
    }
    else if (!fJustCheck) {
        sigmaState.AddBlock(pindexNew);
    }
    return true;
}


bool SigmaBuildStateFromIndex(CChain *chain) {
    sigmaState.Reset();
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
    {
        sigmaState.AddBlock(blockIndex);
    }
    // DEBUG
    LogPrintf(
        "Latest IDs for sigma coin groups are %d, %d, %d, %d, %d\n",
        sigmaState.GetLatestCoinID(sigma::CoinDenomination::SIGMA_0_1),
        sigmaState.GetLatestCoinID(sigma::CoinDenomination::SIGMA_1),
        sigmaState.GetLatestCoinID(sigma::CoinDenomination::SIGMA_10),
        sigmaState.GetLatestCoinID(sigma::CoinDenomination::SIGMA_100),
        sigmaState.GetLatestCoinID(sigma::CoinDenomination::SIGMA_1000));
    return true;
}

// CSigmaTxInfo

void CSigmaTxInfo::Complete() {
    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it. Denomination doesn't matter but we will sort by it as well
    sort(mints.begin(), mints.end(),
            [](decltype(mints)::const_reference m1, decltype(mints)::const_reference m2)->bool {
            CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
            ds1 << m1;
            ds2 << m2;
            return ds1.str() < ds2.str();
            });

    // Mark this info as complete
    fInfoIsComplete = true;
}

// CSigmaState

CSigmaState::CSigmaState() {
}

int CSigmaState::AddMint(
        CBlockIndex *index,
        const sigma::PublicCoin &pubCoin) {
    sigma::CoinDenomination denomination = pubCoin.getDenomination();

    if (latestCoinIds[denomination] < 1)
        latestCoinIds[denomination] = 1;
    int	mintCoinGroupId = latestCoinIds[denomination];

    // ZC_SPEND__COINSPERID = 15.000, yet the actual limit of coins per accumlator is 16.000.
    // We need to cut at 15.000, such that we always have enough space for new mints. Mints for
    // each block will end up in the same accumulator.
    CoinGroupInfo &coinGroup = coinGroups[make_pair(denomination, mintCoinGroupId)];
    int coinsPerId = COINS_PER_ID;
    if (coinGroup.nCoins < coinsPerId // there's still space in the accumulator
        || coinGroup.lastBlock == index // or we have already placed some coins from current block.
        ) {
        if (coinGroup.nCoins++ == 0) {
            // first group of coins for given denomination
            coinGroup.firstBlock = coinGroup.lastBlock = index;
        }
        else {
            coinGroup.lastBlock = index;
        }
    }
    else {
        latestCoinIds[denomination] = ++mintCoinGroupId;
        CoinGroupInfo& newCoinGroup = coinGroups[std::make_pair(denomination, mintCoinGroupId)];
        newCoinGroup.firstBlock = newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins = 1;
    }
    CMintedCoinInfo coinInfo;
    coinInfo.denomination = denomination;
    coinInfo.id = mintCoinGroupId;
    coinInfo.nHeight = index->nHeight;
    mintedPubCoins.insert(std::make_pair(pubCoin, coinInfo));
    return mintCoinGroupId;
}

void CSigmaState::AddSpend(const Scalar &serial) {
    usedCoinSerials.insert(serial);
}

void CSigmaState::AddBlock(CBlockIndex *index) {
    for(
        const PAIRTYPE(PAIRTYPE(sigma::CoinDenomination, int), vector<sigma::PublicCoin>) &pubCoins:
            index->mintedPubCoinsV2) {
        if (!pubCoins.second.empty()) {
            CoinGroupInfo& coinGroup = coinGroups[pubCoins.first];

            if (coinGroup.firstBlock == NULL)
                coinGroup.firstBlock = index;
            coinGroup.lastBlock = index;
            coinGroup.nCoins += pubCoins.second.size();
        }

        latestCoinIds[pubCoins.first.first] = pubCoins.first.second;
        for(const sigma::PublicCoin &coin: pubCoins.second) {
            CMintedCoinInfo coinInfo;
            coinInfo.denomination = pubCoins.first.first;
            coinInfo.id = pubCoins.first.second;
            coinInfo.nHeight = index->nHeight;
            mintedPubCoins.insert(pair<sigma::PublicCoin, CMintedCoinInfo>(coin, coinInfo));
        }
    }

    for(const Scalar &serial: index->spentSerialsV2) {
        usedCoinSerials.insert(serial);
    }
}

void CSigmaState::RemoveBlock(CBlockIndex *index) {
    // roll back accumulator updates
    for(
        const PAIRTYPE(PAIRTYPE(sigma::CoinDenomination, int),vector<sigma::PublicCoin>) &coin:
        index->mintedPubCoinsV2)
    {
        CoinGroupInfo   &coinGroup = coinGroups[coin.first];
        int  nMintsToForget = coin.second.size();

        assert(coinGroup.nCoins >= nMintsToForget);

        if ((coinGroup.nCoins -= nMintsToForget) == 0) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(coin.first);
            // decrease pubcoin id for this denomination
            latestCoinIds[coin.first.first]--;
        }
        else {
            // roll back lastBlock to previous position
            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->mintedPubCoinsV2.count(coin.first) == 0);
        }
    }

    // roll back mints
    for(const PAIRTYPE(PAIRTYPE(sigma::CoinDenomination, int),vector<sigma::PublicCoin>) &pubCoins:
                  index->mintedPubCoinsV2) {
        for(const sigma::PublicCoin &coin: pubCoins.second) {
            auto coins = mintedPubCoins.equal_range(coin);
            auto coinIt = find_if(
                coins.first, coins.second,
                [=](const decltype(mintedPubCoins)::value_type &v) {
                    return v.second.denomination == pubCoins.first.first &&
                        v.second.id == pubCoins.first.second;
                });
            assert(coinIt != coins.second);
            mintedPubCoins.erase(coinIt);
        }
    }
    index->mintedPubCoinsV2.clear();
    // roll back spends
    for(const Scalar &serial: index->spentSerialsV2) {
        usedCoinSerials.erase(serial);
    }
    index->spentSerialsV2.clear();
}

bool CSigmaState::GetCoinGroupInfo(
        sigma::CoinDenomination denomination,
        int group_id,
        CoinGroupInfo& result) {
    std::pair<sigma::CoinDenomination, int> key =
        std::make_pair(denomination, group_id);
    if (coinGroups.count(key) == 0)
        return false;

    result = coinGroups[key];
    return true;
}

bool CSigmaState::IsUsedCoinSerial(const Scalar &coinSerial) {
    return usedCoinSerials.count(coinSerial) != 0;
}

bool CSigmaState::HasCoin(const sigma::PublicCoin& pubCoin) {
    return mintedPubCoins.find(pubCoin) != mintedPubCoins.end();
}

int CSigmaState::GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        sigma::CoinDenomination denomination,
        int coinGroupID,
        uint256& blockHash_out,
        std::vector<sigma::PublicCoin>& coins_out) {

    pair<sigma::CoinDenomination, int> denomAndId = std::make_pair(denomination, coinGroupID);

    if (coinGroups.count(denomAndId) == 0)
        return 0;

    CoinGroupInfo coinGroup = coinGroups[denomAndId];

    int numberOfCoins = 0;
    for (CBlockIndex *block = coinGroup.lastBlock;
            ;
            block = block->pprev) {
        if (block->mintedPubCoinsV2[denomAndId].size() > 0) {
            if (block->nHeight <= maxHeight) {
                if (numberOfCoins == 0) {
                    // latest block satisfying given conditions
                    // remember block hash
                    blockHash_out = block->GetBlockHash();
                }
                numberOfCoins += block->mintedPubCoinsV2[denomAndId].size();
                coins_out.insert(coins_out.end(),
                        block->mintedPubCoinsV2[denomAndId].begin(),
                        block->mintedPubCoinsV2[denomAndId].end());
            }
        }
        if (block == coinGroup.firstBlock) {
            break ;
        }
    }
    return numberOfCoins;
}

std::pair<int, int> CSigmaState::GetMintedCoinHeightAndId(
        const sigma::PublicCoin& pubCoin) {
    auto coinIt = mintedPubCoins.find(pubCoin);

    if (coinIt != mintedPubCoins.end()) {
        return std::make_pair(coinIt->second.nHeight, coinIt->second.id);
    }
    return std::make_pair(-1, -1);
}

bool CSigmaState::AddSpendToMempool(const vector<Scalar> &coinSerials, uint256 txHash) {
    for(Scalar coinSerial: coinSerials){
        if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
            return false;

        mempoolCoinSerials[coinSerial] = txHash;
    }

    return true;
}

bool CSigmaState::AddSpendToMempool(const Scalar &coinSerial, uint256 txHash) {
    if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
        return false;

    mempoolCoinSerials[coinSerial] = txHash;
    return true;
}

void CSigmaState::RemoveSpendFromMempool(const Scalar& coinSerial) {
    mempoolCoinSerials.erase(coinSerial);
}

uint256 CSigmaState::GetMempoolConflictingTxHash(const Scalar& coinSerial) {
    if (mempoolCoinSerials.count(coinSerial) == 0)
        return uint256();

    return mempoolCoinSerials[coinSerial];
}

bool CSigmaState::CanAddSpendToMempool(const Scalar& coinSerial) {
    return !IsUsedCoinSerial(coinSerial) && mempoolCoinSerials.count(coinSerial) == 0;
}

bool CSigmaState::AddMintToMempool(const sigma::PublicCoin &coinMint, uint256 txHash) {
    if (HasCoin(coinMint) || mempoolCoinMints.count(coinMint))
        return false;

    mempoolCoinMints[coinMint] = txHash;
    return true;
}

void CSigmaState::RemoveMintFromMempool(const sigma::PublicCoin &coinMint) {
    mempoolCoinMints.erase(coinMint);
}

uint256 CSigmaState::GetMempoolMintConflictingTxHash(const sigma::PublicCoin &coinMint) {
    if (mempoolCoinMints.count(coinMint) == 0)
        return uint256();

    return mempoolCoinMints[coinMint];
}

bool CSigmaState::CanAddMintToMempool(const sigma::PublicCoin &coinMint) {
    return !HasCoin(coinMint) && mempoolCoinMints.count(coinMint) == 0;
}


void CSigmaState::Reset() {
    coinGroups.clear();
    usedCoinSerials.clear();
    latestCoinIds.clear();
    mintedPubCoins.clear();
    mempoolCoinSerials.clear();
}

CSigmaState* CSigmaState::GetSigmaState() {
    return &sigmaState;
}

int CSigmaState::GetLatestCoinID(sigma::CoinDenomination denomination) const {
    auto iter = latestCoinIds.find(denomination);
    if (iter == latestCoinIds.end()) {
        // Do not throw here, if there was no sigma mint, that's fine.
        return 0;
    }
    return iter->second;
}

bool CSigmaState::HasCoinHash(GroupElement &pubCoinValue, const uint256 &pubCoinValueHash) {
    for ( auto it = mintedPubCoins.begin(); it != mintedPubCoins.end(); ++it ){
        sigma::PublicCoin pubCoin = (*it).first;
        if(GetPubCoinValueHash(pubCoin.getValue())==pubCoinValueHash){
            pubCoinValue = pubCoin.getValue();
            return true;
        }
    }
    return false;
}

bool CSigmaState::IsUsedCoinSerialHash(Scalar &coinSerial, const uint256 &coinSerialHash) {
    for ( auto it = usedCoinSerials.begin(); it != usedCoinSerials.end(); ++it ){
        if(GetSerialHash(*it)==coinSerialHash){
            coinSerial = *it;
            return true;
        }
    }
    return false;
}


bool SigmaGetMintTxHash(uint256& txHash, GroupElement pubCoinValue) {
    int mintHeight = 0;
    int coinId = 0;

    CSigmaState *sigmaState = CSigmaState::GetSigmaState();
    std::vector<sigma::CoinDenomination> denominations;
    sigma::GetAllDenoms(denominations);
    for(sigma::CoinDenomination denomination: denominations){
        sigma::PublicCoin pubCoin(pubCoinValue, denomination);
        auto mintedCoinHeightAndId = sigmaState->GetMintedCoinHeightAndId(pubCoin);
        mintHeight = mintedCoinHeightAndId.first;
        coinId = mintedCoinHeightAndId.second;
        if(mintHeight!=-1 && coinId!=-1)
            break;
    }

    if(mintHeight==-1 && coinId==-1)
        return false;

    // get block containing mint
    CBlockIndex *mintBlock;

    {
        LOCK(cs_main);
        mintBlock = chainActive[mintHeight];
    }

    CBlock block;
    if(!ReadBlockFromDisk(block, mintBlock, Params().GetConsensus()))
        LogPrintf("can't read block from disk.\n");

    secp_primitives::GroupElement txPubCoinValue;
    // cycle transaction hashes, looking for this pubcoin.
    for(CTransactionRef tx: block.vtx){
        if(tx->IsSigmaMint()){
            for (const CTxOut &txout: tx->vout) {
                if (txout.scriptPubKey.IsSigmaMint()){

                    vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                                          txout.scriptPubKey.end());
                    txPubCoinValue.deserialize(&coin_serialised[0]);
                    if(pubCoinValue==txPubCoinValue){
                        txHash = tx->GetHash();
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

bool SigmaGetMintTxHash(uint256& txHash, uint256 pubCoinValueHash) {
    GroupElement pubCoinValue;
    if(!sigmaState.HasCoinHash(pubCoinValue, pubCoinValueHash)){
        return false;
    }

    return SigmaGetMintTxHash(txHash, pubCoinValue);
}
