#include "zerocoin.h"
#include "timedata.h"
#include "util.h"
#include "base58.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include <atomic>
#include <sstream>
#include <chrono>
#include <boost/foreach.hpp>
#include "utilstrencodings.h"
#include "consensus/airdropaddresses.h"

using namespace std;
using namespace boost;

// btzc: add zerocoin init
// zerocoin init
static CBigNum bnTrustedModulus(ZEROCOIN_MODULUS);
static CBigNum bnTrustedSeed(ZEROCOIN_SEED);
// Set up the Zerocoin Params object
libzerocoin::Params *ZCParams = new libzerocoin::Params(bnTrustedModulus, bnTrustedSeed);


static CZerocoinState zerocoinState;

static map<uint256, int64_t> ghostedCoins;

static bool CheckZerocoinSpendSerial(CValidationState &state, CZerocoinTxInfo *zerocoinTxInfo, libzerocoin::CoinDenomination denomination, const CBigNum &serial, int nHeight, bool fConnectTip) {
    // check for zerocoin transaction in this block as well
    if (zerocoinTxInfo && !zerocoinTxInfo->fInfoIsComplete && zerocoinTxInfo->spentSerials.count(serial) > 0)
        return state.DoS(0, error("CTransaction::CheckTransaction() : two or more spends with same serial in the same block"));

    // check for used serials in zerocoinState
    if (zerocoinState.IsUsedCoinSerial(serial)) {
        // Proceed with checks ONLY if we're accepting tx into the memory pool or connecting block to the existing blockchain
        if (nHeight == INT_MAX || fConnectTip) {
            return state.DoS(0, error("CTransaction::CheckTransaction() : The CoinSpend serial has been used"));
        }
    }


    return true;
}

bool CheckSpendZerocoinTransaction(const CTransaction &tx,
                                libzerocoin::CoinDenomination targetDenomination,
                                CValidationState &state,
                                uint256 hashTx,
                                bool isVerifyDB,
                                int nHeight,
                                bool isCheckWallet,
                                CZerocoinTxInfo *zerocoinTxInfo, int indexOfSpend) {

    // Check for inputs only, everything else was checked before
    LogPrintf("CheckSpendZerocoinTransaction denomination=%d nHeight=%d\n", targetDenomination, nHeight);

    const CTxIn &txin = tx.vin[indexOfSpend];

    if (!txin.scriptSig.IsZerocoinSpend())
        return state.DoS(100,
                         false,
                         NSEQUENCE_INCORRECT,
                         "CTransaction::CheckTransaction() : Error: zerocoin spend txin not a zerocoin spend script");

    uint32_t pubcoinId = txin.nSequence;
    if (pubcoinId < 1 || pubcoinId >= INT_MAX) {
        // coin id should be positive integer
        return state.DoS(100,
                         false,
                         NSEQUENCE_INCORRECT,
                         "CTransaction::CheckTransaction() : Error: zerocoin spend nSequence is incorrect");
    }

    if (txin.scriptSig.size() < 4)
        return state.DoS(100,
                         false,
                         REJECT_MALFORMED,
                         "CheckSpendZerocoinTransaction: invalid spend transaction");

    // Deserialize the CoinSpend intro a fresh object
    CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                    (const char *)&*txin.scriptSig.end(),
                                    SER_NETWORK, PROTOCOL_VERSION);
    libzerocoin::CoinSpend newSpend(ZCParams, serializedCoinSpend);

    int spendVersion = newSpend.getVersion();
    if (spendVersion != ZEROCOIN_VERSION_1) {
        return state.DoS(100,
                         false,
                         NSEQUENCE_INCORRECT,
                         "CTransaction::CheckTransaction() : Error: incorrect spend transaction verion");
    }




    spendVersion = ZEROCOIN_VERSION_1;
    newSpend.setVersion(ZEROCOIN_VERSION_1);



    uint256 txHashForMetadata;

    if (spendVersion >= ZEROCOIN_VERSION_1) {
        // Obtain the hash of the transaction sans the zerocoin part
        CMutableTransaction txTemp = tx;
        BOOST_FOREACH(CTxIn &txTempIn, txTemp.vin) {
            if (txTempIn.scriptSig.IsZerocoinSpend()) {
                txTempIn.scriptSig.clear();
                txTempIn.prevout.SetNull();
            }
        }
        txHashForMetadata = txTemp.GetHash();
    }


    libzerocoin::SpendMetaData newMetadata(txin.nSequence, txHashForMetadata);


    CZerocoinState::CoinGroupInfo coinGroup;
    if (!zerocoinState.GetCoinGroupInfo(targetDenomination, pubcoinId, coinGroup))
        return state.DoS(100, false, NO_MINT_ZEROCOIN, "CheckSpendZerocoinTransaction: Error: no coins were minted with such parameters at height %d", nHeight);

    bool passVerify = false;
    CBlockIndex *index = coinGroup.lastBlock;
    pair<int,int> denominationAndId = make_pair(targetDenomination, pubcoinId);


    bool spendHasBlockHash;

    // Zerocoin  transaction can cointain block hash of the last mint tx seen at the moment of spend. It speeds
    // up verification
    if (spendVersion >= ZEROCOIN_VERSION_1 && !newSpend.getAccumulatorBlockHash().IsNull()) {
        spendHasBlockHash = true;
        uint256 accumulatorBlockHash = newSpend.getAccumulatorBlockHash();

        // find index for block with hash of accumulatorBlockHash or set index to the coinGroup.firstBlock if not found
        while (index != coinGroup.firstBlock && index->GetBlockHash() != accumulatorBlockHash)
            index = index->pprev;
    }

    // Enumerate all the accumulator changes seen in the blockchain starting with the latest block
    // In most cases the latest accumulator value will be used for verification
    do {
        if (index->accumulatorChanges.count(denominationAndId) > 0) {
            libzerocoin::Accumulator accumulator(ZCParams,
                                                 index->accumulatorChanges[denominationAndId].first,
                                                 targetDenomination);
            LogPrintf("CheckSpendZerocoinTransaction: accumulator=%s\n", accumulator.getValue().ToString().substr(0,15));
            passVerify = newSpend.Verify(accumulator, newMetadata);

        }

        if (index == coinGroup.firstBlock || spendHasBlockHash)
            break;
        else
            index = index->pprev;
    } while (!passVerify);

    if (passVerify) {

        CBigNum serial = newSpend.getCoinSerialNumber();
        // do not check for duplicates in case we've seen exact copy of this tx in this block before
        if (!(zerocoinTxInfo && zerocoinTxInfo->zcTransactions.count(hashTx) > 0)) {
            if (!CheckZerocoinSpendSerial(state, zerocoinTxInfo, newSpend.getDenomination(), serial, nHeight, false))
                return state.DoS(100, error("CheckZerocoinTransaction : invalid zerocoin spend serial"));
        }
        //batching transactions, make sure the same serial is not used twice
        else if(tx.vout.size() > 1){
            if (!CheckZerocoinSpendSerial(state, zerocoinTxInfo, newSpend.getDenomination(), serial, nHeight, false))
                return state.DoS(100, error("CheckZerocoinTransaction : invalid zerocoin spend, serial used twice"));
        }

        if(!isVerifyDB && !isCheckWallet) {
            if (zerocoinTxInfo && !zerocoinTxInfo->fInfoIsComplete) {
                // add spend information to the index
                zerocoinTxInfo->spentSerials[serial] = (int)newSpend.getDenomination();
                zerocoinTxInfo->zcTransactions.insert(hashTx);

            }
        }
    }
    else {
        return false;
    }

    return true;
}

bool CheckMintZerocoinTransaction(const CTxOut &txout,
                               CValidationState &state,
                               uint256 hashTx,
                               CZerocoinTxInfo *zerocoinTxInfo) {

    if (txout.scriptPubKey.size() < 6)
        return state.DoS(100,
            false,
            PUBCOIN_NOT_VALIDATE,
            "CTransaction::CheckTransaction() : PubCoin validation failed");

    CBigNum pubCoin(vector<unsigned char>(txout.scriptPubKey.begin()+6, txout.scriptPubKey.end()));

    bool hasCoin = zerocoinState.HasCoin(pubCoin);

    if (!hasCoin && zerocoinTxInfo && !zerocoinTxInfo->fInfoIsComplete) {
        BOOST_FOREACH(const PAIRTYPE(int,CBigNum) &mint, zerocoinTxInfo->mints) {
            if (mint.second == pubCoin) {
                hasCoin = true;
                break;
            }
        }
    }

    if (hasCoin) {
        /*return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckZerocoinTransaction: duplicate mint");*/
        //LogPrintf("CheckMintZerocoinTransaction: double mint, tx=%s\n", txout.GetHash().ToString());
    }

    switch (txout.nValue) {
    default:
        return state.DoS(100,
                         false,
                         PUBCOIN_NOT_VALIDATE,
                         "CheckZerocoinTransaction : PubCoin denomination is invalid");

    case libzerocoin::ZQ_ONE*COIN:
    case libzerocoin::ZQ_FIVE*COIN:
    case libzerocoin::ZQ_TEN*COIN:
    case libzerocoin::ZQ_FIFTY*COIN:
    case libzerocoin::ZQ_ONE_HUNDRED*COIN:
    case libzerocoin::ZQ_FIVE_HUNDRED*COIN:
    case libzerocoin::ZQ_ONE_THOUSAND*COIN:
    case libzerocoin::ZQ_FIVE_THOUSAND*COIN:
        libzerocoin::CoinDenomination denomination = (libzerocoin::CoinDenomination)(txout.nValue / COIN);
        libzerocoin::PublicCoin checkPubCoin(ZCParams, pubCoin, denomination);
        if (!checkPubCoin.validate())
            return state.DoS(100,
                             false,
                             PUBCOIN_NOT_VALIDATE,
                             "CheckZerocoinTransaction : PubCoin validation failed");

        if (zerocoinTxInfo != NULL && !zerocoinTxInfo->fInfoIsComplete) {
            // Update public coin list in the info
            zerocoinTxInfo->mints.push_back(make_pair(denomination, pubCoin));
            zerocoinTxInfo->zcTransactions.insert(hashTx);
        }
        break;
    }


    return true;
}

bool CheckDevFundInputs(const CTransaction &tx, CValidationState &state, int nHeight, bool fTestNet) {

    //checks blocks on startup, no need to verify
    if(nHeight == INT_MAX)
        return true;

    // To airdrop
    if(Params().GetConsensus().nPosHeightActivate > nHeight){
        if (nHeight == 1) {

            //Split 38m into 100 unique addresses for faster tx processing
            CAmount airdropValuePerAddress = GetBlockSubsidy(nHeight, Params().GetConsensus())/100;

            bool found_1 = false;

            CScript AIRDROP_SCRIPT;

            std::string addresses;

            if (!fTestNet) {
                for(int i = 0; i < 100; i++){
                    addresses = airdrop_addresses[i];
                    AIRDROP_SCRIPT = GetScriptForDestination(DecodeDestination(addresses));
                    found_1 = false;
                    BOOST_FOREACH(const CTxOut &output, tx.vout) {
                        //check for first 93 address with 3.8m
                        if (output.scriptPubKey == AIRDROP_SCRIPT && output.nValue == (int64_t)(airdropValuePerAddress)) {
                            found_1 = true;
                            break;
                        }
                        //check for the stacked address
                        else if (output.scriptPubKey == AIRDROP_SCRIPT && output.nValue == (int64_t)((airdropValuePerAddress * 7) - (240000*COIN))) {
                            found_1 = true;
                            break;
                        }
                        //check for 6 ghosnode outputs
                        else if (output.scriptPubKey == AIRDROP_SCRIPT && output.nValue == (int64_t)(40000*COIN)) {
                            found_1 = true;
                            break;
                        }
                    }
                    if (!(found_1)) {
                        return state.DoS(100, false, REJECT_FOUNDER_REWARD_MISSING,
                                         "CTransaction::CheckTransaction() : airdrop funds missing");
                    }
                }
            }
        }

        if (nHeight >= 2) {
            bool found_1 = false;
            bool found_2 = false;

            CScript DEV_1_SCRIPT;
            CScript DEV_2_SCRIPT;

            if (!fTestNet) {
                DEV_1_SCRIPT = GetScriptForDestination(DecodeDestination("NVbGEghDbxPUe97oY8N5RvagQ61cHQiouW"));
                DEV_2_SCRIPT = GetScriptForDestination(DecodeDestination("NWF7QNfT1b8a9dSQmVTT6hcwzwEVYVmDsG"));

                //7% development fee total
                BOOST_FOREACH(const CTxOut &output, tx.vout) {
                    //5% for first address
                    if (output.scriptPubKey == DEV_1_SCRIPT && output.nValue == (int64_t)(0.05 * GetBlockSubsidy(nHeight, Params().GetConsensus()))) {
                        found_1 = true;
                    }
                    //2% for second address
                    if (output.scriptPubKey == DEV_2_SCRIPT && output.nValue == (int64_t)(0.02 * GetBlockSubsidy(nHeight, Params().GetConsensus()))) {
                        found_2 = true;
                    }
                }

                if (!(found_1 && found_2)) {
                    return state.DoS(100, false, REJECT_FOUNDER_REWARD_MISSING,
                                     "CTransaction::CheckTransaction() : dev reward missing");
                }
            }
        }

        /* Check for Ghostnode payment in block */

        if(nHeight >= Params().GetConsensus().nGhostnodePaymentsStartBlock){

            int total_payment_tx = 0;
            CAmount ghostnodePayment = GetGhostnodePayment(nHeight, 0);

            BOOST_FOREACH(const CTxOut &output, tx.vout) {
                if (ghostnodePayment == output.nValue) {
                    total_payment_tx = total_payment_tx + 1;
                }
            }
            // no more than 1 output for payment, possible no winner if list is not populated
            if (total_payment_tx > 1) {
                return state.DoS(100, false, REJECT_INVALID_GHOSTNODE_PAYMENT,
                                 "CTransaction::CheckTransaction() : invalid ghostnode payment");
            }
        }
    }
    //PoS reward distribution
    else{

        bool found_1 = false;
        bool found_2 = false;

        CScript DEV_1_SCRIPT;
        CScript DEV_2_SCRIPT;

        if (!fTestNet) {
            DEV_1_SCRIPT = GetScriptForDestination(DecodeDestination("NVbGEghDbxPUe97oY8N5RvagQ61cHQiouW"));
            DEV_2_SCRIPT = GetScriptForDestination(DecodeDestination("NWF7QNfT1b8a9dSQmVTT6hcwzwEVYVmDsG"));

            //7% development fee total
            BOOST_FOREACH(const CTxOut &output, tx.vout) {
                //5% for first address
                if (output.scriptPubKey == DEV_1_SCRIPT && output.nValue == (int64_t)(DEVELOPMENT_REWARD_POST_POS/2 * GetBlockSubsidy(nHeight, Params().GetConsensus()))) {
                    found_1 = true;
                }
                //2% for second address
                if (output.scriptPubKey == DEV_2_SCRIPT && output.nValue == (int64_t)(DEVELOPMENT_REWARD_POST_POS/2 * GetBlockSubsidy(nHeight, Params().GetConsensus()))) {
                    found_2 = true;
                }
            }

            if (!(found_1 && found_2)) {
                return state.DoS(100, false, REJECT_FOUNDER_REWARD_MISSING,
                                 "CTransaction::CheckTransaction() : dev reward missing");
            }
        }

        /* Check for Ghostnode payment in block */

        if(nHeight >= Params().GetConsensus().nGhostnodePaymentsStartBlock){

            int total_payment_tx = 0;
            CAmount ghostnodePayment = GetGhostnodePayment(nHeight, 0);

            BOOST_FOREACH(const CTxOut &output, tx.vout) {
                if (output.nValue >= ghostnodePayment) {
                    total_payment_tx = total_payment_tx + 1;
                }
            }
            // no more than 1 output for payment, possible no winner if list is not populated
            if (total_payment_tx > 1) {
                return state.DoS(100, false, REJECT_INVALID_GHOSTNODE_PAYMENT,
                                 "CTransaction::CheckTransaction() : invalid ghostnode payment");
            }
        }
    }

    return true;
}

bool CheckZerocoinTransaction(const CTransaction &tx,
                              CValidationState &state,
                              uint256 hashTx,
                              bool isVerifyDB,
                              int nHeight,
                              bool isCheckWallet,
                              CZerocoinTxInfo *zerocoinTxInfo)
{
    // Check Mint Zerocoin Transaction
    BOOST_FOREACH(const CTxOut &txout, tx.vout) {
        if (!txout.scriptPubKey.empty() && txout.scriptPubKey.IsZerocoinMint()) {
            if (!CheckMintZerocoinTransaction(txout, state, hashTx, zerocoinTxInfo))
                return false;
        }
    }

    // Check Spend Zerocoin Transaction
    if(tx.IsZerocoinSpend()) {
        // Check vOut
        int i = 0;
        BOOST_FOREACH(const CTxOut &txout, tx.vout)
        {
            if (!isVerifyDB) {
                switch (txout.nValue) {
                case libzerocoin::ZQ_ONE*COIN:
                case libzerocoin::ZQ_FIVE*COIN:
                case libzerocoin::ZQ_TEN*COIN:
                case libzerocoin::ZQ_FIFTY*COIN:
                case libzerocoin::ZQ_ONE_HUNDRED*COIN:
                case libzerocoin::ZQ_FIVE_HUNDRED*COIN:
                case libzerocoin::ZQ_ONE_THOUSAND*COIN:
                case libzerocoin::ZQ_FIVE_THOUSAND*COIN:
                    if(!CheckSpendZerocoinTransaction(tx, (libzerocoin::CoinDenomination)(txout.nValue / COIN), state, hashTx, isVerifyDB, nHeight, isCheckWallet, zerocoinTxInfo, i))
                            return false;
                    break;
                default:
                    return state.DoS(100, error("CheckZerocoinTransaction : invalid spending txout value"));
                }
            }
            ghostedCoins[hashTx] = tx.GetValueOut();
            i++;
        }
    }

    return true;
}

void DisconnectTipGhost(CBlock & /*block*/, CBlockIndex *pindexDelete) {
    zerocoinState.RemoveBlock(pindexDelete);
}


/**
 * Connect a new ZCblock to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectBlockGhost(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock) {

    // Add zerocoin transaction information to index
    if (pblock && pblock->zerocoinTxInfo) {

        pindexNew->spentSerials.clear();

        BOOST_FOREACH(const PAIRTYPE(CBigNum,int) &serial, pblock->zerocoinTxInfo->spentSerials) {
            pindexNew->spentSerials.insert(serial.first);
            if (!CheckZerocoinSpendSerial(state, pblock->zerocoinTxInfo.get(), (libzerocoin::CoinDenomination)serial.second, serial.first, pindexNew->nHeight, true))
                return false;
            zerocoinState.AddSpend(serial.first);
        }


        // Update minted values and accumulators
        BOOST_FOREACH(const PAIRTYPE(int,CBigNum) &mint, pblock->zerocoinTxInfo->mints) {
            int denomination = mint.first;
            CBigNum oldAccValue = ZCParams->accumulatorParams.accumulatorBase;
            int mintId = zerocoinState.AddMint(pindexNew, denomination, mint.second, oldAccValue);
            LogPrintf("ConnectTipZC: mint added denomination=%d, id=%d\n", denomination, mintId);
            pair<int,int> denomAndId = make_pair(denomination, mintId);

            pindexNew->mintedPubCoins[denomAndId].push_back(mint.second);

            CZerocoinState::CoinGroupInfo coinGroupInfo;
            zerocoinState.GetCoinGroupInfo(denomination, mintId, coinGroupInfo);

            libzerocoin::PublicCoin pubCoin(ZCParams, mint.second, (libzerocoin::CoinDenomination)denomination);
            libzerocoin::Accumulator accumulator(ZCParams,
                                                 oldAccValue,
                                                 (libzerocoin::CoinDenomination)denomination);
            accumulator += pubCoin;

            if (pindexNew->accumulatorChanges.count(denomAndId) > 0) {
                pair<CBigNum,int> &accChange = pindexNew->accumulatorChanges[denomAndId];
                accChange.first = accumulator.getValue();
                accChange.second++;
            }
            else {
                pindexNew->accumulatorChanges[denomAndId] = make_pair(accumulator.getValue(), 1);
            }
        }
    }
    else {
        zerocoinState.AddBlock(pindexNew);
    }

    // TODO: notify the wallet
    return true;
}

int ZerocoinGetNHeight(const CBlockHeader &block) {
    CBlockIndex *pindexPrev = NULL;
    int nHeight = 0;
    BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
    if (mi != mapBlockIndex.end()) {
        pindexPrev = (*mi).second;
        nHeight = pindexPrev->nHeight + 1;
    }
    return nHeight;
}


bool ZerocoinBuildStateFromIndex(CChain *chain, set<CBlockIndex *> &changes) {

    zerocoinState.Reset();
    for (CBlockIndex *blockIndex = chain->Genesis(); blockIndex; blockIndex=chain->Next(blockIndex))
        zerocoinState.AddBlock(blockIndex);

    changes = zerocoinState.RecalculateAccumulators(chain);
    // DEBUG
    LogPrintf("Latest IDs are %d, %d, %d, %d, %d, %d, %d, %d\n",
            zerocoinState.latestCoinIds[1],
            zerocoinState.latestCoinIds[5],
            zerocoinState.latestCoinIds[10],
            zerocoinState.latestCoinIds[50],
            zerocoinState.latestCoinIds[100],
            zerocoinState.latestCoinIds[500],
            zerocoinState.latestCoinIds[1000],
            zerocoinState.latestCoinIds[5000]);
    return true;
}

// CZerocoinTxInfo

void CZerocoinTxInfo::Complete() {
    // We need to sort mints lexicographically by serialized value of pubCoin. That's the way old code
    // works, we need to stick to it. Denomination doesn't matter but we will sort by it as well
    sort(mints.begin(), mints.end(),
         [](decltype(mints)::const_reference m1, decltype(mints)::const_reference m2)->bool {
            CDataStream ds1(SER_DISK, CLIENT_VERSION), ds2(SER_DISK, CLIENT_VERSION);
            ds1 << m1.second;
            ds2 << m2.second;
            return (m1.first < m2.first) || ((m1.first == m2.first) && (ds1.str() < ds2.str()));
         });

    // Mark this info as complete
    fInfoIsComplete = true;
}

// CZerocoinState::CBigNumHash

std::size_t CZerocoinState::CBigNumHash::operator ()(const CBigNum &bn) const noexcept {
    // we are operating on almost random big numbers and least significant bytes (save for few last bytes) give us a good hash
    vector<unsigned char> bnData = bn.ToBytes();
    if (bnData.size() < sizeof(size_t)*3)
        // rare case, put ones like that into one hash bin
        return 0;
    else
        return ((size_t*)bnData.data())[1];
}

// CZerocoinState

CZerocoinState::CZerocoinState() {
}

int CZerocoinState::AddMint(CBlockIndex *index, int denomination, const CBigNum &pubCoin, CBigNum &previousAccValue) {

    int mintId = 1;

    if (latestCoinIds[denomination] < 1)
        latestCoinIds[denomination] = mintId;
    else
        mintId = latestCoinIds[denomination];

    // There is a limit of 10 coins per group but mints belonging to the same block must have the same id thus going
    // beyond 10
    CoinGroupInfo &coinGroup = coinGroups[make_pair(denomination, mintId)];
    int coinsPerId = 10000;
    if (coinGroup.nCoins < coinsPerId || coinGroup.lastBlock == index) {
        if (coinGroup.nCoins++ == 0) {
            // first groups of coins for given denomination
            coinGroup.firstBlock = coinGroup.lastBlock = index;
        }
        else {
            previousAccValue = coinGroup.lastBlock->accumulatorChanges[make_pair(denomination,mintId)].first;
            coinGroup.lastBlock = index;
        }
    }
    else {
        latestCoinIds[denomination] = ++mintId;
        CoinGroupInfo &newCoinGroup = coinGroups[make_pair(denomination, mintId)];
        newCoinGroup.firstBlock = newCoinGroup.lastBlock = index;
        newCoinGroup.nCoins = 1;
    }

    CMintedCoinInfo coinInfo;
    coinInfo.denomination = denomination;
    coinInfo.id = mintId;
    coinInfo.nHeight = index->nHeight;
    mintedPubCoins.insert(pair<CBigNum,CMintedCoinInfo>(pubCoin, coinInfo));

    return mintId;
}

void CZerocoinState::AddSpend(const CBigNum &serial) {
    usedCoinSerials.insert(serial);
}

void CZerocoinState::AddBlock(CBlockIndex *index) {
    for(const pair<pair<int,int>, pair<CBigNum,int>> &accUpdate: index->accumulatorChanges)
    {
        CoinGroupInfo   &coinGroup = coinGroups[accUpdate.first];

        if (coinGroup.firstBlock == NULL)
            coinGroup.firstBlock = index;
        coinGroup.lastBlock = index;
        coinGroup.nCoins += accUpdate.second.second;
    }

    for(const pair<pair<int,int>,vector<CBigNum>> &pubCoins: index->mintedPubCoins) {
        latestCoinIds[pubCoins.first.first] = pubCoins.first.second;
        BOOST_FOREACH(const CBigNum &coin, pubCoins.second) {
            CMintedCoinInfo coinInfo;
            coinInfo.denomination = pubCoins.first.first;
            coinInfo.id = pubCoins.first.second;
            coinInfo.nHeight = index->nHeight;
            mintedPubCoins.insert(pair<CBigNum,CMintedCoinInfo>(coin, coinInfo));
        }
    }
    BOOST_FOREACH(const CBigNum &serial, index->spentSerials) {
        usedCoinSerials.insert(serial);
    }

}

void CZerocoinState::RemoveBlock(CBlockIndex *index) {
    // roll back accumulator updates
    for(const pair<pair<int,int>, pair<CBigNum,int>> &accUpdate: index->accumulatorChanges)
    {
        CoinGroupInfo   &coinGroup = coinGroups[accUpdate.first];
        int  nMintsToForget = accUpdate.second.second;

        assert(coinGroup.nCoins >= nMintsToForget);

        if ((coinGroup.nCoins -= nMintsToForget) == 0) {
            // all the coins of this group have been erased, remove the group altogether
            coinGroups.erase(accUpdate.first);
            // decrease pubcoin id for this denomination
            latestCoinIds[accUpdate.first.first]--;
        }
        else {
            // roll back lastBlock to previous position
            do {
                assert(coinGroup.lastBlock != coinGroup.firstBlock);
                coinGroup.lastBlock = coinGroup.lastBlock->pprev;
            } while (coinGroup.lastBlock->accumulatorChanges.count(accUpdate.first) == 0);
        }
    }

    // roll back mints
    for(const pair<pair<int,int>,vector<CBigNum>> &pubCoins: index->mintedPubCoins) {
        BOOST_FOREACH(const CBigNum &coin, pubCoins.second) {
            auto coins = mintedPubCoins.equal_range(coin);
            auto coinIt = find_if(coins.first, coins.second, [=](const decltype(mintedPubCoins)::value_type &v) {
                return v.second.denomination == pubCoins.first.first &&
                        v.second.id == pubCoins.first.second;
            });
            assert(coinIt != mintedPubCoins.end());
            mintedPubCoins.erase(coinIt);
        }
    }

    // roll back spends
    BOOST_FOREACH(const CBigNum &serial, index->spentSerials) {
        usedCoinSerials.erase(serial);
    }
}

bool CZerocoinState::GetCoinGroupInfo(int denomination, int id, CoinGroupInfo &result) {
    pair<int,int>   key = make_pair(denomination, id);
    if (coinGroups.count(key) == 0)
        return false;

    result = coinGroups[key];
    return true;
}

bool CZerocoinState::IsUsedCoinSerial(const CBigNum &coinSerial) {
    return usedCoinSerials.count(coinSerial) != 0;
}

bool CZerocoinState::HasCoin(const CBigNum &pubCoin) {
    return mintedPubCoins.count(pubCoin) != 0;
}

int CZerocoinState::GetAccumulatorValueForSpend(CChain *chain, int maxHeight, int denomination, int id, CBigNum &accumulator, uint256 &blockHash) {
    pair<int, int> denomAndId = pair<int, int>(denomination, id);

    if (coinGroups.count(denomAndId) == 0)
        return 0;

    CoinGroupInfo coinGroup = coinGroups[denomAndId];
    CBlockIndex *lastBlock = coinGroup.lastBlock;

    assert(lastBlock->accumulatorChanges.count(denomAndId) > 0);
    assert(coinGroup.firstBlock->accumulatorChanges.count(denomAndId) > 0);

    // field in the block index structure for accesing accumulator changes
    decltype(&CBlockIndex::accumulatorChanges) accChangeField;
    accChangeField = &CBlockIndex::accumulatorChanges;

    int numberOfCoins = 0;
    for (;;) {
        map<pair<int,int>, pair<CBigNum,int>> &accumulatorChanges = lastBlock->*accChangeField;
        if (accumulatorChanges.count(denomAndId) > 0) {
            if (lastBlock->nHeight <= maxHeight) {
                if (numberOfCoins == 0) {
                    // latest block satisfying given conditions
                    // remember accumulator value and block hash
                    accumulator = accumulatorChanges[denomAndId].first;
                    blockHash = lastBlock->GetBlockHash();
                }
                numberOfCoins += accumulatorChanges[denomAndId].second;
            }
        }
        if (lastBlock == coinGroup.firstBlock)
            break;
        else
            lastBlock = lastBlock->pprev;
    }

    return numberOfCoins;
}

libzerocoin::AccumulatorWitness CZerocoinState::GetWitnessForSpend(CChain *chain, int maxHeight, int denomination, int id, const CBigNum &pubCoin) {
    libzerocoin::CoinDenomination d = (libzerocoin::CoinDenomination)denomination;
    pair<int, int> denomAndId = pair<int, int>(denomination, id);

    assert(coinGroups.count(denomAndId) > 0);

    CoinGroupInfo coinGroup = coinGroups[denomAndId];

    int coinId;
    int mintHeight = GetMintedCoinHeightAndId(pubCoin, denomination, coinId);

    assert(coinId == id);

    // Find accumulator value preceding mint operation
    CBlockIndex *mintBlock = (*chain)[mintHeight];
    CBlockIndex *block = mintBlock;
    libzerocoin::Accumulator accumulator(ZCParams, d);
    if (block != coinGroup.firstBlock) {
        do {
            block = block->pprev;
        } while (block->accumulatorChanges.count(denomAndId) == 0);
        accumulator = libzerocoin::Accumulator(ZCParams, block->accumulatorChanges[denomAndId].first, d);
    }

    // Now add to the accumulator every coin minted since that moment except pubCoin
    block = coinGroup.lastBlock;
    while(true) {
        if (block->nHeight <= maxHeight && block->mintedPubCoins.count(denomAndId) > 0) {
            vector<CBigNum> &pubCoins = block->mintedPubCoins[denomAndId];
            for (const CBigNum &coin: pubCoins) {
                if (block != mintBlock || coin != pubCoin)
                    accumulator += libzerocoin::PublicCoin(ZCParams, coin, d);
            }
        }
        if (block != mintBlock)
            block = block->pprev;
        else
            break;
    }

    return libzerocoin::AccumulatorWitness(ZCParams, accumulator, libzerocoin::PublicCoin(ZCParams, pubCoin, d));
}

int CZerocoinState::GetMintedCoinHeightAndId(const CBigNum &pubCoin, int denomination, int &id) {
    auto coins = mintedPubCoins.equal_range(pubCoin);
    auto coinIt = find_if(coins.first, coins.second,
                          [=](const decltype(mintedPubCoins)::value_type &v) { return v.second.denomination == denomination; });

    if (coinIt != mintedPubCoins.end()) {
        id = coinIt->second.id;
        return coinIt->second.nHeight;
    }
    else
        return -1;
}

bool ZerocoinUpgradeBlockIndex(CChain *chain) {
    CBlockIndex	*blockIndex = chain->Genesis();
    if (blockIndex->nVersion != 130500)
        // chain already at correct version
        return true;

    set<CBigNum> spentSerials;
    map<pair<int, int>, vector<CBigNum>> mintedCoins;

    FILE	*blockFile = NULL;
    int		nFile = -1;

    for (; blockIndex; blockIndex = chain->Next(blockIndex)) {
        CBlock	block;
        CDiskBlockPos  pos = blockIndex->GetBlockPos();

        if (pos.nFile != nFile) {
            if (blockFile != NULL)
                fclose(blockFile);
            blockFile = OpenBlockFile(pos, true);
        }
        else {
            fseek(blockFile, pos.nPos, SEEK_SET);
        }

        block.SetNull();
        CAutoFile filein(blockFile, SER_DISK, CLIENT_VERSION);

        if (filein.IsNull())
            return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

        try {
            filein >> block;
        }
        catch (const std::exception &e) {
            return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
        }

        filein.release();
    }

    if (blockFile != NULL)
        fclose(blockFile);

    return true;
}

bool CZerocoinState::TestValidity(CChain *chain) {
    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), CoinGroupInfo) &coinGroup, coinGroups) {
        fprintf(stderr, "TestValidity[denomination=%d, id=%d]\n", coinGroup.first.first, coinGroup.first.second);

        libzerocoin::Params *zcParams = ZCParams;

        libzerocoin::Accumulator acc(&zcParams->accumulatorParams, (libzerocoin::CoinDenomination)coinGroup.first.first);

        CBlockIndex *block = coinGroup.second.firstBlock;
        for (;;) {
            if (block->accumulatorChanges.count(coinGroup.first) > 0) {
                if (block->mintedPubCoins.count(coinGroup.first) == 0) {
                    fprintf(stderr, "  no minted coins\n");
                    return false;
                }

                BOOST_FOREACH(const CBigNum &pubCoin, block->mintedPubCoins[coinGroup.first]) {
                    acc += libzerocoin::PublicCoin(zcParams, pubCoin, (libzerocoin::CoinDenomination)coinGroup.first.first);
                }

                if (acc.getValue() != block->accumulatorChanges[coinGroup.first].first) {
                    fprintf (stderr, "  accumulator value mismatch at height %d\n", block->nHeight);
                    return false;
                }

                if (block->accumulatorChanges[coinGroup.first].second != (int)block->mintedPubCoins[coinGroup.first].size()) {
                    fprintf(stderr, "  number of minted coins mismatch at height %d\n", block->nHeight);
                    return false;
                }
            }

            if (block != coinGroup.second.lastBlock)
                block = (*chain)[block->nHeight+1];
            else
                break;
        }

        fprintf(stderr, "  verified ok\n");
    }

    return true;
}

set<CBlockIndex *> CZerocoinState::RecalculateAccumulators(CChain *chain) {
    set<CBlockIndex *> changes;

    BOOST_FOREACH(const PAIRTYPE(PAIRTYPE(int,int), CoinGroupInfo) &coinGroup, coinGroups) {

        libzerocoin::Accumulator acc(&ZCParams->accumulatorParams, (libzerocoin::CoinDenomination)coinGroup.first.first);

        // Try to calculate accumulator for the first batch of mints. If it doesn't match we need to recalculate the rest of it
        CBlockIndex *block = coinGroup.second.firstBlock;
        for (;;) {
            if (block->accumulatorChanges.count(coinGroup.first) > 0) {
                BOOST_FOREACH(const CBigNum &pubCoin, block->mintedPubCoins[coinGroup.first]) {
                    acc += libzerocoin::PublicCoin(ZCParams, pubCoin, (libzerocoin::CoinDenomination)coinGroup.first.first);
                }

                // First block case is special: do the check
                if (block == coinGroup.second.firstBlock) {
                    if (acc.getValue() != block->accumulatorChanges[coinGroup.first].first)
                        // recalculation is needed
                        LogPrintf("ZerocoinState: accumulator recalculation for denomination=%d, id=%d\n", coinGroup.first.first, coinGroup.first.second);
                    else
                        // everything's ok
                        break;
                }

                block->accumulatorChanges[coinGroup.first] = make_pair(acc.getValue(), (int)block->mintedPubCoins[coinGroup.first].size());
                changes.insert(block);
            }

            if (block != coinGroup.second.lastBlock)
                block = (*chain)[block->nHeight+1];
            else
                break;
        }
    }

    return changes;
}

bool CZerocoinState::AddSpendToMempool(const CBigNum &coinSerial, uint256 txHash) {
    if (IsUsedCoinSerial(coinSerial) || mempoolCoinSerials.count(coinSerial))
        return false;

    mempoolCoinSerials[coinSerial] = txHash;
    return true;
}

void CZerocoinState::RemoveSpendFromMempool(const CBigNum &coinSerial) {
    mempoolCoinSerials.erase(coinSerial);
}

uint256 CZerocoinState::GetMempoolConflictingTxHash(const CBigNum &coinSerial) {
    if (mempoolCoinSerials.count(coinSerial) == 0)
        return uint256();

    return mempoolCoinSerials[coinSerial];
}

bool CZerocoinState::CanAddSpendToMempool(const CBigNum &coinSerial) {
    return !IsUsedCoinSerial(coinSerial) && mempoolCoinSerials.count(coinSerial) == 0;
}

bool CZerocoinState::AddMintToMempool(const CBigNum &coinMint, uint256 txHash) {
    if (HasCoin(coinMint) || mempoolCoinMints.count(coinMint))
        return false;

    mempoolCoinMints[coinMint] = txHash;
    return true;
}

void CZerocoinState::RemoveMintFromMempool(const CBigNum &coinMint) {
    mempoolCoinMints.erase(coinMint);
}

uint256 CZerocoinState::GetMempoolMintConflictingTxHash(const CBigNum &coinMint) {
    if (mempoolCoinMints.count(coinMint) == 0)
        return uint256();

    return mempoolCoinMints[coinMint];
}

bool CZerocoinState::CanAddMintToMempool(const CBigNum &coinMint) {
    return !HasCoin(coinMint) && mempoolCoinMints.count(coinMint) == 0;
}

void CZerocoinState::Reset() {
    coinGroups.clear();
    usedCoinSerials.clear();
    mintedPubCoins.clear();
    latestCoinIds.clear();
    mempoolCoinSerials.clear();
    mempoolCoinMints.clear();
}

CZerocoinState *CZerocoinState::GetZerocoinState() {
    return &zerocoinState;
}

CBigNum ZerocoinGetSpendSerialNumber(const CTransaction &tx, int i) {
    if (!tx.IsZerocoinSpend())
        return CBigNum(0);

    const CTxIn &txin = tx.vin[i];
    try {
        CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                        (const char *)&*txin.scriptSig.end(),
                                        SER_NETWORK, PROTOCOL_VERSION);
        libzerocoin::CoinSpend spend(ZCParams, serializedCoinSpend);
        return spend.getCoinSerialNumber();
    }
    catch (const std::runtime_error &) {
        return CBigNum(0);
    }
}

uint64_t CZerocoinState::GetTotalZerocoins(){

    uint64_t totalZerocoins = 0;
    //total coins minted
    for(auto it = mintedPubCoins.begin(); it != mintedPubCoins.end(); it++) {
        totalZerocoins += it->second.denomination;
    }
    //total coins spent
    for(auto it = ghostedCoins.begin(); it != ghostedCoins.end(); it++) {
        totalZerocoins -= it->second/COIN;
    }

    return totalZerocoins;
}

uint64_t TotalGhosted(){
    return zerocoinState.GetTotalZerocoins();
}
