// Copyright (c) 2019 The NIX Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/ghostwallet.h>
#include <init.h>
#include <db.h>
#include <wallet/wallet.h>
#include <sigma/sigma_primitives.h>
#include <sigma/openssl_context.h>
#include <validation.h>
#include <hash.h>

CGhostWallet::CGhostWallet(CWallet *pwalletMain)
{
    this->pwalletMain = pwalletMain;

    CWalletDB walletdb(pwalletMain->GetDBHandle());

    uint256 hashSeed;
    bool fFirstRun = !walletdb.ReadCurrentSeedHash(hashSeed);

    //Don't try to do anything if the wallet is locked.
    if (pwalletMain->IsLocked()) {
        seedMaster.SetNull();
        nCountLastUsed = 0;
        this->mintPool = CMintPool();
        this->LoadMintPoolFromDB();
        return;
    }

    //First time running, generate master seed
    uint256 seed;
    if (fFirstRun) {
        // Borrow random generator from the key class so that we don't have to worry about randomness
        CKey key;
        key.MakeNewKey(true);
        seed = key.GetPrivKey_256();
        seedMaster = seed;
        LogPrintf("%s: first run of sigma wallet detected, new seed generated. Seedhash=%s\n", __func__, Hash(seed.begin(), seed.end()).GetHex());
    } else if (!pwalletMain->GetDeterministicSeed(hashSeed, seed)) {
        LogPrintf("%s: failed to get deterministic seed for hashseed %s\n", __func__, hashSeed.GetHex());
        return;
    }

    if (!SetMasterSeed(seed)) {
        LogPrintf("%s: failed to save deterministic seed for hashseed %s\n", __func__, hashSeed.GetHex());
        return;
    }
    this->mintPool = CMintPool(nCountLastUsed);
}

bool CGhostWallet::SetMasterSeed(const uint256& seedMaster, bool fResetCount)
{

    CWalletDB walletdb(pwalletMain->GetDBHandle());
    if (pwalletMain->IsLocked())
        return false;

    if (!seedMaster.IsNull() && !pwalletMain->AddDeterministicSeed(seedMaster)) {
        return error("%s: failed to set master seed.", __func__);
    }

    this->seedMaster = seedMaster;

    nCountLastUsed = 0;

    if (fResetCount)
        walletdb.WriteSigmaCount(nCountLastUsed);
    else if (!walletdb.ReadSigmaCount(nCountLastUsed))
        nCountLastUsed = 0;

    mintPool.Reset();

    return true;
}

void CGhostWallet::Lock()
{
    seedMaster.SetNull();
}

void CGhostWallet::AddToMintPool(const std::pair<uint256, uint32_t>& pMint, bool fVerbose)
{
    mintPool.Add(pMint, fVerbose);
}

void CGhostWallet::GenerateMintPool(uint32_t nCountStart, uint32_t nCountEnd)
{

    //Is locked
    if (seedMaster.IsNull())
        return;

    uint32_t n = nCountLastUsed + 1;

    if (nCountStart > 0)
        n = nCountStart;

    uint32_t nStop = n + 50;
    if (nCountEnd > 0)
        nStop = std::max(n, n + nCountEnd);

    bool fFound;

    uint256 hashSeed = Hash(seedMaster.begin(), seedMaster.end());
    LogPrintf("%s : n=%d nStop=%d\n", __func__, n, nStop - 1);
    for (uint32_t i = n; i < nStop; ++i) {
        if (ShutdownRequested())
            return;

        fFound = false;

        // Prevent unnecessary repeated minted
        for (auto& pair : mintPool) {
            if(pair.second == i) {
                fFound = true;
                break;
            }
        }

        if(fFound)
            continue;

        uint512 seedZerocoin = GetSigmaSeed(i);
        GroupElement bnValue;
        CKey key;
        sigma::PrivateCoin coin(SParams, sigma::CoinDenomination::SIGMA_1);
        SeedToSigma(seedZerocoin, bnValue, coin);

        mintPool.Add(bnValue, i);
        CWalletDB(pwalletMain->GetDBHandle()).WriteMintPoolPair(hashSeed, GetPubCoinValueHash(bnValue), i);
        LogPrintf("%s : %s count=%d\n", __func__, bnValue.GetHex().substr(0, 6), i);
    }
}

// pubcoin hashes are stored to db so that a full accounting of mints belonging to the seed can be tracked without regenerating
bool CGhostWallet::LoadMintPoolFromDB()
{
    map<uint256, vector<pair<uint256, uint32_t> > > mapMintPool = CWalletDB(pwalletMain->GetDBHandle()).MapMintPool();

     map<uint256, vector<pair<uint256, uint32_t>>>::iterator it;

    for (it = mapMintPool.begin(); it != mapMintPool.end(); it++)
    {
         uint256 hashSeed =  it->first;
         for (auto& pair : mapMintPool[hashSeed]){
             mintPool.Add(pair);
         }
    }

    return true;
}

void CGhostWallet::RemoveMintsFromPool(const std::vector<uint256>& vPubcoinHashes)
{
    for (const uint256& hash : vPubcoinHashes)
        mintPool.Remove(hash);
}

void CGhostWallet::GetState(int& nCount, int& nLastGenerated)
{
    nCount = this->nCountLastUsed + 1;
    nLastGenerated = mintPool.CountOfLastGenerated();
}

//Catch the counter up with the chain
void CGhostWallet::SyncWithChain(bool fGenerateMintPool)
{
    uint32_t nLastCountUsed = 0;
    bool found = true;
    CWalletDB walletdb(pwalletMain->GetDBHandle());

    set<uint256> setAddedTx;
    while (found) {
        found = false;
        if (fGenerateMintPool)
            GenerateMintPool();
        LogPrintf("%s: Mintpool size=%d\n", __func__, mintPool.size());

        std::set<uint256> setChecked;
        list<pair<uint256,uint32_t> > listMints = mintPool.List();
        for (pair<uint256, uint32_t> pMint : listMints) {
            LOCK(cs_main);
            if (setChecked.count(pMint.first))
                return;
            setChecked.insert(pMint.first);

            if (ShutdownRequested())
                return;

            if (pwalletMain->sigmaTracker->HasPubcoinHash(pMint.first)) {
                mintPool.Remove(pMint.first);
                continue;
            }

            uint256 txHash;
            if (SigmaGetMintTxHash(txHash, pMint.first)) {
                //this mint has already occurred on the chain, increment counter's state to reflect this
                LogPrintf("%s : Found wallet coin mint=%s count=%d tx=%s\n", __func__, pMint.first.GetHex(), pMint.second, txHash.GetHex());
                found = true;

                uint256 hashBlock;
                CTransactionRef tx;
                if (!GetTransaction(txHash, tx, Params().GetConsensus(), hashBlock, true)) {
                    LogPrintf("%s : failed to get transaction for mint %s!\n", __func__, pMint.first.GetHex());
                    found = false;
                    nLastCountUsed = std::max(pMint.second, nLastCountUsed);
                    continue;
                }

                //Find the denomination
                sigma::CoinDenomination denomination = sigma::CoinDenomination::SIGMA_ERROR;
                bool fFoundMint = false;
                GroupElement bnValue;
                for (const CTxOut& out : tx->vout) {
                    if (!out.scriptPubKey.IsSigmaMint())
                        continue;

                    sigma::PublicCoin pubcoin;
                    CValidationState state;
                    if (!TxOutToPublicCoin(out, pubcoin, state)) {
                        LogPrintf("%s : failed to get mint from txout for %s!\n", __func__, pMint.first.GetHex());
                        continue;
                    }

                    // See if this is the mint that we are looking for
                    uint256 hashPubcoin = GetPubCoinValueHash(pubcoin.getValue());
                    if (pMint.first == hashPubcoin) {
                        denomination = pubcoin.getDenomination();
                        bnValue = pubcoin.getValue();
                        fFoundMint = true;
                        break;
                    }
                }

                if (!fFoundMint || denomination == sigma::CoinDenomination::SIGMA_ERROR) {
                    LogPrintf("%s : failed to get mint %s from tx %s!\n", __func__, pMint.first.GetHex(), tx->GetHash().GetHex());
                    found = false;
                    break;
                }

                CBlockIndex* pindex = nullptr;
                if (mapBlockIndex.count(hashBlock))
                    pindex = mapBlockIndex.at(hashBlock);

                if (!setAddedTx.count(txHash)) {
                    CBlock block;
                    CWalletTx wtx(pwalletMain, tx);
                    if (pindex && ReadBlockFromDisk(block, pindex, Params().GetConsensus())){
                        int nIndex = 0;
                        for (nIndex = 0; nIndex < (int) block.vtx.size(); nIndex++)
                            if (block.vtx[nIndex]->GetHash() == tx->GetHash())
                                break;
                        if (nIndex == (int) block.vtx.size()) {
                            nIndex = -1;
                        }
                        wtx.SetMerkleBranch(pindex, nIndex);
                    }

                    //Fill out wtx so that a transaction record can be created
                    wtx.nTimeReceived = pindex->GetBlockTime();
                    pwalletMain->AddToWallet(wtx, false);
                    setAddedTx.insert(txHash);
                }

                SetMintSeen(bnValue, pindex->nHeight, txHash, denomination);
                nLastCountUsed = std::max(pMint.second, nLastCountUsed);
                nCountLastUsed = std::max(nLastCountUsed, nCountLastUsed);
                LogPrintf("CGhostWallet::SyncWithChain(): updated count to %d\n", nCountLastUsed);
            }
        }
    }
}

bool CGhostWallet::SetMintSeen(const GroupElement& bnValue, const int& nHeight, const uint256& txid, const sigma::CoinDenomination& denom)
{
    if (!mintPool.Has(bnValue))
        return error("%s: value not in pool", __func__);
    pair<uint256, uint32_t> pMint = mintPool.Get(bnValue);

    CWalletDB walletdb(pwalletMain->GetDBHandle());
    CSigmaMint dMint;

    // Regenerate the mint
    uint512 seedZerocoin = GetSigmaSeed(pMint.second);
    GroupElement bnValueGen;
    sigma::PrivateCoin coin(SParams, denom, false);
    SeedToSigma(seedZerocoin, bnValueGen, coin);

    // we are checking for ckp payments
    CSigmaMint dMint_;
    if(seedMaster.IsNull()){
        uint256 hashPubCoin = pMint.first;
        if(walletdb.ReadSigmaMint(hashPubCoin, dMint_)){
            bnValueGen = dMint_.GetPubcoinValue();
            dMint = dMint_;
        } else {
            return error("%s: dMint not in pool", __func__);
        }
    }

    //Sanity check
    if (bnValueGen != bnValue)
        return error("%s: generated pubcoin and expected value do not match!", __func__);

    // Create mint object and database it
    uint256 hashSerial;
    uint256 hashSeed = Hash(seedMaster.begin(), seedMaster.end());
    if(!seedMaster.IsNull()){
        hashSerial = GetSerialHash(coin.getSerialNumber());
        dMint = CSigmaMint(pMint.second, hashSeed, hashSerial, bnValue);
    }

    dMint.SetDenomination(denom);
    dMint.SetHeight(nHeight);

    // Check if this is also already spent
    int nHeightTx;
    uint256 txidSpend;
    CTransactionRef txSpend;
    if (!seedMaster.IsNull() && IsSerialInBlockchain(hashSerial, nHeightTx, txidSpend, txSpend)) {
        //Find transaction details and make a wallettx and add to wallet
        dMint.SetUsed(true);
        CWalletTx wtx(pwalletMain, txSpend);
        CBlockIndex* pindex = chainActive[nHeightTx];
        CBlock block;
        if (ReadBlockFromDisk(block, pindex, Params().GetConsensus())){
            int nIndex = 0;
            for (nIndex = 0; nIndex < (int) block.vtx.size(); nIndex++)
                if (block.vtx[nIndex]->GetHash() == txSpend->GetHash())
                    break;
            if (nIndex == (int) block.vtx.size()) {
                nIndex = -1;
            }
            wtx.SetMerkleBranch(pindex, nIndex);
        }

        wtx.nTimeReceived = pindex->nTime;
        pwalletMain->AddToWallet(wtx, false);
    }

    // Add to hdMintTracker which also adds to database
    pwalletMain->sigmaTracker->Add(dMint, true);

    //Update the count if it is less than the mint's count
    if (nCountLastUsed < pMint.second) {
        nCountLastUsed = pMint.second;
        walletdb.WriteSigmaCount(nCountLastUsed);
    }

    //remove from the pool
    mintPool.Remove(dMint.GetPubCoinHash());

    return true;
}

void CGhostWallet::SeedToSigma(const uint512& seedZerocoin, GroupElement& commit, sigma::PrivateCoin& coin)
{
    //convert state seed into a seed for the private key
    uint256 nSeedPrivKey = seedZerocoin.trim256();
    nSeedPrivKey = Hash(nSeedPrivKey.begin(), nSeedPrivKey.end());
    coin.setEcdsaSeckey(nSeedPrivKey);

    // Create a key pair
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(OpenSSLContext::get_context(), &pubkey, coin.getEcdsaSeckey())){
        throw ZerocoinException("Unable to create public key.");
    }
    // Hash the public key in the group to obtain a serial number
    Scalar serialNumber = coin.serialNumberFromSerializedPublicKey(OpenSSLContext::get_context(), &pubkey);
    coin.setSerialNumber(serialNumber);

    //hash randomness seed with Bottom 256 bits of seedZerocoin
    Scalar randomness;
    uint256 nSeedRandomness = ArithToUint512(UintToArith512(seedZerocoin) >> 256).trim256();
    randomness.memberFromSeed(nSeedRandomness.begin());
    coin.setRandomness(randomness);

    // Generate a Pedersen commitment to the serial number
    commit = sigma::SigmaPrimitives<Scalar, GroupElement>::commit(
             coin.getParams()->get_g(), coin.getSerialNumber(), coin.getParams()->get_h0(), coin.getRandomness());
}

uint512 CGhostWallet::GetSigmaSeed(uint32_t n)
{
    CDataStream ss(SER_GETHASH, 0);
    ss << seedMaster << n;
    uint512 sigmaSeed = Hash512(ss.begin(), ss.end());
    return sigmaSeed;
}

uint32_t CGhostWallet::GetCount()
{
    return nCountLastUsed;
}

void CGhostWallet::SetCount(uint32_t nCount)
{
    nCountLastUsed = nCount;
}

void CGhostWallet::UpdateCountLocal()
{
    nCountLastUsed++;
}

void CGhostWallet::UpdateCountDB()
{
    CWalletDB walletdb(pwalletMain->GetDBHandle());
    walletdb.WriteSigmaCount(nCountLastUsed);
}

void CGhostWallet::UpdateCount()
{
    UpdateCountLocal();
    UpdateCountDB();
}

void CGhostWallet::GenerateHDMint(sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CSigmaMint& dMint, bool fGenerateOnly)
{
    GenerateMint(nCountLastUsed + 1, denom, coin, dMint);
    if (fGenerateOnly)
        return;
}

void CGhostWallet::GenerateMint(const uint32_t& nCount, const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CSigmaMint& dMint)
{
    uint512 seedZerocoin = GetSigmaSeed(nCount);
    GroupElement commitmentValue;
    SeedToSigma(seedZerocoin, commitmentValue, coin);

    coin.setPublicCoin(sigma::PublicCoin(commitmentValue, denom));

    uint256 hashSeed = Hash(seedMaster.begin(), seedMaster.end());
    uint256 hashSerial = GetSerialHash(coin.getSerialNumber());
    dMint = CSigmaMint(nCount, hashSeed, hashSerial, coin.getPublicCoin().getValue());
    dMint.SetDenomination(denom);
}

bool CGhostWallet::CheckSeed(const CSigmaMint& dMint)
{
    //Check that the seed is correct    todo:handling of incorrect, or multiple seeds
    uint256 hashSeed = Hash(seedMaster.begin(), seedMaster.end());
    return hashSeed == dMint.GetSeedHash();
}

bool CGhostWallet::RegenerateMint(const CSigmaMint& dMint, CSigmaEntry& sigma)
{
    if (!CheckSeed(dMint)) {
        uint256 hashSeed = Hash(seedMaster.begin(), seedMaster.end());
        return error("%s: master seed does not match!\ndmint:\n %s \nhashSeed: %s\nseed: %s", __func__, dMint.ToString(), hashSeed.GetHex(), seedMaster.GetHex());
    }

    //Generate the coin
    sigma::PrivateCoin coin(sigma::Params::get_default(), dMint.GetDenomination(), false);
    CSigmaMint dMintDummy;
    GenerateMint(dMint.GetCount(), dMint.GetDenomination(), coin, dMintDummy);

    //Fill in the zerocoinmint object's details
    GroupElement bnValue = coin.getPublicCoin().getValue();
    if (GetPubCoinValueHash(bnValue) != dMint.GetPubCoinHash())
        return error("%s: failed to correctly generate mint, pubcoin hash mismatch", __func__);
    sigma.value = bnValue;

    Scalar bnSerial = coin.getSerialNumber();
    if (GetSerialHash(bnSerial) != dMint.GetSerialHash())
        return error("%s: failed to correctly generate mint, serial hash mismatch", __func__);

    sigma.set_denomination(dMint.GetDenomination());
    sigma.randomness = coin.getRandomness();
    sigma.serialNumber = bnSerial;
    sigma.IsUsed = dMint.IsUsed();
    sigma.nHeight = dMint.GetHeight();
    sigma.id = dMint.GetId();
    sigma.ecdsaSecretKey = std::vector<unsigned char>(&coin.getEcdsaSeckey()[0],&coin.getEcdsaSeckey()[32]);

    return true;
}


/*****************************
       *  Mint Pool *
       *            *
*****************************/

CMintPool::CMintPool()
{
    this->nCountLastGenerated = 0;
    this->nCountLastRemoved = 0;
}

CMintPool::CMintPool(uint32_t nCount)
{
    this->nCountLastRemoved = nCount;
    this->nCountLastGenerated = nCount;
}

void CMintPool::Add(const GroupElement& bnValue, const uint32_t& nCount)
{
    uint256 hash = GetPubCoinValueHash(bnValue);
    Add(make_pair(hash, nCount));
    LogPrintf("%s : add %s to mint pool, nCountLastGenerated=%d\n", __func__, bnValue.GetHex().substr(0, 6), nCountLastGenerated);
}

void CMintPool::Add(const pair<uint256, uint32_t>& pMint, bool fVerbose)
{
    insert(pMint);
    if (pMint.second > nCountLastGenerated)
        nCountLastGenerated = pMint.second;

    if (fVerbose)
        LogPrintf("%s : add %s count %d to mint pool\n", __func__, pMint.first.GetHex().substr(0, 6), pMint.second);
}

bool CMintPool::Has(const GroupElement& bnValue)
{
    return static_cast<bool>(count(GetPubCoinValueHash(bnValue)));
}

std::pair<uint256, uint32_t> CMintPool::Get(const GroupElement& bnValue)
{
    auto it = find(GetPubCoinValueHash(bnValue));
    return *it;
}

bool SortSmallest(const pair<uint256, uint32_t>& a, const pair<uint256, uint32_t>& b)
{
    return a.second < b.second;
}

std::list<pair<uint256, uint32_t> > CMintPool::List()
{
    list<pair<uint256, uint32_t> > listMints;
    for (auto pMint : *(this)) {
        listMints.emplace_back(pMint);
    }

    listMints.sort(SortSmallest);

    return listMints;
}

void CMintPool::Reset()
{
    clear();
    nCountLastGenerated = 0;
    nCountLastRemoved = 0;
}

bool CMintPool::Front(std::pair<uint256, uint32_t>& pMint)
{
    if (empty())
        return false;
    pMint = *begin();
    return true;
}

bool CMintPool::Next(pair<uint256, uint32_t>& pMint)
{
    auto it = find(pMint.first);
    if (it == end() || ++it == end())
        return false;

    pMint = *it;
    return true;
}

void CMintPool::Remove(const GroupElement& bnValue)
{
    Remove(GetPubCoinValueHash(bnValue));
    LogPrintf("%s : remove %s from mint pool\n", __func__, bnValue.GetHex().substr(0, 6));
}

void CMintPool::Remove(const uint256& hashPubcoin)
{
    auto it = find(hashPubcoin);
    if (it == end())
        return;

    nCountLastRemoved = it->second;
    erase(it);
}

/*****************************
       *   Chain    *
       *            *
*****************************/

// 6 comes from OPCODE (1) + vch.size() (1) + BIGNUM size (4)
#define SCRIPT_OFFSET 6
// For Script size (BIGNUM/Uint256 size)
#define BIGNUM_SIZE   4

bool IsBlockHashInChain(const uint256& hashBlock)
{
    LOCK(cs_main);

    if (hashBlock.IsNull() || !mapBlockIndex.count(hashBlock))
        return false;

    return chainActive.Contains(mapBlockIndex[hashBlock]);
}

bool IsTransactionInChain(const uint256& txId, int& nHeightTx, CTransactionRef& tx)
{
    uint256 hashBlock;
    if (!GetTransaction(txId, tx, Params().GetConsensus(), hashBlock, true))
        return false;
    if (!IsBlockHashInChain(hashBlock))
        return false;

    nHeightTx = mapBlockIndex.at(hashBlock)->nHeight;
    return true;
}

bool IsTransactionInChain(const uint256& txId, int& nHeightTx)
{
    CTransactionRef tx;
    return IsTransactionInChain(txId, nHeightTx, tx);
}

bool IsSerialInBlockchain(const Scalar& bnSerial, int& nHeightTx)
{
    uint256 txHash;
    txHash.SetNull();
    // if not in zerocoinState then its not in the blockchain
    if (!CSigmaState::GetSigmaState()->IsUsedCoinSerial(bnSerial))
        return false;

    return IsTransactionInChain(txHash, nHeightTx);
}

bool IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransactionRef& tx)
{
    txidSpend.SetNull();
    CMintMeta mMeta;
    Scalar bnSerial;
    if (!CSigmaState::GetSigmaState()->IsUsedCoinSerialHash(bnSerial, hashSerial))
        return false;

    if(!vpwallets[0]->sigmaTracker->Get(hashSerial, mMeta))
        return false;

    txidSpend = mMeta.txid;

    return IsTransactionInChain(txidSpend, nHeightTx, tx);
}

bool TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoin& pubCoin, CValidationState& state)
{
    vector<unsigned char> coin_serialised(txout.scriptPubKey.begin() + 1,
                                          txout.scriptPubKey.end());
    secp_primitives::GroupElement publicZerocoin;
    publicZerocoin.deserialize(&coin_serialised[0]);

    sigma::CoinDenomination denomination;
    sigma::IntegerToDenomination(txout.nValue, denomination);
    LogPrintf("CGhostWallet::TxOutToPublicCoin(): denomination %d pubcoin %s\n", denomination, publicZerocoin.GetHex());
    if (denomination == sigma::CoinDenomination::SIGMA_ERROR)
        return state.DoS(100, error("TxOutToPublicCoin : txout.nValue is not correct"));

    sigma::PublicCoin checkPubCoin(publicZerocoin, denomination);
    pubCoin = checkPubCoin;

    return true;
}
