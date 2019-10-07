// Copyright (c) 2019 The Zcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/sigmamint.h>
#include <wallet/ghostwallet.h>
#include <wallet/sigmatracker.h>
#include <util.h>
#include <sync.h>
#include <txdb.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <libzerocoin/Zerocoin.h>
#include <validation.h>
#include <zerocoin/sigma.h>
//#include "accumulators.h"

using namespace std;

CSigmaTracker::CSigmaTracker(CWallet *pwallet)
{
    this->pwalletMain = pwallet;
    mapSerialHashes.clear();
    mapPendingSpends.clear();
    fInitialized = false;
}

CSigmaTracker::~CSigmaTracker()
{
    mapSerialHashes.clear();
    mapPendingSpends.clear();
}

void CSigmaTracker::Init()
{
    //Load all CSigmaEntries and CSigmaMints from the database
    if (!fInitialized) {
        ListMints(false, false, true);
        fInitialized = true;
    }
}

bool CSigmaTracker::Archive(CMintMeta& meta)
{
    uint256 hashPubcoin = GetPubCoinValueHash(meta.pubCoinValue);

    if (HasSerialHash(meta.hashSerial))
        mapSerialHashes.at(meta.hashSerial).isArchived = true;

    LogPrintf("%s: archived pubcoinhash %s\n", __func__, hashPubcoin.GetHex());
    return true;
}

bool CSigmaTracker::UnArchive(const uint256& hashPubcoin, bool isDeterministic)
{
    CWalletDB walletdb(pwalletMain->GetDBHandle());
    if (isDeterministic) {
        CSigmaMint dMint;
        if (!walletdb.UnarchiveSigmaMint(hashPubcoin, dMint))
            return error("%s: failed to unarchive deterministic mint", __func__);
        Add(dMint, false);
    } else {
        CSigmaEntry sigma;
        if (!walletdb.UnarchiveSigmaEntry(hashPubcoin, sigma))
            return error("%s: failed to unarchivesigma mint", __func__);
        Add(sigma, false);
    }

    LogPrintf("%s: unarchived %s\n", __func__, hashPubcoin.GetHex());
    return true;
}

bool CSigmaTracker::Get(const uint256 &hashSerial, CMintMeta& mMeta)
{
    auto it = mapSerialHashes.find(hashSerial);
    if(it == mapSerialHashes.end())
        return false;

    mMeta = mapSerialHashes.at(hashSerial);
    return true;
}

CMintMeta CSigmaTracker::GetMetaFromPubcoin(const uint256& hashPubcoin)
{
    for (auto it : mapSerialHashes) {
        CMintMeta meta = it.second;
        if (GetPubCoinValueHash(meta.pubCoinValue) == hashPubcoin)
            return meta;
    }

    return CMintMeta();
}

std::vector<uint256> CSigmaTracker::GetSerialHashes()
{
    vector<uint256> vHashes;
    for (auto it : mapSerialHashes) {
        if (it.second.isArchived)
            continue;

        vHashes.emplace_back(it.first);
    }


    return vHashes;
}

CAmount CSigmaTracker::GetBalance(bool fConfirmedOnly, bool fUnconfirmedOnly) const
{
    CAmount nTotal = 0;
    //! zerocoin specific fields

    std::map<sigma::CoinDenomination, unsigned int> mySigmaSupply;
    std::vector<sigma::CoinDenomination> denominations;
    sigma::GetAllDenoms(denominations);
    for(sigma::CoinDenomination denomination: denominations){
        mySigmaSupply.insert(make_pair(denomination, 0));
    }

    {
        //LOCK(cs_pivtracker);
        // Get Unused coins
        for (auto& it : mapSerialHashes) {
            CMintMeta meta = it.second;
            if (meta.isUsed || meta.isArchived)
                continue;
            bool fConfirmed = ((meta.nHeight < chainActive.Height()) && (meta.nHeight != INT_MAX));
            if (fConfirmedOnly && !fConfirmed)
                continue;
            if (fUnconfirmedOnly && fConfirmed)
                continue;
            int64_t nValue;
            sigma::DenominationToInteger(meta.denom, nValue);
            nTotal += nValue;
            mySigmaSupply.at(meta.denom)++;
        }
    }

    if (nTotal < 0 ) nTotal = 0; // Sanity never hurts

    return nTotal;
}

CAmount CSigmaTracker::GetUnconfirmedBalance() const
{
    return GetBalance(false, true);
}

std::list<CMintMeta> CSigmaTracker::GetMints(bool fConfirmedOnly, bool fInactive) const
{
    LOCK(cs_main);
    std::list<CMintMeta> vMints;
    for (auto& it : mapSerialHashes) {
        CMintMeta mint = it.second;
        if ((mint.isArchived || mint.isUsed) && fInactive)
            continue;
        if(mint.watchOnly && fConfirmedOnly)
            continue;
        bool fConfirmed = ((mint.nHeight != INT_MAX) && (mint.nHeight <= chainActive.Height()));
        if (fConfirmedOnly && !fConfirmed)
            continue;
        vMints.push_back(mint);
    }
    return vMints;
}

//Does a mint in the tracker have this txid
bool CSigmaTracker::HasMintTx(const uint256& txid)
{
    for (auto it : mapSerialHashes) {
        if (it.second.txid == txid)
            return true;
    }

    return false;
}

bool CSigmaTracker::HasPubcoin(const GroupElement &pubcoin) const
{
    // Check if this mint's pubcoin value belongs to our mapSerialHashes (which includes hashpubcoin values)
    uint256 hash = GetPubCoinValueHash(pubcoin);
    return HasPubcoinHash(hash);
}

bool CSigmaTracker::HasPubcoinHash(const uint256& hashPubcoin) const
{
    for (auto it : mapSerialHashes) {
        CMintMeta meta = it.second;
        if (GetPubCoinValueHash(meta.pubCoinValue) == hashPubcoin)
            return true;
    }
    return false;
}

bool CSigmaTracker::HasSerial(const Scalar& bnSerial) const
{
    uint256 hash = GetSerialHash(bnSerial);
    return HasSerialHash(hash);
}

bool CSigmaTracker::HasSerialHash(const uint256& hashSerial) const
{
    auto it = mapSerialHashes.find(hashSerial);
    return it != mapSerialHashes.end();
}

bool CSigmaTracker::UpdateZerocoinEntry(const CSigmaEntry& sigma)
{
    if (!HasSerial(sigma.serialNumber))
        return error("%s: sigma %s is not known", __func__, sigma.value.GetHex());

    uint256 hashSerial = GetSerialHash(sigma.serialNumber);

    //Update the meta object
    CMintMeta meta;
    Get(hashSerial, meta);
    meta.isUsed = sigma.IsUsed;
    meta.denom = sigma.get_denomination();
    meta.nHeight = sigma.nHeight;
    mapSerialHashes.at(hashSerial) = meta;

    //Write to db
    return CWalletDB(pwalletMain->GetDBHandle()).WriteSigmaEntry(sigma);
}

bool CSigmaTracker::UpdateState(const CMintMeta& meta)
{
    uint256 hashPubcoin = GetPubCoinValueHash(meta.pubCoinValue);
    CWalletDB walletdb(pwalletMain->GetDBHandle());

    if (meta.isDeterministic) {
        CSigmaMint dMint;
        if (!walletdb.ReadSigmaMint(hashPubcoin, dMint)) {
            // Check archive just in case
            if (!meta.isArchived)
                return error("%s: failed to read deterministic mint from database", __func__);

            // Unarchive this mint since it is being requested and updated
            if (!walletdb.UnarchiveSigmaMint(hashPubcoin, dMint))
                return error("%s: failed to unarchive deterministic mint from database", __func__);
        }

        dMint.SetHeight(meta.nHeight);
        dMint.SetId(meta.nId);
        dMint.SetUsed(meta.isUsed);
        dMint.SetDenomination(meta.denom);

        if (!walletdb.WriteSigmaMint(dMint))
            return error("%s: failed to update deterministic mint when writing to db", __func__);
    } else {
        CSigmaEntry sigma;
        // if (!walletdb.ReadZerocoinEntry(meta.pubCoinValue, zerocoin))
        //     return error("%s: failed to read mint from database", __func__);

        sigma.nHeight = meta.nHeight;
        sigma.id = meta.nId;
        sigma.IsUsed = meta.isUsed;
        sigma.set_denomination(meta.denom);

        if (!walletdb.WriteSigmaEntry(sigma))
            return error("%s: failed to write mint to database", __func__);
    }

    mapSerialHashes[meta.hashSerial] = meta;

    return true;
}

void CSigmaTracker::Add(const CSigmaMint& dMint, bool isNew, bool isArchived, CGhostWallet* ghostWallet)
{
    bool isGhostWalletInitialized = (NULL != ghostWallet);
    CMintMeta meta;
    meta.pubCoinValue = dMint.GetPubcoinValue();
    meta.nHeight = dMint.GetHeight();
    meta.nId = dMint.GetId();
    meta.txid = dMint.GetTxHash();
    meta.isUsed = dMint.IsUsed();
    meta.hashSerial = dMint.GetSerialHash();
    meta.denom = dMint.GetDenomination();
    meta.isArchived = isArchived;
    meta.isDeterministic = true;
    if (!isGhostWalletInitialized)
        ghostWallet = new CGhostWallet(pwalletMain);
    meta.isSeedCorrect = ghostWallet->CheckSeed(dMint);
    if (!isGhostWalletInitialized)
        delete ghostWallet;

    mapSerialHashes[meta.hashSerial] = meta;

    if (isNew)
        CWalletDB(pwalletMain->GetDBHandle()).WriteSigmaMint(dMint);
}

void CSigmaTracker::Add(const CSigmaEntry& sigma, bool isNew, bool isArchived)
{
    CMintMeta meta;
    meta.pubCoinValue = sigma.value;
    meta.nHeight = sigma.nHeight;
    meta.nId = sigma.id;
    //meta.txid = zerocoin.GetTxHash();
    meta.isUsed = sigma.IsUsed;
    meta.hashSerial = GetSerialHash(sigma.serialNumber);
    meta.denom = sigma.get_denomination();
    meta.isArchived = isArchived;
    meta.isDeterministic = false;
    meta.isSeedCorrect = true;
    mapSerialHashes[meta.hashSerial] = meta;

    if (isNew)
        CWalletDB(pwalletMain->GetDBHandle()).WriteSigmaEntry(sigma);
}

void CSigmaTracker::SetPubcoinUsed(const uint256& hashPubcoin, const uint256& txid)
{
    if (!HasPubcoinHash(hashPubcoin))
        return;
    CMintMeta meta = GetMetaFromPubcoin(hashPubcoin);
    meta.isUsed = true;
    mapPendingSpends.insert(make_pair(meta.hashSerial, txid));
    UpdateState(meta);
}

void CSigmaTracker::SetPubcoinNotUsed(const uint256& hashPubcoin)
{
    if (!HasPubcoinHash(hashPubcoin))
        return;
    CMintMeta meta = GetMetaFromPubcoin(hashPubcoin);
    meta.isUsed = false;

    if (mapPendingSpends.count(meta.hashSerial))
        mapPendingSpends.erase(meta.hashSerial);

    UpdateState(meta);
}

void CSigmaTracker::RemovePending(const uint256& txid)
{
    uint256 hashSerial;
    for (auto it : mapPendingSpends) {
        if (it.second == txid) {
            hashSerial = it.first;
            break;
        }
    }
    if (UintToArith256(hashSerial) > 0)
        mapPendingSpends.erase(hashSerial);
}

bool CSigmaTracker::UpdateStatusInternal(const std::set<uint256>& setMempool, CMintMeta& mint)
{
    uint256 hashPubcoin = GetPubCoinValueHash(mint.pubCoinValue);
    //! Check whether this mint has been spent and is considered 'pending' or 'confirmed'
    // If there is not a record of the block height, then look it up and assign it
    uint256 txidMint;
    bool isMintInChain = SigmaGetMintTxHash(txidMint, mint.pubCoinValue);

    //See if there is internal record of spending this mint (note this is memory only, would reset on restart)
    bool isPendingSpend = static_cast<bool>(mapPendingSpends.count(mint.hashSerial));

    // See if there is a blockchain record of spending this mint
    CSigmaState *sigmaState = CSigmaState::GetSigmaState();
    Scalar bnSerial;
    bool isConfirmedSpend = sigmaState->IsUsedCoinSerialHash(bnSerial, mint.hashSerial);

    // Double check the mempool for pending spend
    if (isPendingSpend) {
        uint256 txidPendingSpend = mapPendingSpends.at(mint.hashSerial);
        if (!setMempool.count(txidPendingSpend) || isConfirmedSpend) {
            RemovePending(txidPendingSpend);
            isPendingSpend = false;
            LogPrintf("%s : Pending txid %s removed because not in mempool\n", __func__, txidPendingSpend.GetHex());
        }
    }

    bool isUsed = isPendingSpend || isConfirmedSpend;

    if ((mint.nHeight == INT_MAX) || (mint.nId<=0) || !isMintInChain || isUsed != mint.isUsed) {
        CTransactionRef tx;
        uint256 hashBlock;

        // Txid will be marked 0 if there is no knowledge of the final tx hash yet
        if (mint.txid.IsNull()) {
            if (!isMintInChain) {
                LogPrintf("%s : Failed to find mint in zerocoinDB %s\n", __func__, hashPubcoin.GetHex().substr(0, 6));
                mint.isArchived = true;
                Archive(mint);
                return true;
            }
            mint.txid = txidMint;
        }

        if (setMempool.count(mint.txid))
            return true;

        // Check the transaction associated with this mint
        if (!IsInitialBlockDownload() && !GetTransaction(mint.txid, tx, Params().GetConsensus(), hashBlock, true)) {
            LogPrintf("%s : Failed to find tx for mint txid=%s\n", __func__, mint.txid.GetHex());
            mint.isArchived = true;
            Archive(mint);
            return true;
        }

        bool isUpdated = false;

        // An orphan tx if hashblock is in mapBlockIndex but not in chain active
        if (mapBlockIndex.count(hashBlock)){
            if(!chainActive.Contains(mapBlockIndex.at(hashBlock))) {
                LogPrintf("%s : Found orphaned mint txid=%s\n", __func__, mint.txid.GetHex());
                mint.isUsed = false;
                mint.nHeight = 0;

                return true;
            }else if((mint.nHeight== INT_MAX) || (mint.nId<=0)){ // assign nHeight if not present
                sigma::PublicCoin pubcoin(mint.pubCoinValue, mint.denom);
                auto MintedCoinHeightAndId = sigmaState->GetMintedCoinHeightAndId(pubcoin);
                mint.nHeight = MintedCoinHeightAndId.first;
                mint.nId = MintedCoinHeightAndId.second;
                LogPrintf("%s : Set mint %s nHeight to %d\n", __func__, hashPubcoin.GetHex(), mint.nHeight);
                LogPrintf("%s : Set mint %s nId to %d\n", __func__, hashPubcoin.GetHex(), mint.nId);
                isUpdated = true;
            }
        }

        // Check that the mint has correct used status
        if (mint.isUsed != isUsed) {
            LogPrintf("%s : Set mint %s isUsed to %d\n", __func__, hashPubcoin.GetHex(), isUsed);
            mint.isUsed = isUsed;
            isUpdated = true;
        }

        if(isUpdated) return true;
    }

    return false;
}

bool CSigmaTracker::MintMetaToZerocoinEntries(std::list <CSigmaEntry>& entries, std::list<CMintMeta> listMints) const {
    CSigmaEntry entry;
    for (const CMintMeta& mint : listMints) {
        if (pwalletMain->GetMint(mint.hashSerial, entry))
            entries.push_back(entry);
    }
    return true;
}

bool CSigmaTracker::UpdateMints(std::set<uint256> serialHashes, bool fReset, bool fUpdateStatus, bool fStatus){
    // if list is populated, only update mints with these serials
    bool fSelection = serialHashes.size()>0;
    // Only allow updates for one or the other
    if(fReset && fUpdateStatus)
        return false;

    std::list<CSigmaEntry> listMintsDB;
    CWalletDB walletdb(pwalletMain->GetDBHandle());
    walletdb.ListSigmaEntries(listMintsDB);
    for (auto& mint : listMintsDB){
        if(fReset){
            mint.nHeight = INT_MAX;
            mint.IsUsed = false;
        }
        else if(fUpdateStatus){
            mint.IsUsed = fStatus;
        }

        if((!fSelection) ||
            (fSelection && (serialHashes.find(GetSerialHash(mint.serialNumber)) != serialHashes.end()))){
            Add(mint);
        }
    }
    std::list<CSigmaMint> listDeterministicDB = walletdb.ListSigmaMints();

    CGhostWallet* zerocoinWallet = new CGhostWallet(pwalletMain);
    for (auto& dMint : listDeterministicDB) {
        if(fReset){
            dMint.SetHeight(INT_MAX);
            dMint.SetUsed(false);
        }
        else if(fUpdateStatus){
            dMint.SetUsed(fStatus);
        }

        if((!fSelection) ||
            (fSelection && (serialHashes.find(dMint.GetSerialHash()) != serialHashes.end()))){
            Add(dMint, true, false, zerocoinWallet);
        }
    }
    delete zerocoinWallet;

    return true;
}

std::vector<CMintMeta> CSigmaTracker::ListMints(bool fUnusedOnly, bool fMatureOnly, bool fUpdateStatus, bool fWrongSeed)
{
    std::vector<CMintMeta> setMints;
    CWalletDB walletdb(pwalletMain->GetDBHandle());
    if (fUpdateStatus) {
        std::list<CSigmaEntry> listMintsDB;
        walletdb.ListSigmaEntries(listMintsDB);
        for (auto& mint : listMintsDB){
            Add(mint);
        }
        //LogPrintf("%s: added %d sigma entries from DB\n", __func__, listMintsDB.size());

        std::list<CSigmaMint> listDeterministicDB = walletdb.ListSigmaMints();

        CGhostWallet* ghostWallet = new CGhostWallet(pwalletMain);
        for (auto& dMint : listDeterministicDB) {
            Add(dMint, false, false, ghostWallet);
        }
        delete ghostWallet;
        LogPrintf("%s: added %d deterministic sigma mints from DB\n", __func__, listDeterministicDB.size());
    }

    std::vector<CMintMeta> vOverWrite;
    std::set<uint256> setMempool;
    {
        LOCK(mempool.cs);
        mempool.getTransactions(setMempool);
    }
    for (auto& it : mapSerialHashes) {
        CMintMeta mint = it.second;

        //This is only intended for unarchived coins
        if (mint.isArchived)
            continue;

        // Update the metadata of the mints if requested
        if (fUpdateStatus && UpdateStatusInternal(setMempool, mint)) {
            if (mint.isArchived)
                continue;

            // Mint was updated, queue for overwrite
            vOverWrite.emplace_back(mint);
        }

        if (fUnusedOnly && mint.isUsed)
            continue;

        if (fMatureOnly) {
            // Not confirmed
            if (!mint.nHeight || mint.nHeight > chainActive.Height())
                continue;
        }

        if (!fWrongSeed && !mint.isSeedCorrect)
            continue;

        setMints.push_back(mint);
    }

    //overwrite any updates
    for (CMintMeta& meta : vOverWrite)
        UpdateState(meta);

    return setMints;
}

void CSigmaTracker::Clear()
{
    mapSerialHashes.clear();
}
