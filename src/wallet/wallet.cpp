// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <base58.h>
#include <checkpoints.h>
#include <chain.h>
#include <wallet/coincontrol.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <fs.h>
#include <wallet/init.h>
#include <key.h>
#include <keystore.h>
#include <validation.h>
#include <net.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <scheduler.h>
#include <timedata.h>
#include <txmempool.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/fees.h>
#include <utilstrencodings.h>
#include <assert.h>
#include <future>
#include <rpc/protocol.h>
#include "ghostnode/activeghostnode.h"
#include "ghostnode/darksend.h"
#include "ghostnode/instantx.h"
#include "ghostnode/ghostnode.h"
#include "ghostnode/ghostnode-payments.h"
#include <ghostnode/ghostnodeman.h>
#include <ghostnode/ghostnode-sync.h>
#include "random.h"
#include <ghost-address/commitmentkey.h>

#include <rpc/server.h>
#include <pos/kernel.h>
#include <pos/miner.h>
#include <consensus/merkle.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>
#include <boost/foreach.hpp>

std::vector<CWalletRef> vpwallets;
/** Transaction fee set by the user */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fWalletRbf = DEFAULT_WALLET_RBF;

const char * DEFAULT_WALLET_DAT = "wallet.dat";
const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;
const int ZEROCOIN_CONFIRM_HEIGHT = 0;

OutputType g_address_type = OUTPUT_TYPE_DEFAULT;
OutputType g_change_type = OUTPUT_TYPE_DEFAULT;
/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

CFeeRate CWallet::m_discard_rate = CFeeRate(DEFAULT_DISCARD_FEE);

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly
{
    bool operator()(const CInputCoin& t1,
                    const CInputCoin& t2) const
    {
        return t1.txout.nValue < t2.txout.nValue;
    }
};

struct CompareByPriority
{
    bool operator()(const COutput& t1,
                    const COutput& t2) const
    {
        return t1.Priority() > t2.Priority();
    }
};

struct CompareByAmount
{
    bool operator()(const CompactTallyItem& t1, const CompactTallyItem& t2) const
    {
        return t1.nAmount > t2.nAmount;
    }
};

int COutput::Priority() const
{
    BOOST_FOREACH(CAmount d, vecPrivateSendDenominations)
    if(tx->tx->vout[i].nValue == d) return 10000;
    if(tx->tx->vout[i].nValue < 1*COIN) return 20000;

    //nondenom return largest first
    return -(tx->tx->vout[i].nValue/COIN);
}

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->tx->vout[i].nValue));
}

CHMAC_SHA256::CHMAC_SHA256(const unsigned char* key, size_t keylen)
{
    unsigned char rkey[64];
    if (keylen <= 64) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, 64 - keylen);
    } else {
        CSHA256().Write(key, keylen).Finalize(rkey);
        memset(rkey + 32, 0, 32);
    }

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c;
    outer.Write(rkey, 64);

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    inner.Write(rkey, 64);
}

void CHMAC_SHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char temp[32];
    inner.Finalize(temp);
    outer.Write(temp, 32).Finalize(hash);
}

CHMAC_SHA512::CHMAC_SHA512(const unsigned char* key, size_t keylen)
{
    unsigned char rkey[128];
    if (keylen <= 128) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, 128 - keylen);
    } else {
        CSHA512().Write(key, keylen).Finalize(rkey);
        memset(rkey + 64, 0, 64);
    }

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c;
    outer.Write(rkey, 128);

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    inner.Write(rkey, 128);
}

void CHMAC_SHA512::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char temp[64];
    inner.Finalize(temp);
    outer.Write(temp, 64).Finalize(hash);
}

class CAffectedKeysVisitor : public boost::static_visitor<void> {
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            for (const CTxDestination &dest : vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const WitnessV0ScriptHash& scriptID)
    {
        CScriptID id;
        CRIPEMD160().Write(scriptID.begin(), 32).Finalize(id.begin());
        CScript script;
        if (keystore.GetCScript(id, script)) {
            Process(script);
        }
    }

    void operator()(const WitnessV0KeyHash& keyid)
    {
        CKeyID id(keyid);
        if (keystore.HaveKey(id)) {
            vKeys.push_back(id);
        }
    }

    void operator()(const CGhostAddress &stxAddr) {
        CScript script;
    }

    template<typename X>
    void operator()(const X &none) {}
};

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return nullptr;
    return &(it->second);
}

CPubKey CWallet::GenerateNewKey(CWalletDB &walletdb, bool internal)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // use HD key derivation if HD was enabled during wallet creation
    if (IsHDEnabled()) {
        DeriveNewChildKey(walletdb, metadata, secret, (CanSupportFeature(FEATURE_HD_SPLIT) ? internal : false));
    } else {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed) {
        SetMinVersion(FEATURE_COMPRPUBKEY);
    }

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    UpdateTimeFirstKey(nCreationTime);

    if (!AddKeyPubKeyWithDB(walletdb, secret, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": AddKey failed");
    }
    return pubkey;
}

void CWallet::DeriveNewChildKey(CWalletDB &walletdb, CKeyMetadata& metadata, CKey& secret, bool internal)
{
    // for now we use a fixed keypath scheme of m/0'/0'/k
    CKey key;                      //master key seed (256bit)
    CExtKey masterKey;             //hd master key
    CExtKey accountKey;            //key at m/0'
    CExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
    CExtKey childKey;              //key at m/0'/0'/<n>'

    // try to get the master key
    if (!GetKey(hdChain.masterKeyID, key))
        throw std::runtime_error(std::string(__func__) + ": Master key not found");

    masterKey.SetMaster(key.begin(), key.size());

    // derive m/0'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

    // derive m/0'/0' (external chain) OR m/0'/1' (internal chain)
    assert(internal ? CanSupportFeature(FEATURE_HD_SPLIT) : true);
    accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT+(internal ? 1 : 0));

    // derive child key at next index, skip keys already known to the wallet
    do {
        // always derive hardened keys
        // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
        // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
        if (internal) {
            chainChildKey.Derive(childKey, hdChain.nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/1'/" + std::to_string(hdChain.nInternalChainCounter) + "'";
            hdChain.nInternalChainCounter++;
        }
        else {
            chainChildKey.Derive(childKey, hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/0'/" + std::to_string(hdChain.nExternalChainCounter) + "'";
            hdChain.nExternalChainCounter++;
        }
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secret = childKey.key;
    metadata.hdMasterKeyID = hdChain.masterKeyID;
    // update the chain model in the database
    if (!walletdb.WriteHDChain(hdChain))
        throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
}

bool CWallet::AddKeyPubKeyWithDB(CWalletDB &walletdb, const CKey& secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata

    // CCryptoKeyStore has no concept of wallet databases, but calls AddCryptedKey
    // which is overridden below.  To avoid flushes, the database handle is
    // tunneled through to it.
    bool needsDB = !pwalletdbEncryption;
    if (needsDB) {
        pwalletdbEncryption = &walletdb;
    }
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey)) {
        if (needsDB) pwalletdbEncryption = nullptr;
        return false;
    }
    if (needsDB) pwalletdbEncryption = nullptr;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }

    if (!IsCrypted()) {
        return walletdb.WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    CWalletDB walletdb(*dbw);
    return CWallet::AddKeyPubKeyWithDB(walletdb, secret, pubkey);
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(*dbw).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
}

bool CWallet::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    UpdateTimeFirstKey(meta.nCreateTime);
    mapKeyMetadata[keyID] = meta;
    return true;
}

bool CWallet::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // m_script_metadata
    UpdateTimeFirstKey(meta.nCreateTime);
    m_script_metadata[script_id] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

/**
 * Update wallet first key creation time. This should be called whenever keys
 * are added to the wallet, with the oldest key creation time.
 */
void CWallet::UpdateTimeFirstKey(int64_t nCreateTime)
{
    AssertLockHeld(cs_wallet);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    return CWalletDB(*dbw).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(CScriptID(redeemScript));
        LogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript& dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    const CKeyMetadata& meta = m_script_metadata[CScriptID(dest)];
    UpdateTimeFirstKey(meta.nCreateTime);
    NotifyWatchonlyChanged(true);
    return CWalletDB(*dbw).WriteWatchOnly(dest, meta);
}

bool CWallet::AddWatchOnly(const CScript& dest, int64_t nCreateTime)
{
    m_script_metadata[CScriptID(dest)].nCreateTime = nCreateTime;
    return AddWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (!CWalletDB(*dbw).EraseWatchOnly(dest))
        return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial _vMasterKey;

    {
        LOCK(cs_wallet);
        for (const MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(_vMasterKey)){
                if(this->fUnlockForStakingOnly)
                    WakeThreadStakeMiner(this);
                return true;
            }
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial _vMasterKey;
        for (MasterKeyMap::value_type& pMasterKey : mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(_vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime))));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + static_cast<unsigned int>(pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime)))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(_vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(*dbw).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(*dbw);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(*dbw);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

std::set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (const CTxIn& txin : wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

bool CWallet::HasWalletSpend(const uint256& txid) const
{
    AssertLockHeld(cs_wallet);
    auto iter = mapTxSpends.lower_bound(COutPoint(txid, 0));
    return (iter != mapTxSpends.end() && iter->first.hash == txid);
}

void CWallet::Flush(bool shutdown)
{
    dbw->Flush(shutdown);
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = nullptr;
    for (TxSpends::iterator it = range.first; it != range.second; ++it) {
        const CWalletTx* wtx = &mapWallet[it->second];
        if (wtx->nOrderPos < nMinOrderPos) {
            nMinOrderPos = wtx->nOrderPos;;
            copyFrom = wtx;
        }
    }

    assert(copyFrom);

    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        assert(copyFrom && "Oldest wallet transaction in range assumed to have been found.");
        if (!copyFrom->IsEquivalentTo(*copyTo)) continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const uint256& hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end()) {
            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0  || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const uint256& wtxid)
{
    auto it = mapWallet.find(wtxid);
    assert(it != mapWallet.end());
    CWalletTx& thisTx = it->second;
    if (thisTx.IsCoinBase() || thisTx.tx->IsZerocoinSpend()) // Coinbases and zerocoin spends don't spend anything!
        return;
    for (const CTxIn& txin : thisTx.tx->vin)
        AddToSpends(txin.prevout, wtxid);
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial _vMasterKey;

    _vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetStrongRandBytes(&_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = static_cast<unsigned int>(2500000 / ((double)(GetTimeMillis() - nStartTime)));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + static_cast<unsigned int>(kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime)))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        assert(!pwalletdbEncryption);
        pwalletdbEncryption = new CWalletDB(*dbw);
        if (!pwalletdbEncryption->TxnBegin()) {
            delete pwalletdbEncryption;
            pwalletdbEncryption = nullptr;
            return false;
        }
        pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);

        if (!EncryptKeys(_vMasterKey))
        {
            pwalletdbEncryption->TxnAbort();
            delete pwalletdbEncryption;
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (!pwalletdbEncryption->TxnCommit()) {
            delete pwalletdbEncryption;
            // We now have keys encrypted in memory, but not on disk...
            // die to avoid confusion and let the user reload the unencrypted wallet.
            assert(false);
        }

        delete pwalletdbEncryption;
        pwalletdbEncryption = nullptr;

        Lock();
        Unlock(strWalletPassphrase);

        // if we are using HD, replace the HD master key (seed) with a new one
        if (IsHDEnabled()) {
            if (!SetHDMasterKey(GenerateNewHDMasterKey())) {
                return false;
            }
        }

        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        dbw->Rewrite();

    }
    NotifyStatusChanged(this);

    return true;
}

DBErrors CWallet::ReorderTransactions()
{
    LOCK(cs_wallet);
    CWalletDB walletdb(*dbw);

    // Old wallets didn't have any defined order for transactions
    // Probably a bad idea to change the output of this

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-time multimap.
    typedef std::pair<CWalletTx*, CAccountingEntry*> TxPair;
    typedef std::multimap<int64_t, TxPair > TxItems;
    TxItems txByTime;

    for (auto& entry : mapWallet)
    {
        CWalletTx* wtx = &entry.second;
        txByTime.insert(std::make_pair(wtx->nTimeReceived, TxPair(wtx, nullptr)));
    }
    std::list<CAccountingEntry> acentries;
    walletdb.ListAccountCreditDebit("", acentries);
    for (CAccountingEntry& entry : acentries)
    {
        txByTime.insert(std::make_pair(entry.nTime, TxPair(nullptr, &entry)));
    }

    nOrderPosNext = 0;
    std::vector<int64_t> nOrderPosOffsets;
    for (TxItems::iterator it = txByTime.begin(); it != txByTime.end(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        CAccountingEntry *const pacentry = (*it).second.second;
        int64_t& nOrderPos = (pwtx != nullptr) ? pwtx->nOrderPos : pacentry->nOrderPos;

        if (nOrderPos == -1)
        {
            nOrderPos = nOrderPosNext++;
            nOrderPosOffsets.push_back(nOrderPos);

            if (pwtx)
            {
                if (!walletdb.WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!walletdb.WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
        else
        {
            int64_t nOrderPosOff = 0;
            for (const int64_t& nOffsetStart : nOrderPosOffsets)
            {
                if (nOrderPos >= nOffsetStart)
                    ++nOrderPosOff;
            }
            nOrderPos += nOrderPosOff;
            nOrderPosNext = std::max(nOrderPosNext, nOrderPos + 1);

            if (!nOrderPosOff)
                continue;

            // Since we're changing the order, write it back
            if (pwtx)
            {
                if (!walletdb.WriteTx(*pwtx))
                    return DB_LOAD_FAIL;
            }
            else
                if (!walletdb.WriteAccountingEntry(pacentry->nEntryNo, *pacentry))
                    return DB_LOAD_FAIL;
        }
    }
    walletdb.WriteOrderPosNext(nOrderPosNext);

    return DB_LOAD_OK;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(*dbw).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

bool CWallet::AccountMove(std::string strFrom, std::string strTo, CAmount nAmount, std::string strComment)
{
    CWalletDB walletdb(*dbw);
    if (!walletdb.TxnBegin())
        return false;

    int64_t nNow = GetAdjustedTime();

    // Debit
    CAccountingEntry debit;
    debit.nOrderPos = IncOrderPosNext(&walletdb);
    debit.strAccount = strFrom;
    debit.nCreditDebit = -nAmount;
    debit.nTime = nNow;
    debit.strOtherAccount = strTo;
    debit.strComment = strComment;
    AddAccountingEntry(debit, &walletdb);

    // Credit
    CAccountingEntry credit;
    credit.nOrderPos = IncOrderPosNext(&walletdb);
    credit.strAccount = strTo;
    credit.nCreditDebit = nAmount;
    credit.nTime = nNow;
    credit.strOtherAccount = strFrom;
    credit.strComment = strComment;
    AddAccountingEntry(credit, &walletdb);

    if (!walletdb.TxnCommit())
        return false;

    return true;
}

bool CWallet::GetAccountDestination(CTxDestination &dest, std::string strAccount, bool bForceNew)
{
    CWalletDB walletdb(*dbw);

    CAccount account;
    walletdb.ReadAccount(strAccount, account);

    if (!bForceNew) {
        if (!account.vchPubKey.IsValid())
            bForceNew = true;
        else {
            // Check if the current key has been used (TODO: check other addresses with the same key)
            CScript scriptPubKey = GetScriptForDestination(GetDestinationForKey(account.vchPubKey, g_address_type));
            for (std::map<uint256, CWalletTx>::iterator it = mapWallet.begin();
                 it != mapWallet.end() && account.vchPubKey.IsValid();
                 ++it)
                for (const CTxOut& txout : (*it).second.tx->vout)
                    if (txout.scriptPubKey == scriptPubKey) {
                        bForceNew = true;
                        break;
                    }
        }
    }

    // Generate a new key
    if (bForceNew) {
        if (!GetKeyFromPool(account.vchPubKey, false))
            return false;

        LearnRelatedScripts(account.vchPubKey, g_address_type);
        dest = GetDestinationForKey(account.vchPubKey, g_address_type);
        SetAddressBook(dest, strAccount, "receive");
        walletdb.WriteAccount(strAccount, account);
    } else {
        dest = GetDestinationForKey(account.vchPubKey, g_address_type);
    }

    return true;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (std::pair<const uint256, CWalletTx>& item : mapWallet)
            item.second.MarkDirty();
    }
}

bool CWallet::MarkReplaced(const uint256& originalHash, const uint256& newHash)
{
    LOCK(cs_wallet);

    auto mi = mapWallet.find(originalHash);

    // There is a bug if MarkReplaced is not called on an existing wallet transaction.
    assert(mi != mapWallet.end());

    CWalletTx& wtx = (*mi).second;

    // Ensure for now that we're not overwriting data
    assert(wtx.mapValue.count("replaced_by_txid") == 0);

    wtx.mapValue["replaced_by_txid"] = newHash.ToString();

    CWalletDB walletdb(*dbw, "r+");

    bool success = true;
    if (!walletdb.WriteTx(wtx)) {
        LogPrintf("%s: Updating walletdb tx %s failed", __func__, wtx.GetHash().ToString());
        success = false;
    }

    NotifyTransactionChanged(this, originalHash, CT_UPDATED);

    return success;
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn, bool fFlushOnClose)
{
    LOCK(cs_wallet);

    CWalletDB walletdb(*dbw, "r+", fFlushOnClose);

    uint256 hash = wtxIn.GetHash();

    // Inserts only if not already there, returns tx inserted or tx found
    std::pair<std::map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(std::make_pair(hash, wtxIn));
    CWalletTx& wtx = (*ret.first).second;
    wtx.BindWallet(this);
    bool fInsertedNew = ret.second;
    if (fInsertedNew)
    {
        wtx.nTimeReceived = GetAdjustedTime();
        wtx.nOrderPos = IncOrderPosNext(&walletdb);
        wtxOrdered.insert(std::make_pair(wtx.nOrderPos, TxPair(&wtx, nullptr)));
        wtx.nTimeSmart = ComputeTimeSmart(wtx);
        AddToSpends(hash);
    }

    bool fUpdated = false;
    if (!fInsertedNew)
    {
        // Merge
        if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock)
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        // If no longer abandoned, update

        if (wtx.IsCoinStake()) { // A coinstake is unabandoned when it's re-attached to a block
            if (!wtxIn.hashUnset() && wtx.isAbandoned()) {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
        }
        if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned())
        {
            wtx.hashBlock = wtxIn.hashBlock;
            fUpdated = true;
        }
        if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex))
        {
            wtx.nIndex = wtxIn.nIndex;
            fUpdated = true;
        }
        if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
        {
            wtx.fFromMe = wtxIn.fFromMe;
            fUpdated = true;
        }
        // If we have a witness-stripped version of this transaction, and we
        // see a new version with a witness, then we must be upgrading a pre-segwit
        // wallet.  Store the new version of the transaction with the witness,
        // as the stripped-version must be invalid.
        // TODO: Store all versions of the transaction, instead of just one.
        if (wtxIn.tx->HasWitness() && !wtx.tx->HasWitness()) {
            wtx.SetTx(wtxIn.tx);
            fUpdated = true;
        }
    }

    //// debug print
    LogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));

    // Write to disk
    if (fInsertedNew || fUpdated)
        if (!walletdb.WriteTx(wtx))
            return false;

    // Break debit/credit balance caches:
    wtx.MarkDirty();

    // Notify UI of new or updated transaction
    NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

    // notify an external script when a wallet transaction comes in or is updated
    std::string strCmd = gArgs.GetArg("-walletnotify", "");

    if (!strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

bool CWallet::LoadToWallet(const CWalletTx& wtxIn)
{
    uint256 hash = wtxIn.GetHash();
    CWalletTx& wtx = mapWallet.emplace(hash, wtxIn).first->second;
    wtx.BindWallet(this);
    wtxOrdered.insert(std::make_pair(wtx.nOrderPos, TxPair(&wtx, nullptr)));
    AddToSpends(hash);
    for (const CTxIn& txin : wtx.tx->vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            CWalletTx& prevtx = it->second;
            if (prevtx.nIndex == -1 && !prevtx.hashUnset()) {
                MarkConflicted(prevtx.hashBlock, wtx.GetHash());
            }
        }
    }

    int nBestHeight = chainActive.Height();

    if (wtx.IsCoinStake() && wtx.isAbandoned())
    {
        if (wtx.nCachedHeight > 0 && wtx.nCachedHeight < INT_MAX && wtx.nCachedHeight > nBestHeight - (MAX_STAKE_SEEN_SIZE))
        {
            // Add to MapStakeSeen to prevent node submitting a block that would be rejected.
            const COutPoint &kernel = wtx.tx->vin[0].prevout;
            AddToMapStakeSeen(kernel, hash);
        }
    }

    return true;
}

bool CWallet::LoadToWallet(const uint256 &hash, const CTransactionRecord &rtx)
{
    std::pair<MapRecords_t::iterator, bool> ret = mapRecords.insert(std::make_pair(hash, rtx));

    MapRecords_t::iterator mri = ret.first;
    rtxOrdered.insert(std::make_pair(rtx.GetTxTime(), mri));

    // TODO: Spend only owned inputs?

    return true;
}

/**
 * Add a transaction to the wallet, or update it.  pIndex and posInBlock should
 * be set when the transaction was known to be included in a block.  When
 * pIndex == nullptr, then wallet state is not updated in AddToWallet, but
 * notifications happen and cached balances are marked dirty.
 *
 * If fUpdate is true, existing transactions will be updated.
 * TODO: One exception to this is that the abandoned state is cleared under the
 * assumption that any further notification of a transaction that was considered
 * abandoned is an indication that it is not safe to be considered abandoned.
 * Abandoned state should probably be more carefully tracked via different
 * posInBlock signals or by checking mempool presence when necessary.
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const CBlockIndex* pIndex, int posInBlock, bool fUpdate)
{
    const CTransaction& tx = *ptx;
    {
        AssertLockHeld(cs_wallet);

        if (pIndex != nullptr) {
            for (const CTxIn& txin : tx.vin) {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range = mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second) {
                    if (range.first->second != tx.GetHash()) {

                        const CWalletTx *wtxConflicted = GetWalletTx(range.first->second); // coinstakes will only be in mapwallet
                        if (wtxConflicted && wtxConflicted->isAbandoned() && wtxConflicted->IsCoinStake())
                        {
                            // Respending input from orphaned coinstake, leave abandoned
                            LogPrintf("Reusing kernel from orphaned stake %s, new tx %s, \n    (kernel %s:%i).\n",
                                      range.first->second.ToString(), tx.GetHash().ToString(), range.first->first.hash.ToString(), range.first->first.n);
                        } else
                        {
                            LogPrintf("Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n", tx.GetHash().ToString(), pIndex->GetBlockHash().ToString(), range.first->second.ToString(), range.first->first.hash.ToString(), range.first->first.n);
                            MarkConflicted(pIndex->GetBlockHash(), range.first->second);
                        }

                    }
                    range.first++;
                }
            }
        }

        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate) return false;

        bool foundZerocoin = FindUnloadedGhostTransactions(tx);
        TopUpUnloadedCommitments();
        if (fExisted || IsMine(tx) || IsFromMe(tx) || foundZerocoin)
        {
            /* Check if any keys in the wallet keypool that were supposed to be unused
             * have appeared in a new transaction. If so, remove those keys from the keypool.
             * This can happen when restoring an old wallet backup that does not contain
             * the mostly recently created transactions from newer versions of the wallet.
             */

            // loop though all outputs
            if(!foundZerocoin){
                for (const CTxOut& txout: tx.vout) {
                    // extract addresses and check if they match with an unused keypool key
                    std::vector<CKeyID> vAffected;
                    CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                    for (const CKeyID &keyid : vAffected) {
                        std::map<CKeyID, int64_t>::const_iterator mi = m_pool_key_to_index.find(keyid);
                        if (mi != m_pool_key_to_index.end()) {
                            LogPrintf("%s: Detected a used keypool key, mark all keypool key up to this key as used\n", __func__);
                            MarkReserveKeysAsUsed(mi->second);

                            if (!TopUpKeyPool()) {
                                LogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
                            }
                        }
                    }
                }
            }

            // A coinstake txn not linked to a block is being orphaned
            if (fExisted && tx.IsCoinStake() && !pIndex)
            {
                uint256 hashTx = tx.GetHash();
                LogPrintf("Orphaning stake txn: %s\n", hashTx.ToString());

                // If block is later reconnected tx will be unabandoned by AddToWallet
                if (!AbandonTransaction(hashTx))
                    LogPrintf("ERROR: %s - Orphaning stake, AbandonTransaction failed for %s\n", __func__, hashTx.ToString());
            }

            CWalletTx wtx(this, ptx);

            // Get merkle branch if transaction was found in a block
            if (pIndex != nullptr)
                wtx.SetMerkleBranch(pIndex, posInBlock);

            bool rv = AddToWallet(wtx, false);
            WakeThreadStakeMiner(this); // wallet balance may have changed

            return rv;
        }
    }
    return false;
}

bool CWallet::TransactionCanBeAbandoned(const uint256& hashTx) const
{
    LOCK2(cs_main, cs_wallet);
    const CWalletTx* wtx = GetWalletTx(hashTx);
    return wtx && !wtx->isAbandoned() && wtx->GetDepthInMainChain() <= 0 && !wtx->InMempool();
}

bool CWallet::AbandonTransaction(const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet);

    CWalletDB walletdb(*dbw, "r+");

    std::set<uint256> todo;
    std::set<uint256> done;

    // Can't mark abandoned if confirmed or in mempool
    auto it = mapWallet.find(hashTx);
    assert(it != mapWallet.end());
    CWalletTx& origtx = it->second;
    if (origtx.GetDepthInMainChain() > 0 || origtx.InMempool()) {
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;
        int currentconfirm = wtx.GetDepthInMainChain();
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned()) {
            // If the orig tx was not in block/mempool, none of its spends can be in mempool
            assert(!wtx.InMempool());
            wtx.nIndex = -1;
            wtx.setAbandoned();
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            NotifyTransactionChanged(this, wtx.GetHash(), CT_UPDATED);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                if (!done.count(iter->second)) {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (const CTxIn& txin : wtx.tx->vin)
            {
                auto it = mapWallet.find(txin.prevout.hash);
                if (it != mapWallet.end()) {
                    it->second.MarkDirty();
                }
            }

            if (wtx.tx->IsZerocoinSpend()) {
                // find out coin serial number
                for(const CTxIn &txin: wtx.tx->vin){
                    CDataStream serializedCoinSpend((const char *)&*(txin.scriptSig.begin() + 4),
                                                    (const char *)&*txin.scriptSig.end(),
                                                    SER_NETWORK, PROTOCOL_VERSION);
                    libzerocoin::CoinSpend spend(ZCParams, serializedCoinSpend);

                    CBigNum serial = spend.getCoinSerialNumber();

                    // mark corresponding mint as unspent
                    list <CZerocoinEntry> pubCoins;
                    walletdb.ListPubCoin(pubCoins);

                    BOOST_FOREACH(const CZerocoinEntry &zerocoinItem, pubCoins) {
                        if (zerocoinItem.serialNumber == serial) {
                            CZerocoinEntry modifiedItem = zerocoinItem;
                            modifiedItem.IsUsed = false;
                            NotifyZerocoinChanged(this, zerocoinItem.value.GetHex(), zerocoinItem.denomination, "New", CT_UPDATED);

                            walletdb.WriteZerocoinEntry(modifiedItem);

                            // erase zerocoin spend entry
                            CZerocoinSpendEntry spendEntry;
                            spendEntry.coinSerial = serial;
                            walletdb.EraseCoinSpendSerialEntry(spendEntry);
                        }
                    }
                }
            }
        }
    }


    return true;
}

void CWallet::MarkConflicted(const uint256& hashBlock, const uint256& hashTx)
{
    LOCK2(cs_main, cs_wallet);

    int conflictconfirms = 0;
    if (mapBlockIndex.count(hashBlock)) {
        CBlockIndex* pindex = mapBlockIndex[hashBlock];
        if (chainActive.Contains(pindex)) {
            conflictconfirms = -(chainActive.Height() - pindex->nHeight + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(*dbw, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty()) {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        auto it = mapWallet.find(now);
        assert(it != mapWallet.end());
        CWalletTx& wtx = it->second;
        int currentconfirm = wtx.GetDepthInMainChain();
        if (conflictconfirms < currentconfirm) {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            walletdb.WriteTx(wtx);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now) {
                 if (!done.count(iter->second)) {
                     todo.insert(iter->second);
                 }
                 iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (const CTxIn& txin : wtx.tx->vin) {
                auto it = mapWallet.find(txin.prevout.hash);
                if (it != mapWallet.end()) {
                    it->second.MarkDirty();
                }
            }
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef& ptx, const CBlockIndex *pindex, int posInBlock) {
    const CTransaction& tx = *ptx;

    if (!AddToWalletIfInvolvingMe(ptx, pindex, posInBlock, true))
        return; // Not one of ours

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    for (const CTxIn& txin : tx.vin) {
        auto it = mapWallet.find(txin.prevout.hash);
        if (it != mapWallet.end()) {
            it->second.MarkDirty();
        }
    }
}

void CWallet::TransactionAddedToMempool(const CTransactionRef& ptx) {
    LOCK2(cs_main, cs_wallet);
    SyncTransaction(ptx);

    auto it = mapWallet.find(ptx->GetHash());
    if (it != mapWallet.end()) {
        it->second.fInMempool = true;
    }
}

void CWallet::TransactionRemovedFromMempool(const CTransactionRef &ptx) {
    LOCK(cs_wallet);
    auto it = mapWallet.find(ptx->GetHash());
    if (it != mapWallet.end()) {
        it->second.fInMempool = false;
    }
}

void CWallet::BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex *pindex, const std::vector<CTransactionRef>& vtxConflicted) {
    LOCK2(cs_main, cs_wallet);
    // TODO: Temporarily ensure that mempool removals are notified before
    // connected transactions.  This shouldn't matter, but the abandoned
    // state of transactions in our wallet is currently cleared when we
    // receive another notification and there is a race condition where
    // notification of a connected conflict might cause an outside process
    // to abandon a transaction and then have it inadvertently cleared by
    // the notification that the conflicted transaction was evicted.

    for (const CTransactionRef& ptx : vtxConflicted) {
        SyncTransaction(ptx);
        TransactionRemovedFromMempool(ptx);
    }
    for (size_t i = 0; i < pblock->vtx.size(); i++) {
        SyncTransaction(pblock->vtx[i], pindex, i);
        TransactionRemovedFromMempool(pblock->vtx[i]);
    }

    m_last_block_processed = pindex;
}

void CWallet::BlockDisconnected(const std::shared_ptr<const CBlock>& pblock) {
    LOCK2(cs_main, cs_wallet);

    for (const CTransactionRef& ptx : pblock->vtx) {
        SyncTransaction(ptx);
    }
}



void CWallet::BlockUntilSyncedToCurrentChain() {
    AssertLockNotHeld(cs_main);
    AssertLockNotHeld(cs_wallet);

    {
        // Skip the queue-draining stuff if we know we're caught up with
        // chainActive.Tip()...
        // We could also take cs_wallet here, and call m_last_block_processed
        // protected by cs_wallet instead of cs_main, but as long as we need
        // cs_main here anyway, its easier to just call it cs_main-protected.
        LOCK(cs_main);
        const CBlockIndex* initialChainTip = chainActive.Tip();

        if (m_last_block_processed->GetAncestor(initialChainTip->nHeight) == initialChainTip) {
            return;
        }
    }

    // ...otherwise put a callback in the validation interface queue and wait
    // for the queue to drain enough to execute it (indicating we are caught up
    // at least with the time we entered this function).
    SyncWithValidationInterfaceQueue();
}


isminetype CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                return IsMine(prev.tx->vout[txin.prevout.n]);
        }
    }
    return ISMINE_NO;
}

// Note that this function doesn't distinguish between a 0-valued input,
// and a not-"is mine" (according to the filter) input.
CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut& txout) const
{
    return ::IsMine(*this, txout.scriptPubKey);
}

CAmount CWallet::GetCredit(const CTxOut& txout, const isminefilter& filter) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut& txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error(std::string(__func__) + ": value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CWallet::IsMine(const CTransaction& tx) const
{
    for (const CTxOut& txout : tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction& tx) const
{
    return (GetDebit(tx, ISMINE_ALL) > 0);
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nDebit = 0;
    for (const CTxIn& txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nDebit;
}

bool CWallet::IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const
{
    LOCK(cs_wallet);

    for (const CTxIn& txin : tx.vin)
    {
        auto mi = mapWallet.find(txin.prevout.hash);
        if (mi == mapWallet.end())
            return false; // any unknown inputs can't be from us

        const CWalletTx& prev = (*mi).second;

        if (txin.prevout.n >= prev.tx->vout.size())
            return false; // invalid input!

        if (!(IsMine(prev.tx->vout[txin.prevout.n]) & filter))
            return false;
    }
    return true;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const isminefilter& filter) const
{
    CAmount nCredit = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction& tx) const
{
    CAmount nChange = 0;
    for (const CTxOut& txout : tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nChange;
}

CPubKey CWallet::GenerateNewHDMasterKey()
{
    CKey key;
    key.MakeNewKey(true);

    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the pubkey
    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));

    // set the hd keypath to "m" -> Master, refers the masterkeyid to itself
    metadata.hdKeypath     = "m";
    metadata.hdMasterKeyID = pubkey.GetID();

    {
        LOCK(cs_wallet);

        // mem store the metadata
        mapKeyMetadata[pubkey.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, pubkey))
            throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");
    }

    return pubkey;
}

bool CWallet::SetHDMasterKey(const CPubKey& pubkey)
{
    LOCK(cs_wallet);
    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.nVersion = CanSupportFeature(FEATURE_HD_SPLIT) ? CHDChain::VERSION_HD_CHAIN_SPLIT : CHDChain::VERSION_HD_BASE;
    newHdChain.masterKeyID = pubkey.GetID();
    SetHDChain(newHdChain, false);

    return true;
}

bool CWallet::SetHDChain(const CHDChain& chain, bool memonly)
{
    LOCK(cs_wallet);
    if (!memonly && !CWalletDB(*dbw).WriteHDChain(chain))
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");

    hdChain = chain;
    return true;
}

bool CWallet::IsHDEnabled() const
{
    return !hdChain.masterKeyID.IsNull();
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase() || IsCoinStake())
        {
            // Generated block
            if (!hashUnset())
            {
                std::map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            std::map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashUnset())
                {
                    std::map<uint256, int>::const_iterator _mi = pwallet->mapRequestCount.find(hashBlock);
                    if (_mi != pwallet->mapRequestCount.end())
                        nRequests = (*_mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(std::list<COutputEntry>& listReceived,
                           std::list<COutputEntry>& listSent, std::list<COutputEntry> &listStaked, CAmount& nFee, std::string& strSentAccount, const isminefilter& filter, bool fForFilterTx) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = tx->GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // staked
    if (tx->IsCoinStake())
    {
        CAmount nCredit = 0;
        CTxDestination address = CNoDestination();
        CTxDestination addressStake = CNoDestination();

        isminetype isMineAll = ISMINE_NO;
        for (unsigned int i = 0; i < tx->vout.size(); ++i)
        {
            isminetype mine = pwallet->IsMine(tx->vout[i]);
            if (!(mine & filter))
                continue;
            isMineAll = (isminetype)((uint8_t)isMineAll |(uint8_t)mine);

            if (fForFilterTx || address.type() == typeid(CNoDestination))
            {
                const CScript &scriptPubKey = tx->vout[i].scriptPubKey;
                ExtractDestination(scriptPubKey, address);

                if (HasIsCoinstakeOp(scriptPubKey))
                {
                    CScript scriptOut;
                    if (GetCoinstakeScriptPath(scriptPubKey, scriptOut)){
                        CScriptID coinstakeScript;
                        ExtractStakingKeyID(scriptOut, coinstakeScript);
                        addressStake = coinstakeScript;
                    }
                };
            };
            nCredit += tx->vout[i].nValue;

            if (fForFilterTx)
            {
                COutputEntry output = {address, tx->vout[i].nValue, (int)i, mine, addressStake};
                listStaked.push_back(output);
            };
        };
        // Recalc fee as GetValueOut might include foundation fund output
        nFee = nDebit - nCredit;

        if (fForFilterTx || !(isMineAll & filter))
            return;

        COutputEntry output = {address, nCredit, 1, isMineAll, addressStake};
        listStaked.push_back(output);
        return;
    }

    // Sent/received.
    for (unsigned int i = 0; i < tx->vout.size(); ++i)
    {
        const CTxOut& txout = tx->vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            //LogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",
            //         this->GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }

}

/**
 * Scan active chain for relevant transactions after importing keys. This should
 * be called whenever new keys are added to the wallet, with the oldest key
 * creation time.
 *
 * @return Earliest timestamp that could be successfully scanned from. Timestamp
 * returned will be higher than startTime if relevant blocks could not be read.
 */
int64_t CWallet::RescanFromTime(int64_t startTime, const WalletRescanReserver& reserver, bool update)
{
    // Find starting block. May be null if nCreateTime is greater than the
    // highest blockchain timestamp, in which case there is nothing that needs
    // to be scanned.
    CBlockIndex* startBlock = nullptr;
    {
        LOCK(cs_main);
        startBlock = chainActive.FindEarliestAtLeast(startTime - TIMESTAMP_WINDOW);
        LogPrintf("%s: Rescanning last %i blocks\n", __func__, startBlock ? chainActive.Height() - startBlock->nHeight + 1 : 0);
    }

    if (startBlock) {
        const CBlockIndex* const failedBlock = ScanForWalletTransactions(startBlock, nullptr, reserver, update);
        if (failedBlock) {
            return failedBlock->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1;
        }
    }
    return startTime;
}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 *
 * Returns null if scan was successful. Otherwise, if a complete rescan was not
 * possible (due to pruning or corruption), returns pointer to the most recent
 * block that could not be scanned.
 *
 * If pindexStop is not a nullptr, the scan will stop at the block-index
 * defined by pindexStop
 *
 * Caller needs to make sure pindexStop (and the optional pindexStart) are on
 * the main chain after to the addition of any new keys you want to detect
 * transactions for.
 */
CBlockIndex* CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, CBlockIndex* pindexStop, const WalletRescanReserver &reserver, bool fUpdate)
{
    int64_t nNow = GetTime();
    const CChainParams& chainParams = Params();

    assert(reserver.isReserved());
    if (pindexStop) {
        assert(pindexStop->nHeight >= pindexStart->nHeight);
    }

    CBlockIndex* pindex = pindexStart;
    CBlockIndex* ret = nullptr;
    {
        fAbortRescan = false;
        ShowProgress(_("Rescanning..."), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        CBlockIndex* tip = nullptr;
        double dProgressStart;
        double dProgressTip;
        {
            LOCK(cs_main);
            tip = chainActive.Tip();
            dProgressStart = GuessVerificationProgress(chainParams.TxData(), pindex);
            dProgressTip = GuessVerificationProgress(chainParams.TxData(), tip);
        }
        while (pindex && !fAbortRescan)
        {
            if (pindex->nHeight % 100 == 0 && dProgressTip - dProgressStart > 0.0) {
                double gvp = 0;
                {
                    LOCK(cs_main);
                    gvp = GuessVerificationProgress(chainParams.TxData(), pindex);
                }
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99, (int)((gvp - dProgressStart) / (dProgressTip - dProgressStart) * 100))));
            }
            if (GetTime() >= nNow + 60) {
                nNow = GetTime();
                LOCK(cs_main);
                LogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex->nHeight, GuessVerificationProgress(chainParams.TxData(), pindex));
            }

            CBlock block;
            if (ReadBlockFromDisk(block, pindex, Params().GetConsensus())) {
                LOCK2(cs_main, cs_wallet);
                if (pindex && !chainActive.Contains(pindex)) {
                    // Abort scan if current block is no longer active, to prevent
                    // marking transactions as coming from the wrong block.
                    ret = pindex;
                    break;
                }
                for (size_t posInBlock = 0; posInBlock < block.vtx.size(); ++posInBlock) {
                    AddToWalletIfInvolvingMe(block.vtx[posInBlock], pindex, posInBlock, fUpdate);
                }
            } else {
                ret = pindex;
            }
            if (pindex == pindexStop) {
                break;
            }
            {
                LOCK(cs_main);
                pindex = chainActive.Next(pindex);
                if (tip != chainActive.Tip()) {
                    tip = chainActive.Tip();
                    // in case the tip has changed, update progress max
                    dProgressTip = GuessVerificationProgress(chainParams.TxData(), tip);
                }
            }
        }
        if (pindex && fAbortRescan) {
            LogPrintf("Rescan aborted at block %d. Progress=%f\n", pindex->nHeight, GuessVerificationProgress(chainParams.TxData(), pindex));
        }
        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;
    LOCK2(cs_main, cs_wallet);
    std::map<int64_t, CWalletTx*> mapSorted;

    // Sort pending wallet transactions based on their initial wallet insertion order
    for (std::pair<const uint256, CWalletTx>& item : mapWallet)
    {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain();

        if ((!wtx.IsCoinBase() && !wtx.tx->IsZerocoinSpend()) && !wtx.IsCoinStake() && (nDepth == 0 && !wtx.isAbandoned())) {
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
        }
    }

    // Try to add wallet transactions to memory pool
    for (std::pair<const int64_t, CWalletTx*>& item : mapSorted) {
        CWalletTx& wtx = *(item.second);
        CValidationState state;
        wtx.AcceptToMemoryPool(maxTxFee, state);
    }
}

bool CWalletTx::RelayWalletTransaction(CConnman* connman)
{
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase() && !IsCoinStake() && !isAbandoned() && GetDepthInMainChain() == 0)
    {
        CValidationState state;
        /* GetDepthInMainChain already catches known conflicts. */
        if (InMempool() || AcceptToMemoryPool(maxTxFee, state)) {
            if (connman) {
                CInv inv(MSG_TX, GetHash());
                connman->ForEachNode([&inv](CNode* pnode)
                {
                    pnode->PushInventory(inv);
                });
                LogPrintf("Relaying wtx %s\n", GetHash().ToString());
                return true;
            }
        }
    }
    return false;
}

std::set<uint256> CWalletTx::GetConflicts() const
{
    std::set<uint256> result;
    if (pwallet != nullptr)
    {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (tx->vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*tx, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*tx, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0)
        return 0;

    CAmount credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE) + pwallet->GetCredit(*tx, ISMINE_WATCH_COLDSTAKE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache, bool fForStaking) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableCreditCached)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(hashTx, i))
        {
            const CTxOut &txout = tx->vout[i];

            const CScript pscriptPubKey = txout.scriptPubKey;

            //only check p2sh balances for staking
            if(fForStaking){
                CTxDestination dest;
                if (!ExtractDestination(pscriptPubKey, dest))
                    continue;
                if(boost::get<CScriptID>(&dest)){
                    nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE) + pwallet->GetCredit(txout, ISMINE_WATCH_COLDSTAKE);
                    if (!MoneyRange(nCredit))
                        throw std::runtime_error(std::string(__func__) + " : value out of range");
                }
                else
                    continue;
            }
            else{
                nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE) + pwallet->GetCredit(txout, ISMINE_WATCH_COLDSTAKE);
                if (!MoneyRange(nCredit))
                    throw std::runtime_error(std::string(__func__) + " : value out of range");
            }
        }
    }

    nAvailableCreditCached = nCredit;
    if(!fForStaking)
        fAvailableCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool fUseCache) const
{
    if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool fUseCache) const
{
    if (pwallet == nullptr)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(GetHash(), i))
        {
            const CTxOut &txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error(std::string(__func__) + ": value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*tx);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const
{
    return fInMempool;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases
    if (!CheckFinalTx(*tx))
        return false;
    if (tx->IsCoinStake() && hashUnset()) // ignore failed stakes
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!InMempool())
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    for (const CTxIn& txin : tx->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == nullptr)
            return false;
        const CTxOut& parentOut = parent->tx->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

bool CWalletTx::IsEquivalentTo(const CWalletTx& _tx) const
{
        CMutableTransaction tx1 = *this->tx;
        CMutableTransaction tx2 = *_tx.tx;
        for (auto& txin : tx1.vin) txin.scriptSig = CScript();
        for (auto& txin : tx2.vin) txin.scriptSig = CScript();
        return CTransaction(tx1) == CTransaction(tx2);
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime, CConnman* connman)
{
    std::vector<uint256> result;

    LOCK(cs_wallet);

    // Sort them in chronological order
    std::multimap<unsigned int, CWalletTx*> mapSorted;
    for (std::pair<const uint256, CWalletTx>& item : mapWallet)
    {
        CWalletTx& wtx = item.second;
        // Don't rebroadcast if newer than nTime:
        if (wtx.nTimeReceived > nTime)
            continue;
        mapSorted.insert(std::make_pair(wtx.nTimeReceived, &wtx));
    }
    for (std::pair<const unsigned int, CWalletTx*>& item : mapSorted)
    {
        CWalletTx& wtx = *item.second;
        if (wtx.RelayWalletTransaction(connman))
            result.push_back(wtx.GetHash());
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime, CConnman* connman)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime-5*60, connman);
    if (!relayed.empty())
        LogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit(true, false);
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableCredit(true, false);
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetGhostBalance() const
{
    std::vector<COutput> vCoins;
    ListAvailableCoinsMintCoins(vCoins);
    int nRequiredDepth = 0;

    CAmount nTotal = 0;
    for(int i = 0; i < vCoins.size(); i++){
            if (vCoins[i].tx->tx->vout[vCoins[i].i].scriptPubKey.IsZerocoinMint()) {

                const uint256& prevHash = vCoins[i].tx->GetHash();
                CTransactionRef tx;
                uint256 hashBlock;
                bool fFound = GetTransaction(prevHash, tx, Params().GetConsensus(), hashBlock);
                if(fFound)
                {
                    if(mapBlockIndex.find(hashBlock) != mapBlockIndex.end())
                    {
                        if(chainActive.Height() - mapBlockIndex[hashBlock]->nHeight >= nRequiredDepth)
                            nTotal += vCoins[i].tx->tx->vout[vCoins[i].i].nValue;

                    }
                }
            }
    }
    return nTotal;
}

CAmount CWallet::GetGhostBalanceUnconfirmed() const
{
    std::vector<COutput> vCoins;
    ListAvailableCoinsMintCoins(vCoins, false);

    CAmount nTotal = 0;
    for(int i = 0; i < vCoins.size(); i++){
            if (vCoins[i].tx->tx->vout[vCoins[i].i].scriptPubKey.IsZerocoinMint()) {
                nTotal += vCoins[i].tx->tx->vout[vCoins[i].i].nValue;
            }
    }
    return nTotal - GetGhostBalance();
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (const auto& entry : mapWallet)
        {
            const CWalletTx* pcoin = &entry.second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

// Calculate total balance in a different way from GetBalance. The biggest
// difference is that GetBalance sums up all unspent TxOuts paying to the
// wallet, while this sums up both spent and unspent TxOuts paying to the
// wallet, and then subtracts the values of TxIns spending from the wallet. This
// also has fewer restrictions on which unconfirmed transactions are considered
// trusted.
CAmount CWallet::GetLegacyBalance(const isminefilter& filter, int minDepth, const std::string* account) const
{
    LOCK2(cs_main, cs_wallet);

    CAmount balance = 0;
    for (const auto& entry : mapWallet) {
        const CWalletTx& wtx = entry.second;
        const int depth = wtx.GetDepthInMainChain();
        if (depth < 0 || !CheckFinalTx(*wtx.tx) || wtx.GetBlocksToMaturity() > 0) {
            continue;
        }

        // Loop through tx outputs and add incoming payments. For outgoing txs,
        // treat change outputs specially, as part of the amount debited.
        CAmount debit = wtx.GetDebit(filter);
        const bool outgoing = debit > 0;
        for (const CTxOut& out : wtx.tx->vout) {
            if (outgoing && IsChange(out)) {
                debit -= out.nValue;
            } else if (IsMine(out) & filter && depth >= minDepth && (!account || *account == GetAccountName(out.scriptPubKey))) {
                balance += out.nValue;
            }
        }

        // For outgoing txs, subtract amount debited.
        if (outgoing && (!account || *account == wtx.strFromAccount)) {
            balance -= debit;
        }
    }

    if (account) {
        balance += CWalletDB(*dbw).GetAccountCreditDebit(*account);
    }

    return balance;
}

CAmount CWallet::GetAvailableBalance(const CCoinControl* coinControl) const
{
    LOCK2(cs_main, cs_wallet);

    CAmount balance = 0;
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl);
    for (const COutput& out : vCoins) {
        if (out.fSpendable) {
            balance += out.tx->tx->vout[out.i].nValue;
        }
    }
    return balance;
}

void CWallet::AvailableCoins(std::vector<COutput> &vCoins, bool fOnlySafe, const CCoinControl *coinControl, const CAmount &nMinimumAmount, const CAmount &nMaximumAmount, const CAmount &nMinimumSumAmount, const uint64_t nMaximumCount, const int nMinDepth, const int nMaxDepth, AvailableCoinsType nCoinType, bool includeImmature) const
{
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);

        CAmount nTotal = 0;

        for (const auto& entry : mapWallet)
        {
            const uint256& wtxid = entry.first;
            const CWalletTx* pcoin = &entry.second;
            bool isGN = false;
            if (!CheckFinalTx(*pcoin->tx))
                continue;

            if (!includeImmature && (pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;

            //int nDepth = pcoin->GetDepthInMainChain();
            int nDepth = pcoin->GetDepthInMainChain(false);
            //if (nDepth < 0)
                //continue;

            // We should not consider coins which aren't at least in our mempool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (nDepth == 0 && !pcoin->InMempool())
                continue;

            bool safeTx = pcoin->IsTrusted();

            // We should not consider coins from transactions that are replacing
            // other transactions.
            //
            // Example: There is a transaction A which is replaced by bumpfee
            // transaction B. In this case, we want to prevent creation of
            // a transaction B' which spends an output of B.
            //
            // Reason: If transaction A were initially confirmed, transactions B
            // and B' would no longer be valid, so the user would have to create
            // a new transaction C to replace B'. However, in the case of a
            // one-block reorg, transactions B' and C might BOTH be accepted,
            // when the user only wanted one of them. Specifically, there could
            // be a 1-block reorg away from the chain where transactions A and C
            // were accepted to another chain where B, B', and C were all
            // accepted.
            if (nDepth == 0 && pcoin->mapValue.count("replaces_txid")) {
                safeTx = false;
            }

            // Similarly, we should not consider coins from transactions that
            // have been replaced. In the example above, we would want to prevent
            // creation of a transaction A' spending an output of A, because if
            // transaction B were initially confirmed, conflicting with A and
            // A', we wouldn't want to the user to create a transaction D
            // intending to replace A', but potentially resulting in a scenario
            // where A, A', and D could all be accepted (instead of just B and
            // D, or just A and A' like the user would want).
            if (nDepth == 0 && pcoin->mapValue.count("replaced_by_txid")) {
                safeTx = false;
            }

            if (fOnlySafe && !safeTx) {
                continue;
            }

            if (nDepth < nMinDepth || nDepth > nMaxDepth)
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {

                bool found = false;
                if (nCoinType == ONLY_DENOMINATED) {
                    found = IsDenominatedAmount(pcoin->tx->vout[i].nValue);
                } else if (nCoinType == ONLY_NOT40000IFMN) {
                    found = !(fGhostNode && pcoin->tx->vout[i].nValue == GHOSTNODE_COIN_REQUIRED * COIN);
                } else if (nCoinType == ONLY_NONDENOMINATED_NOT40000IFMN) {
                    if (IsCollateralAmount(pcoin->tx->vout[i].nValue)) continue; // do not use collateral amounts
                    found = !IsDenominatedAmount(pcoin->tx->vout[i].nValue);
                    if (found && fGhostNode) found = pcoin->tx->vout[i].nValue != GHOSTNODE_COIN_REQUIRED * COIN; // do not use Hot MN funds
                } else if (nCoinType == ONLY_40000) {
                    //LogPrintf("nCoinType = ONLY_40000\n");
                    //LogPrintf("pcoin->vout[i].nValue = %s\n", pcoin->tx->vout[i].nValue);
                    found = pcoin->tx->vout[i].nValue == GHOSTNODE_COIN_REQUIRED * COIN;
                    isGN = true;
                } else if (nCoinType == ONLY_PRIVATESEND_COLLATERAL) {
                    found = IsCollateralAmount(pcoin->tx->vout[i].nValue);
                } else {
                    found = true;
                }
                if (!found) continue;


                if (pcoin->tx->vout[i].nValue < nMinimumAmount || pcoin->tx->vout[i].nValue > nMaximumAmount)
                    continue;

                if(isGN){
                    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(pcoin->tx->vout[i].GetHash(), i)))
                        continue;
                    if (IsLockedCoin(pcoin->tx->vout[i].GetHash(), i))
                        continue;
                    if (IsSpent(pcoin->tx->vout[i].GetHash(), i))
                        continue;
                }
                else{
                    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs && !coinControl->IsSelected(COutPoint(entry.first, i)))
                        continue;
                    if (IsLockedCoin(entry.first, i))
                        continue;
                    if (IsSpent(wtxid, i))
                        continue;
                }



                isminetype mine = IsMine(pcoin->tx->vout[i]);

                if (mine == ISMINE_NO) {
                    continue;
                }

                bool fSpendableIn = ((mine & ISMINE_SPENDABLE) != ISMINE_NO) || (coinControl && coinControl->fAllowWatchOnly && (mine & ISMINE_WATCH_SOLVABLE) != ISMINE_NO);
                bool fSolvableIn = (mine & (ISMINE_SPENDABLE | ISMINE_WATCH_SOLVABLE)) != ISMINE_NO;

                vCoins.push_back(COutput(pcoin, i, nDepth, fSpendableIn, fSolvableIn, safeTx));

                // Checks the sum amount of all UTXO's.
                if (nMinimumSumAmount != MAX_MONEY) {
                    nTotal += pcoin->tx->vout[i].nValue;

                    if (nTotal >= nMinimumSumAmount) {
                        return;
                    }
                }

                // Checks the maximum number of UTXO's.
                if (nMaximumCount > 0 && vCoins.size() >= nMaximumCount) {
                    return;
                }
            }
        }
    }
}

std::map<CTxDestination, std::vector<COutput>> CWallet::ListCoins() const
{
    // TODO: Add AssertLockHeld(cs_wallet) here.
    //
    // Because the return value from this function contains pointers to
    // CWalletTx objects, callers to this function really should acquire the
    // cs_wallet lock before calling it. However, the current caller doesn't
    // acquire this lock yet. There was an attempt to add the missing lock in
    // https://github.com/bitcoin/bitcoin/pull/10340, but that change has been
    // postponed until after https://github.com/bitcoin/bitcoin/pull/10244 to
    // avoid adding some extra complexity to the Qt code.

    std::map<CTxDestination, std::vector<COutput>> result;

    std::vector<COutput> availableCoins;
    AvailableCoins(availableCoins);

    LOCK2(cs_main, cs_wallet);
    for (auto& coin : availableCoins) {
        CTxDestination address;
        if (coin.fSpendable &&
            ExtractDestination(FindNonChangeParentOutput(*coin.tx->tx, coin.i).scriptPubKey, address)) {
            result[address].emplace_back(std::move(coin));
        }
    }

    std::vector<COutPoint> lockedCoins;
    ListLockedCoins(lockedCoins);
    for (const auto& output : lockedCoins) {
        auto it = mapWallet.find(output.hash);
        if (it != mapWallet.end()) {
            int depth = it->second.GetDepthInMainChain();
            if (depth >= 0 && output.n < it->second.tx->vout.size() &&
                IsMine(it->second.tx->vout[output.n]) == ISMINE_SPENDABLE) {
                CTxDestination address;
                if (ExtractDestination(FindNonChangeParentOutput(*it->second.tx, output.n).scriptPubKey, address)) {
                    result[address].emplace_back(
                        &it->second, output.n, depth, true /* spendable */, true /* solvable */, false /* safe */);
                }
            }
        }
    }

    return result;
}

const CTxOut& CWallet::FindNonChangeParentOutput(const CTransaction& tx, int output) const
{
    const CTransaction* ptx = &tx;
    int n = output;
    while (IsChange(ptx->vout[n]) && ptx->vin.size() > 0) {
        const COutPoint& prevout = ptx->vin[0].prevout;
        auto it = mapWallet.find(prevout.hash);
        if (it == mapWallet.end() || it->second.tx->vout.size() <= prevout.n ||
            !IsMine(it->second.tx->vout[prevout.n])) {
            break;
        }
        ptx = it->second.tx.get();
        n = prevout.n;
    }
    return ptx->vout[n];
}

static void ApproximateBestSubset(const std::vector<CInputCoin>& vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,
                                  std::vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    FastRandomContext insecure_rand;

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand.randbool() : !vfIncluded[i])
                {
                    nTotal += vValue[i].txout.nValue;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].txout.nValue;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(const CAmount& nTargetValue, const int nConfMine, const int nConfTheirs, const uint64_t nMaxAncestors, std::vector<COutput> vCoins,
                                 std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    boost::optional<CInputCoin> coinLowestLarger;
    std::vector<CInputCoin> vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    for (const COutput &output : vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        if (!mempool.TransactionWithinChainLimit(pcoin->GetHash(), nMaxAncestors))
            continue;

        int i = output.i;

        CInputCoin coin = CInputCoin(pcoin, i);

        if (coin.txout.nValue == nTargetValue)
        {
            setCoinsRet.insert(coin);
            nValueRet += coin.txout.nValue;
            return true;
        }
        else if (coin.txout.nValue < nTargetValue + MIN_CHANGE)
        {
            vValue.push_back(coin);
            nTotalLower += coin.txout.nValue;
        }
        else if (!coinLowestLarger || coin.txout.nValue < coinLowestLarger->txout.nValue)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (const auto& input : vValue)
        {
            setCoinsRet.insert(input);
            nValueRet += input.txout.nValue;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (!coinLowestLarger)
            return false;
        setCoinsRet.insert(coinLowestLarger.get());
        nValueRet += coinLowestLarger->txout.nValue;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.begin(), vValue.end(), CompareValueOnly());
    std::reverse(vValue.begin(), vValue.end());
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger->txout.nValue <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.get());
        nValueRet += coinLowestLarger->txout.nValue;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i]);
                nValueRet += vValue[i].txout.nValue;
            }

        if (LogAcceptCategory(BCLog::SELECTCOINS)) {
            LogPrint(BCLog::SELECTCOINS, "SelectCoins() best subset: ");
            for (unsigned int i = 0; i < vValue.size(); i++) {
                if (vfBest[i]) {
                    LogPrint(BCLog::SELECTCOINS, "%s ", FormatMoney(vValue[i].txout.nValue));
                }
            }
            LogPrint(BCLog::SELECTCOINS, "total %s\n", FormatMoney(nBest));
        }
    }

    return true;
}

bool CWallet::SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet, const CCoinControl* coinControl, AvailableCoinsType nCoinType, bool fUseInstantSend) const
{
    std::vector<COutput> vCoins(vAvailableCoins);

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        for (const COutput& out : vCoins)
        {
            if (!out.fSpendable)
                 continue;
            if (nCoinType == ONLY_DENOMINATED) {
                CTxIn txin = CTxIn(out.tx->GetHash(), out.i);
                int nRounds = GetInputPrivateSendRounds(txin);
                // make sure it's actually anonymized
                if (nRounds < nPrivateSendRounds) continue;
            }
            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.insert(CInputCoin(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    //if we're doing only denominated, we need to round up to the nearest smallest denomination
    if (nCoinType == ONLY_DENOMINATED) {
        CAmount nSmallestDenom = vecPrivateSendDenominations.back();
        // Make outputs by looping through denominations, from large to small
        BOOST_FOREACH(CAmount nDenom, vecPrivateSendDenominations)
        {
            BOOST_FOREACH(const COutput &out, vCoins)
            {
                //make sure it's the denom we're looking for, round the amount up to smallest denom
                if (out.tx->tx->vout[out.i].nValue == nDenom && nValueRet + nDenom < nTargetValue + nSmallestDenom) {
                    CTxIn txin = CTxIn(out.tx->GetHash(), out.i);
                    int nRounds = GetInputPrivateSendRounds(txin);
                    // make sure it's actually anonymized
                    if (nRounds < nPrivateSendRounds) continue;
                    nValueRet += nDenom;
                    setCoinsRet.insert(CInputCoin(out.tx, out.i));
                }
            }
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    std::set<CInputCoin> setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    for (const COutPoint& outpoint : vPresetInputs)
    {
        std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->tx->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->tx->vout[outpoint.n].nValue;
            setPresetCoins.insert(CInputCoin(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (std::vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(CInputCoin(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

    size_t nMaxChainLength = std::min(gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT), gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT));
    bool fRejectLongChains = gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS);

    bool res = nTargetValue <= nValueFromPresetInputs ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 6, 0, vCoins, setCoinsRet, nValueRet) ||
        SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 1, 0, vCoins, setCoinsRet, nValueRet) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, 2, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, std::min((size_t)4, nMaxChainLength/3), vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength/2, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, nMaxChainLength, vCoins, setCoinsRet, nValueRet)) ||
        (bSpendZeroConfChange && !fRejectLongChains && SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, std::numeric_limits<uint64_t>::max(), vCoins, setCoinsRet, nValueRet));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CWallet::SignTransaction(CMutableTransaction &tx)
{
    AssertLockHeld(cs_wallet); // mapWallet

    // sign the new tx
    CTransaction txNewConst(tx);
    int nIn = 0;
    for (const auto& input : tx.vin) {
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(input.prevout.hash);
        if(mi == mapWallet.end() || input.prevout.n >= mi->second.tx->vout.size()) {
            return false;
        }
        const CScript& scriptPubKey = mi->second.tx->vout[input.prevout.n].scriptPubKey;
        const CAmount& amount = mi->second.tx->vout[input.prevout.n].nValue;
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, amount, SIGHASH_ALL), scriptPubKey, sigdata)) {
            return false;
        }
        UpdateTransaction(tx, nIn, sigdata);
        nIn++;
    }
    return true;
}

bool CWallet::FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosInOut, std::string& strFailReason, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, CCoinControl coinControl)
{
    std::vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector.
    for (size_t idx = 0; idx < tx.vout.size(); idx++) {
        const CTxOut& txOut = tx.vout[idx];
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, setSubtractFeeFromOutputs.count(idx) == 1};
        vecSend.push_back(recipient);
    }

    coinControl.fAllowOtherInputs = true;

    for (const CTxIn& txin : tx.vin) {
        coinControl.Select(txin.prevout);
    }

    // Acquire the locks to prevent races to the new locked unspents between the
    // CreateTransaction call and LockCoin calls (when lockUnspents is true).
    LOCK2(cs_main, cs_wallet);

    CReserveKey reservekey(this);
    CWalletTx wtx;
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosInOut, strFailReason, coinControl, false)) {
        return false;
    }

    if (nChangePosInOut != -1) {
        tx.vout.insert(tx.vout.begin() + nChangePosInOut, wtx.tx->vout[nChangePosInOut]);
        // We don't have the normal Create/Commit cycle, and don't want to risk
        // reusing change, so just remove the key from the keypool here.
        reservekey.KeepKey();
    }

    // Copy output sizes from new transaction; they may have had the fee
    // subtracted from them.
    for (unsigned int idx = 0; idx < tx.vout.size(); idx++) {
        tx.vout[idx].nValue = wtx.tx->vout[idx].nValue;
    }

    // Add new txins while keeping original txin scriptSig/order.
    for (const CTxIn& txin : wtx.tx->vin) {
        if (!coinControl.IsSelected(txin.prevout)) {
            tx.vin.push_back(txin);

            if (lockUnspents) {
                LockCoin(txin.prevout);
            }
        }
    }

    return true;
}

bool CWallet::GetFeeForTransaction(const std::vector<CRecipient>& vecSend, CAmount& nFeeRet, int& nChangePosInOut, std::string& strFailReason,
                                   const CCoinControl& coin_control, AvailableCoinsType nCoinType, bool fUseInstantSend)
{
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    for (const auto& recipient : vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must not be negative");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty())
    {
        strFailReason = _("Transaction must have at least one recipient");
        return false;
    }

    CMutableTransaction txNew;

    txNew.nLockTime = chainActive.Height();

    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    unsigned int nBytes;
    {
        std::set<CInputCoin> setCoins;
        LOCK2(cs_main, cs_wallet);
        {
            std::vector<COutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, &coin_control, false, MAX_MONEY, MAX_MONEY,0, 0, 9999999, nCoinType, fUseInstantSend);

            CScript scriptChange = vecSend.front().scriptPubKey;
            CTxOut change_prototype_txout(0, scriptChange);
            size_t change_prototype_size = GetSerializeSize(change_prototype_txout, SER_DISK, 0);

            CFeeRate discard_rate = GetDiscardRate(::feeEstimator);
            nFeeRet = 0;
            bool pick_new_inputs = true;
            CAmount nValueIn = 0;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                // vouts to the payees
                for (const auto& recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        assert(nSubtractFeeFromAmount != 0);
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    if (IsDust(txout, ::dustRelayFee))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                if (pick_new_inputs) {
                    nValueIn = 0;
                    setCoins.clear();
                    if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, &coin_control))
                    {
                        if (nCoinType == ONLY_NOT40000IFMN) {
                            strFailReason = _("Unable to locate enough funds for this transaction that are not equal 40000 NIX.");
                        } else if (nCoinType == ONLY_NONDENOMINATED_NOT40000IFMN) {
                            strFailReason = _("Unable to locate enough PrivateSend non-denominated funds for this transaction that are not equal 40000 NIX.");
                        } else if (nCoinType == ONLY_DENOMINATED) {
                            strFailReason = _("Unable to locate enough PrivateSend denominated funds for this transaction.");
                            strFailReason += _("PrivateSend uses exact denominated amounts to send funds, you might simply need to anonymize some more coins.");
                        } else if (nValueIn < nValueToSelect) {
                            strFailReason = _("Insufficient funds.");
                        }
                        strFailReason = _("Insufficient funds");
                        return false;
                    }
                }

                const CAmount nChange = nValueIn - nValueToSelect;

                if (nChange > 0) {
                    //over pay for denominated transactions
                    if (nCoinType == ONLY_DENOMINATED) {
                        nFeeRet += nChange;
                        // recheck skipped denominations during next mixing
                        darkSendPool.ClearSkippedDenominations();
                    } else {
                        // Fill a vout to ourself
                        // TODO: pass in scriptChange instead of reservekey so
                        // change transaction isn't always pay-to-bitcoin-address
                        CScript scriptChange = vecSend.front().scriptPubKey;

                        CTxOut newTxOut(nChange, scriptChange);

                        // We do not move dust-change to fees, because the sender would end up paying more than requested.
                        // This would be against the purpose of the all-inclusive feature.
                        // So instead we raise the change and deduct from the recipient.
                        if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust()) {
                            CAmount nDust = GetDustThreshold(newTxOut, ::minRelayTxFee) - newTxOut.nValue;
                            newTxOut.nValue += nDust; // raise change until no more dust
                            for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                            {
                                if (vecSend[i].fSubtractFeeFromAmount) {
                                    txNew.vout[i].nValue -= nDust;
                                    if (txNew.vout[i].IsDust()) {
                                        strFailReason = _(
                                                "The transaction amount is too small to send after the fee has been deducted");
                                        return false;
                                    }
                                    break;
                                }
                            }
                        }

                        // Never create dust outputs; if we would, just
                        // add the dust to the fee.
                        if (newTxOut.IsDust()) {
                            nChangePosInOut = -1;
                            nFeeRet += nChange;
                        } else {
                            if (nChangePosInOut == -1) {
                                // Insert change txn at random position:
                                nChangePosInOut = GetRandInt(txNew.vout.size() + 1);
                            } else if ((unsigned int) nChangePosInOut > txNew.vout.size()) {
                                strFailReason = _("Change index out of range");
                                return false;
                            }

                            vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosInOut;
                            txNew.vout.insert(position, newTxOut);
                        }
                    }
                }

                const uint32_t nSequence = coin_control.signalRbf ? MAX_BIP125_RBF_SEQUENCE : (CTxIn::SEQUENCE_FINAL - 1);
                for (const auto& coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.outpoint,CScript(),
                                              nSequence));

                // Fill in dummy signatures for fee calculation.
                if (!DummySignTx(txNew, setCoins)) {
                    strFailReason = _("Signing transaction failed");
                    return false;
                }

                nBytes = GetVirtualTransactionSize(txNew);

                // Remove scriptSigs to eliminate the fee calculation dummy signatures
                for (auto& vin : txNew.vin) {
                    vin.scriptSig = CScript();
                    vin.scriptWitness.SetNull();
                }

                nFeeNeeded = GetMinimumFee(nBytes, coin_control, ::mempool, ::feeEstimator, &feeCalc);

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded) {
                    // Reduce fee to only the needed amount if possible. This
                    // prevents potential overpayment in fees if the coins
                    // selected to meet nFeeNeeded result in a transaction that
                    // requires less fee than the prior iteration.

                    // If we have no change and a big enough excess fee, then
                    // try to construct transaction again only without picking
                    // new inputs. We now know we only need the smaller fee
                    // (because of reduced tx size) and so we should add a
                    // change output. Only try this once.
                    if (nChangePosInOut == -1 && nSubtractFeeFromAmount == 0 && pick_new_inputs) {
                        unsigned int tx_size_with_change = nBytes + change_prototype_size + 2; // Add 2 as a buffer in case increasing # of outputs changes compact size
                        CAmount fee_needed_with_change = GetMinimumFee(tx_size_with_change, coin_control, ::mempool, ::feeEstimator, nullptr);
                        CAmount minimum_value_for_change = GetDustThreshold(change_prototype_txout, discard_rate);
                        if (nFeeRet >= fee_needed_with_change + minimum_value_for_change) {
                            pick_new_inputs = false;
                            nFeeRet = fee_needed_with_change;
                            continue;
                        }
                    }

                    // If we have change output already, just increase it
                    if (nFeeRet > nFeeNeeded && nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                        CAmount extraFeePaid = nFeeRet - nFeeNeeded;
                        std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                        change_position->nValue += extraFeePaid;
                        nFeeRet -= extraFeePaid;
                    }
                    break; // Done, enough fee included.
                }
                else if (!pick_new_inputs) {
                    // This shouldn't happen, we should have had enough excess
                    // fee to pay for the new output and still meet nFeeNeeded
                    // Or we should have just subtracted fee from recipients and
                    // nFeeNeeded should not have changed
                    strFailReason = _("Transaction fee and change calculation failed");
                    return false;
                }

                // Try to reduce change to include necessary fee
                if (nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                    CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;
                    std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                    // Only reduce change if remaining amount is still a large enough output.
                    if (change_position->nValue >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                        change_position->nValue -= additionalFeeNeeded;
                        nFeeRet += additionalFeeNeeded;
                        break; // Done, able to increase fee from change
                    }
                }

                // If subtracting fee from recipients, we now know what fee we
                // need to subtract, we have no reason to reselect inputs
                if (nSubtractFeeFromAmount > 0) {
                    pick_new_inputs = false;
                }

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }

        // Limit size
        if (GetTransactionWeight(CTransaction(txNew)) >= MAX_STANDARD_TX_WEIGHT)
        {
            strFailReason = _("Transaction too large");
            return false;
        }
    }

    return true;
}


bool CWallet::CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet,
                                int& nChangePosInOut, std::string& strFailReason, const CCoinControl& coin_control, bool sign, AvailableCoinsType nCoinType, bool fUseInstantSend)
{
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    for (const auto& recipient : vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must not be negative");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty())
    {
        strFailReason = _("Transaction must have at least one recipient");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    txNew.nLockTime = chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);
    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    unsigned int nBytes;
    {
        std::set<CInputCoin> setCoins;
        LOCK2(cs_main, cs_wallet);
        {
            std::vector<COutput> vAvailableCoins;
            AvailableCoins(vAvailableCoins, true, &coin_control, false, MAX_MONEY, MAX_MONEY,0, 0, 9999999, nCoinType, fUseInstantSend);


            // Create change script that will be used if we need change
            // TODO: pass in scriptChange instead of reservekey so
            // change transaction isn't always pay-to-bitcoin-address
            CScript scriptChange;
            // coin control: send change to custom address
            if (!boost::get<CNoDestination>(&coin_control.destChange)) {
                LogPrintf("\nCOIN CONTROL %s\n", CBitcoinAddress(coin_control.destChange).ToString());
                LogPrintf("\nCOIN CONTROL %d\n", coin_control.change_type);
                scriptChange = GetScriptForDestination(coin_control.destChange);
            } else { // no coin control: send change to newly generated address
                // Note: We use a new key here to keep it from being obvious which side is the change.
                //  The drawback is that by not reusing a previous key, the change may be lost if a
                //  backup is restored, if the backup doesn't have the new private key for the change.
                //  If we reused the old key, it would be possible to add code to look for and
                //  rediscover unknown transactions that were written with keys of ours to recover
                //  post-backup change.
                LogPrintf("\nRandom coin control %d\n", coin_control.change_type);
                // Reserve a new key pair from key pool
                CPubKey vchPubKey;
                bool ret;
                ret = reservekey.GetReservedKey(vchPubKey, true);
                if (!ret)
                {
                    strFailReason = _("Keypool ran out, please call keypoolrefill first");
                    return false;
                }

                const OutputType change_type = g_change_type;

                LearnRelatedScripts(vchPubKey, change_type);
                scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
            }
            CTxOut change_prototype_txout(0, scriptChange);
            size_t change_prototype_size = GetSerializeSize(change_prototype_txout, SER_DISK, 0);

            CFeeRate discard_rate = GetDiscardRate(::feeEstimator);
            nFeeRet = 0;
            bool pick_new_inputs = true;
            CAmount nValueIn = 0;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                // vouts to the payees
                for (const auto& recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        assert(nSubtractFeeFromAmount != 0);
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    if (IsDust(txout, ::dustRelayFee))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                if (pick_new_inputs) {
                    nValueIn = 0;
                    setCoins.clear();
                    if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, &coin_control))
                    {
                        if (nCoinType == ONLY_NOT40000IFMN) {
                            strFailReason = _("Unable to locate enough funds for this transaction that are not equal 40000 NIX.");
                        } else if (nCoinType == ONLY_NONDENOMINATED_NOT40000IFMN) {
                            strFailReason = _("Unable to locate enough PrivateSend non-denominated funds for this transaction that are not equal 40000 NIX.");
                        } else if (nCoinType == ONLY_DENOMINATED) {
                            strFailReason = _("Unable to locate enough PrivateSend denominated funds for this transaction.");
                            strFailReason += _("PrivateSend uses exact denominated amounts to send funds, you might simply need to anonymize some more coins.");
                        } else if (nValueIn < nValueToSelect) {
                            strFailReason = _("Insufficient funds.");
                        }
                        strFailReason = _("Insufficient funds");
                        return false;
                    }
                }

                const CAmount nChange = nValueIn - nValueToSelect;

                if (nChange > 0) {
                    //over pay for denominated transactions
                    if (nCoinType == ONLY_DENOMINATED) {
                        nFeeRet += nChange;
                        wtxNew.mapValue["DS"] = "1";
                        // recheck skipped denominations during next mixing
                        darkSendPool.ClearSkippedDenominations();
                    } else {
                        // Fill a vout to ourself
                        // TODO: pass in scriptChange instead of reservekey so
                        // change transaction isn't always pay-to-bitcoin-address
                        CScript scriptChange;

                        // coin control: send change to custom address
                        if (!boost::get<CNoDestination>(&coin_control.destChange))
                            scriptChange = GetScriptForDestination(coin_control.destChange);

                            // no coin control: send change to newly generated address
                        else {
                            // Note: We use a new key here to keep it from being obvious which side is the change.
                            //  The drawback is that by not reusing a previous key, the change may be lost if a
                            //  backup is restored, if the backup doesn't have the new private key for the change.
                            //  If we reused the old key, it would be possible to add code to look for and
                            //  rediscover unknown transactions that were written with keys of ours to recover
                            //  post-backup change.

                            // Reserve a new key pair from key pool
                            CPubKey vchPubKey;
                            bool ret;
                            ret = reservekey.GetReservedKey(vchPubKey, true);
                            if (!ret)
                            {
                                strFailReason = _("Keypool ran out, please call keypoolrefill first");
                                return false;
                            }

                            const OutputType change_type = g_change_type;

                            LearnRelatedScripts(vchPubKey, change_type);
                            scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
                        }

                        CTxOut newTxOut(nChange, scriptChange);

                        // We do not move dust-change to fees, because the sender would end up paying more than requested.
                        // This would be against the purpose of the all-inclusive feature.
                        // So instead we raise the change and deduct from the recipient.
                        if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust()) {
                            CAmount nDust = GetDustThreshold(newTxOut, ::minRelayTxFee) - newTxOut.nValue;
                            newTxOut.nValue += nDust; // raise change until no more dust
                            for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                            {
                                if (vecSend[i].fSubtractFeeFromAmount) {
                                    txNew.vout[i].nValue -= nDust;
                                    if (txNew.vout[i].IsDust()) {
                                        strFailReason = _(
                                                "The transaction amount is too small to send after the fee has been deducted");
                                        return false;
                                    }
                                    break;
                                }
                            }
                        }

                        // Never create dust outputs; if we would, just
                        // add the dust to the fee.
                        if (newTxOut.IsDust()) {
                            nChangePosInOut = -1;
                            nFeeRet += nChange;
                            reservekey.ReturnKey();
                        } else {
                            if (nChangePosInOut == -1) {
                                // Insert change txn at random position:
                                nChangePosInOut = GetRandInt(txNew.vout.size() + 1);
                            } else if ((unsigned int) nChangePosInOut > txNew.vout.size()) {
                                strFailReason = _("Change index out of range");
                                return false;
                            }

                            vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosInOut;
                            txNew.vout.insert(position, newTxOut);
                        }
                    }
                } else
                    reservekey.ReturnKey();

                // Fill vin
                //
                // Note how the sequence number is set to non-maxint so that
                // the nLockTime set above actually works.
                //
                // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
                // we use the highest possible value in that range (maxint-2)
                // to avoid conflicting with other possible uses of nSequence,
                // and in the spirit of "smallest possible change from prior
                // behavior."
                const uint32_t nSequence = coin_control.signalRbf ? MAX_BIP125_RBF_SEQUENCE : (CTxIn::SEQUENCE_FINAL - 1);
                for (const auto& coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.outpoint,CScript(),
                                              nSequence));

                // Fill in dummy signatures for fee calculation.
                if (!DummySignTx(txNew, setCoins)) {
                    strFailReason = _("Dummy Signing transaction failed");
                    return false;
                }

                nBytes = GetVirtualTransactionSize(txNew);

                // Remove scriptSigs to eliminate the fee calculation dummy signatures
                for (auto& vin : txNew.vin) {
                    vin.scriptSig = CScript();
                    vin.scriptWitness.SetNull();
                }

                nFeeNeeded = GetMinimumFee(nBytes, coin_control, ::mempool, ::feeEstimator, &feeCalc);

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded) {
                    // Reduce fee to only the needed amount if possible. This
                    // prevents potential overpayment in fees if the coins
                    // selected to meet nFeeNeeded result in a transaction that
                    // requires less fee than the prior iteration.

                    // If we have no change and a big enough excess fee, then
                    // try to construct transaction again only without picking
                    // new inputs. We now know we only need the smaller fee
                    // (because of reduced tx size) and so we should add a
                    // change output. Only try this once.
                    if (nChangePosInOut == -1 && nSubtractFeeFromAmount == 0 && pick_new_inputs) {
                        unsigned int tx_size_with_change = nBytes + change_prototype_size + 2; // Add 2 as a buffer in case increasing # of outputs changes compact size
                        CAmount fee_needed_with_change = GetMinimumFee(tx_size_with_change, coin_control, ::mempool, ::feeEstimator, nullptr);
                        CAmount minimum_value_for_change = GetDustThreshold(change_prototype_txout, discard_rate);
                        if (nFeeRet >= fee_needed_with_change + minimum_value_for_change) {
                            pick_new_inputs = false;
                            nFeeRet = fee_needed_with_change;
                            continue;
                        }
                    }

                    // If we have change output already, just increase it
                    if (nFeeRet > nFeeNeeded && nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                        CAmount extraFeePaid = nFeeRet - nFeeNeeded;
                        std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                        change_position->nValue += extraFeePaid;
                        nFeeRet -= extraFeePaid;
                    }
                    break; // Done, enough fee included.
                }
                else if (!pick_new_inputs) {
                    // This shouldn't happen, we should have had enough excess
                    // fee to pay for the new output and still meet nFeeNeeded
                    // Or we should have just subtracted fee from recipients and
                    // nFeeNeeded should not have changed
                    strFailReason = _("Transaction fee and change calculation failed");
                    return false;
                }

                // Try to reduce change to include necessary fee
                if (nChangePosInOut != -1 && nSubtractFeeFromAmount == 0) {
                    CAmount additionalFeeNeeded = nFeeNeeded - nFeeRet;
                    std::vector<CTxOut>::iterator change_position = txNew.vout.begin()+nChangePosInOut;
                    // Only reduce change if remaining amount is still a large enough output.
                    if (change_position->nValue >= MIN_FINAL_CHANGE + additionalFeeNeeded) {
                        change_position->nValue -= additionalFeeNeeded;
                        nFeeRet += additionalFeeNeeded;
                        break; // Done, able to increase fee from change
                    }
                }

                // If subtracting fee from recipients, we now know what fee we
                // need to subtract, we have no reason to reselect inputs
                if (nSubtractFeeFromAmount > 0) {
                    pick_new_inputs = false;
                }

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }

        if (nChangePosInOut == -1) reservekey.ReturnKey(); // Return any reserved key if we don't have change

        if (sign)
        {
            CTransaction txNewConst(txNew);
            int nIn = 0;
            for (const auto& coin : setCoins)
            {
                CScript scriptPubKeyOut = coin.txout.scriptPubKey;

                //check if this is a coldstake
                if ((HasIsCoinstakeOp(scriptPubKeyOut)))
                {
                    CScript nonCoinstakePath;
                    if (!GetNonCoinstakeScriptPath(scriptPubKeyOut, nonCoinstakePath))
                        return error("%s: Cannot retrieve non-coinstake script.", __func__);;
                    scriptPubKeyOut = nonCoinstakePath;
                }

                const CScript& scriptPubKey = scriptPubKeyOut;
                SignatureData sigdata;

                if (!ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.txout.nValue, SIGHASH_ALL), scriptPubKey, sigdata))
                {
                    strFailReason = _("Signing transaction failed");
                    return false;
                } else {
                    UpdateTransaction(txNew, nIn, sigdata);
                }

                nIn++;
            }
        }

        // Embed the constructed transaction data in wtxNew.
        wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));

        // Limit size
        if (GetTransactionWeight(*wtxNew.tx) >= MAX_STANDARD_TX_WEIGHT)
        {
            strFailReason = _("Transaction too large");
            return false;
        }
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(wtxNew.tx, 0, 0, 0, false, 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }

    LogPrintf("Fee Calculation: Fee:%d Bytes:%u Needed:%d Tgt:%d (requested %d) Reason:\"%s\" Decay %.5f: Estimation: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
              nFeeRet, nBytes, nFeeNeeded, feeCalc.returnedTarget, feeCalc.desiredTarget, StringForFeeReason(feeCalc.reason), feeCalc.est.decay,
              feeCalc.est.pass.start, feeCalc.est.pass.end,
              100 * feeCalc.est.pass.withinTarget / (feeCalc.est.pass.totalConfirmed + feeCalc.est.pass.inMempool + feeCalc.est.pass.leftMempool),
              feeCalc.est.pass.withinTarget, feeCalc.est.pass.totalConfirmed, feeCalc.est.pass.inMempool, feeCalc.est.pass.leftMempool,
              feeCalc.est.fail.start, feeCalc.est.fail.end,
              100 * feeCalc.est.fail.withinTarget / (feeCalc.est.fail.totalConfirmed + feeCalc.est.fail.inMempool + feeCalc.est.fail.leftMempool),
              feeCalc.est.fail.withinTarget, feeCalc.est.fail.totalConfirmed, feeCalc.est.fail.inMempool, feeCalc.est.fail.leftMempool);
    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman, CValidationState& state)
{
    FindUnloadedGhostTransactions(*wtxNew.tx);
    {
        LOCK2(cs_main, cs_wallet);
        //LogPrintf("CommitTransaction:\n%s", wtxNew.tx->ToString());
        {
            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            for (const CTxIn& txin : wtxNew.tx->vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Get the inserted-CWalletTx from mapWallet so that the
        // fInMempool flag is cached properly
        CWalletTx& wtx = mapWallet[wtxNew.GetHash()];

        if (fBroadcastTransactions)
        {
            // Broadcast
            if (!wtx.AcceptToMemoryPool(maxTxFee, state)) {
                LogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", state.GetRejectReason());
                // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
            } else {
                wtx.RelayWalletTransaction(connman);
            }
        }
    }
    return true;
}

bool CWallet::CommitZerocoinSpendTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman, CValidationState& state)
{
    {
        LOCK2(cs_main, cs_wallet);
        {
            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew);

            // Notify that old coins are spent
            for (const CTxIn& txin : wtxNew.tx->vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        // Get the inserted-CWalletTx from mapWallet so that the
        // fInMempool flag is cached properly
        CWalletTx& wtx = mapWallet[wtxNew.GetHash()];

        if (fBroadcastTransactions)
        {
            // Broadcast
            if (!wtxNew.AcceptToMemoryPool(maxTxFee, state)) {
                LogPrintf("CommitTransaction(): Transaction cannot be broadcast immediately, %s\n", state.GetRejectReason());
                // TODO: if we expect the failure to be long term or permanent, instead delete wtx from the wallet and return failure.
            } else {
                wtxNew.RelayWalletTransaction(connman);
            }
        }
    }
    return true;
}

void CWallet::ListAccountCreditDebit(const std::string& strAccount, std::list<CAccountingEntry>& entries) {
    CWalletDB walletdb(*dbw);
    return walletdb.ListAccountCreditDebit(strAccount, entries);
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry)
{
    CWalletDB walletdb(*dbw);

    return AddAccountingEntry(acentry, &walletdb);
}

bool CWallet::AddAccountingEntry(const CAccountingEntry& acentry, CWalletDB *pwalletdb)
{
    if (!pwalletdb->WriteAccountingEntry(++nAccountingEntryNumber, acentry)) {
        return false;
    }

    laccentries.push_back(acentry);
    CAccountingEntry & entry = laccentries.back();
    wtxOrdered.insert(std::make_pair(entry.nOrderPos, TxPair(nullptr, &entry)));

    return true;
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    LOCK2(cs_main, cs_wallet);

    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(*dbw,"cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (dbw->Rewrite("\x04pool"))
        {
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    // This wallet is in its first run if all of these are empty
    fFirstRunRet = mapKeys.empty() && mapCryptedKeys.empty() && mapWatchKeys.empty() && setWatchOnly.empty() && mapScripts.empty();

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;

    uiInterface.LoadWallet(this);

    return DB_LOAD_OK;
}

DBErrors CWallet::ZapSelectTx(std::vector<uint256>& vHashIn, std::vector<uint256>& vHashOut)
{
    AssertLockHeld(cs_wallet); // mapWallet
    DBErrors nZapSelectTxRet = CWalletDB(*dbw,"cr+").ZapSelectTx(vHashIn, vHashOut);
    for (uint256 hash : vHashOut)
        mapWallet.erase(hash);

    if (nZapSelectTxRet == DB_NEED_REWRITE)
    {
        if (dbw->Rewrite("\x04pool"))
        {
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapSelectTxRet != DB_LOAD_OK)
        return nZapSelectTxRet;

    MarkDirty();

    return DB_LOAD_OK;

}

DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    DBErrors nZapWalletTxRet = CWalletDB(*dbw,"cr+").ZapWalletTx(vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (dbw->Rewrite("\x04pool"))
        {
            LOCK(cs_wallet);
            setInternalKeyPool.clear();
            setExternalKeyPool.clear();
            m_pool_key_to_index.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}

bool CWallet::SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& strPurpose, bool bech32)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
        mapAddressBook[address].fBech32 = bech32;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW) );
    if (!strPurpose.empty() && !CWalletDB(*dbw).WritePurpose(EncodeDestination(address), strPurpose))
        return false;
    return CWalletDB(*dbw).WriteName(EncodeDestination(address), strName);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        // Delete destdata tuples associated with address
        std::string strAddress = EncodeDestination(address);
        for (const std::pair<std::string, std::string> &item : mapAddressBook[address].destdata)
        {
            CWalletDB(*dbw).EraseDestData(strAddress, item.first);
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    CWalletDB(*dbw).ErasePurpose(EncodeDestination(address));
    return CWalletDB(*dbw).EraseName(EncodeDestination(address));
}

const std::string& CWallet::GetAccountName(const CScript& scriptPubKey) const
{
    CTxDestination address;
    if (ExtractDestination(scriptPubKey, address) && !scriptPubKey.IsUnspendable()) {
        auto mi = mapAddressBook.find(address);
        if (mi != mapAddressBook.end()) {
            return mi->second.name;
        }
    }
    // A scriptPubKey that doesn't have an entry in the address book is
    // associated with the default account ("").
    const static std::string DEFAULT_ACCOUNT_NAME;
    return DEFAULT_ACCOUNT_NAME;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(*dbw);

        for (int64_t nIndex : setInternalKeyPool) {
            walletdb.ErasePool(nIndex);
        }
        setInternalKeyPool.clear();

        for (int64_t nIndex : setExternalKeyPool) {
            walletdb.ErasePool(nIndex);
        }
        setExternalKeyPool.clear();

        m_pool_key_to_index.clear();

        if (!TopUpKeyPool()) {
            return false;
        }
        LogPrintf("CWallet::NewKeyPool rewrote keypool\n");
    }
    return true;
}

size_t CWallet::KeypoolCountExternalKeys()
{
    AssertLockHeld(cs_wallet); // setExternalKeyPool
    return setExternalKeyPool.size();
}

void CWallet::LoadKeyPool(int64_t nIndex, const CKeyPool &keypool)
{
    AssertLockHeld(cs_wallet);
    if (keypool.fInternal) {
        setInternalKeyPool.insert(nIndex);
    } else {
        setExternalKeyPool.insert(nIndex);
    }
    m_max_keypool_index = std::max(m_max_keypool_index, nIndex);
    m_pool_key_to_index[keypool.vchPubKey.GetID()] = nIndex;

    // If no metadata exists yet, create a default with the pool key's
    // creation time. Note that this may be overwritten by actually
    // stored metadata for that key later, which is fine.
    CKeyID keyid = keypool.vchPubKey.GetID();
    if (mapKeyMetadata.count(keyid) == 0)
        mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = std::max(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);

        // count amount of available keys (internal, external)
        // make sure the keypool of external and internal keys fits the user selected target (-keypool)
        int64_t missingExternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setExternalKeyPool.size(), (int64_t) 0);
        int64_t missingInternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setInternalKeyPool.size(), (int64_t) 0);

        if (!IsHDEnabled() || !CanSupportFeature(FEATURE_HD_SPLIT))
        {
            // don't create extra internal keys
            missingInternal = 0;
        }
        bool internal = false;
        CWalletDB walletdb(*dbw);
        for (int64_t i = missingInternal + missingExternal; i--;)
        {
            if (i < missingInternal) {
                internal = true;
            }

            assert(m_max_keypool_index < std::numeric_limits<int64_t>::max()); // How in the hell did you use so many keys?
            int64_t index = ++m_max_keypool_index;

            CPubKey pubkey(GenerateNewKey(walletdb, internal));
            if (!walletdb.WritePool(index, CKeyPool(pubkey, internal))) {
                throw std::runtime_error(std::string(__func__) + ": writing generated key failed");
            }

            if (internal) {
                setInternalKeyPool.insert(index);
            } else {
                setExternalKeyPool.insert(index);
            }
            m_pool_key_to_index[pubkey.GetID()] = index;
        }
        if (missingInternal + missingExternal > 0) {
            LogPrintf("keypool added %d keys (%d internal), size=%u (%u internal)\n", missingInternal + missingExternal, missingInternal, setInternalKeyPool.size() + setExternalKeyPool.size(), setInternalKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fRequestedInternal)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        bool fReturningInternal = IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT) && fRequestedInternal;
        std::set<int64_t>& setKeyPool = fReturningInternal ? setInternalKeyPool : setExternalKeyPool;

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(*dbw);

        auto it = setKeyPool.begin();
        nIndex = *it;
        setKeyPool.erase(it);
        if (!walletdb.ReadPool(nIndex, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read failed");
        }
        if (!HaveKey(keypool.vchPubKey.GetID())) {
            throw std::runtime_error(std::string(__func__) + ": unknown key in key pool");
        }
        if (keypool.fInternal != fReturningInternal) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry misclassified");
        }

        assert(keypool.vchPubKey.IsValid());
        m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        LogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    CWalletDB walletdb(*dbw);
    walletdb.ErasePool(nIndex);
    LogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex, bool fInternal, const CPubKey& pubkey)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        if (fInternal) {
            setInternalKeyPool.insert(nIndex);
        } else {
            setExternalKeyPool.insert(nIndex);
        }
        m_pool_key_to_index[pubkey.GetID()] = nIndex;
    }
    LogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result, bool internal)
{
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        int64_t nIndex = 0;
        ReserveKeyFromKeyPool(nIndex, keypool, internal);
        if (nIndex == -1)
        {
            if (IsLocked()) return false;
            CWalletDB walletdb(*dbw);
            result = GenerateNewKey(walletdb, internal);
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

static int64_t GetOldestKeyTimeInPool(const std::set<int64_t>& setKeyPool, CWalletDB& walletdb) {
    if (setKeyPool.empty()) {
        return GetTime();
    }

    CKeyPool keypool;
    int64_t nIndex = *(setKeyPool.begin());
    if (!walletdb.ReadPool(nIndex, keypool)) {
        throw std::runtime_error(std::string(__func__) + ": read oldest key in keypool failed");
    }
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    LOCK(cs_wallet);

    CWalletDB walletdb(*dbw);

    // load oldest key from keypool, get time and return
    int64_t oldestKey = GetOldestKeyTimeInPool(setExternalKeyPool, walletdb);
    if (IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT)) {
        oldestKey = std::max(GetOldestKeyTimeInPool(setInternalKeyPool, walletdb), oldestKey);
    }

    return oldestKey;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        for (const auto& walletEntry : mapWallet)
        {
            const CWalletTx *pcoin = &walletEntry.second;

            if (!pcoin->IsTrusted())
                continue;

            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->tx->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->tx->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set< std::set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    std::set< std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (const auto& walletEntry : mapWallet)
    {
        const CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->tx->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (CTxIn txin : pcoin->tx->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].tx->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               for (CTxOut txout : pcoin->tx->vout)
                   if (IsChange(txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (const auto& txout : pcoin->tx->vout)
            if (IsMine(txout))
            {
                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set< std::set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    std::map< CTxDestination, std::set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    for (std::set<CTxDestination> _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set< std::set<CTxDestination>* > hits;
        std::map< CTxDestination, std::set<CTxDestination>* >::iterator it;
        for (CTxDestination address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination>* merged = new std::set<CTxDestination>(_grouping);
        for (std::set<CTxDestination>* hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (CTxDestination element : *merged)
            setmap[element] = merged;
    }

    std::set< std::set<CTxDestination> > ret;
    for (std::set<CTxDestination>* uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CWallet::GetAccountAddresses(const std::string& strAccount) const
{
    LOCK(cs_wallet);
    std::set<CTxDestination> result;
    for (const std::pair<CTxDestination, CAddressBookData>& item : mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey, bool internal)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool, internal);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            return false;
        }
        fInternal = keypool.fInternal;
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1) {
        pwallet->ReturnKey(nIndex, fInternal, vchPubKey);
    }
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::MarkReserveKeysAsUsed(int64_t keypool_id)
{
    AssertLockHeld(cs_wallet);
    bool internal = setInternalKeyPool.count(keypool_id);
    if (!internal) assert(setExternalKeyPool.count(keypool_id));
    std::set<int64_t> *setKeyPool = internal ? &setInternalKeyPool : &setExternalKeyPool;
    auto it = setKeyPool->begin();

    CWalletDB walletdb(*dbw);
    while (it != std::end(*setKeyPool)) {
        const int64_t& index = *(it);
        if (index > keypool_id) break; // set*KeyPool is ordered

        CKeyPool keypool;
        if (walletdb.ReadPool(index, keypool)) { //TODO: This should be unnecessary
            m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        }
        LearnAllRelatedScripts(keypool.vchPubKey);
        walletdb.ErasePool(index);
        LogPrintf("keypool index %d removed\n", index);
        it = setKeyPool->erase(it);
    }
}

void CWallet::GetScriptForMining(std::shared_ptr<CReserveScript> &script)
{
    OutputType output_type = g_address_type;

    std::shared_ptr<CReserveKey> rKey = std::make_shared<CReserveKey>(this);
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;


    LearnRelatedScripts(pubkey, g_address_type);

    script = rKey;
    CTxDestination dest = GetDestinationForKey(pubkey, output_type);
    script->reserveScript = GetScriptForDestination(dest);
}

void CWallet::LockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(const COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

void CWallet::GetKeyBirthTimes(std::map<CTxDestination, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (const auto& entry : mapKeyMetadata) {
        if (entry.second.nCreateTime) {
            mapKeyBirth[entry.first] = entry.second.nCreateTime;
        }
    }

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = chainActive[std::max(0, chainActive.Height() - 720)]; // the tip can be reorganized; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    for (const CKeyID &keyid : GetKeys()) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (const auto& entry : mapWallet) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = entry.second;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second)) {
            // ... which are already in a block
            int nHeight = blit->second->nHeight;
            for (const CTxOut &txout : wtx.tx->vout) {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                for (const CKeyID &keyid : vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (const auto& entry : mapKeyFirstBlock)
        mapKeyBirth[entry.first] = entry.second->GetBlockTime() - TIMESTAMP_WINDOW; // block times can be 2h off
}

/**
 * Compute smart timestamp for a transaction being added to the wallet.
 *
 * Logic:
 * - If sending a transaction, assign its timestamp to the current time.
 * - If receiving a transaction outside a block, assign its timestamp to the
 *   current time.
 * - If receiving a block with a future timestamp, assign all its (not already
 *   known) transactions' timestamps to the current time.
 * - If receiving a block with a past timestamp, before the most recent known
 *   transaction (that we care about), assign all its (not already known)
 *   transactions' timestamps to the same timestamp as that most-recent-known
 *   transaction.
 * - If receiving a block with a past timestamp, but after the most recent known
 *   transaction, assign all its (not already known) transactions' timestamps to
 *   the block time.
 *
 * For more information see CWalletTx::nTimeSmart,
 * https://bitcointalk.org/?topic=54527, or
 * https://github.com/bitcoin/bitcoin/pull/1393.
 */
unsigned int CWallet::ComputeTimeSmart(const CWalletTx& wtx) const
{
    unsigned int nTimeSmart = wtx.nTimeReceived;
    if (!wtx.hashUnset()) {
        if (mapBlockIndex.count(wtx.hashBlock)) {
            int64_t latestNow = wtx.nTimeReceived;
            int64_t latestEntry = 0;

            // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
            int64_t latestTolerated = latestNow + 300;
            const TxItems& txOrdered = wtxOrdered;
            for (auto it = txOrdered.rbegin(); it != txOrdered.rend(); ++it) {
                CWalletTx* const pwtx = it->second.first;
                if (pwtx == &wtx) {
                    continue;
                }
                CAccountingEntry* const pacentry = it->second.second;
                int64_t nSmartTime;
                if (pwtx) {
                    nSmartTime = pwtx->nTimeSmart;
                    if (!nSmartTime) {
                        nSmartTime = pwtx->nTimeReceived;
                    }
                } else {
                    nSmartTime = pacentry->nTime;
                }
                if (nSmartTime <= latestTolerated) {
                    latestEntry = nSmartTime;
                    if (nSmartTime > latestNow) {
                        latestNow = nSmartTime;
                    }
                    break;
                }
            }

            int64_t blocktime = mapBlockIndex[wtx.hashBlock]->GetBlockTime();
            nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
        } else {
            LogPrintf("%s: found %s in block %s not in index\n", __func__, wtx.GetHash().ToString(), wtx.hashBlock.ToString());
        }
    }
    return nTimeSmart;
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return CWalletDB(*dbw).WriteDestData(EncodeDestination(dest), key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    return CWalletDB(*dbw).EraseDestData(EncodeDestination(dest), key);
}

bool CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if(i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if(j != i->second.destdata.end())
        {
            if(value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

std::vector<std::string> CWallet::GetDestValues(const std::string& prefix) const
{
    LOCK(cs_wallet);
    std::vector<std::string> values;
    for (const auto& address : mapAddressBook) {
        for (const auto& data : address.second.destdata) {
            if (!data.first.compare(0, prefix.size(), prefix)) {
                values.emplace_back(data.second);
            }
        }
    }
    return values;
}

CWallet* CWallet::CreateWalletFromFile(const std::string walletFile)
{
    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector<CWalletTx> vWtx;

    if (gArgs.GetBoolArg("-zapwallettxes", false)) {
        uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, walletFile));
        std::unique_ptr<CWallet> tempWallet = MakeUnique<CWallet>(std::move(dbw));
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DB_LOAD_OK) {
            InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return nullptr;
        }
    }

    uiInterface.InitMessage(_("Loading wallet..."));

    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, walletFile));
    CWallet *walletInstance = new CWallet(std::move(dbw));
    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT) {
            InitError(strprintf(_("Error loading %s: Wallet corrupted"), walletFile));
            return nullptr;
        }
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            InitWarning(strprintf(_("Error reading %s! All keys read correctly, but transaction data"
                                         " or address book entries might be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DB_TOO_NEW) {
            InitError(strprintf(_("Error loading %s: Wallet requires newer version of %s"), walletFile, _(PACKAGE_NAME)));
            return nullptr;
        }
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            InitError(strprintf(_("Wallet needed to be rewritten: restart %s to complete"), _(PACKAGE_NAME)));
            return nullptr;
        }
        else {
            InitError(strprintf(_("Error loading %s"), walletFile));
            return nullptr;
        }
    }

    if (gArgs.GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = gArgs.GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < walletInstance->GetVersion())
        {
            InitError(_("Cannot downgrade wallet"));
            return nullptr;
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun)
    {
        // ensure this wallet.dat can only be opened by clients supporting HD with chain split and expects no default key
        if (!gArgs.GetBoolArg("-usehd", true)) {
            InitError(strprintf(_("Error creating %s: You can't create non-HD wallets with this version."), walletFile));
            return nullptr;
        }
        walletInstance->SetMinVersion(FEATURE_NO_DEFAULT_KEY);

        // generate a new master key
        CPubKey masterPubKey = walletInstance->GenerateNewHDMasterKey();
        if (!walletInstance->SetHDMasterKey(masterPubKey))
            throw std::runtime_error(std::string(__func__) + ": Storing master key failed");

        // Top up the keypool
        if (!walletInstance->TopUpKeyPool()) {
            InitError(_("Unable to generate initial keys") += "\n");
            return nullptr;
        }

        walletInstance->SetBestChain(chainActive.GetLocator());
    }
    else if (gArgs.IsArgSet("-usehd")) {
        bool useHD = gArgs.GetBoolArg("-usehd", true);
        if (walletInstance->IsHDEnabled() && !useHD) {
            InitError(strprintf(_("Error loading %s: You can't disable HD on an already existing HD wallet"), walletFile));
            return nullptr;
        }
        if (!walletInstance->IsHDEnabled() && useHD) {
            InitError(strprintf(_("Error loading %s: You can't enable HD on an already existing non-HD wallet"), walletFile));
            return nullptr;
        }
    }

    LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);

    // Try to top up keypool. No-op if the wallet is locked.
    walletInstance->TopUpKeyPool();

    CBlockIndex *pindexRescan = chainActive.Genesis();
    if (!gArgs.GetBoolArg("-rescan", false))
    {
        CWalletDB walletdb(*walletInstance->dbw);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = FindForkInGlobalIndex(chainActive, locator);
    }

    walletInstance->m_last_block_processed = chainActive.Tip();
    RegisterValidationInterface(walletInstance);

    if (chainActive.Tip() && chainActive.Tip() != pindexRescan)
    {
        //We can't rescan beyond non-pruned blocks, stop and throw an error
        //this might happen if a user uses an old wallet within a pruned node
        // or if he ran -disablewallet for a longer time, then decided to re-enable
        if (fPruneMode)
        {
            CBlockIndex *block = chainActive.Tip();
            while (block && block->pprev && (block->pprev->nStatus & BLOCK_HAVE_DATA) && block->pprev->nTx > 0 && pindexRescan != block)
                block = block->pprev;

            if (pindexRescan != block) {
                InitError(_("Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of pruned node)"));
                return nullptr;
            }
        }

        uiInterface.InitMessage(_("Rescanning..."));
        LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight);

        // No need to read and scan block if block was created before
        // our wallet birthday (as adjusted for block time variability)
        while (pindexRescan && walletInstance->nTimeFirstKey && (pindexRescan->GetBlockTime() < (walletInstance->nTimeFirstKey - TIMESTAMP_WINDOW))) {
            pindexRescan = chainActive.Next(pindexRescan);
        }

        nStart = GetTimeMillis();
        {
            WalletRescanReserver reserver(walletInstance);
            if (!reserver.reserve()) {
                InitError(_("Failed to rescan the wallet during initialization"));
                return nullptr;
            }
            walletInstance->ScanForWalletTransactions(pindexRescan, nullptr, reserver, true);
        }
        LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
        walletInstance->SetBestChain(chainActive.GetLocator());
        walletInstance->dbw->IncrementUpdateCounter();

        // Restore wallet transaction metadata after -zapwallettxes=1
        if (gArgs.GetBoolArg("-zapwallettxes", false) && gArgs.GetArg("-zapwallettxes", "1") != "2")
        {
            CWalletDB walletdb(*walletInstance->dbw);

            for (const CWalletTx& wtxOld : vWtx)
            {
                uint256 hash = wtxOld.GetHash();
                std::map<uint256, CWalletTx>::iterator mi = walletInstance->mapWallet.find(hash);
                if (mi != walletInstance->mapWallet.end())
                {
                    const CWalletTx* copyFrom = &wtxOld;
                    CWalletTx* copyTo = &mi->second;
                    copyTo->mapValue = copyFrom->mapValue;
                    copyTo->vOrderForm = copyFrom->vOrderForm;
                    copyTo->nTimeReceived = copyFrom->nTimeReceived;
                    copyTo->nTimeSmart = copyFrom->nTimeSmart;
                    copyTo->fFromMe = copyFrom->fFromMe;
                    copyTo->strFromAccount = copyFrom->strFromAccount;
                    copyTo->nOrderPos = copyFrom->nOrderPos;
                    walletdb.WriteTx(*copyTo);
                }
            }
        }
    }
    walletInstance->SetBroadcastTransactions(gArgs.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    {
        LOCK(walletInstance->cs_wallet);
        LogPrintf("setKeyPool.size() = %u\n",      walletInstance->GetKeyPoolSize());
        LogPrintf("mapWallet.size() = %u\n",       walletInstance->mapWallet.size());
        LogPrintf("mapAddressBook.size() = %u\n",  walletInstance->mapAddressBook.size());
    }

    return walletInstance;
}

std::atomic<bool> CWallet::fFlushScheduled(false);

void CWallet::postInitProcess(CScheduler& scheduler)
{
    // Add wallet transactions that aren't already in a block to mempool
    // Do this here as mempool requires genesis block to be loaded
    ReacceptWalletTransactions();

    // Run a thread to flush wallet periodically
    if (!CWallet::fFlushScheduled.exchange(true)) {
        scheduler.scheduleEvery(MaybeCompactWalletDB, 500);
    }
}

bool CWallet::BackupWallet(const std::string& strDest)
{
    return dbw->Backup(strDest);
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
    fInternal = false;
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
    fInternal = internalIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

void CMerkleTx::SetMerkleBranch(const CBlockIndex* pindex, int posInBlock)
{
    // Update the tx's hashBlock
    hashBlock = pindex->GetBlockHash();

    // set the position of the transaction in the block
    nIndex = posInBlock;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex *&pindexRet, bool enableIX) const {
    int nResult;

    if (hashUnset())
        nResult = 0;
    else {
        AssertLockHeld(cs_main);

        // Find the block it claims to be in
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi == mapBlockIndex.end())
            nResult = 0;
        else {
            CBlockIndex *pindex = (*mi).second;
            if (!pindex || !chainActive.Contains(pindex))
                nResult = 0;
            else {
                pindexRet = pindex;
                nResult = ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);

                if (nResult == 0 && !mempool.exists(GetHash()))
                    return -1; // Not in chain, not in mempool
            }
        }
    }

    if (enableIX && nResult < 6 && instantsend.IsLockedInstantSendTransaction(GetHash()))
        return nInstantSendDepth + nResult;

    return nResult;
}


int CMerkleTx::GetDepthInMainChain(const CBlockIndex* &pindexRet) const
{
    if (hashUnset())
        return 0;

    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;

    int coinbaseMaturity = 0;
    if(!this->fHeightCached){
        int nChainHeight = chainActive.Height();
        const CBlockIndex *pindexRet;
        int nDepth = GetDepthInMainChain(pindexRet);
        //If this tx has confirmed in a block
        if (nDepth > 0)
        {
            coinbaseMaturity = (nChainHeight - nDepth) >= Params().GetConsensus().nCoinMaturityReductionHeight ?
                        COINBASE_MATURITY_V2 : COINBASE_MATURITY;

        }
        //tx has not confirmed
        else{
            coinbaseMaturity = COINBASE_MATURITY;
        }

    }
    //if height is cached
    else{
        coinbaseMaturity = nCachedHeight >= Params().GetConsensus().nCoinMaturityReductionHeight ?
                    COINBASE_MATURITY_V2 : COINBASE_MATURITY;
    }

    bool fTestNet = (Params().NetworkIDString() == CBaseChainParams::TESTNET);
    if(fTestNet)
        coinbaseMaturity = COINBASE_MATURITY_TESTNET;

    return std::max(0, (coinbaseMaturity+1) - GetDepthInMainChain());
}


bool CWalletTx::AcceptToMemoryPool(const CAmount& nAbsurdFee, CValidationState& state)
{
    // Quick check to avoid re-setting fInMempool to false
    if (mempool.exists(tx->GetHash())) {
        return false;
    }

    // We must set fInMempool here - while it will be re-set to true by the
    // entered-mempool callback, if we did not there would be a race where a
    // user could call sendmoney in a loop and hit spurious out of funds errors
    // because we think that the transaction they just generated's change is
    // unavailable as we're not yet aware its in mempool.
    bool ret = ::AcceptToMemoryPool(mempool, state, tx, nullptr /* pfMissingInputs */,
                                nullptr /* plTxnReplaced */, false /* bypass_limits */, nAbsurdFee);
    fInMempool = ret;
    return ret;
}

static const std::string OUTPUT_TYPE_STRING_LEGACY = "legacy";
static const std::string OUTPUT_TYPE_STRING_GHOSTNODE = "ghostnode";
static const std::string OUTPUT_TYPE_STRING_P2SH_SEGWIT = "p2sh-segwit";
static const std::string OUTPUT_TYPE_STRING_BECH32 = "bech32";

OutputType ParseOutputType(const std::string& type, OutputType default_type)
{
    if (type.empty()) {
        return default_type;
    } else if (type == OUTPUT_TYPE_STRING_LEGACY) {
        return OUTPUT_TYPE_LEGACY;
    } else if (type == OUTPUT_TYPE_STRING_P2SH_SEGWIT) {
        return OUTPUT_TYPE_P2SH_SEGWIT;
    } else if (type == OUTPUT_TYPE_STRING_BECH32) {
        return OUTPUT_TYPE_BECH32;
    }  else if (type == OUTPUT_TYPE_STRING_GHOSTNODE) {
        return OUTPUT_TYPE_LEGACY;
    } else {
        return OUTPUT_TYPE_NONE;
    }
}

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OUTPUT_TYPE_LEGACY: return OUTPUT_TYPE_STRING_LEGACY;
    case OUTPUT_TYPE_P2SH_SEGWIT: return OUTPUT_TYPE_STRING_P2SH_SEGWIT;
    case OUTPUT_TYPE_BECH32: return OUTPUT_TYPE_STRING_BECH32;
    default: assert(false);
    }
}

void CWallet::LearnRelatedScripts(const CPubKey& key, OutputType type)
{
    if (key.IsCompressed() && (type == OUTPUT_TYPE_P2SH_SEGWIT || type == OUTPUT_TYPE_BECH32)) {
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        // Make sure the resulting program is solvable.
        assert(IsSolvable(*this, witprog));
        AddCScript(witprog);
    }
}

void CWallet::LearnAllRelatedScripts(const CPubKey& key)
{
    // OUTPUT_TYPE_P2SH_SEGWIT always adds all necessary scripts for all types.
    LearnRelatedScripts(key, OUTPUT_TYPE_P2SH_SEGWIT);
}

CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type)
{
    switch (type) {
    case OUTPUT_TYPE_LEGACY: return key.GetID();
    case OUTPUT_TYPE_P2SH_SEGWIT:
    case OUTPUT_TYPE_BECH32: {
        if (!key.IsCompressed()) return key.GetID();
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        if (type == OUTPUT_TYPE_P2SH_SEGWIT) {
            return CScriptID(witprog);
        } else {
            return witdest;
        }
    }
    default: assert(false);
    }
}

std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key)
{
    CKeyID keyid = key.GetID();
    if (key.IsCompressed()) {
        CTxDestination segwit = WitnessV0KeyHash(keyid);
        CTxDestination p2sh = CScriptID(GetScriptForDestination(segwit));
        return std::vector<CTxDestination>{std::move(keyid), std::move(p2sh), std::move(segwit)};
    } else {
        return std::vector<CTxDestination>{std::move(keyid)};
    }
}

CTxDestination CWallet::AddAndGetDestinationForScript(const CScript& script, OutputType type)
{
    // Note that scripts over 520 bytes are not yet supported.
    switch (type) {
    case OUTPUT_TYPE_LEGACY:
        return CScriptID(script);
    case OUTPUT_TYPE_P2SH_SEGWIT:
    case OUTPUT_TYPE_BECH32: {
        WitnessV0ScriptHash hash;
        CSHA256().Write(script.data(), script.size()).Finalize(hash.begin());
        CTxDestination witdest = hash;
        CScript witprog = GetScriptForDestination(witdest);
        // Check if the resulting program is solvable (i.e. doesn't use an uncompressed key)
        if (!IsSolvable(*this, witprog)) return CScriptID(script);
        // Add the redeemscript, so that P2WSH and P2SH-P2WSH outputs are recognized as ours.
        AddCScript(witprog);
        if (type == OUTPUT_TYPE_BECH32) {
            return witdest;
        } else {
            return CScriptID(witprog);
        }
    }
    default: assert(false);
    }
}

//Zerocoin methods

bool CWallet::CreateZerocoinMintModel(string &stringError, string denomAmount) {

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    // Amount
    if (denomAmount == "1") {
        denomination = libzerocoin::ZQ_ONE;
        nAmount = roundint64(1 * COIN);
    } else if (denomAmount == "5") {
        denomination = libzerocoin::ZQ_FIVE;
        nAmount = roundint64(5 * COIN);
    } else if (denomAmount == "10") {
        denomination = libzerocoin::ZQ_TEN;
        nAmount = roundint64(10 * COIN);
    } else if (denomAmount == "50") {
        denomination = libzerocoin::ZQ_FIFTY;
        nAmount = roundint64(50 * COIN);
    } else if (denomAmount == "100") {
        denomination = libzerocoin::ZQ_ONE_HUNDRED;
        nAmount = roundint64(100 * COIN);
    }  else if (denomAmount == "500") {
        denomination = libzerocoin::ZQ_FIVE_HUNDRED;
        nAmount = roundint64(500 * COIN);
    } else if (denomAmount == "1000") {
        denomination = libzerocoin::ZQ_ONE_THOUSAND;
        nAmount = roundint64(1000 * COIN);
    } else if (denomAmount == "5000") {
        denomination = libzerocoin::ZQ_FIVE_THOUSAND;
        nAmount = roundint64(5000 * COIN);
    } else {
        return false;
    }

    // Set up the Zerocoin Params object
    libzerocoin::Params *zcParams = ZCParams;

    int mintVersion = 1;

    // The following constructor does all the work of minting a brand
    // new zerocoin. It stores all the private values inside the
    // PrivateCoin object. This includes the coin secrets, which must be
    // stored in a secure location (wallet) at the client.
    libzerocoin::PrivateCoin newCoin(zcParams, denomination, mintVersion);

    // Get a copy of the 'public' portion of the coin. You should
    // embed this into a Zerocoin 'MINT' transaction along with a series
    // of currency inputs totaling the assigned value of one zerocoin.
    libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();

    // Validate
    if (pubCoin.validate()) {
        //TODOS
        CScript scriptSerializedCoin =
                CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();

        // Wallet comments
        CWalletTx wtx;

        stringError = MintZerocoin(scriptSerializedCoin, nAmount, wtx);

        if (stringError != "")
            return false;

        const unsigned char *ecdsaSecretKey = newCoin.getEcdsaSeckey();
        CZerocoinEntry zerocoinTx;
        zerocoinTx.IsUsed = false;
        zerocoinTx.denomination = denomination;
        zerocoinTx.value = pubCoin.getValue();
        zerocoinTx.randomness = newCoin.getRandomness();
        zerocoinTx.serialNumber = newCoin.getSerialNumber();
        zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
        LogPrintf("CreateZerocoinMintModel() -> NotifyZerocoinChanged\n");
        LogPrintf("pubcoin=%s, isUsed=%s\n", zerocoinTx.value.GetHex(), zerocoinTx.IsUsed);
        LogPrintf("randomness=%s, serialNumber=%s\n", zerocoinTx.randomness.ToString(), zerocoinTx.serialNumber.ToString());
        NotifyZerocoinChanged(this, zerocoinTx.value.GetHex(), zerocoinTx.denomination, zerocoinTx.IsUsed ? "Used" : "New", CT_NEW);
        if (!CWalletDB(*dbw).WriteZerocoinEntry(zerocoinTx))
            return false;
        return true;
    } else {
        return false;
    }
}

bool CWallet::CreateZerocoinMintModelBatch(string &stringError, vector <string> denomAmount) {

    vector <CScript> scriptBatch;
    vector <int64_t> nAmountBatch;
    vector <libzerocoin::PrivateCoin> privCoinBatch;
    vector <libzerocoin::PublicCoin> pubCoinBatch;
    vector <libzerocoin::CoinDenomination> denominationBatch;

    //Batch zerocoins
    for(auto denomAmountString: denomAmount){

        int64_t nAmount = 0;
        libzerocoin::CoinDenomination denomination;

        // Amount
        if (denomAmountString == "1") {
            denomination = libzerocoin::ZQ_ONE;
            nAmount = roundint64(1 * COIN);
        } else if (denomAmountString == "5") {
            denomination = libzerocoin::ZQ_FIVE;
            nAmount = roundint64(5 * COIN);
        } else if (denomAmountString == "10") {
            denomination = libzerocoin::ZQ_TEN;
            nAmount = roundint64(10 * COIN);
        } else if (denomAmountString == "50") {
            denomination = libzerocoin::ZQ_FIFTY;
            nAmount = roundint64(50 * COIN);
        } else if (denomAmountString == "100") {
            denomination = libzerocoin::ZQ_ONE_HUNDRED;
            nAmount = roundint64(100 * COIN);
        }  else if (denomAmountString == "500") {
            denomination = libzerocoin::ZQ_FIVE_HUNDRED;
            nAmount = roundint64(500 * COIN);
        } else if (denomAmountString == "1000") {
            denomination = libzerocoin::ZQ_ONE_THOUSAND;
            nAmount = roundint64(1000 * COIN);
        } else if (denomAmountString == "5000") {
            denomination = libzerocoin::ZQ_FIVE_THOUSAND;
            nAmount = roundint64(5000 * COIN);
        } else {
            return false;
        }

        // Set up the Zerocoin Params object
        libzerocoin::Params *zcParams = ZCParams;

        int mintVersion = 1;

        // The following constructor does all the work of minting a brand
        // new zerocoin. It stores all the private values inside the
        // PrivateCoin object. This includes the coin secrets, which must be
        // stored in a secure location (wallet) at the client.
        libzerocoin::PrivateCoin newCoin(zcParams, denomination, mintVersion);

        // Get a copy of the 'public' portion of the coin. You should
        // embed this into a Zerocoin 'MINT' transaction along with a series
        // of currency inputs totaling the assigned value of one zerocoin.
        libzerocoin::PublicCoin pubCoin = newCoin.getPublicCoin();

        // Validate
        if (pubCoin.validate()) {
            //TODOS
            CScript scriptSerializedCoin =
                    CScript() << OP_ZEROCOINMINT << pubCoin.getValue().getvch().size() << pubCoin.getValue().getvch();


            privCoinBatch.push_back(newCoin);
            pubCoinBatch.push_back(pubCoin);
            scriptBatch.push_back(scriptSerializedCoin);
            nAmountBatch.push_back(nAmount);
            denominationBatch.push_back(denomination);

        } else {
            return false;
        }
    }

    // Wallet comments
    CWalletTx wtx;

    stringError = MintZerocoinBatch(scriptBatch, nAmountBatch, wtx);

    if (stringError != "")
        return false;

    for(int i = 0; i < nAmountBatch.size(); i++){
        const unsigned char *ecdsaSecretKey = privCoinBatch[i].getEcdsaSeckey();
        CZerocoinEntry zerocoinTx;
        zerocoinTx.IsUsed = false;
        zerocoinTx.denomination = denominationBatch[i];
        zerocoinTx.value = pubCoinBatch[i].getValue();
        zerocoinTx.randomness = privCoinBatch[i].getRandomness();
        zerocoinTx.serialNumber = privCoinBatch[i].getSerialNumber();
        zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
        LogPrintf("CreateZerocoinMintModel() -> NotifyZerocoinChanged\n");
        LogPrintf("pubcoin=%s, isUsed=%s\n", zerocoinTx.value.GetHex(), zerocoinTx.IsUsed);
        LogPrintf("randomness=%s, serialNumber=%s\n", zerocoinTx.randomness.ToString(), zerocoinTx.serialNumber.ToString());
        NotifyZerocoinChanged(this, zerocoinTx.value.GetHex(), zerocoinTx.denomination, zerocoinTx.IsUsed ? "Used" : "New", CT_NEW);
        if (!CWalletDB(*dbw).WriteZerocoinEntry(zerocoinTx))
            return false;
    }

    return true;
}

bool CWallet::CreateZerocoinMintModelBatch(string &stringError, vector <string> denomAmount, vector<CScript> pubCoinScripts) {

    vector <CScript> scriptBatch;
    vector <int64_t> nAmountBatch;

    scriptBatch.clear();
    nAmountBatch.clear();
    //Batch zerocoins
    for(auto denomAmountString: denomAmount){

        int64_t nAmount = 0;
        libzerocoin::CoinDenomination denomination;

        // Amount
        if (denomAmountString == "1") {
            denomination = libzerocoin::ZQ_ONE;
            nAmount = roundint64(1 * COIN);
        } else if (denomAmountString == "5") {
            denomination = libzerocoin::ZQ_FIVE;
            nAmount = roundint64(5 * COIN);
        } else if (denomAmountString == "10") {
            denomination = libzerocoin::ZQ_TEN;
            nAmount = roundint64(10 * COIN);
        } else if (denomAmountString == "50") {
            denomination = libzerocoin::ZQ_FIFTY;
            nAmount = roundint64(50 * COIN);
        } else if (denomAmountString == "100") {
            denomination = libzerocoin::ZQ_ONE_HUNDRED;
            nAmount = roundint64(100 * COIN);
        }  else if (denomAmountString == "500") {
            denomination = libzerocoin::ZQ_FIVE_HUNDRED;
            nAmount = roundint64(500 * COIN);
        } else if (denomAmountString == "1000") {
            denomination = libzerocoin::ZQ_ONE_THOUSAND;
            nAmount = roundint64(1000 * COIN);
        } else if (denomAmountString == "5000") {
            denomination = libzerocoin::ZQ_FIVE_THOUSAND;
            nAmount = roundint64(5000 * COIN);
        } else {
            return false;
        }

        nAmountBatch.push_back(nAmount);

    }

    // Wallet comments
    CWalletTx wtx;

    if(pubCoinScripts.size() < nAmountBatch.size())
    {
        stringError = "Not enough commitment key packs!";
        return false;
    }

    for(int i = 0; i < nAmountBatch.size(); i++)
        scriptBatch.push_back(pubCoinScripts[i]);

    stringError = MintZerocoinBatch(scriptBatch, nAmountBatch, wtx);

    if (stringError != "")
        return false;

    return true;
}

bool CWallet::CreateZerocoinSpendModel(string &stringError, string denomAmount, string toAddr) {

    int64_t nAmount = 0;
    libzerocoin::CoinDenomination denomination;
    // Amount
    if (denomAmount == "1") {
        denomination = libzerocoin::ZQ_ONE;
        nAmount = roundint64(1 * COIN);
    } else if (denomAmount == "5") {
        denomination = libzerocoin::ZQ_FIVE;
        nAmount = roundint64(5 * COIN);
    } else if (denomAmount == "10") {
        denomination = libzerocoin::ZQ_TEN;
        nAmount = roundint64(10 * COIN);
    } else if (denomAmount == "50") {
        denomination = libzerocoin::ZQ_FIFTY;
        nAmount = roundint64(50 * COIN);
    } else if (denomAmount == "100") {
        denomination = libzerocoin::ZQ_ONE_HUNDRED;
        nAmount = roundint64(100 * COIN);
    }  else if (denomAmount == "500") {
        denomination = libzerocoin::ZQ_FIVE_HUNDRED;
        nAmount = roundint64(500 * COIN);
    } else if (denomAmount == "1000") {
        denomination = libzerocoin::ZQ_ONE_THOUSAND;
        nAmount = roundint64(1000 * COIN);
    } else if (denomAmount == "5000") {
        denomination = libzerocoin::ZQ_FIVE_THOUSAND;
        nAmount = roundint64(5000 * COIN);
    } else {
        return false;
    }

    // Wallet comments
    CWalletTx wtx;

    CBigNum coinSerial;
    uint256 txHash;
    CBigNum zcSelectedValue;
    bool zcSelectedIsUsed;

    string toKey = "";
    if(toAddr != "")
        toKey = toAddr;

    stringError = SpendZerocoin(toKey, nAmount, denomination, wtx, coinSerial, txHash, zcSelectedValue, zcSelectedIsUsed);

    if (stringError != "")
        return false;

    return true;

}

bool CWallet::CreateZerocoinSpendModelBatch(string &stringError, vector <string> denomAmountBatch, string toAddr, vector <CScript> pubCoinScripts) {

    vector <libzerocoin::CoinDenomination> denominationBatch;
    vector <int64_t> nAmountBatch;

    //Batch zerocoin spends
    for(auto denomAmount: denomAmountBatch){
        // Amount
        libzerocoin::CoinDenomination denomination;
        int64_t nAmount = 0;
        if (denomAmount == "1") {
            denomination = libzerocoin::ZQ_ONE;
            nAmount = roundint64(1 * COIN);
        } else if (denomAmount == "5") {
            denomination = libzerocoin::ZQ_FIVE;
            nAmount = roundint64(5 * COIN);
        } else if (denomAmount == "10") {
            denomination = libzerocoin::ZQ_TEN;
            nAmount = roundint64(10 * COIN);
        } else if (denomAmount == "50") {
            denomination = libzerocoin::ZQ_FIFTY;
            nAmount = roundint64(50 * COIN);
        } else if (denomAmount == "100") {
            denomination = libzerocoin::ZQ_ONE_HUNDRED;
            nAmount = roundint64(100 * COIN);
        }  else if (denomAmount == "500") {
            denomination = libzerocoin::ZQ_FIVE_HUNDRED;
            nAmount = roundint64(500 * COIN);
        } else if (denomAmount == "1000") {
            denomination = libzerocoin::ZQ_ONE_THOUSAND;
            nAmount = roundint64(1000 * COIN);
        } else if (denomAmount == "5000") {
            denomination = libzerocoin::ZQ_FIVE_THOUSAND;
            nAmount = roundint64(5000 * COIN);
        } else {
            return false;
        }

        denominationBatch.push_back(denomination);
        nAmountBatch.push_back(nAmount);
    }

    // Wallet comments
    CWalletTx wtx;

    vector <CBigNum> coinSerialBatch;
    vector <uint256> txHashBatch;
    vector <CBigNum> zcSelectedValueBatch;
    bool zcSelectedIsUsed;

    string toKey = "";
    if(toAddr != "")
        toKey = toAddr;

    stringError = SpendZerocoinBatch(toKey, pubCoinScripts, nAmountBatch, denominationBatch, wtx, coinSerialBatch, txHashBatch, zcSelectedValueBatch, zcSelectedIsUsed);

    if (stringError != ""){
        return false;
    }

    return true;
}

/**
 * @brief CWallet::CreateZerocoinMintTransaction
 * @param vecSend
 * @param wtxNew
 * @param reservekey
 * @param nFeeRet
 * @param strFailReason
 * @param coinControl
 * @return
 */
bool CWallet::CreateZerocoinMintTransaction(const vector <CRecipient> &vecSend, CWalletTx &wtxNew,
                                            CReserveKey &reservekey,
                                            CAmount &nFeeRet, int &nChangePosInOut, std::string &strFailReason,
                                            const CCoinControl &coinControl, bool sign) {
    CAmount nValue = 0;
    int nChangePosRequest = nChangePosInOut;
    unsigned int nSubtractFeeFromAmount = 0;
    for(const CRecipient &recipient: vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0) {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;
//        if (recipient.fSubtractFeeFromAmount)
//            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty() || nValue < 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }
    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    txNew.nLockTime = chainActive.Height();
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int) txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int) chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);
    FeeCalculation feeCalc;
    CAmount nFeeNeeded;
    unsigned int nBytes;
    {
        std::set<CInputCoin> setCoins;
        LOCK2(cs_main, cs_wallet);
        {
            std::vector<COutput> vAvailableCoinsTemp;
            std::vector<COutput> vAvailableCoins;
            vAvailableCoins.clear();
            AvailableCoins(vAvailableCoinsTemp, true, &coinControl);

            //Remove any delegated coins
            for(int i = 0; i < vAvailableCoinsTemp.size(); i++){
                if (!vAvailableCoinsTemp[i].tx->tx->vout[vAvailableCoinsTemp[i].i].scriptPubKey.IsPayToScriptHash_CS()) {
                    vAvailableCoins.push_back(vAvailableCoinsTemp[i]);
                }
            }

            // Create change script that will be used if we need change
            // TODO: pass in scriptChange instead of reservekey so
            // change transaction isn't always pay-to-bitcoin-address
            CScript scriptChange;

            // coin control: send change to custom address
            if (!boost::get<CNoDestination>(&coinControl.destChange)) {
                scriptChange = GetScriptForDestination(coinControl.destChange);
            } else { // no coin control: send change to newly generated address
                // Note: We use a new key here to keep it from being obvious which side is the change.
                //  The drawback is that by not reusing a previous key, the change may be lost if a
                //  backup is restored, if the backup doesn't have the new private key for the change.
                //  If we reused the old key, it would be possible to add code to look for and
                //  rediscover unknown transactions that were written with keys of ours to recover
                //  post-backup change.

                // Reserve a new key pair from key pool
                CPubKey vchPubKey;
                bool ret;
                ret = reservekey.GetReservedKey(vchPubKey, true);
                if (!ret)
                {
                    strFailReason = _("Keypool ran out, please call keypoolrefill first");
                    return false;
                }

                const OutputType change_type = g_change_type;

                LearnRelatedScripts(vchPubKey, change_type);
                scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
            }
            CTxOut change_prototype_txout(0, scriptChange);
            size_t change_prototype_size = GetSerializeSize(change_prototype_txout, SER_DISK, 0);

            CFeeRate discard_rate = GetDiscardRate(::feeEstimator);
            nFeeRet = payTxFee.GetFeePerK();
            bool pick_new_inputs = true;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                nChangePosInOut = nChangePosRequest;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;

                CAmount nValueToSelect = nValue + nFeeRet;

                // vouts to the payees
                for (const auto& recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (IsDust(txout, ::dustRelayFee))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                CAmount nValueIn = 0;
                if (!SelectCoins(vAvailableCoins, nValueToSelect, setCoins, nValueIn, &coinControl)) {
                    if (nValueIn < nValueToSelect) {
                        strFailReason = _("Insufficient funds.");
                    }
                    return false;
                }


                CAmount nChangeTemp = nValueIn - nValueToSelect;

                // NOTE: this depends on the exact behaviour of GetMinFee
                if (nFeeRet < 1000000 && nChangeTemp > 0 && nChangeTemp < CENT) {
                    int64_t nMoveToFee = min(nChangeTemp, 1000000 - nFeeRet);
                    nChangeTemp -= nMoveToFee;
                    nFeeRet += nMoveToFee;
                }

                const CAmount nChange = nChangeTemp;

                if (nChange > 0) {

                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;

                    // coin control: send change to custom address
                    if (!boost::get<CNoDestination>(&coinControl.destChange))
                        scriptChange = GetScriptForDestination(coinControl.destChange);

                    // no coin control: send change to newly generated address
                    else {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey, true);
                        if (!ret)
                        {
                            strFailReason = _("Keypool ran out, please call keypoolrefill first");
                            return false;
                        }

                        const OutputType change_type = g_change_type;

                        LearnRelatedScripts(vchPubKey, change_type);
                        scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
                    }

                    CTxOut newTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust()) {
                        CAmount nDust = GetDustThreshold(newTxOut, ::minRelayTxFee) - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount) {
                                txNew.vout[i].nValue -= nDust;
                                if (txNew.vout[i].IsDust()) {
                                    strFailReason = _(
                                                "The transaction amount is too small to send after the fee has been deducted");
                                    return false;
                                }
                                break;
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust()) {
                        nChangePosInOut = -1;
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    } else {
                        if (nChangePosInOut == -1) {
                            // Insert change txn at random position:
                            nChangePosInOut = GetRandInt(txNew.vout.size() + 1);
                        } else if ((unsigned int) nChangePosInOut > txNew.vout.size()) {
                            strFailReason = _("Change index out of range");
                            return false;
                        }

                        vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosInOut;
                        txNew.vout.insert(position, newTxOut);
                    }

                } else
                    reservekey.ReturnKey();

                // Fill vin
                //
                // Note how the sequence number is set to non-maxint so that
                // the nLockTime set above actually works.
                //
                // BIP125 defines opt-in RBF as any nSequence < maxint-1, so
                // we use the highest possible value in that range (maxint-2)
                // to avoid conflicting with other possible uses of nSequence,
                // and in the spirit of "smallest possible change from prior
                // behavior."
                const uint32_t nSequence = coinControl.signalRbf ? MAX_BIP125_RBF_SEQUENCE : (CTxIn::SEQUENCE_FINAL - 1);
                for (const auto& coin : setCoins)
                    txNew.vin.push_back(CTxIn(coin.outpoint,CScript(),
                                              nSequence));

                // Fill in dummy signatures for fee calculation.
                if (!DummySignTx(txNew, setCoins)) {
                    strFailReason = _("Signing transaction failed");
                    return false;
                }

                nBytes = GetVirtualTransactionSize(txNew);

                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (sign) {
                    for (auto& vin : txNew.vin) {
                        vin.scriptSig = CScript();
                        vin.scriptWitness.SetNull();
                    }
                }

                nFeeNeeded = payTxFee.GetFeePerK() * (1 + (int64_t) GetTransactionWeight(txNew) / 1000);
                //int64_t nMinFee = GetMinimumFee(nBytes, coinControl, ::mempool, ::feeEstimator, &feeCalc);

                //add 0.25% tx fee to all ghostprotocol transaction
                int64_t nMinFee = nValue * 0.0025;

                if (nFeeNeeded < nMinFee) {
                    nFeeNeeded = nMinFee;
                }

                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }

        if (nChangePosInOut == -1) reservekey.ReturnKey(); // Return any reserved key if we don't have change

        if (sign)
        {
            CTransaction txNewConst(txNew);
            int nIn = 0;
            for (const auto& coin : setCoins)
            {
                const CScript& scriptPubKey = coin.txout.scriptPubKey;
                SignatureData sigdata;

                if (!ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.txout.nValue, SIGHASH_ALL), scriptPubKey, sigdata))
                {
                    strFailReason = _("Signing transaction failed");
                    return false;
                } else {
                    UpdateTransaction(txNew, nIn, sigdata);
                }

                nIn++;
            }
        }

        // Embed the constructed transaction data in wtxNew.
        wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));

        // Limit size
        if (GetTransactionWeight(*wtxNew.tx) >= MAX_STANDARD_TX_WEIGHT)
        {
            strFailReason = _("Transaction too large");
            return false;
        }
    }

    if (gArgs.GetBoolArg("-walletrejectlongchains", DEFAULT_WALLET_REJECT_LONG_CHAINS)) {
        // Lastly, ensure this tx will pass the mempool's chain limits
        LockPoints lp;
        CTxMemPoolEntry entry(wtxNew.tx, 0, 0, 0, false, 0, lp);
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;
        if (!mempool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                                               nLimitDescendants, nLimitDescendantSize, errString)) {
            strFailReason = _("Transaction has too long of a mempool chain");
            return false;
        }
    }
    return true;
}

bool CWallet::CreateZerocoinMintTransaction(CScript pubCoin, int64_t nValue, CWalletTx &wtxNew, CReserveKey &reservekey,
                                       int64_t &nFeeRet, std::string &strFailReason,
                                       const CCoinControl &coinControl) {
    vector <CRecipient> vecSend;
    CRecipient recipient = {pubCoin, nValue, false};
    vecSend.push_back(recipient);
    int nChangePosRet = -1;
    return CreateZerocoinMintTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePosRet, strFailReason,
                                         coinControl);
}

bool CWallet::CreateZerocoinMintTransactionBatch(vector <CScript> pubCoin, vector <int64_t> nValue, CWalletTx &wtxNew, CReserveKey &reservekey,
                                       int64_t &nFeeRet, std::string &strFailReason,
                                       const CCoinControl &coinControl) {
    vector <CRecipient> vecSend;
    for(int i = 0; i < pubCoin.size(); i++){
        CRecipient recipient = {pubCoin[i], nValue[i], false};
        vecSend.push_back(recipient);
    }
    int nChangePosRet = -1;
    return CreateZerocoinMintTransaction(vecSend, wtxNew, reservekey, nFeeRet, nChangePosRet, strFailReason,
                                         coinControl);
}

/**
 * @brief CWallet::CreateZerocoinSpendTransaction
 * @param nValue
 * @param denomination
 * @param wtxNew
 * @param reservekey
 * @param coinSerial
 * @param txHash
 * @param zcSelectedValue
 * @param zcSelectedIsUsed
 * @param strFailReason
 * @return
 */
bool CWallet::CreateZerocoinSpendTransaction(std::string &toKey, int64_t nValue, libzerocoin::CoinDenomination denomination,
                                             CWalletTx &wtxNew, CReserveKey &reservekey, CBigNum &coinSerial,
                                             uint256 &txHash, CBigNum &zcSelectedValue, bool &zcSelectedIsUsed,
                                             std::string &strFailReason) {
    if (nValue <= 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.BindWallet(this);
    CMutableTransaction txNew;
    {
        LOCK2(cs_main, cs_wallet);
        {
            txNew.vin.clear();
            txNew.vout.clear();
            //wtxNew.fFromMe = true;

            //We will integrate stealth address pairing to increase privacy on chain
            //essentially we can mint/spend right away without risking user privacy.
            // Reserve a new key pair from key pool

            std::string sLabel;
            uint32_t num_prefix_bits = 0;
            std::string sPrefix_num;
            bool fBech32 = false;

            CScript scriptChange;

            //On empty key input, creates and send to stealthkey default - UI should require toKey input
            if(toKey == ""){
                /*
                CEKAStealthKey akStealth;
                if (0 != this->NewStealthKeyFromAccount(sLabel, akStealth, num_prefix_bits, sPrefix_num.empty() ? nullptr : sPrefix_num.c_str(), fBech32)){
                    strFailReason = _("zerocoin stealth output creation failed!");
                    return false;
                }
                CStealthAddress sxAddr;
                akStealth.SetSxAddr(sxAddr);
                scriptChange = GetScriptForDestination(sxAddr);
                */

                CPubKey vchPubKey;
                bool ret;
                ret = reservekey.GetReservedKey(vchPubKey, true);
                if (!ret)
                {
                    strFailReason = _("Keypool ran out, please call keypoolrefill first");
                    return false;
                }

                const OutputType change_type = OUTPUT_TYPE_P2SH_SEGWIT;

                LearnRelatedScripts(vchPubKey, change_type);
                scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
            }
            //Check if output key is a stealth address
            else if(IsStealthAddress(toKey)){
                CTxDestination sxAddr = DecodeDestination(toKey);
                scriptChange = GetScriptForDestination(sxAddr);
            }
            //If not, send to normal address
            else
            {
                scriptChange = GetScriptForDestination(CBitcoinAddress(toKey).Get());
            }


            CTxOut newTxOut(nValue, scriptChange);

            // Insert change txn at random position:
            vector<CTxOut>::iterator position = txNew.vout.begin() + GetRandInt(txNew.vout.size() + 1);
            txNew.vout.insert(position, newTxOut);
//            LogPrintf("txNew:%s\n", txNew.ToString());
            LogPrintf("txNew.GetHash():%s\n", txNew.GetHash().ToString());

            // Fill vin

            // Zerocoin
            // zerocoin init
            static CBigNum bnTrustedModulus;
            bool setParams = bnTrustedModulus.SetHexBool(ZEROCOIN_MODULUS);
            if (!setParams) {
                LogPrintf("bnTrustedModulus.SetHexBool(ZEROCOIN_MODULUS) failed");
            }
            libzerocoin::Params *zcParams = ZCParams;

            // Set up the Zerocoin Params object

            // Select not yet used coin from the wallet with minimal possible id

            list <CZerocoinEntry> listPubCoin;
            CWalletDB(*dbw).ListPubCoin(listPubCoin);
            listPubCoin.sort(CompHeight);
            CZerocoinEntry coinToUse;
            CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

            CBigNum accumulatorValue;
            uint256 accumulatorBlockHash;

            int coinId = INT_MAX;
            int coinHeight;

            BOOST_FOREACH(const CZerocoinEntry &minIdPubcoin, listPubCoin) {
                if (minIdPubcoin.denomination == denomination
                        && minIdPubcoin.IsUsed == false
                        && minIdPubcoin.randomness != 0
                        && minIdPubcoin.serialNumber != 0) {

                    int id;
                    coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
                    if (coinHeight > 0
                            && id < coinId
                            && coinHeight + (ZEROCOIN_CONFIRM_HEIGHT) <= chainActive.Height()
                            && zerocoinState->GetAccumulatorValueForSpend( &chainActive,
                                    chainActive.Height()-(ZEROCOIN_CONFIRM_HEIGHT),
                                    denomination,
                                    id,
                                    accumulatorValue,
                                    accumulatorBlockHash) > 1
                            ) {
                        coinId = id;
                        coinToUse = minIdPubcoin;
                    }
                }
            }

            if (coinId == INT_MAX){
                strFailReason = _("network privacy set too low. There needs to be at least 2 ghosted values of this type! ");
                return false;
            }

            libzerocoin::Accumulator accumulator(zcParams, accumulatorValue, denomination);
            // 2. Get pubcoin from the private coin
            libzerocoin::PublicCoin pubCoinSelected(zcParams, coinToUse.value, denomination);

            // Now make sure the coin is valid.
            if (!pubCoinSelected.validate()) {
                // If this returns false, don't accept the coin for any purpose!
                // Any ZEROCOIN_MINT with an invalid coin should NOT be
                // accepted as a valid transaction in the block chain.
                strFailReason = _("the selected mint coin is an invalid coin");
                return false;
            }

            // 4. Get witness from the index
            libzerocoin::AccumulatorWitness witness =
                    zerocoinState->GetWitnessForSpend(&chainActive,
                                                      chainActive.Height()-(ZEROCOIN_CONFIRM_HEIGHT),
                                                      denomination, coinId,
                                                      coinToUse.value);

            CTxIn newTxIn;
            newTxIn.nSequence = coinId;
            newTxIn.scriptSig = CScript();
            newTxIn.prevout.SetNull();
            txNew.vin.push_back(newTxIn);

            // We use incomplete transaction hash for now as a metadata
            libzerocoin::SpendMetaData metaData(coinId, txNew.GetHash());

            // Construct the CoinSpend object. This acts like a signature on the
            // transaction.
            libzerocoin::PrivateCoin privateCoin(zcParams, denomination);

            int txVersion = 1;

            LogPrintf("CreateZerocoinSpendTransation: tx version=%d, tx metadata hash=%s\n", txVersion, txNew.GetHash().ToString());

            privateCoin.setVersion(txVersion);
            privateCoin.setPublicCoin(pubCoinSelected);
            privateCoin.setRandomness(coinToUse.randomness);
            privateCoin.setSerialNumber(coinToUse.serialNumber);
            privateCoin.setEcdsaSeckey(coinToUse.ecdsaSecretKey);

            libzerocoin::CoinSpend spend(zcParams, privateCoin, accumulator, witness, metaData, accumulatorBlockHash);
            spend.setVersion(txVersion);

            // This is a sanity check. The CoinSpend object should always verify,
            // but why not check before we put it onto the wire?
            if (!spend.Verify(accumulator, metaData)) {
                strFailReason = _("the spend coin transaction did not verify");
                return false;
            }

            // Serialize the CoinSpend object into a buffer.
            CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
            serializedCoinSpend << spend;

            CScript tmp = CScript() << OP_ZEROCOINSPEND << serializedCoinSpend.size();
            tmp.insert(tmp.end(), serializedCoinSpend.begin(), serializedCoinSpend.end());
            txNew.vin[0].scriptSig.assign(tmp.begin(), tmp.end());

            // Embed the constructed transaction data in wtxNew.
             wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));

            // Limit size
            if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
                strFailReason = _("Transaction too large");
                return false;
            }


            std::list <CZerocoinSpendEntry> listCoinSpendSerial;
            CWalletDB(*dbw).ListCoinSpendSerial(listCoinSpendSerial);
            BOOST_FOREACH(const CZerocoinSpendEntry &item, listCoinSpendSerial){
                if (spend.getCoinSerialNumber() == item.coinSerial) {
                    // THIS SELECEDTED COIN HAS BEEN USED, SO UPDATE ITS STATUS
                    CZerocoinEntry pubCoinTx;
                    pubCoinTx.nHeight = coinHeight;
                    pubCoinTx.denomination = coinToUse.denomination;
                    pubCoinTx.id = coinId;
                    pubCoinTx.IsUsed = true;
                    pubCoinTx.randomness = coinToUse.randomness;
                    pubCoinTx.serialNumber = coinToUse.serialNumber;
                    pubCoinTx.value = coinToUse.value;
                    pubCoinTx.ecdsaSecretKey = coinToUse.ecdsaSecretKey;
                    CWalletDB(*dbw).WriteZerocoinEntry(pubCoinTx);
                    LogPrintf("CreateZerocoinSpendTransaction() -> NotifyZerocoinChanged\n");
                    LogPrintf("pubcoin=%s, isUsed=Used\n", coinToUse.value.GetHex());
                    NotifyZerocoinChanged(this, coinToUse.value.GetHex(), pubCoinTx.denomination, "Used",
                                                       CT_UPDATED);
                    strFailReason = _("the coin spend has been used");
                    return false;
                }
            }

            coinSerial = spend.getCoinSerialNumber();
            txHash = wtxNew.GetHash();
            LogPrintf("txHash:\n%s", txHash.ToString());
            zcSelectedValue = coinToUse.value;
            zcSelectedIsUsed = coinToUse.IsUsed;

            CZerocoinSpendEntry entry;
            entry.coinSerial = coinSerial;
            entry.hashTx = txHash;
            entry.pubCoin = zcSelectedValue;
            entry.id = coinId;
            entry.denomination = coinToUse.denomination;
            LogPrintf("WriteCoinSpendSerialEntry, serialNumber=%s\n", coinSerial.ToString());
            if (!CWalletDB(*dbw).WriteCoinSpendSerialEntry(entry)) {
                strFailReason = _("it cannot write coin serial number into wallet");
            }

            coinToUse.IsUsed = true;
            coinToUse.id = coinId;
            coinToUse.nHeight = coinHeight;
            CWalletDB(*dbw).WriteZerocoinEntry(coinToUse);
            NotifyZerocoinChanged(this, coinToUse.value.GetHex(), coinToUse.denomination, "Used",
                                               CT_UPDATED);
        }
    }

    return true;
}

bool CWallet::CreateZerocoinSpendTransactionBatch(std::string &toKey, vector <CScript> pubCoinScripts, vector <int64_t> nValueBatch, vector <libzerocoin::CoinDenomination> denominationBatch,
                                             CWalletTx &wtxNew, CReserveKey &reservekey, vector <CBigNum> &coinSerialBatch,
                                             vector <uint256> &txHashBatch, vector <CBigNum> &zcSelectedValueBatch, bool &zcSelectedIsUsed,
                                             std::string &strFailReason) {

    int64_t nTotalValue = 0;
    for(auto i: nValueBatch)
        nTotalValue += i;

    if (nTotalValue <= 0) {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.BindWallet(this);

    //Batch zerocoin spends
    CMutableTransaction txNew;
    CMutableTransaction txNewTemp;
    txNew.vin.clear();
    txNew.vout.clear();
    txNewTemp.vin.clear();
    txNewTemp.vout.clear();

    //We will integrate stealth address pairing to increase privacy on chain
    //essentially we can mint/spend right away without risking user privacy.

    CScript ghostKey;
    CScript scriptChange;

    //On empty key input, creates and send to p2sh default - UI should require toKey input
    //For now send to personal segwit
    //Only calculate/generate key if we are not spending to zerocoin mint
    if(pubCoinScripts.empty()){
        if(toKey == ""){

            CPubKey vchPubKey;
            bool ret;
            ret = reservekey.GetReservedKey(vchPubKey, true);
            if (!ret)
            {
                strFailReason = _("Keypool ran out, please call keypoolrefill first");
                return false;
            }

            const OutputType change_type = g_change_type;

            LearnRelatedScripts(vchPubKey, change_type);
            scriptChange = GetScriptForDestination(GetDestinationForKey(vchPubKey, change_type));
        }
        else if (IsGhostAddress(toKey))
        {
            CGhostAddress sxAddr;
            if (sxAddr.SetEncoded(toKey))
            {
                ec_secret ephem_secret;
                ec_secret secretShared;
                ec_point pkSendTo;
                ec_point ephem_pubkey;


                if (GenerateRandomSecret(ephem_secret) != 0)
                {
                    LogPrintf("GenerateRandomSecret failed.\n");
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
                };

                if (StealthSecret(ephem_secret, sxAddr.scan_pubkey, sxAddr.spend_pubkey, secretShared, pkSendTo) != 0)
                {
                    LogPrintf("Could not generate receiving public key.\n");
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
                };

                CPubKey cpkTo(pkSendTo);
                if (!cpkTo.IsValid())
                {
                    LogPrintf("Invalid public key generated.\n");
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
                };

                CKeyID ckidTo = cpkTo.GetID();

                CBitcoinAddress addrTo(ckidTo);

                if (SecretToPublicKey(ephem_secret, ephem_pubkey) != 0)
                {
                    LogPrintf("Could not generate ephem public key.\n");
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
                };

                ghostKey = CScript() << OP_RETURN << ephem_pubkey;

                scriptChange = GetScriptForDestination(addrTo.Get());
            }
        }
        //If not, send to normal address
        else
        {
            scriptChange = GetScriptForDestination(CBitcoinAddress(toKey).Get());
        }
    }
    for(int i = 0; i < nValueBatch.size(); i++){
        if(!pubCoinScripts.empty())
            scriptChange = pubCoinScripts[i];
        CTxOut newTxOut(nValueBatch[i], scriptChange);
        txNew.vout.push_back(newTxOut);
        txNewTemp.vout.push_back(newTxOut);
    }

    //empty vins
    vector <int> coinIdBatch;
    vector <CZerocoinEntry> coinToUseBatch;
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
    vector <CBigNum> accumulatorValueBatch;
    vector <uint256> accumulatorBlockHashBatch;
    vector <libzerocoin::CoinSpend> spendBatch;
    vector <int> coinHeightBatch;

    list <CZerocoinEntry> listPubCoin;
    CWalletDB(*dbw).ListPubCoin(listPubCoin);
    listPubCoin.sort(CompHeight);

    vector <CBigNum> usedSerials;

    for(int i = 0; i < nValueBatch.size(); i++){
        {
            LOCK2(cs_main, cs_wallet);
            {
                CZerocoinEntry coinToUse;

                CBigNum accumulatorValue;
                uint256 accumulatorBlockHash;

                int coinId = INT_MAX;
                int coinHeight;

                // Select not yet used coin from the wallet with minimal possible id
                BOOST_FOREACH(CZerocoinEntry &minIdPubcoin, listPubCoin) {
                    if (minIdPubcoin.denomination == denominationBatch[i]
                            && minIdPubcoin.IsUsed == false
                            && minIdPubcoin.randomness != 0
                            && minIdPubcoin.serialNumber != 0
                            && std::find(usedSerials.begin(), usedSerials.end(), minIdPubcoin.serialNumber) == usedSerials.end()) {

                        int id;
                        coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
                        if (coinHeight > 0
                                && id < coinId
                                && coinHeight + ZEROCOIN_CONFIRM_HEIGHT <= chainActive.Height()
                                && zerocoinState->GetAccumulatorValueForSpend( &chainActive,
                                                                               chainActive.Height() - ZEROCOIN_CONFIRM_HEIGHT,
                                                                               denominationBatch[i],
                                                                               id,
                                                                               accumulatorValue,
                                                                               accumulatorBlockHash) > 1
                                ) {

                            //log the serial number and check on next iteration
                            usedSerials.push_back(minIdPubcoin.serialNumber);

                            coinId = id;
                            coinToUse = minIdPubcoin;
                            coinIdBatch.push_back(coinId);
                            coinToUseBatch.push_back(coinToUse);
                            accumulatorValueBatch.push_back(accumulatorValue);
                            accumulatorBlockHashBatch.push_back(accumulatorBlockHash);
                            coinHeightBatch.push_back(coinHeight);
                            break;
                        }
                    }
                }

                if (coinId == INT_MAX){
                    strFailReason = _("network privacy set too low. There needs to be at least 2 ghosted values of this type!")  + std::to_string(coinHeight) + " " + std::to_string(coinId);
                    return false;
                }

                CTxIn newTxIn;
                newTxIn.nSequence = coinId;
                newTxIn.scriptSig = CScript();
                newTxIn.prevout.SetNull();
                txNew.vin.push_back(newTxIn);
                txNewTemp.vin.push_back(newTxIn);
            }
        }
    }

    for(int i = 0; i < nValueBatch.size(); i++){
        {
            LOCK2(cs_main, cs_wallet);
            {
                // Fill vin

                // Zerocoin
                // zerocoin init
                static CBigNum bnTrustedModulus;
                bool setParams = bnTrustedModulus.SetHexBool(ZEROCOIN_MODULUS);
                if (!setParams) {
                    LogPrintf("bnTrustedModulus.SetHexBool(ZEROCOIN_MODULUS) failed");
                }
                libzerocoin::Params *zcParams = ZCParams;

                libzerocoin::Accumulator accumulator(zcParams, accumulatorValueBatch[i], denominationBatch[i]);
                // 2. Get pubcoin from the private coin
                libzerocoin::PublicCoin pubCoinSelected(zcParams, coinToUseBatch[i].value, denominationBatch[i]);

                // Now make sure the coin is valid.
                if (!pubCoinSelected.validate()) {
                    // If this returns false, don't accept the coin for any purpose!
                    // Any ZEROCOIN_MINT with an invalid coin should NOT be
                    // accepted as a valid transaction in the block chain.
                    strFailReason = _("the selected mint coin is an invalid coin");
                    return false;
                }

                // 4. Get witness from the index
                libzerocoin::AccumulatorWitness witness =
                        zerocoinState->GetWitnessForSpend(&chainActive,
                                                          chainActive.Height()-(ZEROCOIN_CONFIRM_HEIGHT),
                                                          denominationBatch[i], coinIdBatch[i],
                                                          coinToUseBatch[i].value);


                // We use incomplete transaction hash for now as a metadata
                libzerocoin::SpendMetaData metaData(coinIdBatch[i], txNewTemp.GetHash());

                // Construct the CoinSpend object. This acts like a signature on the
                // transaction.
                libzerocoin::PrivateCoin privateCoin(zcParams, denominationBatch[i]);

                int txVersion = 1;

                LogPrintf("CreateZerocoinSpendTransation: tx version=%d, tx metadata hash=%s\n", txVersion, txNewTemp.GetHash().ToString());

                CZerocoinEntry decryptedCoinToUse = coinToUseBatch[i];

                //If ECDSA key is greater than size 32, it means this is an encrypted zerocoin object
                if(coinToUseBatch[i].ecdsaSecretKey.size() > 32){
                    //If this wallet is encrypted and unlocked, we need to decrypt zerocoin private data
                    if(IsCrypted() && !IsLocked()){
                        DecryptPrivateZerocoinData(decryptedCoinToUse);
                        coinToUseBatch[i].randomness = decryptedCoinToUse.randomness;
                        coinToUseBatch[i].serialNumber = decryptedCoinToUse.serialNumber;
                        coinToUseBatch[i].ecdsaSecretKey = decryptedCoinToUse.ecdsaSecretKey;
                    }
                    else if(IsCrypted() && IsLocked()){
                        strFailReason = _("need to unlock wallet to spend encrypted zerocoin");
                        return false;
                    }
                }
                privateCoin.setVersion(txVersion);
                privateCoin.setPublicCoin(pubCoinSelected);
                privateCoin.setRandomness(decryptedCoinToUse.randomness);
                privateCoin.setSerialNumber(decryptedCoinToUse.serialNumber);
                privateCoin.setEcdsaSeckey(decryptedCoinToUse.ecdsaSecretKey);

                libzerocoin::CoinSpend spend(zcParams, privateCoin, accumulator, witness, metaData, accumulatorBlockHashBatch[i]);
                spend.setVersion(txVersion);

                // This is a sanity check. The CoinSpend object should always verify,
                // but why not check before we put it onto the wire?
                if (!spend.Verify(accumulator, metaData)) {
                    strFailReason = _("the spend coin transaction did not verify");
                    return false;
                }

                spendBatch.push_back(spend);

                // Serialize the CoinSpend object into a buffer.
                CDataStream serializedCoinSpend(SER_NETWORK, PROTOCOL_VERSION);
                serializedCoinSpend << spend;

                CScript tmp = CScript() << OP_ZEROCOINSPEND << serializedCoinSpend.size();
                tmp.insert(tmp.end(), serializedCoinSpend.begin(), serializedCoinSpend.end());
                txNew.vin[i].scriptSig.assign(tmp.begin(), tmp.end());
            }
        }
    }

    // Embed the constructed transaction data in wtxNew.
    wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));

    // Limit size
    if (GetTransactionWeight(txNew) >= MAX_STANDARD_TX_WEIGHT) {
        strFailReason = _("Transaction too large");
        return false;
    }

    txHashBatch.push_back(wtxNew.GetHash());
    LogPrintf("txHash:\n%s", txHashBatch[0].ToString());


    for(int i = 0; i < nValueBatch.size(); i++){
        {
            LOCK2(cs_main, cs_wallet);
            {
                std::list <CZerocoinSpendEntry> listCoinSpendSerial;
                CWalletDB(*dbw).ListCoinSpendSerial(listCoinSpendSerial);
                BOOST_FOREACH(const CZerocoinSpendEntry &item, listCoinSpendSerial){
                    if (spendBatch[i].getCoinSerialNumber() == item.coinSerial) {
                        // THIS SELECEDTED COIN HAS BEEN USED, SO UPDATE ITS STATUS
                        CZerocoinEntry pubCoinTx;
                        pubCoinTx.nHeight = coinHeightBatch[i];
                        pubCoinTx.denomination = coinToUseBatch[i].denomination;
                        pubCoinTx.id = coinIdBatch[i];
                        pubCoinTx.IsUsed = true;
                        pubCoinTx.randomness = coinToUseBatch[i].randomness;
                        pubCoinTx.serialNumber = coinToUseBatch[i].serialNumber;
                        pubCoinTx.value = coinToUseBatch[i].value;
                        pubCoinTx.ecdsaSecretKey = coinToUseBatch[i].ecdsaSecretKey;
                        CWalletDB(*dbw).WriteZerocoinEntry(pubCoinTx);
                        LogPrintf("\nCreateZerocoinSpendTransaction() -> NotifyZerocoinChanged\n");
                        LogPrintf("\npubcoin=%s, isUsed=Used\n", coinToUseBatch[i].value.GetHex());
                        NotifyZerocoinChanged(this, coinToUseBatch[i].value.GetHex(), pubCoinTx.denomination, "Used",
                                              CT_UPDATED);
                        strFailReason = _("the coin spend has been used");
                        return false;
                    }
                }
            }
        }
    }

    for(int i = 0; i < nValueBatch.size(); i++){
        {
            LOCK2(cs_main, cs_wallet);
            {
                coinSerialBatch.push_back(spendBatch[i].getCoinSerialNumber());
                zcSelectedValueBatch.push_back(coinToUseBatch[i].value);
                zcSelectedIsUsed = coinToUseBatch[i].IsUsed;

                CZerocoinSpendEntry entry;
                entry.coinSerial = coinSerialBatch[i];
                entry.hashTx = txHashBatch[0];
                entry.pubCoin = zcSelectedValueBatch[i];
                entry.id = coinIdBatch[i];
                entry.denomination = coinToUseBatch[i].denomination;
                LogPrintf("\nWriteCoinSpendSerialEntry, serialNumber=%s\n", coinSerialBatch[i].ToString());
                if (!CWalletDB(*dbw).WriteCoinSpendSerialEntry(entry)) {
                    strFailReason = _("it cannot write coin serial number into wallet");
                }

                coinToUseBatch[i].IsUsed = true;
                coinToUseBatch[i].id = coinIdBatch[i];
                coinToUseBatch[i].nHeight = coinHeightBatch[i];
                CWalletDB(*dbw).WriteZerocoinEntry(coinToUseBatch[i]);
                NotifyZerocoinChanged(this, coinToUseBatch[i].value.GetHex(), coinToUseBatch[i].denomination, "Used",
                                      CT_UPDATED);
            }
        }
    }

    return true;
}

/**
 * @brief CWallet::MintZerocoin
 * @param pubCoin
 * @param nValue
 * @param wtxNew
 * @param fAskFee
 * @return
 */
string CWallet::MintZerocoin(CScript pubCoin, int64_t nValue, CWalletTx &wtxNew, bool fAskFee) {
    // Do not allow mint to take place until fully synced
    // Temporary measure: we can remove this limitation when well after spend v1.5 HF block
    if (fImporting || fReindex)// || !znodeSync.IsBlockchainSynced())
        return _("Not fully synced yet");

    LogPrintf("MintZerocoin: value = %s\n", nValue);
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");
    if (nValue + payTxFee.GetFeePerK() > GetBalance())
        return _("Insufficient funds");
    LogPrintf("payTxFee.GetFeePerK()=%s\n", payTxFee.GetFeePerK());
    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked()) {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintZerocoin() : %s", strError);
        return strError;
    }

    string strError;
    CCoinControl coin_control;
    if (!CreateZerocoinMintTransaction(pubCoin, nValue, wtxNew, reservekey, nFeeRequired, strError, coin_control)) {
        LogPrintf("nFeeRequired=%s\n", nFeeRequired);
        if (nValue + nFeeRequired > GetBalance())
            return strprintf(
                    _("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"),
                    FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
        return "ABORTED";

    CValidationState state;

    if (!CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    } else {
        LogPrintf("CommitTransaction success!\n");
    }

    return "";
}

string CWallet::MintZerocoinBatch(vector <CScript> pubCoinBatch, vector <int64_t> nValueBatch, CWalletTx &wtxNew, bool fAskFee) {
    // Do not allow mint to take place until fully synced
    // Temporary measure: we can remove this limitation when well after spend v1.5 HF block
    if (fImporting || fReindex)// || !znodeSync.IsBlockchainSynced())
        return _("Not fully synced yet");

    int64_t nTotalValue = 0;
    for(auto i: nValueBatch)
        nTotalValue += i;

    LogPrintf("MintZerocoinBatch: value = %s\n", nTotalValue);
    // Check amount
    if (nTotalValue <= 0)
        return _("Invalid amount");
    if ((nTotalValue * 1.0025)  > GetBalance())
        return _("Insufficient funds");

    CReserveKey reservekey(this);
    int64_t nFeeRequired;

    if (IsLocked()) {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("MintZerocoin() : %s", strError);
        return strError;
    }

    string strError;
    CCoinControl coin_control;
    if (!CreateZerocoinMintTransactionBatch(pubCoinBatch, nValueBatch, wtxNew, reservekey, nFeeRequired, strError, coin_control)) {
        LogPrintf("nFeeRequired=%s\n", nFeeRequired);
        if (nTotalValue + nFeeRequired > GetBalance())
            return strprintf(
                    _("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!"),
                    FormatMoney(nFeeRequired).c_str());
        return strError;
    }

    if (fAskFee && !uiInterface.ThreadSafeAskFee(nFeeRequired))
        return "ABORTED";

    CValidationState state;

    if (!CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    } else {
        LogPrintf("CommitTransaction success!\n");
    }

    return "";
}

/**
 * @brief CWallet::SpendZerocoin
 * @param nValue
 * @param denomination
 * @param wtxNew
 * @param coinSerial
 * @param txHash
 * @param zcSelectedValue
 * @param zcSelectedIsUsed
 * @return
 */
string CWallet::SpendZerocoin(std::string &toKey, int64_t nValue, libzerocoin::CoinDenomination denomination, CWalletTx &wtxNew,
                              CBigNum &coinSerial, uint256 &txHash, CBigNum &zcSelectedValue,
                              bool &zcSelectedIsUsed) {
    // Check amount
    if (nValue <= 0)
        return _("Invalid amount");

    // Do not allow spend to take place until fully synced
    // Temporary measure: we can remove this limitation when well after spend v1.5 HF block
    if (fImporting || fReindex) // || !znodeSync.IsBlockchainSynced())
        return _("Not fully synced yet");

    CReserveKey reservekey(this);

    if (IsLocked()) {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("SpendZerocoin() : %s", strError);
        return strError;
    }

    string strError;
    if (!CreateZerocoinSpendTransaction(toKey, nValue, denomination, wtxNew, reservekey, coinSerial, txHash,
                                        zcSelectedValue, zcSelectedIsUsed, strError)) {
        LogPrintf("SpendZerocoin() : %s\n", strError.c_str());
        return strError;
    }

    CValidationState state;

    if (!CommitZerocoinSpendTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
        CZerocoinEntry pubCoinTx;
        list <CZerocoinEntry> listPubCoin;
        listPubCoin.clear();

        CWalletDB walletdb(*dbw);
        walletdb.ListPubCoin(listPubCoin);
        BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
            if (zcSelectedValue == pubCoinItem.value) {
                pubCoinTx.id = pubCoinItem.id;
                pubCoinTx.IsUsed = false; // having error, so set to false, to be able to use again
                pubCoinTx.value = pubCoinItem.value;
                pubCoinTx.nHeight = pubCoinItem.nHeight;
                pubCoinTx.randomness = pubCoinItem.randomness;
                pubCoinTx.serialNumber = pubCoinItem.serialNumber;
                pubCoinTx.denomination = pubCoinItem.denomination;
                pubCoinTx.ecdsaSecretKey = pubCoinItem.ecdsaSecretKey;
                CWalletDB(*dbw).WriteZerocoinEntry(pubCoinTx);
                LogPrintf("SpendZerocoin failed, re-updated status -> NotifyZerocoinChanged\n");
                LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
                NotifyZerocoinChanged(this, pubCoinItem.value.GetHex(), pubCoinItem.denomination, "New", CT_UPDATED);
            }
        }
        CZerocoinSpendEntry entry;
        entry.coinSerial = coinSerial;
        entry.hashTx = txHash;
        entry.pubCoin = zcSelectedValue;
        if (!CWalletDB(*dbw).EraseCoinSpendSerialEntry(entry)) {
            return _("Error: It cannot delete coin serial number in wallet");
        }
        return _(
                "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    }
    return "";
}

string CWallet::SpendZerocoinBatch(std::string &toKey, vector <CScript> pubCoinScripts, vector <int64_t> nValueBatch, vector <libzerocoin::CoinDenomination> denominationBatch, CWalletTx &wtxNew,
                              vector <CBigNum> &coinSerialBatch, vector <uint256> &txHashBatch, vector <CBigNum> &zcSelectedValueBatch,
                              bool &zcSelectedIsUsed) {
    // Check amount

    int64_t nTotalValue = 0;
    for(auto i: nValueBatch)
        nTotalValue += i;

    if (nTotalValue <= 0)
        return _("Invalid amount");

    // Do not allow spend to take place until fully synced
    // Temporary measure: we can remove this limitation when well after spend v1.5 HF block
    if (fImporting || fReindex) // || !znodeSync.IsBlockchainSynced())
        return _("Not fully synced yet");

    CReserveKey reservekey(this);

    if (IsLocked()) {
        string strError = _("Error: Wallet locked, unable to create transaction!");
        LogPrintf("SpendZerocoin() : %s", strError);
        return strError;
    }

    string strError;
    if (!CreateZerocoinSpendTransactionBatch(toKey, pubCoinScripts, nValueBatch, denominationBatch, wtxNew, reservekey, coinSerialBatch, txHashBatch,
                                        zcSelectedValueBatch, zcSelectedIsUsed, strError)) {
        LogPrintf("SpendZerocoin() : %s\n", strError.c_str());
        return strError;
    }

    CValidationState state;

    if (!CommitZerocoinSpendTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        for(int i = 0; i < coinSerialBatch.size(); i++){
            LogPrintf("CommitZerocoinSpendTransaction() -> FAILED!\n");
            CZerocoinEntry pubCoinTx;
            list <CZerocoinEntry> listPubCoin;
            listPubCoin.clear();

            CWalletDB walletdb(*dbw);
            walletdb.ListPubCoin(listPubCoin);
            BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
                if (zcSelectedValueBatch[i] == pubCoinItem.value) {
                    pubCoinTx.id = pubCoinItem.id;
                    pubCoinTx.IsUsed = false; // having error, so set to false, to be able to use again
                    pubCoinTx.value = pubCoinItem.value;
                    pubCoinTx.nHeight = pubCoinItem.nHeight;
                    pubCoinTx.randomness = pubCoinItem.randomness;
                    pubCoinTx.serialNumber = pubCoinItem.serialNumber;
                    pubCoinTx.denomination = pubCoinItem.denomination;
                    pubCoinTx.ecdsaSecretKey = pubCoinItem.ecdsaSecretKey;
                    CWalletDB(*dbw).WriteZerocoinEntry(pubCoinTx);
                    LogPrintf("SpendZerocoin failed, re-updated status -> NotifyZerocoinChanged\n");
                    LogPrintf("pubcoin=%s, isUsed=New\n", pubCoinItem.value.GetHex());
                    NotifyZerocoinChanged(this, pubCoinItem.value.GetHex(), pubCoinItem.denomination, "New", CT_UPDATED);
                }
            }
            CZerocoinSpendEntry entry;
            entry.coinSerial = coinSerialBatch[i];
            entry.hashTx = txHashBatch[i];
            entry.pubCoin = zcSelectedValueBatch[i];
            if (!CWalletDB(*dbw).EraseCoinSpendSerialEntry(entry)) {
                return _("Error: It cannot delete coin serial number in wallet");
            }
            return _(
                    "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
        }
    }
    return "";
}

void CWallet::ListAvailableCoinsMintCoins(vector <COutput> &vCoins, bool fOnlyConfirmed) const {
    vCoins.clear();
    {
        LOCK(cs_wallet);
        list <CZerocoinEntry> listPubCoin = list<CZerocoinEntry>();
        CWalletDB walletdb(*dbw);
        walletdb.ListPubCoin(listPubCoin);
        //LogPrintf("listPubCoin.size()=%s\n", listPubCoin.size());
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
//            LogPrintf("pcoin=%s\n", pcoin->GetHash().ToString());
            if (!CheckFinalTx(*pcoin->tx,0)) {
                //LogPrintf("!CheckFinalTx(*pcoin)=%s\n", !CheckFinalTx(*pcoin->tx,0));
                continue;
            }

            if (fOnlyConfirmed && !pcoin->IsTrusted()) {
                //LogPrintf("fOnlyConfirmed = %s, !pcoin->IsTrusted(): %s\n", fOnlyConfirmed, !pcoin->IsTrusted());
                continue;
            }

            if ((pcoin->IsCoinBase() || pcoin->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0) {
                //LogPrintf("Not trusted\n");
                continue;
            }

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0) {
                //LogPrintf("nDepth=%s\n", nDepth);
                continue;
            }
            //LogPrintf("pcoin->vout.size()=%s\n", pcoin->tx->vout.size());

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                if (pcoin->tx->vout[i].scriptPubKey.IsZerocoinMint()) {
                    CTxOut txout = pcoin->tx->vout[i];
                    vector<unsigned char> vchZeroMint;
                    vchZeroMint.insert(vchZeroMint.end(), txout.scriptPubKey.begin() + 6,
                                       txout.scriptPubKey.begin() + txout.scriptPubKey.size());

                    CBigNum pubCoin;
                    pubCoin.setvch(vchZeroMint);
                    //LogPrintf("Pubcoin=%s\n", pubCoin.ToString());
                    // CHECKING PROCESS
                    BOOST_FOREACH(const CZerocoinEntry &pubCoinItem, listPubCoin) {
//                        LogPrintf("*******\n");
//                        LogPrintf("pubCoinItem.value=%s,\n", pubCoinItem.value.ToString());
//                        LogPrintf("pubCoinItem.IsUsed=%s\n, ", pubCoinItem.IsUsed);
//                        LogPrintf("pubCoinItem.randomness=%s\n, ", pubCoinItem.randomness);
//                        LogPrintf("pubCoinItem.serialNumber=%s\n, ", pubCoinItem.serialNumber);
                        if (pubCoinItem.value == pubCoin && pubCoinItem.IsUsed == false &&
                            pubCoinItem.randomness != 0 && pubCoinItem.serialNumber != 0) {
                            vCoins.push_back(COutput(pcoin, i, nDepth, true, true, true));
                            //LogPrintf("-->OK\n");
                        }
                    }

                }
            }
        }
    }
}

bool CompHeight(const CZerocoinEntry &a, const CZerocoinEntry &b) { return a.nHeight < b.nHeight; }

bool CompID(const CZerocoinEntry &a, const CZerocoinEntry &b) { return a.id < b.id; }

static const char * CoinDenominationStrings[] = { "0", "1", "5", "10", "50", "100", "500", "1000", "5000" };

//unlock wallet and create ghost timer
bool CWallet::EnableGhostMode(SecureString strWalletPass, string totalAmount){

    this->NotifyZerocoinChanged.connect(boost::bind(&CWallet::NotifyGhostChanged, this, _1, _2, _3, _4, _5));

    //sanity check for decimal
    if (totalAmount.find('.') != std::string::npos)
        return error("%s: Error: The Ghost Mode value needs to be a whole number.", __func__);
    if (!this->Unlock(strWalletPass)) {
        return error("%s: Error: The wallet passphrase entered was incorrect.", __func__);
    }

    //TODO: Change amount.h total money circulation
    if(!GhostModeMintTrigger(totalAmount))
        return error("%s: Error: Cannot trigger ghost mode mint.", __func__);

    return true;
}

//Lock wallet and destroy ghost timer
bool CWallet::DisableGhostMode(){
    LOCK(this->cs_wallet);
    this->nRelockTime = 0;
    this->NotifyZerocoinChanged.disconnect(boost::bind(&CWallet::NotifyGhostChanged, this, _1, _2, _3, _4, _5));
    this->Lock();
    return true;
}

//push mint and spends into a queue
void CWallet::NotifyGhostChanged(CWallet *wallet, const std::string &pubCoin, int denomination, const std::string &isUsed, ChangeType status)
{

    libzerocoin::CoinDenomination denom = libzerocoin::ZQ_ERROR;
    if (denomination == 1) {
        denom = libzerocoin::ZQ_ONE;
    } else if (denomination == 5) {
        denom = libzerocoin::ZQ_FIVE;
    } else if (denomination == 10) {
        denom = libzerocoin::ZQ_TEN;
    } else if (denomination == 50) {
        denom = libzerocoin::ZQ_FIFTY;
    } else if (denomination == 100) {
        denom = libzerocoin::ZQ_ONE_HUNDRED;
    }  else if (denomination == 500) {
        denom = libzerocoin::ZQ_FIVE_HUNDRED;
    } else if (denomination == 1000) {
        denom = libzerocoin::ZQ_ONE_THOUSAND;
    } else if (denomination == 5000) {
        denom = libzerocoin::ZQ_FIVE_THOUSAND;
    }
    if(isUsed == "New")
        GhostModeSpendTrigger(std::to_string(denom));
    if(isUsed == "Used")
        GhostModeMintTrigger(std::to_string(denom));

}

bool CWallet::SpendAllZerocoins(){

    std::list<CZerocoinEntry> pc;
    CWalletDB(*dbw).ListPubCoin(pc);
    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();
    int coinHeight;

    BOOST_FOREACH(const CZerocoinEntry &minIdPubcoin, pc) {
        if(minIdPubcoin.IsUsed == false){
            int id;
            coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
            if(coinHeight >= chainActive.Height() + ZEROCOIN_CONFIRM_HEIGHT){
                //if(!GhostModeSpendTrigger(std::to_string(minIdPubcoin.denomination)))
                 //   return error("%s: Error: Failed to spend all zerocoins.", __func__);
            }
        }
     }

    return true;
}

//ghost timer mint responder
bool CWallet::GhostModeMintTrigger(string totalAmount, vector<CScript> pubCoinScripts){

    string stringError;
    //Autobackup wallet into ghostbackups
    string backupDir = GetDataDir().string() + "/ghostbackups/wallet-" + std::to_string(GetTime()) + ".dat";
    fs::create_directories(fs::path(GetDataDir().string() + "/ghostbackups/"));

    //only maintain max of 20 backups
    std::string path = GetDataDir().string() + "/ghostbackups/";
    int m = 0;
    int t = 0;
    for (auto & p : fs::directory_iterator(path)){
        if(m > 17){
            t++;
        }
        m++;
    }
    for (auto & p : fs::directory_iterator(path)){
        if(t > 1){
            fs::remove(p.path());
            t--;
        }
        else
            break;
    }

    if(!this->GetDBHandle().Backup(backupDir))
        return error("%s: Error: Cannot create wallet backup.", __func__);

    CAmount amount = 0;
    CAmount nRemaining = 0;
    libzerocoin::CoinDenomination denomination = libzerocoin::ZQ_ONE;
    if (!ParseFixedPoint(totalAmount, 8, &amount))
        return error("%s: Error: Invalid amount.", __func__);
    if (!MoneyRange(amount))
        return error("%s: Error: Amount out of range.", __func__);

    vector<string> denominationBatch;
    //TODO: Create timer function to mint and recognize freshly finished mints to spend
    denomination = libzerocoin::AmountToClosestDenomination(amount, amount);
    while(denomination != libzerocoin::ZQ_ERROR){
        //amount = nRemaining;
        denominationBatch.push_back(std::to_string((int)denomination));
        denomination = libzerocoin::AmountToClosestDenomination(amount * COIN, amount);
    }

    if (this->IsLocked())
        return error("%s: Error: The wallet needs to be unlocked.", __func__);
    if(pubCoinScripts.empty()){
        if(!CreateZerocoinMintModelBatch(stringError, denominationBatch))
            return error("%s: Error: Failed to create zerocoin mint model - %s.", __func__, stringError);
    }
    else{
        for(int ps = 0; ps < pubCoinScripts.size(); ps++){
            CZerocoinState *zcState = CZerocoinState::GetZerocoinState();
            // Check for conflicts with in-memory transactions
            CBigNum pubCoin(vector<unsigned char>(pubCoinScripts[ps].begin()+6, pubCoinScripts[ps].end()));
            if (!zcState->CanAddMintToMempool(pubCoin)) {
                return error("%s: Error: key has already been used! - %s.", __func__, stringError);
            }
        }
        if(!CreateZerocoinMintModelBatch(stringError, denominationBatch, pubCoinScripts))
            return error("%s: Error: Failed to create zerocoin mint model - %s.", __func__, stringError);
    }

    return true;
}

int GhostDenom(CAmount amount){
    switch(amount){
    case CAmount(1):
        return 0;
    case CAmount(5):
        return 1;
    case CAmount(10):
        return 2;
    case CAmount(50):
        return 3;
    case CAmount(100):
        return 4;
    case CAmount(500):
        return 5;
    case CAmount(1000):
        return 6;
    case CAmount(5000):
        return 7;
    default:
        return -1;
        break;
    }
}

bool ClosestDenoms(CAmount amount, int totalZerocoins, CAmount demoniationList[8][1]){

    CAmount currentDenomination[] = {1,5,10,50,100,500,1000,5000};
    int currentDenominationIndex = 7;

    for (int i = 0; i < totalZerocoins; i++) {

        //exact match
        if (amount == currentDenomination[currentDenominationIndex]) {
            //check if we have this denomination
            if(demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0] > 0){
                demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0]--;
                amount = 0;
            }
            i = totalZerocoins;
            break;
        }

        else if(amount > currentDenomination[currentDenominationIndex]){
            if(demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0] > 0){
                demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0]--;
                amount -= currentDenomination[currentDenominationIndex];
            }
            else{
                i--;
                currentDenominationIndex--;
            }

        }
        //less than
        else{
            i--;
            currentDenominationIndex--;
        }

        if(currentDenominationIndex < 0)
            i = totalZerocoins;

    }

    if(amount  == 0)
        return true;

    return false;
}
//ghost timer spend responder
std::string CWallet::GhostModeSpendTrigger(string totalAmount, string toKey, vector<CScript> pubCoinScripts){

    //Autobackup wallet into ghostbackups
    string backupDir = GetDataDir().string() + "/ghostbackups/wallet-" + std::to_string(GetTime()) + ".dat";
    fs::create_directories(fs::path(GetDataDir().string() + "/ghostbackups/"));
    //only maintain max of 20 backups
    std::string path = GetDataDir().string() + "/ghostbackups/";
    int m = 0;
    int t = 0;
    for (auto & p : fs::directory_iterator(path)){
        if(m > 17){
            t++;
        }
        m++;
    }
    for (auto & p : fs::directory_iterator(path)){
        if(t > 1){
            fs::remove(p.path());
            t--;
        }
        else
            break;
    }

    if(!this->GetDBHandle().Backup(backupDir))
        return "GhostModeSpendTrigger(): Error: Cannot create wallet backup.";

    /*                          *
     *     Convert amount       *
     *                          */
    string stringError;
    CAmount amount = 0;
    if (!ParseFixedPoint(totalAmount, 8, &amount))
        return "GhostModeSpendTrigger(): Error: Invalid amount.";
    if (!MoneyRange(amount))
        return "GhostModeSpendTrigger(): Error: Amount out of range.";

    amount = amount/COIN;
    CAmount finalTotal = amount;

    /*                          *
     *  Find all denominations  *
     *                          */
    std::vector<COutput> vCoins;
    ListAvailableCoinsMintCoins(vCoins);
    CAmount demoniationList[8][1] = {
      {0}, //1
      {0}, //5
      {0}, //10
      {0}, //50
      {0}, //100
      {0}, //500
      {0}, //1000
      {0}  //5000
    };

    CAmount demoniationListCopy[8][1] = {
      {0}, //1
      {0}, //5
      {0}, //10
      {0}, //50
      {0}, //100
      {0}, //500
      {0}, //1000
      {0}  //5000
    };


    int totalZerocoins = 0 ;
    int totalZerocoinAmount = 0;
    for(COutput n: vCoins){
        if (n.tx->tx->vout[n.i].scriptPubKey.IsZerocoinMint()) {
            CTxOut txout = n.tx->tx->vout[n.i];
            switch(txout.nValue){
            case CAmount(1 * COIN):
                demoniationList[0][0]++;
                totalZerocoins++;
                totalZerocoinAmount++;
                break;
            case CAmount(5 * COIN):
                demoniationList[1][0]++;
                totalZerocoins++;
                totalZerocoinAmount+=5;
                break;
            case CAmount(10 * COIN):
                demoniationList[2][0]++;
                totalZerocoins++;
                totalZerocoinAmount+=10;
                break;
            case CAmount(50 * COIN):
                demoniationList[3][0]++;
                totalZerocoins++;
                totalZerocoinAmount+=50;
                break;
            case CAmount(100 * COIN):
                demoniationList[4][0]++;
                totalZerocoins++;
                totalZerocoinAmount+=100;
                break;
            case CAmount(500 * COIN):
                demoniationList[5][0]++;
                totalZerocoins++;
                totalZerocoinAmount+=500;
                break;
            case CAmount(1000 * COIN):
                demoniationList[6][0]++;
                totalZerocoins++;
                totalZerocoinAmount+=1000;
                break;
            case CAmount(5000 * COIN):
                demoniationList[7][0]++;
                totalZerocoins++;
                totalZerocoinAmount+=5000;
                break;
            default:
                break;
            }
        }

    }

    for(int i = 0; i < 7; i++)
        demoniationListCopy[i][0] = demoniationList[i][0];

    /*                          *
     *    Get list to spend     *
     *                          */
    CAmount toSpend[8][1] = {
      {0}, //1
      {0}, //5
      {0}, //10
      {0}, //50
      {0}, //100
      {0}, //500
      {0}, //1000
      {0}  //5000
    };

    CAmount currentDenomination[] = {1,5,10,50,100,500,1000,5000};
    int currentDenominationIndex = 7;

    for (int i = 0; i <= totalZerocoins; i++) {

        //exact match
        if (amount == currentDenomination[currentDenominationIndex]) {
            //check if we have this denomination
            if(demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0] > 0){
                toSpend[GhostDenom(currentDenomination[currentDenominationIndex])][0]++;
                demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0]--;
                amount = 0;
                i = totalZerocoins;
                break;
            }
            else{
                i--;
                currentDenominationIndex--;
            }
        }

        else if(amount > currentDenomination[currentDenominationIndex]){
            if(demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0] > 0){
                toSpend[GhostDenom(currentDenomination[currentDenominationIndex])][0]++;
                demoniationList[GhostDenom(currentDenomination[currentDenominationIndex])][0]--;
                amount -= currentDenomination[currentDenominationIndex];
            }
            else{
                i--;
                currentDenominationIndex--;
            }

        }
        //less than
        else{
            i--;
            currentDenominationIndex--;
        }

        if(currentDenominationIndex < 0)
            i = totalZerocoins;

    }

    /*                          *
     *         Spend all        *
     *                          */
    if(amount == 0){
        int index = 0;
        vector <std::string> denominationBatch;
        denominationBatch.clear();
        while(1){
            if(toSpend[index][0] > 0){
                denominationBatch.push_back(std::to_string(currentDenomination[index]));
                toSpend[index][0]--;
            }
            else
                index++;
            if(index > 7)
                break;
        }

        if (this->IsLocked())
            return "GhostModeSpendTrigger(): Error: The wallet needs to be unlocked.";

        //check if minting these spends
        if(!pubCoinScripts.empty()){
            //Not enough payout scripts
            if(pubCoinScripts.size() < denominationBatch.size())
                return "GhostModeSpendTrigger(): Error: Not enough mint payout scripts "
                        + std::to_string(pubCoinScripts.size()) + " < " + std::to_string(denominationBatch.size());
            for(int ps = 0; ps < pubCoinScripts.size(); ps++){
                CZerocoinState *zcState = CZerocoinState::GetZerocoinState();
                // Check for conflicts with in-memory transactions
                CBigNum pubCoin(vector<unsigned char>(pubCoinScripts[ps].begin()+6, pubCoinScripts[ps].end()));
                if (!zcState->CanAddMintToMempool(pubCoin)) {
                    return "GhostModeSpendTrigger(): Error: key has already been used!";
                }
            }

        }

        //limit a batch to 4 zerocoins
        int startIndex = 0;
        int endIndex = denominationBatch.size() > 4 ? 3 : denominationBatch.size() - 1;
        for(int vecSplit = 0; vecSplit < ((denominationBatch.size()/4) + 1); vecSplit++){
            vector <std::string> denominationBatchSub;
            vector <CScript> pubCoinScriptsSub;
            for(int vecSub = startIndex; vecSub <= endIndex; vecSub++){
                denominationBatchSub.push_back(denominationBatch[vecSub]);
                if(!pubCoinScripts.empty())
                    pubCoinScriptsSub.push_back(pubCoinScripts[vecSub]);
            }

            if(denominationBatchSub.size() < 1)
                continue;

            if(!CreateZerocoinSpendModelBatch(stringError, denominationBatchSub, toKey, pubCoinScriptsSub)){
                if(vecSplit > 0){
                    CAmount amountGhosted = 0;
                    for (int x = 0; x < vecSplit; x++){
                        amountGhosted += currentDenomination[x];
                        amountGhosted += currentDenomination[x + 1];
                        amountGhosted += currentDenomination[x + 2];
                        amountGhosted += currentDenomination[x + 3];
                    }
                    return "GhostModeSpendTrigger(): Error: Was only able to unghost %s NIX - %s." + std::to_string(amountGhosted) + stringError;
                }
                else
                    return "GhostModeSpendTrigger(): Error: Failed to unghost ghosted NIX - %s." +  stringError;
            }

            startIndex = endIndex + 1;
            endIndex = endIndex + 4;

            if (endIndex > denominationBatch.size() - 1)
                endIndex = denominationBatch.size() - 1;
        }

        return "Sucessfully sent " + totalAmount + " ghosted NIX";
    }
    else {

        //Check all possible combos

        CAmount actualMin = -1;
        CAmount actualMax = -1;

        for(int i = 1; i < totalZerocoinAmount; i++){

            if(finalTotal - i < 1)
                break;

            CAmount denomTemp[8][1] = {
              {0}, //1
              {0}, //5
              {0}, //10
              {0}, //50
              {0}, //100
              {0}, //500
              {0}, //1000
              {0}  //5000
            };
            for(int j = 0; j < 7; j++)
                denomTemp[j][0] = demoniationListCopy[j][0];

            bool success = false;
            success =  ClosestDenoms(finalTotal - i, totalZerocoins, denomTemp);

            if(success){
                actualMin = finalTotal - i;
                break;
            }
        }

        for(int i = 1; i < totalZerocoinAmount; i++){

            if(finalTotal + i > totalZerocoinAmount)
                break;

            CAmount denomTemp[8][1] = {
              {0}, //1
              {0}, //5
              {0}, //10
              {0}, //50
              {0}, //100
              {0}, //500
              {0}, //1000
              {0}  //5000
            };
            for(int j = 0; j < 7; j++)
                denomTemp[j][0] = demoniationListCopy[j][0];

            bool success = false;
            success =  ClosestDenoms(finalTotal + i, totalZerocoins, denomTemp);

            if(success){
                actualMax = finalTotal + i;
                break;
            }
        }

        return "Closest amount you can send: " + std::to_string(actualMin) + ", " + std::to_string(actualMax);

    }
    return "error";
}


//Ghostnode insert

CAmount CWallet::GetAnonymizableBalance(bool fSkipDenominated) const {
    if (fLiteMode) return 0;

    std::vector <CompactTallyItem> vecTally;
    if (!SelectCoinsGrouppedByAddresses(vecTally, fSkipDenominated)) return 0;

    CAmount nTotal = 0;

    BOOST_FOREACH(CompactTallyItem & item, vecTally)
    {
        bool fIsDenominated = IsDenominatedAmount(item.nAmount);
        if (fSkipDenominated && fIsDenominated) continue;
        // assume that the fee to create denoms be PRIVATESEND_COLLATERAL at max
        if (item.nAmount >= vecPrivateSendDenominations.back() + (fIsDenominated ? 0 : PRIVATESEND_COLLATERAL))
            nTotal += item.nAmount;
    }

    return nTotal;
}

CAmount CWallet::GetAnonymizedBalance() const {
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;

            if (pcoin->IsTrusted())
                nTotal += 0;
        }
    }

    return nTotal;
}

CAmount CWalletTx::GetAnonymizedCredit(bool fUseCache) const {
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if ((IsCoinBase() || IsCoinStake()) && GetBlocksToMaturity() > 0)
        return 0;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++) {
        const CTxOut &txout = tx->vout[i];
        const CTxIn txin = CTxIn(hashTx, i);

        if (pwallet->IsSpent(hashTx, i) || !pwallet->IsDenominated(txin)) continue;

//        const int nRounds = pwallet->GetInputPrivateSendRounds(txin);
        const int nRounds = 0;
        if (nRounds >= nPrivateSendRounds) {
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAnonymizedCredit() : value out of range");
        }
    }

    return nCredit;
}


CAmount CWallet::GetNeedsToBeAnonymizedBalance(CAmount nMinBalance) const {
    if (fLiteMode) return 0;

    CAmount nAnonymizedBalance = GetAnonymizedBalance();
    CAmount nNeedsToAnonymizeBalance = nPrivateSendAmount * COIN - nAnonymizedBalance;

    // try to overshoot target DS balance up to nMinBalance
    nNeedsToAnonymizeBalance += nMinBalance;

    CAmount nAnonymizableBalance = GetAnonymizableBalance();

    // anonymizable balance is way too small
    if (nAnonymizableBalance < nMinBalance) return 0;

    // not enough funds to anonymze amount we want, try the max we can
    if (nNeedsToAnonymizeBalance > nAnonymizableBalance) nNeedsToAnonymizeBalance = nAnonymizableBalance;

    // we should never exceed the pool max
    if (nNeedsToAnonymizeBalance > PRIVATESEND_POOL_MAX) nNeedsToAnonymizeBalance = PRIVATESEND_POOL_MAX;

    return nNeedsToAnonymizeBalance;
}

CAmount CWallet::GetDenominatedBalance(bool unconfirmed) const {
    if (fLiteMode) return 0;

    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;

        }
    }

    return nTotal;
}

// Recursively determine the rounds of a given input (How deep is the PrivateSend chain for a given input)
int CWallet::GetRealInputPrivateSendRounds(CTxIn txin, int nRounds) const
{
    static std::map<uint256, CMutableTransaction> mDenomWtxes;

    if(nRounds >= 16) return 15; // 16 rounds max

    uint256 hash = txin.prevout.hash;
    unsigned int nout = txin.prevout.n;

    const CWalletTx* wtx = GetWalletTx(hash);
    if(wtx != NULL)
    {
        std::map<uint256, CMutableTransaction>::const_iterator mdwi = mDenomWtxes.find(hash);
        if (mdwi == mDenomWtxes.end()) {
            // not known yet, let's add it
            //LogPrint("privatesend", "GetRealInputPrivateSendRounds INSERTING %s\n", hash.ToString());
            LogPrintf("privatesend GetRealInputPrivateSendRounds UPDATED \n");
            CMutableTransaction txHash = *wtx->tx;
            mDenomWtxes[hash] = txHash;
        } else if(mDenomWtxes[hash].vout[nout].nRounds != -10) {
            // found and it's not an initial value, just return it
            return mDenomWtxes[hash].vout[nout].nRounds;
        }


        // bounds check
        if (nout >= wtx->tx->vout.size()) {
            // should never actually hit this
            //LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, -4);
            LogPrintf("privatesend GetRealInputPrivateSendRounds UPDATED \n");
            return -4;
        }

        if (IsCollateralAmount(wtx->tx->vout[nout].nValue)) {
            mDenomWtxes[hash].vout[nout].nRounds = -3;
            //LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            LogPrintf("privatesend GetRealInputPrivateSendRounds UPDATED \n");
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        //make sure the final output is non-denominate
        if (!IsDenominatedAmount(wtx->tx->vout[nout].nValue)) { //NOT DENOM
            mDenomWtxes[hash].vout[nout].nRounds = -2;
            //LogPrint("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            LogPrintf("privatesend GetRealInputPrivateSendRounds UPDATED \n");
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        bool fAllDenoms = true;
        BOOST_FOREACH(CTxOut out, wtx->tx->vout) {
            fAllDenoms = fAllDenoms && IsDenominatedAmount(out.nValue);
        }

        // this one is denominated but there is another non-denominated output found in the same tx
        if (!fAllDenoms) {
            mDenomWtxes[hash].vout[nout].nRounds = 0;
            LogPrintf("privatesend", "GetRealInputPrivateSendRounds UPDATED   %s %3d %3d\n", hash.ToString(), nout, mDenomWtxes[hash].vout[nout].nRounds);
            return mDenomWtxes[hash].vout[nout].nRounds;
        }

        int nShortest = -10; // an initial value, should be no way to get this by calculations
        bool fDenomFound = false;
        // only denoms here so let's look up
        BOOST_FOREACH(CTxIn txinNext, wtx->tx->vin) {
            if (IsMine(txinNext)) {
                int n = GetRealInputPrivateSendRounds(txinNext, nRounds + 1);
                // denom found, find the shortest chain or initially assign nShortest with the first found value
                if(n >= 0 && (n < nShortest || nShortest == -10)) {
                    nShortest = n;
                    fDenomFound = true;
                }
            }
        }
        mDenomWtxes[hash].vout[nout].nRounds = fDenomFound
                                               ? (nShortest >= 15 ? 16 : nShortest + 1) // good, we a +1 to the shortest one but only 16 rounds max allowed
                                               : 0;            // too bad, we are the fist one in that chain
        LogPrintf("privatesend", "GetRealInputPrivateSendRounds UPDATED %s \n", hash.ToString());
        return mDenomWtxes[hash].vout[nout].nRounds;
    }

    return nRounds - 1;
}

// respect current settings
int CWallet::GetInputPrivateSendRounds(CTxIn txin) const
{
    LOCK(cs_wallet);
    int realPrivateSendRounds = GetRealInputPrivateSendRounds(txin, 0);
    return realPrivateSendRounds > nPrivateSendRounds ? nPrivateSendRounds : realPrivateSendRounds;
}


bool CWallet::IsDenominated(const CTxIn &txin) const {
    LOCK(cs_wallet);

    map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
    if (mi != mapWallet.end()) {
        const CWalletTx &prev = (*mi).second;
        if (txin.prevout.n < prev.tx->vout.size()) {
            return IsDenominatedAmount(prev.tx->vout[txin.prevout.n].nValue);
        }
    }

    return false;
}

bool CWallet::IsDenominatedAmount(CAmount nInputAmount) const {
    BOOST_FOREACH(CAmount d, vecPrivateSendDenominations)
    if(nInputAmount == d)
        return true;
    return false;
}

int CWallet::CountInputsWithAmount(CAmount nInputAmount) {
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
            const CWalletTx *pcoin = &(*it).second;
            if (pcoin->IsTrusted()) {
                int nDepth = pcoin->GetDepthInMainChain(false);

                for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
                    COutput out = COutput(pcoin, i, nDepth, true, true, true);
                    CTxIn txin = CTxIn(out.tx->GetHash(), out.i);

                    if (out.tx->tx->vout[out.i].nValue != nInputAmount) continue;
                    if (!IsDenominatedAmount(pcoin->tx->vout[i].nValue)) continue;
                    if (IsSpent(out.tx->GetHash(), i) || IsMine(pcoin->tx->vout[i]) != ISMINE_SPENDABLE ||
                        !IsDenominated(txin))
                        continue;

                    nTotal++;
                }
            }
        }
    }

    return nTotal;
}

bool CWallet::HasCollateralInputs(bool fOnlyConfirmed) const {
    vector <COutput> vCoins;
    AvailableCoins(vCoins, fOnlyConfirmed, NULL, false, MAX_MONEY, MAX_MONEY,0, 0, 9999999, ONLY_PRIVATESEND_COLLATERAL);

    return !vCoins.empty();
}


bool CWallet::IsCollateralAmount(CAmount nInputAmount) const {
    // collateral inputs should always be a 2x..4x of PRIVATESEND_COLLATERAL
    return nInputAmount >= PRIVATESEND_COLLATERAL * 2 &&
           nInputAmount <= PRIVATESEND_COLLATERAL * 4 &&
           nInputAmount % PRIVATESEND_COLLATERAL == 0;
}

bool CWallet::SelectCoinsDark(CAmount nValueMin, CAmount nValueMax, std::vector <CTxIn> &vecTxInRet, CAmount &nValueRet,
                              int nPrivateSendRoundsMin, int nPrivateSendRoundsMax) const {
    CCoinControl *coinControl = NULL;

    vecTxInRet.clear();
    nValueRet = 0;

    vector <COutput> vCoins;
    AvailableCoins(vCoins, true, coinControl, false, MAX_MONEY, MAX_MONEY,0, 0, 9999999, nPrivateSendRoundsMin < 0 ? ONLY_NONDENOMINATED_NOT40000IFMN : ONLY_DENOMINATED);

    //order the array so largest nondenom are first, then denominations, then very small inputs.
    sort(vCoins.rbegin(), vCoins.rend(), CompareByPriority());

    BOOST_FOREACH(const COutput &out, vCoins)
    {
        //do not allow inputs less than 1/10th of minimum value
        if (out.tx->tx->vout[out.i].nValue < nValueMin / 10) continue;
        //do not allow collaterals to be selected
        if (IsCollateralAmount(out.tx->tx->vout[out.i].nValue)) continue;
        if (fGhostNode && out.tx->tx->vout[out.i].nValue == GHOSTNODE_COIN_REQUIRED * COIN) continue; //ghostnode input

        if (nValueRet + out.tx->tx->vout[out.i].nValue <= nValueMax) {
            CTxIn txin = CTxIn(out.tx->tx->GetHash(), out.i);

            int nRounds = GetInputPrivateSendRounds(txin);
            if (nRounds >= nPrivateSendRoundsMax) continue;
            if (nRounds < nPrivateSendRoundsMin) continue;

            txin.prevPubKey = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet += out.tx->tx->vout[out.i].nValue;
            vecTxInRet.push_back(txin);
        }
    }

    return nValueRet >= nValueMin;
}

bool CWallet::GetCollateralTxIn(CTxIn& txinRet, CAmount& nValueRet) const
{
    vector<COutput> vCoins;

    AvailableCoins(vCoins);

    BOOST_FOREACH(const COutput& out, vCoins)
    {
        if(IsCollateralAmount(out.tx->tx->vout[out.i].nValue))
        {
            txinRet = CTxIn(out.tx->GetHash(), out.i);
            txinRet.prevPubKey = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey
            nValueRet = out.tx->tx->vout[out.i].nValue;
            return true;
        }
    }

    return false;
}

bool CWallet::GetGhostnodeVinAndKeys(CTxIn &txinRet, CPubKey &pubKeyRet, CKey &keyRet, std::string strTxHash,
                                 std::string strOutputIndex) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    std::vector <COutput> vPossibleCoins;
    AvailableCoins(vPossibleCoins, true, NULL, false, MAX_MONEY, MAX_MONEY,0, 0, 9999999, ONLY_40000);

    if (vPossibleCoins.empty()) {
        LogPrintf("CWallet::GetGhostnodeVinAndKeys -- Could not locate any valid ghostnode vin\n");
        return false;
    }

    if (strTxHash.empty()) // No output specified, select the first one
        return GetVinAndKeysFromOutput(vPossibleCoins[0], txinRet, pubKeyRet, keyRet);

    // Find specific vin
    uint256 txHash = uint256S(strTxHash);
    int nOutputIndex = atoi(strOutputIndex.c_str());

    BOOST_FOREACH(COutput & out, vPossibleCoins)
    if (out.tx->GetHash() == txHash && out.i == nOutputIndex) // found it!
        return GetVinAndKeysFromOutput(out, txinRet, pubKeyRet, keyRet);

    LogPrintf("CWallet::GetGhostnodeVinAndKeys -- Could not locate specified ghostnode vin\n");
    return false;
}

bool CWallet::GetVinAndKeysFromOutput(COutput out, CTxIn &txinRet, CPubKey &pubKeyRet, CKey &keyRet) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;

    txinRet = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);
    CBitcoinAddress address2(address1);

    //if (!address2.GetKeyID(keyID)) {
    //    LogPrintf("CWallet::GetVinAndKeysFromOutput -- Address does not refer to a key\n");
    //    return false;
    //}
    if (!address2.IsValid()) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Address does not refer to a key\n");
        return false;
    }

    const CWallet *pw = this;
    if (!GetKey(GetKeyForDestination(*pw, address1), keyRet)) {
        LogPrintf("CWallet::GetVinAndKeysFromOutput -- Private key for address is not known\n");
        return false;
    }

    pubKeyRet = keyRet.GetPubKey();
    return true;
}

bool CWallet::ConvertList(std::vector <CTxIn> vecTxIn, std::vector <CAmount> &vecAmounts) {
    BOOST_FOREACH(CTxIn txin, vecTxIn) {
        if (mapWallet.count(txin.prevout.hash)) {
            CWalletTx &wtx = mapWallet[txin.prevout.hash];
            if (txin.prevout.n < wtx.tx->vout.size()) {
                vecAmounts.push_back(wtx.tx->vout[txin.prevout.n].nValue);
            }
        } else {
            LogPrintf("CWallet::ConvertList -- Couldn't find transaction\n");
        }
    }
    return true;
}

bool CWallet::SelectCoinsByDenominations(int nDenom, CAmount nValueMin, CAmount nValueMax,
                                         std::vector <CTxIn> &vecTxInRet, std::vector <COutput> &vCoinsRet,
                                         CAmount &nValueRet, int nPrivateSendRoundsMin, int nPrivateSendRoundsMax) {
    vecTxInRet.clear();
    vCoinsRet.clear();
    nValueRet = 0;

    vector <COutput> vCoins;
    AvailableCoins(vCoins, true, NULL, false, MAX_MONEY, MAX_MONEY,0, 0, 9999999, ONLY_DENOMINATED);
    std::random_shuffle(vCoins.rbegin(), vCoins.rend(), GetRandInt);

    std::vector<int> vecBits;
    if (!darkSendPool.GetDenominationsBits(nDenom, vecBits)) {
        return false;
    }

    int nDenomResult = 0;

    InsecureRand insecureRand;
    BOOST_FOREACH(const COutput &out, vCoins)
    {
        // ghostnode-like input should not be selected by AvailableCoins now anyway
        if (nValueRet + out.tx->tx->vout[out.i].nValue <= nValueMax) {

            CTxIn txin = CTxIn(out.tx->GetHash(), out.i);

            int nRounds = GetInputPrivateSendRounds(txin);
            if (nRounds >= nPrivateSendRoundsMax) continue;
            if (nRounds < nPrivateSendRoundsMin) continue;

            BOOST_FOREACH(int nBit, vecBits) {
                if (out.tx->tx->vout[out.i].nValue == vecPrivateSendDenominations[nBit]) {
                    if (nValueRet >= nValueMin) {
                        //randomly reduce the max amount we'll submit (for anonymity)
                        nValueMax -= insecureRand(nValueMax/5);
                        //on average use 50% of the inputs or less
                        int r = insecureRand(vCoins.size());
                        if ((int) vecTxInRet.size() > r) return true;
                    }
                    txin.prevPubKey = out.tx->tx->vout[out.i].scriptPubKey; // the inputs PubKey
                    nValueRet += out.tx->tx->vout[out.i].nValue;
                    vecTxInRet.push_back(txin);
                    vCoinsRet.push_back(out);
                    nDenomResult |= 1 << nBit;
                }
            }
        }
    }

    return nValueRet >= nValueMin && nDenom == nDenomResult;
}

bool CWallet::CreateCollateralTransaction(CMutableTransaction &txCollateral, std::string &strReason) {
    txCollateral.vin.clear();
    txCollateral.vout.clear();

    CReserveKey reservekey(this);
    CAmount nValue = 0;
    CTxIn txinCollateral;

    if (!GetCollateralTxIn(txinCollateral, nValue)) {
        strReason = "PrivateSend requires a collateral transaction and could not locate an acceptable input!";
        return false;
    }

    // make our change address
    CScript scriptChange;
    CPubKey vchPubKey;
    assert(reservekey.GetReservedKey(vchPubKey)); // should never fail, as we just unlocked
    scriptChange = GetScriptForDestination(vchPubKey.GetID());
    reservekey.KeepKey();

    txCollateral.vin.push_back(txinCollateral);

    //pay collateral charge in fees
    CTxOut txout = CTxOut(nValue - PRIVATESEND_COLLATERAL, scriptChange);
    txCollateral.vout.push_back(txout);
    CAmount amount;
    if (!SignSignature(*this, txinCollateral.prevPubKey, txCollateral, 0, amount, int(SIGHASH_ALL | SIGHASH_ANYONECANPAY))) {
        strReason = "Unable to sign collateral transaction!";
        return false;
    }

    return true;
}

bool CWallet::SelectCoinsGrouppedByAddresses(std::vector <CompactTallyItem> &vecTallyRet, bool fSkipDenominated,
                                             bool fAnonymizable) const {
    LOCK2(cs_main, cs_wallet);

    isminefilter filter = ISMINE_SPENDABLE;

    // try to use cache
    if (fAnonymizable) {
        if(fSkipDenominated && fAnonymizableTallyCachedNonDenom) {
            vecTallyRet = vecAnonymizableTallyCachedNonDenom;
            LogPrintf("selectcoins SelectCoinsGrouppedByAddresses - using cache for non-denom inputs\n");
            return vecTallyRet.size() > 0;
        }
        if(!fSkipDenominated && fAnonymizableTallyCached) {
            vecTallyRet = vecAnonymizableTallyCached;
            LogPrintf("selectcoins SelectCoinsGrouppedByAddresses - using cache for all inputs\n");
            return vecTallyRet.size() > 0;
        }
    }

    // Tally
    map <CBitcoinAddress, CompactTallyItem> mapTally;
    for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it) {
        const CWalletTx &wtx = (*it).second;

        if ((wtx.IsCoinBase() || wtx.IsCoinStake()) && wtx.GetBlocksToMaturity() > 0) continue;
        if (!fAnonymizable && !wtx.IsTrusted()) continue;

        for (unsigned int i = 0; i < wtx.tx->vout.size(); i++) {
            CTxDestination address;
            if (!ExtractDestination(wtx.tx->vout[i].scriptPubKey, address)) continue;

            isminefilter mine = ::IsMine(*this, address);
            if (!(mine & filter)) continue;

            if (IsSpent(wtx.GetHash(), i) || IsLockedCoin(wtx.GetHash(), i)) continue;

            if (fSkipDenominated && IsDenominatedAmount(wtx.tx->vout[i].nValue)) continue;

            if (fAnonymizable) {
                // ignore collaterals
                if (IsCollateralAmount(wtx.tx->vout[i].nValue)) continue;
                if (fGhostNode && wtx.tx->vout[i].nValue == GHOSTNODE_COIN_REQUIRED * COIN) continue;
                // ignore outputs that are 10 times smaller then the smallest denomination
                // otherwise they will just lead to higher fee / lower priority
                if (wtx.tx->vout[i].nValue <= vecPrivateSendDenominations.back() / 10) continue;
                // ignore anonymized
                if(GetInputPrivateSendRounds(CTxIn(wtx.GetHash(), i)) >= nPrivateSendRounds) continue;
            }

            CompactTallyItem &item = mapTally[address];
            item.address = address;
            item.nAmount += wtx.tx->vout[i].nValue;
            item.vecTxIn.push_back(CTxIn(wtx.GetHash(), i));
        }
    }

    // construct resulting vector
    vecTallyRet.clear();
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, CompactTallyItem)&item, mapTally) {
        if (fAnonymizable && item.second.nAmount < vecPrivateSendDenominations.back()) continue;
        vecTallyRet.push_back(item.second);
    }

    // order by amounts per address, from smallest to largest
    sort(vecTallyRet.rbegin(), vecTallyRet.rend(), CompareByAmount());

    // cache anonymizable for later use
    if (fAnonymizable) {
        if (fSkipDenominated) {
            vecAnonymizableTallyCachedNonDenom = vecTallyRet;
            fAnonymizableTallyCachedNonDenom = true;
        } else {
            vecAnonymizableTallyCached = vecTallyRet;
            fAnonymizableTallyCached = true;
        }
    }

    // debug
    std::string strMessage = "SelectCoinsGrouppedByAddresses - vecTallyRet:\n";
    BOOST_FOREACH(CompactTallyItem & item, vecTallyRet)
        strMessage += strprintf("  %s %f\n", item.address.ToString().c_str(), float(item.nAmount) / COIN);
    LogPrintf("selectcoins %s \n", strMessage);

    return vecTallyRet.size() > 0;
}


/* ***************** */
/* POS Functionality */
/* ***************** */

bool hashUnset(const uint256 &hash)
{
    return (hash.IsNull() || hash == ABANDON_HASH);
}

int CWallet::GetDepthInMainChain(const uint256 &blockhash, int nIndex) const
{
    if (hashUnset(blockhash))
        return 0;

    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(blockhash);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex *pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    return ((nIndex == -1) ? (-1) : 1) * (chainActive.Height() - pindex->nHeight + 1);
}

size_t CWallet::CountColdstakeOutputs()
{
    size_t nColdstakeOutputs = 0;

    CCoinControl coinControl;
    std::vector<COutput> vAvailableCoins;
    CAmount nMinimumAmount = 0, nMaximumAmount = MAX_MONEY, nMinimumSumAmount = 0;
    uint64_t nMaximumCount = 0;
    int nMinDepth = 0, nMaxDepth = 0x7FFFFFFF;
    AvailableCoins(vAvailableCoins, false, &coinControl, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount, nMinDepth, nMaxDepth, ONLY_NONDENOMINATED_NOT40000IFMN);
    for (auto &coin : vAvailableCoins)
    {
        assert(coin.i < (int)coin.tx->tx->vout.size());
        auto txoutBase = coin.tx->tx->vout[coin.i];

        if (HasIsCoinstakeOp(txoutBase.scriptPubKey))
            nColdstakeOutputs++;
    };

    return nColdstakeOutputs;
}

bool CWallet::GetScriptForAddress(CScript &script, const CBitcoinAddress &addr, bool fUpdate, std::vector<uint8_t> *vData)
{
    LOCK(cs_wallet);

    CTxDestination dest = addr.Get();
    if (dest.type() == typeid(CKeyID))
    {
        CKeyID idk = boost::get<CKeyID>(dest);
        script = GetScriptForDestination(idk);
    } else if(dest.type() == typeid(CScriptID)){
        script = GetScriptForDestination(dest);
    } else
    {
        return error("%s: Unknown destination type.", __func__);
    };

    return true;
}

bool CWallet::SetReserveBalance(CAmount nNewReserveBalance)
{
    LogPrintf("SetReserveBalance %d\n", nReserveBalance);
    LOCK(cs_wallet);

    nReserveBalance = nNewReserveBalance;
    return true;
}

uint64_t CWallet::GetStakeWeight() const
{
    // Choose coins to use
    int64_t nBalance = GetStakeableBalance();

    if (nBalance <= nReserveBalance)
        return 0;

    int nHeight;
    {
        LOCK(cs_main);
        nHeight = chainActive.Height()+1;
    }

    // Choose coins to use
    std::set<std::pair<const CWalletTx*,unsigned int> > setCoins;
    CAmount nValueIn = 0;

    // Select coins with suitable depth
    if (!SelectCoinsForStaking(nBalance - nReserveBalance, GetTime(), nHeight, setCoins, nValueIn))
        return 0;

    if (setCoins.empty())
        return 0;

    uint64_t nWeight = 0;

    LOCK2(cs_main, cs_wallet);
    for (auto pcoin : setCoins)
    {
        nWeight += pcoin.first->tx->vout[pcoin.second].nValue;
    }

    return nWeight;
}

bool SortWeight(const COutput &a, const COutput &b) { return (a.tx->tx->vout[a.i].nValue/a.tx->GetTxTime()) > (b.tx->tx->vout[b.i].nValue/b.tx->GetTxTime()); }

void CWallet::AvailableCoinsForStaking(std::vector<COutput> &vCoins, int64_t nTime, int nHeight) const
{
    vCoins.clear();

    deepestTxnDepth = 0;

    {
        LOCK2(cs_main, cs_wallet);

        int nHeight = chainActive.Tip()->nHeight;
        int coinbaseMaturity = nHeight >= Params().GetConsensus().nStartGhostFeeDistribution ? COINBASE_MATURITY_V2 : COINBASE_MATURITY;

        bool fTestNet = (Params().NetworkIDString() == CBaseChainParams::TESTNET);
        if(fTestNet)
            coinbaseMaturity = COINBASE_MATURITY_TESTNET;

        int nRequiredDepth = coinbaseMaturity + 1;

        for (MapWallet_t::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx *pcoin = &it->second;
            CTransactionRef tx = pcoin->tx;

            int nDepth = pcoin->GetDepthInMainChainCached();

            if (nDepth > deepestTxnDepth)
                deepestTxnDepth = nDepth;

            if (nDepth < nRequiredDepth)
                continue;

            const uint256 &wtxid = it->first;
            for (size_t i = 0; i < tx->vout.size(); ++i)
            {
                const auto &txout = tx->vout[i];

                COutPoint kernel(wtxid, i);
                if (!CheckStakeUnused(kernel) ||
                        IsSpent(wtxid, i)
                        || IsLockedCoin(wtxid, i))
                    continue;

                const CScript pscriptPubKey = txout.scriptPubKey;

                if(pscriptPubKey.IsPayToScriptHash_CS()){
                    // Check if contract allows fee payouts
                    int64_t feeOut = 0;
                    if(GetCoinstakeScriptFee(pscriptPubKey, feeOut)){
                        if(feeOut < nMinimumDelagatePercentage)
                            continue;
                    }
                    //If script does not include fee and percentage is set, skip
                    else if(nMinimumDelagatePercentage > 0)
                        continue;

                    CScript scriptOut;
                    if(GetCoinstakeScriptFeeRewardAddress(pscriptPubKey, scriptOut)){
                        if(nDelegateRewardToMe){
                            CScriptID delegateRewardID;
                            ExtractStakingKeyID(scriptOut, delegateRewardID);
                            if(!HaveCScript(delegateRewardID))
                                continue;
                        }
                        else if(!nDelegateRewardAddresses.empty()){
                            bool found = false;
                            for(std::string addressString: nDelegateRewardAddresses){
                                CBitcoinAddress rewardAddress(addressString);
                                if(!rewardAddress.IsValid() || !rewardAddress.IsScript())
                                    continue;

                                CScriptID delegateRewardID;
                                ExtractStakingKeyID(scriptOut, delegateRewardID);

                                CTxDestination rewardDest = rewardAddress.Get();
                                CScriptID rewardID = boost::get<CScriptID>(rewardDest);

                                if(rewardID == delegateRewardID)
                                    found = true;
                            }
                            if(!found)
                                continue;

                        }

                    }
                    //If script does not include reward addres and fields are set, skip
                    else if(nDelegateRewardToMe || !nDelegateRewardAddresses.empty())
                        continue;
                }

                CScriptID dest;
                //Returns false if not coldstake or p2sh script
                if (!ExtractStakingKeyID(pscriptPubKey, dest))
                    continue;

                // for staking we ONLY support P2SH Segwit
                const CScriptID& destScriptID = dest;
                if (HaveCScript(destScriptID))
                    vCoins.push_back(COutput(pcoin, i, nDepth, true, true, true));

            }
        }
    }

    //Sort staking list by (amount/height) instead of randomness
    std::sort(vCoins.begin(), vCoins.end(), SortWeight);

    //random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);
    return;
}

bool CWallet::SelectCoinsForStaking(int64_t nTargetValue, int64_t nTime, int nHeight, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const
{
    std::vector<COutput> vCoins;
    AvailableCoinsForStaking(vCoins, nTime, nHeight);

    setCoinsRet.clear();
    nValueRet = 0;

    for (auto &output : vCoins)
    {
        const CWalletTx *pcoin = output.tx;
        int i = output.i;

        // Stop if we've chosen enough inputs
        if (nValueRet >= nTargetValue)
            break;

        int64_t n = pcoin->tx->vout[i].nValue;
        //LogPrintf("\nSelectCoinsForStaking() amount %llf\n", n);
        std::pair<int64_t, std::pair<const CWalletTx*, unsigned int> > coin = std::make_pair(n, std::make_pair(pcoin, i));

        if (n >= nTargetValue)
        {
            // If input value is greater or equal to target then simply insert
            //    it into the current subset and exit
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            break;
        } else
        if (n < nTargetValue + CENT)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
        };
    };

    return true;
}

bool CWallet::CreateCoinStake(unsigned int nBits, int64_t nTime, int nBlockHeight, int64_t nFees, CMutableTransaction &txNew, CKey &key, CBlockTemplate *pblocktemplate, int64_t nGhostFees, std::vector<unsigned char> &commitment, uint256 witnessroot)
{
    CBlockIndex *pindexPrev = chainActive.Tip();
    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    CAmount nBalance = GetStakeableBalance();
    if (nBalance <= nReserveBalance)
        return false;

    // Choose coins to use
    std::vector<const CWalletTx*> vwtxPrev;
    std::set<std::pair<const CWalletTx*,unsigned int> > setCoins;
    CAmount nValueIn = 0;

    // Select coins with suitable depth
    if (!SelectCoinsForStaking(nBalance - nReserveBalance, nTime, nBlockHeight, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    CAmount nCredit = 0;
    CScript scriptPubKeyKernel;

    std::set<std::pair<const CWalletTx*,unsigned int> >::iterator it = setCoins.begin();

    for (; it != setCoins.end(); ++it)
    {
        auto pcoin = *it;
        if (ThreadStakeMinerStopped()) // interruption_point
            return false;

        COutPoint prevoutStake = COutPoint(pcoin.first->GetHash(), pcoin.second);

        int64_t nBlockTime;

        if (CheckKernel(pindexPrev, nBits, nTime, prevoutStake, &nBlockTime))
        {
            LOCK(cs_wallet);
            // Found a kernel
            LogPrintf("%s: Kernel found.\n", __func__);


            CTxOut kernelOut = pcoin.first->tx->vout[pcoin.second];

            std::vector<valtype> vSolutions;
            txnouttype whichType;

            const CScript *pscriptPubKey = &kernelOut.scriptPubKey;
            CScript coinstakePath;
            bool fConditionalStake = false;

            //check if this is a coldstake
            if ((HasIsCoinstakeOp(*pscriptPubKey)))
            {
                fConditionalStake = true;
                if (!GetCoinstakeScriptPath(*pscriptPubKey, coinstakePath))
                    continue;
                pscriptPubKey = &coinstakePath;
            };

            if (!Solver(*pscriptPubKey, whichType, vSolutions))
            {
                LogPrint(BCLog::POS, "%s: Failed to parse kernel.\n", __func__);
                break;
            };

            LogPrint(BCLog::POS, "%s: Parsed kernel type=%d.\n", __func__, whichType);
            CKeyID spendId;
            CScriptID idScript;
            /*
            if (whichType == TX_PUBKEYHASH)
            {
                spendId = CKeyID(uint160(vSolutions[0]));
            }
            */
            if(whichType == TX_SCRIPTHASH){
                if (vSolutions[0].size() == 20)
                    idScript = CScriptID(uint160(vSolutions[0]));
                else
                    break;
            }
            else
            {
                LogPrint(BCLog::POS, "%s: No support for kernel type=%d.\n", __func__, whichType);
                break;  // only support pay to address (pay to pubkey hash)
            }

            const CWallet *pw = this;
            /*
            if ((whichType != TX_SCRIPTHASH) && !GetKey(spendId, key))
            {
                LogPrint(BCLog::POS, "%s: Failed to get key for kernel type=%d.\n", __func__, whichType);
                break;  // unable to find corresponding key
            }
            */
            if(!GetKey(GetKeyForDestination(*pw, idScript), key)){
                LogPrint(BCLog::POS, "%s: Failed to get script key for kernel type=%d.\n", __func__, whichType);
                break;  // unable to find corresponding key
            }

            //staking existing cold stake output
            if (fConditionalStake)
            {
                scriptPubKeyKernel = kernelOut.scriptPubKey;
            } else
            {
                //payment to scripthash only
                if(whichType == TX_SCRIPTHASH)
                    scriptPubKeyKernel << OP_HASH160 << ToByteVector(idScript) << OP_EQUAL;

                // If the wallet has a coldstaking-change-address loaded, send the output to a coldstaking-script.
                std::string coldStakeAddress = gArgs.GetArg("-coldstakeaddress", "");

                //set up coldstake script
                if (coldStakeAddress  != "")
                {
                    LogPrintf("%s: Sending output to coldstakingscript %s.\n", __func__, coldStakeAddress);

                    CBitcoinAddress addrColdStaking(coldStakeAddress);
                    if (!addrColdStaking.IsValid())
                        return error("%s: coldstaking address IsValid() failed.", __func__);

                    CScript scriptStaking;
                    if (!GetScriptForAddress(scriptStaking, addrColdStaking, true))
                        return error("%s: GetScriptForAddress failed.", __func__);

                    std::shared_ptr<CReserveScript> coinbaseScript;
                    GetScriptForMining(coinbaseScript);
                    if (!coinbaseScript) {
                        return error("%s: Error: Keypool ran out, please call keypoolrefill first.", __func__);
                    }
                    if (coinbaseScript->reserveScript.empty()) {
                        return error("%s: No coinbase script available.", __func__);
                    }

                    // Generate new key for local wallet, remove coins from existing address
                    scriptPubKeyKernel = coinbaseScript->reserveScript;

                    //payout to script
                    if (scriptStaking.IsPayToScriptHash())
                    {
                        CScript script = CScript() << OP_ISCOINSTAKE << OP_IF;
                        //cold stake address
                        script += scriptStaking;
                        script << OP_ELSE;
                        //local wallet address
                        script += scriptPubKeyKernel;
                        script << OP_ENDIF;

                        scriptPubKeyKernel = script;
                    } else
                    {
                        return error("%s: Unknown scriptStaking type, must be pay-to-script-hash.", __func__);
                    };
                };
            };

            // Ensure txn is empty
            txNew.vin.clear();
            txNew.vout.clear();

            // Mark as coin stake transaction
            txNew.nVersion = NIX_TXN_VERSION;
            txNew.SetType(TXN_COINSTAKE);

            txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));

            nCredit += kernelOut.nValue;
            vwtxPrev.push_back(pcoin.first);

            txNew.vout.push_back(CTxOut(0,scriptPubKeyKernel));

            LogPrintf("%s: Added kernel with value: %lf.\n", __func__, nCredit);

            setCoins.erase(it);
            break;
        };
    };

    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
    {
        return false;
    };

    // Attempt to add more inputs
    // Only advantage here is to setup the next stake using this output as a kernel to have a higher chance of staking
    size_t nStakesCombined = 0;
    it = setCoins.begin();
    while (it != setCoins.end())
    {
        if (nStakesCombined >= nMaxStakeCombine)
            break;

        // Stop adding more inputs if already too many inputs
        if (txNew.vin.size() >= 100)
            break;

        // Stop adding more inputs if value is already pretty significant
        if (nCredit >= nStakeCombineThreshold)
            break;

        std::set<std::pair<const CWalletTx*, unsigned int> >::iterator itc = it++; // copy the current iterator then increment it
        auto pcoin = *itc;

        CTxOut prevOut = pcoin.first->tx->vout[pcoin.second];

        // Only add coins of the same key/address as kernel
        if (prevOut.scriptPubKey != scriptPubKeyKernel)
            continue;

        // Stop adding inputs if reached reserve limit
        if (nCredit + prevOut.nValue > nBalance - nReserveBalance)
            break;

        // Do not add additional significant input
        if (prevOut.nValue >= nStakeCombineThreshold)
            continue;

        txNew.vin.push_back(CTxIn(pcoin.first->GetHash(), pcoin.second));
        nCredit += prevOut.nValue;
        vwtxPrev.push_back(pcoin.first);

        LogPrint(BCLog::POS, "%s: Combining kernel %s, %d.\n", __func__, pcoin.first->GetHash().ToString(), pcoin.second);
        nStakesCombined++;
        setCoins.erase(itc);
    }

    bool fTestNet = (Params().NetworkIDString() == CBaseChainParams::TESTNET);

    // Get block reward
    CAmount nReward = Params().GetProofOfStakeReward(pindexPrev, nFees);
    if (nReward < 0)
        return false;

    // Process development fund
    CAmount nRewardOut;
    nRewardOut = nReward;

    // Check if contract allows fee payouts, require delegate address payout for now
    int64_t nfeeOut = 0;
    CAmount nFeeAmount = 0;
    CAmount nAmount = 0;
    if(GetCoinstakeScriptFee(scriptPubKeyKernel, nfeeOut)){
        double feePercent = (double)nfeeOut;
        if(nfeeOut > 10000 || nfeeOut < 0){
            return false;
        }
        feePercent /= 100;
        //coldstake reward
        nAmount = nReward * (double)((100.0 - feePercent)/100.0);
        //delegate fee reward
        nFeeAmount = nReward * (double)((feePercent)/100.0);

        CScript scriptOut;
        if(!GetCoinstakeScriptFeeRewardAddress(scriptPubKeyKernel, scriptOut)){
            return false;
        }

        nCredit += nAmount;

        if (nCredit >= nStakeSplitThreshold)
        {
            txNew.vout.back().nValue = (nCredit / 2);
            txNew.vout.push_back(CTxOut((nCredit - txNew.vout.back().nValue), scriptPubKeyKernel));
        } else
        {
            txNew.vout.back().nValue = (nCredit);
        }

        //push back delegate fee reward
        txNew.vout.push_back((CTxOut(nFeeAmount, scriptOut)));
    }
    // Set output amount, split outputs if > nStakeSplitThreshold
    else if (nCredit >= nStakeSplitThreshold)
    {
        nCredit += nRewardOut;
        txNew.vout.back().nValue = (nCredit / 2);
        txNew.vout.push_back(CTxOut((nCredit - txNew.vout.back().nValue), scriptPubKeyKernel));
    } else
    {
        nCredit += nRewardOut;
        txNew.vout.back().nValue = (nCredit);
    }



    // Place dev fund output
    CScript DEV_1_SCRIPT;
    CScript DEV_2_SCRIPT;
    if (!fTestNet) {
        DEV_1_SCRIPT = GetScriptForDestination(DecodeDestination("NVbGEghDbxPUe97oY8N5RvagQ61cHQiouW"));
        DEV_2_SCRIPT = GetScriptForDestination(DecodeDestination("NWF7QNfT1b8a9dSQmVTT6hcwzwEVYVmDsG"));
    }
    else {
        DEV_1_SCRIPT = GetScriptForDestination(DecodeDestination("2PosyBduiL7yMfBK8DZEtCBJaQF76zgE8f"));
        DEV_2_SCRIPT = GetScriptForDestination(DecodeDestination("2WT5wFpLXoWm1H8CSgWVcq2F2LyhwKJcG1"));
    }

    //Push dev block reward of 2% based on coinbase rewards, 1% each
    txNew.vout.push_back(CTxOut(DEVELOPMENT_REWARD_POST_POS/2 * GetBlockSubsidy(chainActive.Height(), Params().GetConsensus()), CScript(DEV_1_SCRIPT.begin(), DEV_1_SCRIPT.end())));
    txNew.vout.push_back(CTxOut(DEVELOPMENT_REWARD_POST_POS/2 * GetBlockSubsidy(chainActive.Height(), Params().GetConsensus()), CScript(DEV_2_SCRIPT.begin(), DEV_2_SCRIPT.end())));

    CBlock *pblock = &pblocktemplate->block; // pointer for convenience


    //payout 10 ghostnodes for rewards
    if(chainActive.Height() + 1 < Params().GetConsensus().nStartGhostFeeDistribution){
        if(nGhostFees > 0 && chainActive.Height() >= Params().GetConsensus().nGhostnodePaymentsStartBlock){
            CAmount ghostnodePayment = GetGhostnodePayment(chainActive.Height() + 1, 0) + nGhostFees/10;
            FillBlockPayments(txNew, chainActive.Height() + 1, ghostnodePayment, pblock->txoutGhostnode, pblock->voutSuperblock);

            for(int g = 2; g < 11; g++){
                CTxOut tempTx;
                mnpayments.FillBlockPayee(txNew, chainActive.Height() + g, nGhostFees/10, tempTx);
            }
        }
        //no ghostnode fees
        else{
            if (chainActive.Height() >= Params().GetConsensus().nGhostnodePaymentsStartBlock) {
                CAmount ghostnodePayment = GetGhostnodePayment(chainActive.Height() + 1, 0);
                FillBlockPayments(txNew, chainActive.Height() + 1, ghostnodePayment, pblock->txoutGhostnode, pblock->voutSuperblock);
            }
        }
    }
    //Utilize new distribuition model
    else{
        int64_t returnFee = 0;
        bool payFees = false;
        //Check for ghost fee distribution
        CBlock block;
        block.SetNull();
        if(!GetGhostnodeFeePayment(returnFee, payFees, block))
            return error("%s: GetGhostnodeFeePayment failed.", __func__);

        //Pay node winner block reward
        CAmount ghostnodePayment = GetGhostnodePayment(chainActive.Height() + 1, 0);
        FillBlockPayments(txNew, chainActive.Height() + 1, ghostnodePayment, pblock->txoutGhostnode, pblock->voutSuperblock);

        //add current block fee since we skip it in GetGhostnodeFeePayment()
        returnFee += nGhostFees;

        //pay or dont pay the fees to all nodes
        if(payFees && returnFee != 0){
            vector<CGhostnode> ghostnodeVector = mnodeman.GetFullGhostnodeVector();

            int totalActiveNodes = 0;
            int startBlock = (chainActive.Height() + 1) - (Params().GetConsensus().nGhostFeeDistributionCycle - 1);
            int64_t ensureNodeActiveBefore = chainActive[startBlock]->GetBlockTime();

            for(auto node: ghostnodeVector){

                if(node.IsEnabled() && (node.sigTime <= ensureNodeActiveBefore))
                    totalActiveNodes++;
            }

            CAmount feePayout = returnFee/totalActiveNodes;

            for(auto node: ghostnodeVector){
                if(node.IsEnabled() && (node.sigTime <= ensureNodeActiveBefore)){
                    CScript mnpayee;
                    mnpayee = GetScriptForDestination(node.pubKeyCollateralAddress.GetID());
                    txNew.vout.push_back(CTxOut(feePayout,mnpayee));
                }
            }
        }
    }

    //insert witness tx
    std::vector<unsigned char> ret(32, 0x00);
    CHash256().Write(witnessroot.begin(), 32).Write(ret.data(), 32).Finalize(witnessroot.begin());
    CTxOut out;
    out.nValue = 0;
    out.scriptPubKey.resize(38);
    out.scriptPubKey[0] = OP_RETURN;
    out.scriptPubKey[1] = 0x24;
    out.scriptPubKey[2] = 0xaa;
    out.scriptPubKey[3] = 0x21;
    out.scriptPubKey[4] = 0xa9;
    out.scriptPubKey[5] = 0xed;
    memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
    commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
    txNew.vout.push_back(out);

    // Sign
    int nIn = 0;
    for (const auto &pcoin : vwtxPrev)
    {
        uint32_t nPrev = txNew.vin[nIn].prevout.n;
        CScript scriptPubKeyOut = pcoin->tx->vout[nPrev].scriptPubKey;

        //check if this is a coldstake
        if ((HasIsCoinstakeOp(scriptPubKeyOut)))
        {
            CScript coinstakePath;
            if (!GetCoinstakeScriptPath(scriptPubKeyOut, coinstakePath))
                return error("%s: Cannot retrieve coinstake script.", __func__);;
            scriptPubKeyOut = coinstakePath;
        }
        CAmount nAmount = pcoin->tx->vout[nPrev].nValue;
        SignatureData sigdata;
        CTransaction txToConst(txNew);
        if (!ProduceSignature(TransactionSignatureCreator(this,&txToConst, nIn, nAmount, SIGHASH_ALL), scriptPubKeyOut, sigdata))
            return error("%s: ProduceSignature failed.", __func__);

        UpdateTransaction(txNew, nIn, sigdata);
        nIn++;
    };

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes >= DEFAULT_BLOCK_MAX_WEIGHT/5)
        return error("%s: Exceeded coinstake size limit.", __func__);

    // Successfully generated coinstake
    return true;
}

bool CWallet::SignBlock(CBlockTemplate *pblocktemplate, int nHeight, int64_t nSearchTime)
{
    LogPrint(BCLog::POS, "%s, nHeight %d\n", __func__, nHeight);

    assert(pblocktemplate);
    CBlock *pblock = &pblocktemplate->block;
    assert(pblock);
    if (pblock->vtx.size() < 1)
        return error("%s: Malformed block.", __func__);

    int64_t nFees = -pblocktemplate->vTxFees[0];
    CBlockIndex *pindexPrev = chainActive.Tip();

    int64_t nGhostFees = 0;

    //check for zerocoin mints, start after coinbase
    if(chainActive.Height() + 1 > Params().GetConsensus().nGhostnodePaymentsStartBlock){
        for(int i = 1; i < pblock->vtx.size(); i++){

            //Avoid 2-way ghosting miscalculation
            if(pblock->vtx[i]->IsZerocoinMint() && !pblock->vtx[i]->IsZerocoinSpend()){
                //scrape fees payouts, 0.25% or minimum of 0.01 coins
                //whole block is zerocoin mint
                CAmount mintAmount = 0;
                for(int k = 0; k < pblock->vtx[i]->vout.size(); k++){
                    if(pblock->vtx[i]->vout[k].scriptPubKey.IsZerocoinMint())
                        mintAmount += pblock->vtx[i]->vout[k].nValue;
                }
                nGhostFees += mintAmount * 0.0025;

            }
        }
    }
    if(nGhostFees > nFees){
        LogPrintf("\nCWallet::SignBlock() ERROR: nGhostFees not able to payout, reverting to nFees, nGhostFees=%llf, nFees=%llf \n", nGhostFees, nFees);
        nGhostFees =  nFees;
        nFees = 0;
    }
    else
        nFees -= nGhostFees;

    //LogPrintf("\nGhost Fees: nGhostFees=%llf, nFees=%llf \n", nGhostFees, nFees);

    CKey key;
    pblock->nVersion = ComputeBlockVersion(pindexPrev, Params().GetConsensus());
    pblock->nBits = GetNextTargetRequired(pindexPrev);

    std::vector<unsigned char> commitment;
    uint256 witnessroot = BlockWitnessMerkleRoot(*pblock, nullptr);

    CMutableTransaction txCoinStake;
    if (CreateCoinStake(pblock->nBits, nSearchTime, nHeight, nFees, txCoinStake, key, pblocktemplate, nGhostFees, commitment, witnessroot))
    {
        LogPrint(BCLog::POS, "%s: Kernel found.\n", __func__);

        if (nSearchTime >= chainActive.Tip()->GetBlockTime()+1)
        {
            // make sure coinstake would meet timestamp protocol
            //    as it would be the same as the block timestamp
            pblock->nTime = nSearchTime;

            // Remove coinbasetxn
            pblock->vtx[0].reset();
            pblock->vtx.erase(pblock->vtx.begin());

            // Insert coinstake as txn0
            pblock->vtx.insert(pblock->vtx.begin(), MakeTransactionRef(txCoinStake));
            //Insert blockwitness commitment
            pblocktemplate->vchCoinbaseCommitment = commitment;

            bool mutated;
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock, &mutated);

            // Append a signature to the block
            return key.Sign(pblock->GetHash(), pblock->vchBlockSig);
        };
    };

    nLastCoinStakeSearchTime = nSearchTime;

    return false;
}

int CMerkleTx::GetDepthInMainChainCached() const
{
    // NOTE: Don't use where accuracy is critical
    if (hashUnset())
        return 0;

    AssertLockHeld(cs_main);

    int nChainHeight = chainActive.Height();

    if (fHeightCached)
        return nChainHeight - nCachedHeight;

    const CBlockIndex *pindexRet;
    int nDepth = GetDepthInMainChain(pindexRet);

    if (nDepth > 0)
    {
        fHeightCached = true;
        nCachedHeight = nChainHeight - nDepth;
    };

    return nDepth;

}

bool CWallet::InMempool(const uint256 &hash) const
{
    LOCK(mempool.cs);
    return mempool.exists(hash);
}

CAmount CWallet::GetStakeableBalance() const
{
    CAmount nBalance = 0;

    LOCK2(cs_main, cs_wallet);

    for (MapWallet_t::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx* pcoin = &(*it).second;
        if (!pcoin->IsTrusted())
            continue;
        nBalance += pcoin->GetAvailableCredit(true, true);
    };

    return nBalance;
}

bool CWallet::ProcessStakingSettings(std::string &sError)
{
    nWalletDonationPercent = gArgs.GetArg("-donationpercent", 0);
    nWalletDonationAddress = gArgs.GetArg("-donationaddress", "");
    nStakeSplitThreshold = gArgs.GetArg("-stakesplitthreshold", 10000) * COIN;
    nStakeCombineThreshold = gArgs.GetArg("-stakecombinethreshold", 5000) * COIN;
    nMaxStakeCombine = gArgs.GetArg("-maxstakecombine", 3);
    nMinimumDelagatePercentage = gArgs.GetArg("-minimumleasepercentage", 0);
    std::string delegateAddressesString = gArgs.GetArg("-leaserewardaddresses", "");
    nDelegateRewardToMe = gArgs.GetArg("-leaserewardtome", false);
    nDelegateRewardAddresses.clear();

    LogPrintf("\nProcessStakingSettings: split %lf, combine %lf, combine amount %d, coldstake address: %s, min lease percent: %llf, lease reward to me: %d \n",
              nStakeSplitThreshold/COIN, nStakeCombineThreshold/COIN, nMaxStakeCombine, gArgs.GetArg("-coldstakeaddress", ""), nMinimumDelagatePercentage, nDelegateRewardToMe);
    LogPrintf("LeaseRewardAddresses: ");

    char sep = ',';
    std::string::size_type b = 0;
    while ((b = delegateAddressesString.find_first_not_of(sep, b)) != std::string::npos) {
        auto e = delegateAddressesString.find_first_of(sep, b);
        nDelegateRewardAddresses.push_back(delegateAddressesString.substr(b, e-b));
        b = e;
    }

    for(auto addr: nDelegateRewardAddresses)
        LogPrintf("\n%s", addr);

    if (nStakeCombineThreshold < 100 * COIN)
    {
        sError = "stakecombinethreshold must be >= 100 and <= 5000.";
        nStakeCombineThreshold = 100 * COIN;
    }

    if (nStakeSplitThreshold < nStakeCombineThreshold * 2 )
    {
        sError = "stakesplitthreshold must be >= 2x stakecombinethreshold.";
        nStakeSplitThreshold = nStakeCombineThreshold * 2;
    }

    if (nWalletDonationPercent < 0)
    {
        sError = "nWalletDonationPercent must be >= 0";
        nWalletDonationPercent = 0;
    }
    else if (nWalletDonationPercent > 10000)
    {
        sError = "nWalletDonationPercent must be <= 10000";
        nWalletDonationPercent = 10000;
    }

    if (nMinimumDelagatePercentage < 0)
    {
        sError = "nMinimumLeasePercentage must be >= 0";
        nMinimumDelagatePercentage = 0;
    }
    else if (nMinimumDelagatePercentage > 10000)
    {
        sError = "nMinimumLeasePercentage must be <= 10000";
        nMinimumDelagatePercentage = 10000;
    }

    return true;
}

/**
 * total coins staked (non-spendable until maturity)
 */
CAmount CWallet::GetStaked()
{
    int64_t nTotal = 0;

    int nHeight = chainActive.Tip()->nHeight + 1;
    int coinbaseMaturity = nHeight >= Params().GetConsensus().nStartGhostFeeDistribution ? COINBASE_MATURITY_V2 : COINBASE_MATURITY;

    bool fTestNet = (Params().NetworkIDString() == CBaseChainParams::TESTNET);
    if(fTestNet)
        coinbaseMaturity = COINBASE_MATURITY_TESTNET;

    coinbaseMaturity++;

    LOCK2(cs_main, cs_wallet);
    for (std::pair<const uint256, CWalletTx>& item : mapWallet)
    {
        CWalletTx &wtx = item.second;

        int mature = 0;
        if(wtx.GetDepthInMainChainCached() > 0)
            mature = coinbaseMaturity - wtx.GetDepthInMainChainCached();

        if (wtx.IsCoinStake()
            && wtx.GetDepthInMainChainCached() > 0 // checks for hashunset
            && wtx.GetBlocksToMaturity() > 0 && mature <= 0)
        {
            nTotal += CWallet::GetCredit(*wtx.tx, ISMINE_SPENDABLE);
        }
    }
    return nTotal;
}

#include <rpc/util.h>

bool CWallet::FindUnloadedGhostTransactions(const CTransaction& tx)
{
    if(!tx.IsZerocoinMint())
        return false;

    bool foundCoin = false;
    LOCK(cs_wallet);

    list <CZerocoinEntry> listUnloadedPubcoin;

    CWalletDB walletdb(this->GetDBHandle());
    walletdb.ListUnloadedPubCoin(listUnloadedPubcoin);

    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        CBigNum pubCoin(vector<unsigned char>(txout.scriptPubKey.begin()+6, txout.scriptPubKey.end()));

        for(const CZerocoinEntry &zerocoinItem: listUnloadedPubcoin) {
            //found our Pedersen commitment
            //store in main zerocoin database
            if(zerocoinItem.value == pubCoin){
                //create new zc object
                CZerocoinEntry zerocoinTx;
                zerocoinTx.IsUsed = false;
                zerocoinTx.denomination = txout.nValue/COIN;
                zerocoinTx.value = zerocoinItem.value;
                zerocoinTx.randomness = zerocoinItem.randomness;
                zerocoinTx.serialNumber = zerocoinItem.serialNumber;
                zerocoinTx.ecdsaSecretKey = zerocoinItem.ecdsaSecretKey;
                NotifyZerocoinChanged(this, zerocoinTx.value.GetHex(), zerocoinTx.denomination, zerocoinTx.IsUsed ? "Used" : "New", CT_NEW);

                //first try and write public payment
                if (!walletdb.WriteZerocoinEntry(zerocoinTx))
                    return false;

                if(!walletdb.EraseUnloadedZCEntry(zerocoinItem))
                    return false;


                //Refill Key
                libzerocoin::CoinDenomination denomination;
                libzerocoin::Params *zcParams = ZCParams;
                int mintVersion = 1;
                denomination = libzerocoin::ZQ_ONE;
                libzerocoin::PrivateCoin newCoinTemp(zcParams, denomination, mintVersion);
                if(newCoinTemp.getPublicCoin().validate()){
                    const unsigned char *ecdsaSecretKey = newCoinTemp.getEcdsaSeckey();
                    CZerocoinEntry zerocoinTxNew;
                    zerocoinTxNew.IsUsed = false;
                    zerocoinTxNew.denomination = libzerocoin::ZQ_ERROR;
                    zerocoinTxNew.value = newCoinTemp.getPublicCoin().getValue();
                    zerocoinTxNew.randomness = newCoinTemp.getRandomness();
                    zerocoinTxNew.serialNumber = newCoinTemp.getSerialNumber();
                    zerocoinTxNew.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
                    if (!walletdb.WriteUnloadedZCEntry(zerocoinTxNew))
                        return false;
                }
                foundCoin = true;
            }
        }
    }

    return foundCoin;
}


bool CWallet::TopUpUnloadedCommitments(int kpSize)
{
    {
        LOCK(cs_wallet);

        //if (IsLocked())
            //return false;


        libzerocoin::CoinDenomination denomination;
        libzerocoin::Params *zcParams = ZCParams;

        int mintVersion = 1;
        denomination = libzerocoin::ZQ_ONE;

        list <CZerocoinEntry> listUnloadedPubcoin;
        CWalletDB walletdb(GetDBHandle());
        walletdb.ListUnloadedPubCoin(listUnloadedPubcoin);

        //refill keys to at least 100 in wallet
        for(int i = listUnloadedPubcoin.size(); i < kpSize; i++){
            libzerocoin::PrivateCoin newCoinTemp(zcParams, denomination, mintVersion);
            if(newCoinTemp.getPublicCoin().validate()){
                const unsigned char *ecdsaSecretKey = newCoinTemp.getEcdsaSeckey();
                CZerocoinEntry zerocoinTx;
                zerocoinTx.IsUsed = false;
                zerocoinTx.denomination = libzerocoin::ZQ_ERROR;
                zerocoinTx.value = newCoinTemp.getPublicCoin().getValue();
                zerocoinTx.randomness = newCoinTemp.getRandomness();
                zerocoinTx.serialNumber = newCoinTemp.getSerialNumber();
                zerocoinTx.ecdsaSecretKey = std::vector<unsigned char>(ecdsaSecretKey, ecdsaSecretKey+32);
                if (!walletdb.WriteUnloadedZCEntry(zerocoinTx))
                    return false;
            }
            else
                i--;
        }
    }

    return true;
}

bool CWallet::GetKeyPackList(std::vector <CommitmentKeyPack> &keyPackList, int packSize){

    {
        LOCK(cs_wallet);

        list <CZerocoinEntry> listUnloadedPubcoin;
        CWalletDB walletdb(GetDBHandle());
        walletdb.ListUnloadedPubCoin(listUnloadedPubcoin);

        int keyAmount;
        std::vector<std::vector<unsigned char>> keyList = std::vector<std::vector<unsigned char>>();

        //make sure we have at least 10 key packs
        if(listUnloadedPubcoin.size()/packSize < 10)
            return false;

        keyList.clear();
        keyAmount = packSize;
        for(const CZerocoinEntry &zerocoinItem: listUnloadedPubcoin) {
            keyAmount--;
            std::vector<unsigned char> commitmentKey = zerocoinItem.value.getvch();
            keyList.push_back(commitmentKey);
            if(keyAmount == 0){
                CommitmentKeyPack pubCoinPack(keyList);
                keyPackList.push_back(pubCoinPack);
                keyList.clear();
                keyAmount = packSize;
            }
            //aim for 10 keys
            if(keyPackList.size() == 10)
                break;
        }

    }

    return true;
}

/*
 * Encryption and decription of 3 private zerocoin parameters
 * pubkey hash, randomness, ecdsa key
 */

bool CWallet::EncryptPrivateZerocoinData(CZerocoinEntry &zerocoinMintPlain){

    if(vMasterKey.empty())
        return false;

    vector<unsigned char> serialNumberPlain;
    vector<unsigned char> randomnessPlain;
    vector<unsigned char> ecdsaKeyPlain;

    vector<unsigned char> serialNumberSecret;
    vector<unsigned char> randomnessSecret;
    vector<unsigned char> ecdsaKeySecret;

    const uint256 key = zerocoinMintPlain.value.getuint256();
    const uint256 nIV = Hash(key.begin(), key.end());

    serialNumberPlain = zerocoinMintPlain.serialNumber.getvch();
    randomnessPlain = zerocoinMintPlain.randomness.getvch();
    ecdsaKeyPlain = zerocoinMintPlain.ecdsaSecretKey;

    CKeyingMaterial kmSerialPlain(serialNumberPlain.begin(), serialNumberPlain.end());
    CKeyingMaterial kmRandomnessPlain(randomnessPlain.begin(), randomnessPlain.end());
    CKeyingMaterial kmECDSAPlain(ecdsaKeyPlain.begin(), ecdsaKeyPlain.end());

    if(!EncryptSecret(vMasterKey, kmSerialPlain, nIV, serialNumberSecret)
       || !EncryptSecret(vMasterKey, kmRandomnessPlain, nIV, randomnessSecret)
       || !EncryptSecret(vMasterKey, kmECDSAPlain, nIV, ecdsaKeySecret)) {
        LogPrintf("Failed to encrypt mint with value:\n%s\n", zerocoinMintPlain.value.ToString());
        return false;
    }

    zerocoinMintPlain.serialNumber = CBigNum(serialNumberSecret);
    zerocoinMintPlain.randomness = CBigNum(randomnessSecret);
    zerocoinMintPlain.ecdsaSecretKey = ecdsaKeySecret;

    return true;
}

bool CWallet::DecryptPrivateZerocoinData(CZerocoinEntry &zerocoinMintSecret)
{
    {
        LOCK(cs_KeyStore);

        if(vMasterKey.empty())
            return false;

        vector<unsigned char> serialNumberPlain;
        vector<unsigned char> randomnessPlain;
        vector<unsigned char> ecdsaKeyPlain;
        vector<unsigned char> serialNumberSecret;
        vector<unsigned char> randomnessSecret;
        vector<unsigned char> ecdsaKeySecret;

        const uint256 &key = zerocoinMintSecret.value.getuint256();
        const uint256 nIV = Hash(key.begin(), key.end());

        serialNumberSecret = zerocoinMintSecret.serialNumber.getvch();
        randomnessSecret = zerocoinMintSecret.randomness.getvch();
        ecdsaKeySecret = zerocoinMintSecret.ecdsaSecretKey;

        CKeyingMaterial kmSerial;
        CKeyingMaterial kmRandomness;
        CKeyingMaterial kmECDSA;

        DecryptSecret(vMasterKey, serialNumberSecret, nIV, kmSerial);
        DecryptSecret(vMasterKey, randomnessSecret, nIV, kmRandomness);
        DecryptSecret(vMasterKey, ecdsaKeySecret, nIV, kmECDSA);

        serialNumberPlain = vector<unsigned char>(kmSerial.begin(), kmSerial.end());
        randomnessPlain = vector<unsigned char>(kmRandomness.begin(), kmRandomness.end());
        ecdsaKeyPlain = vector<unsigned char>(kmECDSA.begin(), kmECDSA.end());

        zerocoinMintSecret.serialNumber = (CBigNum(serialNumberPlain));
        zerocoinMintSecret.randomness = (CBigNum(randomnessPlain));
        zerocoinMintSecret.ecdsaSecretKey = ecdsaKeyPlain;

        return true;
    }
}
