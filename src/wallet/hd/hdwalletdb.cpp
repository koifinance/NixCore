// Copyright (c) 2017 The Particl Core developers
// Copyright (c) 2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hd/hdwalletdb.h>
#include <wallet/hd/hdwallet.h>
#include <serialize.h>
#include <boost/tuple/tuple.hpp>
#include <boost/foreach.hpp>


bool CHDWalletDB::WriteStealthKeyMeta(const CKeyID &keyId, const CStealthKeyMetadata &sxKeyMeta)
{
    return WriteIC(std::make_pair(std::string("sxkm"), keyId), sxKeyMeta, true);
};

bool CHDWalletDB::EraseStealthKeyMeta(const CKeyID &keyId)
{
    return EraseIC(std::make_pair(std::string("sxkm"), keyId));
};


bool CHDWalletDB::WriteStealthAddress(const CStealthAddress &sxAddr)
{
    return WriteIC(std::make_pair(std::string("sxad"), sxAddr.scan_pubkey), sxAddr, true);
};

bool CHDWalletDB::ReadStealthAddress(CStealthAddress& sxAddr)
{
    // Set scan_pubkey before reading
    return batch.Read(std::make_pair(std::string("sxad"), sxAddr.scan_pubkey), sxAddr);
};

bool CHDWalletDB::EraseStealthAddress(const CStealthAddress& sxAddr)
{
    return EraseIC(std::make_pair(std::string("sxad"), sxAddr.scan_pubkey));
};


bool CHDWalletDB::ReadNamedExtKeyId(const std::string &name, CKeyID &identifier, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("eknm"), name), identifier, nFlags);
};

bool CHDWalletDB::WriteNamedExtKeyId(const std::string &name, const CKeyID &identifier)
{
    return WriteIC(std::make_pair(std::string("eknm"), name), identifier, true);
};


bool CHDWalletDB::ReadExtKey(const CKeyID &identifier, CStoredExtKey &ek32, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("ek32"), identifier), ek32, nFlags);
};

bool CHDWalletDB::WriteExtKey(const CKeyID &identifier, const CStoredExtKey &ek32)
{
    return WriteIC(std::make_pair(std::string("ek32"), identifier), ek32, true);
};


bool CHDWalletDB::ReadExtAccount(const CKeyID &identifier, CExtKeyAccount &ekAcc, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("eacc"), identifier), ekAcc, nFlags);
};

bool CHDWalletDB::WriteExtAccount(const CKeyID &identifier, const CExtKeyAccount &ekAcc)
{
    return WriteIC(std::make_pair(std::string("eacc"), identifier), ekAcc, true);
};


bool CHDWalletDB::ReadExtKeyPack(const CKeyID &identifier, const uint32_t nPack, std::vector<CEKAKeyPack> &ekPak, uint32_t nFlags)
{
    return batch.Read(boost::make_tuple(std::string("epak"), identifier, nPack), ekPak, nFlags);
};

bool CHDWalletDB::WriteExtKeyPack(const CKeyID &identifier, const uint32_t nPack, const std::vector<CEKAKeyPack> &ekPak)
{
    return WriteIC(boost::make_tuple(std::string("epak"), identifier, nPack), ekPak, true);
};


bool CHDWalletDB::ReadExtStealthKeyPack(const CKeyID &identifier, const uint32_t nPack, std::vector<CEKAStealthKeyPack> &aksPak, uint32_t nFlags)
{
    return batch.Read(boost::make_tuple(std::string("espk"), identifier, nPack), aksPak, nFlags);
};

bool CHDWalletDB::WriteExtStealthKeyPack(const CKeyID &identifier, const uint32_t nPack, const std::vector<CEKAStealthKeyPack> &aksPak)
{
    return WriteIC(boost::make_tuple(std::string("espk"), identifier, nPack), aksPak, true);
};


bool CHDWalletDB::ReadExtStealthKeyChildPack(const CKeyID &identifier, const uint32_t nPack, std::vector<CEKASCKeyPack> &asckPak, uint32_t nFlags)
{
    return batch.Read(boost::make_tuple(std::string("ecpk"), identifier, nPack), asckPak, nFlags);
};

bool CHDWalletDB::WriteExtStealthKeyChildPack(const CKeyID &identifier, const uint32_t nPack, const std::vector<CEKASCKeyPack> &asckPak)
{
    return WriteIC(boost::make_tuple(std::string("ecpk"), identifier, nPack), asckPak, true);
};

bool CHDWalletDB::ReadFlag(const std::string &name, int32_t &nValue, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("flag"), name), nValue, nFlags);
};

bool CHDWalletDB::WriteFlag(const std::string &name, int32_t nValue)
{
    return WriteIC(std::make_pair(std::string("flag"), name), nValue, true);
};

bool CHDWalletDB::ReadExtKeyIndex(uint32_t id, CKeyID &identifier, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("ine"), id), identifier, nFlags);
};

bool CHDWalletDB::WriteExtKeyIndex(uint32_t id, const CKeyID &identifier)
{
    return WriteIC(std::make_pair(std::string("ine"), id), identifier, true);
};

bool CHDWalletDB::ReadStealthAddressIndex(uint32_t id, CStealthAddressIndexed &sxi, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("ins"), id), sxi, nFlags);
};

bool CHDWalletDB::WriteStealthAddressIndex(uint32_t id, const CStealthAddressIndexed &sxi)
{
    return WriteIC(std::make_pair(std::string("ins"), id), sxi, true);
};

bool CHDWalletDB::ReadStealthAddressIndexReverse(const uint160 &hash, uint32_t &id, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("ris"), hash), id, nFlags);
};

bool CHDWalletDB::WriteStealthAddressIndexReverse(const uint160 &hash, uint32_t id)
{
    return WriteIC(std::make_pair(std::string("ris"), hash), id, true);
};

bool CHDWalletDB::ReadStealthAddressLink(const CKeyID &keyId, uint32_t &id, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("lns"), keyId), id, nFlags);
};

bool CHDWalletDB::WriteStealthAddressLink(const CKeyID &keyId, uint32_t id)
{
    return WriteIC(std::make_pair(std::string("lns"), keyId), id, true);
};

bool CHDWalletDB::WriteAddressBookEntry(const std::string &sKey, const CAddressBookData &data)
{
    return WriteIC(std::make_pair(std::string("abe"), sKey), data, true);
};

bool CHDWalletDB::EraseAddressBookEntry(const std::string &sKey)
{
    return EraseIC(std::make_pair(std::string("abe"), sKey));
};

bool CHDWalletDB::WriteTxRecord(const uint256 &hash, const CTransactionRecord &rtx)
{
    return WriteIC(std::make_pair(std::string("rtx"), hash), rtx, true);
};

bool CHDWalletDB::EraseTxRecord(const uint256 &hash)
{
    return EraseIC(std::make_pair(std::string("rtx"), hash));
};


bool CHDWalletDB::ReadStoredTx(const uint256 &hash, CStoredTransaction &stx, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("stx"), hash), stx, nFlags);
};

bool CHDWalletDB::WriteStoredTx(const uint256 &hash, const CStoredTransaction &stx)
{
    return WriteIC(std::make_pair(std::string("stx"), hash), stx, true);
};

bool CHDWalletDB::EraseStoredTx(const uint256 &hash)
{
    return EraseIC(std::make_pair(std::string("stx"), hash));
};



bool CHDWalletDB::ReadWalletSetting(const std::string &setting, std::string &json, uint32_t nFlags)
{
    return batch.Read(std::make_pair(std::string("wset"), setting), json, nFlags);
};

bool CHDWalletDB::WriteWalletSetting(const std::string &setting, const std::string &json)
{
    return WriteIC(std::make_pair(std::string("wset"), setting), json, true);
};

bool CHDWalletDB::EraseWalletSetting(const std::string &setting)
{
    return EraseIC(std::make_pair(std::string("wset"), setting));
};

/**
 *
 * @brief CHDWALLETDB: ZEROCOIN DB
 *
 */
bool CWalletDB::WriteCoinSpendSerialEntry(const CZerocoinSpendEntry &zerocoinSpend) {
    return batch.Write(make_pair(string("zcserial"), zerocoinSpend.coinSerial), zerocoinSpend, true);
}

bool CWalletDB::EraseCoinSpendSerialEntry(const CZerocoinSpendEntry &zerocoinSpend) {
    return batch.Erase(make_pair(string("zcserial"), zerocoinSpend.coinSerial));
}

bool
CWalletDB::WriteZerocoinAccumulator(libzerocoin::Accumulator accumulator, libzerocoin::CoinDenomination denomination,
                                    int pubcoinid) {
    return batch.Write(std::make_tuple(string("zcaccumulator"), (unsigned int) denomination, pubcoinid), accumulator);
}

bool
CWalletDB::ReadZerocoinAccumulator(libzerocoin::Accumulator &accumulator, libzerocoin::CoinDenomination denomination,
                                   int pubcoinid) {
    return batch.Read(std::make_tuple(string("zcaccumulator"), (unsigned int) denomination, pubcoinid), accumulator);
}

bool CWalletDB::WriteZerocoinEntry(const CZerocoinEntry &zerocoin) {
    return batch.Write(make_pair(string("zerocoin"), zerocoin.value), zerocoin, true);
}

bool CWalletDB::EraseZerocoinEntry(const CZerocoinEntry &zerocoin) {
    return batch.Erase(make_pair(string("zerocoin"), zerocoin.value));
}

// Check Calculated Blocked for Zerocoin
bool CWalletDB::ReadCalculatedZCBlock(int &height) {
    height = 0;
    return batch.Read(std::string("calculatedzcblock"), height);
}

bool CWalletDB::WriteCalculatedZCBlock(int height) {
    return batch.Write(std::string("calculatedzcblock"), height);
}

void CWalletDB::ListPubCoin(std::list <CZerocoinEntry> &listPubCoin) {
    Dbc *pcursor = batch.GetCursor();
    if (!pcursor)
        throw runtime_error("CWalletDB::ListPubCoin() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true) {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("zerocoin"), CBigNum(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = batch.ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0) {
            pcursor->close();
            throw runtime_error("CWalletDB::ListPubCoin() : error scanning DB");
        }
        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "zerocoin")
            break;
        CBigNum value;
        ssKey >> value;
        CZerocoinEntry zerocoinItem;
        ssValue >> zerocoinItem;
        listPubCoin.push_back(zerocoinItem);
    }
    pcursor->close();
}

void CWalletDB::ListCoinSpendSerial(std::list <CZerocoinSpendEntry> &listCoinSpendSerial) {
    Dbc *pcursor = batch.GetCursor();
    if (!pcursor)
        throw runtime_error("CWalletDB::ListCoinSpendSerial() : cannot create DB cursor");
    unsigned int fFlags = DB_SET_RANGE;
    while (true) {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("zcserial"), CBigNum(0));
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = batch.ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0) {
            pcursor->close();
            throw runtime_error("CWalletDB::ListCoinSpendSerial() : error scanning DB");
        }

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType != "zcserial")
            break;
        CBigNum value;
        ssKey >> value;
        CZerocoinSpendEntry zerocoinSpendItem;
        ssValue >> zerocoinSpendItem;
        listCoinSpendSerial.push_back(zerocoinSpendItem);
    }

    pcursor->close();
}

// This should be called carefully:
// either supply "wallet" (if already loaded) or "strWalletFile" (if wallet wasn't loaded yet)
bool AutoBackupWallet (CWallet* wallet, std::string strWalletFile, std::string& strBackupWarning, std::string& strBackupError)
{
    CHDWallet *phdwallet = GetHDWallet(wallet);
    namespace fs = boost::filesystem;

    strBackupWarning = strBackupError = "";

    if(nWalletBackups > 0)
    {
        fs::path backupsDir = GetBackupsDir();

        if (!fs::exists(backupsDir))
        {
            // Always create backup folder to not confuse the operating system's file browser
            LogPrintf("Creating backup folder %s\n", backupsDir.string());
            if(!fs::create_directories(backupsDir)) {
                // smth is wrong, we shouldn't continue until it's resolved
                strBackupError = strprintf(_("Wasn't able to create wallet backup folder %s!"), backupsDir.string());
                LogPrintf("%s\n", strBackupError);
                nWalletBackups = -1;
                return false;
            }
        }

        // Create backup of the ...
        std::string dateTimeStr = DateTimeStrFormat(".%Y-%m-%d-%H-%M", GetTime());
        if (phdwallet)
        {
            // ... opened wallet
            LOCK2(cs_main, phdwallet->cs_wallet);
            //TODO: create a walletbackup
            //strWalletFile = wallet->strWalletFile;
            fs::path backupFile = backupsDir / (strWalletFile + dateTimeStr);

            // Update nKeysLeftSinceAutoBackup using current pool size
            phdwallet->nKeysLeftSinceAutoBackup = phdwallet->GetKeyPoolSize();
            LogPrintf("nKeysLeftSinceAutoBackup: %d\n", phdwallet->nKeysLeftSinceAutoBackup);
            if(phdwallet->IsLocked(true)) {
                strBackupWarning = _("Wallet is locked, can't replenish keypool! Automatic backups and mixing are disabled, please unlock your wallet to replenish keypool.");
                LogPrintf("%s\n", strBackupWarning);
                nWalletBackups = -2;
                return false;
            }
        } else {
            // ... strWalletFile file
            fs::path sourceFile = GetDataDir() / strWalletFile;
            fs::path backupFile = backupsDir / (strWalletFile + dateTimeStr);
            sourceFile.make_preferred();
            backupFile.make_preferred();
            if (fs::exists(backupFile))
            {
                strBackupWarning = _("Failed to create backup, file already exists! This could happen if you restarted wallet in less than 60 seconds. You can continue if you are ok with this.");
                LogPrintf("%s\n", strBackupWarning);
                return false;
            }
            if(fs::exists(sourceFile)) {
                try {
                    fs::copy_file(sourceFile, backupFile);
                    LogPrintf("Creating backup of %s -> %s\n", sourceFile.string(), backupFile.string());
                } catch(fs::filesystem_error &error) {
                    strBackupWarning = strprintf(_("Failed to create backup, error: %s"), error.what());
                    LogPrintf("%s\n", strBackupWarning);
                    nWalletBackups = -1;
                    return false;
                }
            }
        }

        // Keep only the last 10 backups, including the new one of course
        typedef std::multimap<std::time_t, fs::path> folder_set_t;
        folder_set_t folder_set;
        fs::directory_iterator end_iter;
        backupsDir.make_preferred();
        // Build map of backup files for current(!) wallet sorted by last write time
        fs::path currentFile;
        for (fs::directory_iterator dir_iter(backupsDir); dir_iter != end_iter; ++dir_iter)
        {
            // Only check regular files
            if ( fs::is_regular_file(dir_iter->status()))
            {
                currentFile = dir_iter->path().filename();
                // Only add the backups for the current wallet, e.g. wallet.dat.*
                if(dir_iter->path().stem().string() == strWalletFile)
                {
                    folder_set.insert(folder_set_t::value_type(fs::last_write_time(dir_iter->path()), *dir_iter));
                }
            }
        }

        // Loop backward through backup files and keep the N newest ones (1 <= N <= 10)
        int counter = 0;
        BOOST_REVERSE_FOREACH(PAIRTYPE(const std::time_t, fs::path) file, folder_set)
        {
            counter++;
            if (counter > nWalletBackups)
            {
                // More than nWalletBackups backups: delete oldest one(s)
                try {
                    fs::remove(file.second);
                    LogPrintf("Old backup deleted: %s\n", file.second);
                } catch(fs::filesystem_error &error) {
                    strBackupWarning = strprintf(_("Failed to delete backup, error: %s"), error.what());
                    LogPrintf("%s\n", strBackupWarning);
                    return false;
                }
            }
        }
        return true;
    }

    LogPrintf("Automatic wallet backups are disabled!\n");
    return false;
}
