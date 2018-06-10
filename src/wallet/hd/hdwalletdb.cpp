// Copyright (c) 2017 The Particl Core developers
// Copyright (c) 2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/hd/hdwalletdb.h>
#include <wallet/hd/hdwallet.h>

#include <serialize.h>
#include <boost/tuple/tuple.hpp>


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

