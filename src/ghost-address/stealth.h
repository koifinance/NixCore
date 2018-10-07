// Copyright (c) 2014 The ShadowCoin developers
// Copyright (c) 2017 The Particl developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#ifndef KEY_STEALTH_H
#define KEY_STEALTH_H

#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <inttypes.h>

#include <util.h>
#include <serialize.h>
#include <key.h>
#include <uint256.h>
#include <ghost-address/types.h>

#include "lz4.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>


class CScript;

const uint32_t MAX_STEALTH_NARRATION_SIZE = 48;
const uint32_t MIN_STEALTH_RAW_SIZE = 1 + 33 + 1 + 33 + 1 + 1; // without checksum (4bytes) or version (1byte)


typedef uint32_t stealth_bitfield;

struct stealth_prefix
{
    uint8_t number_bits;
    stealth_bitfield bitfield;
};

class CStealthAddress
{
public:
    CStealthAddress()
    {
        options = 0;
        number_signatures = 0;
        prefix.number_bits = 0;

        //index = 0;
    };

    uint8_t options;
    stealth_prefix prefix;
    int number_signatures;
    ec_point scan_pubkey;
    ec_point spend_pubkey;

    mutable std::string label;

    CKey scan_secret;       // Better to store the scan secret here as it's needed often
    CKeyID spend_secret_id; // store the spend secret in a keystore
    //CKey spend_secret;
    //uint32_t index;

    bool SetEncoded(const std::string &encodedAddress);
    std::string Encoded(bool fBech32=false) const;
    std::string ToString(bool fBech32=false) const {return Encoded(fBech32);}

    int FromRaw(const uint8_t *p, size_t nSize);
    int ToRaw(std::vector<uint8_t> &raw) const;

    int SetScanPubKey(CPubKey pk);

    CKeyID GetSpendKeyID() const;

    bool operator <(const CStealthAddress &y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], EC_COMPRESSED_SIZE) < 0;
    };

    bool operator ==(const CStealthAddress &y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], EC_COMPRESSED_SIZE) == 0;
    };

    template<typename Stream>
    void Serialize(Stream &s) const
    {
        s << options;

        s << number_signatures;
        s << prefix.number_bits;
        s << prefix.bitfield;

        s << scan_pubkey;
        s << spend_pubkey;
        s << label;

        bool fHaveScanSecret = scan_secret.IsValid();
        s << fHaveScanSecret;
        if (fHaveScanSecret)
            s.write((char*)scan_secret.begin(), EC_SECRET_SIZE);
    }
    template <typename Stream>
    void Unserialize(Stream &s)
    {
        s >> options;

        s >> number_signatures;
        s >> prefix.number_bits;
        s >> prefix.bitfield;

        s >> scan_pubkey;
        s >> spend_pubkey;
        s >> label;

        bool fHaveScanSecret;
        s >> fHaveScanSecret;

        if (fHaveScanSecret)
        {
            s.read((char*)scan_secret.begin(), EC_SECRET_SIZE);
            scan_secret.SetFlags(true, true);

            // Only derive spend_secret_id if also have the scan secret.
            if (spend_pubkey.size() == EC_COMPRESSED_SIZE) // TODO: won't work for multiple spend pubkeys
                spend_secret_id = GetSpendKeyID();
        };
    }
};

int SecretToPublicKey(const CKey &secret, ec_point &out);

int StealthShared(const CKey &secret, const ec_point &pubkey, CKey &sharedSOut);
int StealthSecret(const CKey &secret, const ec_point &pubkey, const ec_point &pkSpend, CKey &sharedSOut, ec_point &pkOut);
int StealthSecretSpend(const CKey &scanSecret, const ec_point &ephemPubkey, const CKey &spendSecret, CKey &secretOut);
int StealthSharedToSecretSpend(const CKey &sharedS, const CKey &spendSecret, CKey &secretOut);

int StealthSharedToPublicKey(const ec_point &pkSpend, const CKey &sharedS, ec_point &pkOut);

bool IsStealthAddress(const std::string &encodedAddress);

inline uint32_t SetStealthMask(uint8_t nBits)
{
    return (nBits == 32 ? 0xFFFFFFFF : ((1<<nBits)-1));
};

uint32_t FillStealthPrefix(uint8_t nBits, uint32_t nBitfield);

bool ExtractStealthPrefix(const char *pPrefix, uint32_t &nPrefix);

int MakeStealthData(const std::string &sNarration, stealth_prefix prefix, const CKey &sShared, const CPubKey &pkEphem,
    std::vector<uint8_t> &vData, uint32_t &nStealthPrefix, std::string &sError);

int PrepareStealthOutput(const CStealthAddress &sx, const std::string &sNarration,
    CScript &scriptPubKey, std::vector<uint8_t> &vData, std::string &sError);

void ECC_Start_Stealth();
void ECC_Stop_Stealth();


/*
 *
 *
 *
 *
 *
 */

typedef std::vector<uint8_t> data_chunk;

const size_t ec_secret_size = 32;
const size_t ec_compressed_size = 33;
const size_t ec_uncompressed_size = 65;

typedef struct ec_secret { uint8_t e[ec_secret_size]; } ec_secret;
typedef data_chunk ec_point;

typedef uint32_t stealth_bitfield;

template <typename T, typename Iterator>
T from_big_endian(Iterator in)
{
    //VERIFY_UNSIGNED(T);
    T out = 0;
    size_t i = sizeof(T);
    while (0 < i)
        out |= static_cast<T>(*in++) << (8 * --i);
    return out;
}

template <typename T, typename Iterator>
T from_little_endian(Iterator in)
{
    //VERIFY_UNSIGNED(T);
    T out = 0;
    size_t i = 0;
    while (i < sizeof(T))
        out |= static_cast<T>(*in++) << (8 * i++);
    return out;
}

class CGhostAddress
{
public:
    CGhostAddress()
    {
        options = 0;
    }

    uint8_t options;
    ec_point scan_pubkey;
    ec_point spend_pubkey;
    size_t number_signatures;
    stealth_prefix prefix;

    mutable std::string label;
    data_chunk scan_secret;
    data_chunk spend_secret;

    bool SetEncoded(const std::string& encodedAddress);
    std::string Encoded() const;

    bool operator <(const CGhostAddress& y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], ec_compressed_size) < 0;
    }

    bool operator ==(const CGhostAddress &y) const
    {
        return memcmp(&scan_pubkey[0], &y.scan_pubkey[0], ec_compressed_size) == 0;
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->options);
        READWRITE(this->scan_pubkey);
        READWRITE(this->spend_pubkey);
        READWRITE(this->label);

        READWRITE(this->scan_secret);
        READWRITE(this->spend_secret);
    }

};

int GenerateRandomSecret(ec_secret& out);

int SecretToPublicKey(const ec_secret& secret, ec_point& out);

int StealthSecret(ec_secret& secret, ec_point& pubkey, const ec_point& pkSpend, ec_secret& sharedSOut, ec_point& pkOut);
int StealthSecretSpend(ec_secret& scanSecret, ec_point& ephemPubkey, ec_secret& spendSecret, ec_secret& secretOut);
int StealthSharedToSecretSpend(ec_secret& sharedS, ec_secret& spendSecret, ec_secret& secretOut);

bool IsGhostAddress(const std::string& encodedAddress);

#endif  // KEY_STEALTH_H
