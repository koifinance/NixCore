// Copyright (c) 2014 The ShadowCoin developers
// Copyright (c) 2017 The Particl developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

//#include <ghost-address/smsg/crypter.h>
#include <ghost-address/stealth.h>
//#include <ghost-address/smsg/smessage.h>
#include <base58.h>
#include <crypto/sha256.h>
#include <ghost-address/keyutil.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <script/script.h>

#include <support/allocators/secure.h>

#include <cmath>
#include <secp256k1.h>

secp256k1_context *secp256k1_ctx_stealth = nullptr;

bool CStealthAddress::SetEncoded(const std::string &encodedAddress)
{
    std::vector<uint8_t> raw;

    if (!DecodeBase58(encodedAddress, raw))
    {
        return false;
    };

    if (!VerifyChecksum(raw))
    {
        return false;
    };

    if (raw.size() < MIN_STEALTH_RAW_SIZE + 5)
    {
        return false;
    };

    uint8_t *p = &raw[0];
    uint8_t version = *p++;

    if (version != Params().Base58Prefix(CChainParams::STEALTH_ADDRESS)[0])
    {
        LogPrintf("%s: version mismatch 0x%x != 0x%x.\n", __func__, version, Params().Base58Prefix(CChainParams::STEALTH_ADDRESS)[0]);
        return false;
    };

    return 0 == FromRaw(p, raw.size()-1);
};

int CStealthAddress::FromRaw(const uint8_t *p, size_t nSize)
{
    if (nSize < MIN_STEALTH_RAW_SIZE)
        return 1;
    options = *p++;

    scan_pubkey.resize(EC_COMPRESSED_SIZE);
    memcpy(&scan_pubkey[0], p, EC_COMPRESSED_SIZE);
    p += EC_COMPRESSED_SIZE;
    uint8_t spend_pubkeys = *p++;

    if (nSize < MIN_STEALTH_RAW_SIZE + EC_COMPRESSED_SIZE * (spend_pubkeys-1))
        return 1;

    spend_pubkey.resize(EC_COMPRESSED_SIZE * spend_pubkeys);
    memcpy(&spend_pubkey[0], p, EC_COMPRESSED_SIZE * spend_pubkeys);
    p += EC_COMPRESSED_SIZE * spend_pubkeys;
    number_signatures = *p++;
    prefix.number_bits = *p++;
    prefix.bitfield = 0;
    size_t nPrefixBytes = std::ceil((float)prefix.number_bits / 8.0);

    if (nSize < MIN_STEALTH_RAW_SIZE + EC_COMPRESSED_SIZE * (spend_pubkeys-1) + nPrefixBytes)
        return 1;

    if (nPrefixBytes)
        memcpy(&prefix.bitfield, p, nPrefixBytes);

    return 0;
}

int CStealthAddress::ToRaw(std::vector<uint8_t> &raw) const
{
    // https://wiki.unsystem.net/index.php/DarkWallet/Stealth#Address_format
    // [version] [options] [scan_key] [N] ... [Nsigs] [prefix_length] ...

    size_t nPrefixBytes = std::ceil((float)prefix.number_bits / 8.0);
    size_t nPkSpend = spend_pubkey.size() / EC_COMPRESSED_SIZE;
    if (scan_pubkey.size() != EC_COMPRESSED_SIZE
        || spend_pubkey.size() < EC_COMPRESSED_SIZE
        || spend_pubkey.size() % EC_COMPRESSED_SIZE != 0
        || nPkSpend > 255
        || nPrefixBytes > 4)
    {
        LogPrintf("%s: sanity checks failed.\n", __func__);
        return 1;
    };

    raw.resize(MIN_STEALTH_RAW_SIZE + EC_COMPRESSED_SIZE * (nPkSpend-1) + nPrefixBytes);

    int o = 0;
    raw[o] = options; o++;
    memcpy(&raw[o], &scan_pubkey[0], EC_COMPRESSED_SIZE); o += EC_COMPRESSED_SIZE;
    raw[o] = nPkSpend; o++;
    memcpy(&raw[o], &spend_pubkey[0], EC_COMPRESSED_SIZE * nPkSpend); o += EC_COMPRESSED_SIZE * nPkSpend;
    raw[o] = number_signatures; o++;
    raw[o] = prefix.number_bits; o++;
    if (nPrefixBytes)
    {
        memcpy(&raw[o], &prefix.bitfield, nPrefixBytes); o += nPrefixBytes;
    };

    return 0;
};

std::string CStealthAddress::Encoded(bool fBech32) const
{
    return CBitcoinAddress(*this, fBech32).ToString();

};

int CStealthAddress::SetScanPubKey(CPubKey pk)
{
    scan_pubkey.resize(pk.size());
    memcpy(&scan_pubkey[0], pk.begin(), pk.size());
    return 0;
};

CKeyID CStealthAddress::GetSpendKeyID() const
{
    return CKeyID(Hash160(spend_pubkey.begin(), spend_pubkey.end()));
};

int SecretToPublicKey(const CKey &secret, ec_point &out)
{
    // Public key = private * G

    CPubKey pkTemp = secret.GetPubKey();
    out.resize(EC_COMPRESSED_SIZE);
    memcpy(&out[0], pkTemp.begin(), EC_COMPRESSED_SIZE);

    return 0;
};

int StealthShared(const CKey &secret, const ec_point &pubkey, CKey &sharedSOut)
{
    if (pubkey.size() != EC_COMPRESSED_SIZE)
        return errorN(1, "%s: sanity checks failed.", __func__);

    secp256k1_pubkey Q;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_stealth, &Q, &pubkey[0], EC_COMPRESSED_SIZE))
        return errorN(1, "%s: secp256k1_ec_pubkey_parse Q failed.", __func__);
    if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx_stealth, &Q, secret.begin())) // eQ
        return errorN(1, "%s: secp256k1_ec_pubkey_tweak_mul failed.", __func__);

    size_t len = 33;
    uint8_t tmp33[33];
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_stealth, tmp33, &len, &Q, SECP256K1_EC_COMPRESSED); // Returns: 1 always.

    CSHA256().Write(tmp33, 33).Finalize(sharedSOut.begin_nc());
    return 0;
};

int StealthSecret(const CKey &secret, const ec_point &pubkey, const ec_point &pkSpend, CKey &sharedSOut, ec_point &pkOut)
{
    /*
    send:
        secret = ephem_secret, pubkey = scan_pubkey

    receive:
        secret = scan_secret, pubkey = ephem_pubkey
        c = H(dP)

    Q = public scan key (EC point, 33 bytes)
    d = private scan key (integer, 32 bytes)
    R = public spend key
    f = private spend key

    Q = dG
    R = fG

    Sender (has Q and R, not d or f):

    P = eG

    c = H(eQ) = H(dP)
    R' = R + cG


    Recipient gets R' and P

    test 0 and infinity?
    */

    if (pubkey.size() != EC_COMPRESSED_SIZE
        || pkSpend.size() != EC_COMPRESSED_SIZE)
        return errorN(1, "%s: sanity checks failed.", __func__);

    secp256k1_pubkey Q, R;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_stealth, &Q, &pubkey[0], EC_COMPRESSED_SIZE))
        return errorN(1, "%s: secp256k1_ec_pubkey_parse Q failed.", __func__);

    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_stealth, &R, &pkSpend[0], EC_COMPRESSED_SIZE))
        return errorN(1, "%s: secp256k1_ec_pubkey_parse R failed.", __func__);

    // eQ
    if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx_stealth, &Q, secret.begin()))
        return errorN(1, "%s: secp256k1_ec_pubkey_tweak_mul failed.", __func__);

    size_t len = 33;
    uint8_t tmp33[33];
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_stealth, tmp33, &len, &Q, SECP256K1_EC_COMPRESSED); // Returns: 1 always.

    CSHA256().Write(tmp33, 33).Finalize(sharedSOut.begin_nc());

    //if (!secp256k1_ec_seckey_verify(secp256k1_ctx_stealth, sharedSOut.begin()))
    //    return errorN(1, "%s: secp256k1_ec_seckey_verify failed.", __func__); // Start again with a new ephemeral key

    // secp256k1_ec_pubkey_tweak_add verifies secret is in correct range

    // C = sharedSOut * G
    // R' = R + C
    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_stealth, &R, sharedSOut.begin()))
        return errorN(1, "%s: secp256k1_ec_pubkey_tweak_add failed.", __func__); // Start again with a new ephemeral key

    try {
        pkOut.resize(EC_COMPRESSED_SIZE);
    } catch (std::exception &e) {
        return errorN(8, "%s: pkOut.resize %u threw: %s.", __func__, EC_COMPRESSED_SIZE);
    };

    len = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_stealth, &pkOut[0], &len, &R, SECP256K1_EC_COMPRESSED); // Returns: 1 always.

    return 0;
};


int StealthSecretSpend(const CKey &scanSecret, const ec_point &ephemPubkey, const CKey &spendSecret, CKey &secretOut)
{
    /*
    c  = H(dP)
    R' = R + cG     [without decrypting wallet]
       = (f + c)G   [after decryption of wallet]
    */

    if (ephemPubkey.size() != EC_COMPRESSED_SIZE)
        return errorN(1, "%s: sanity checks failed.", __func__);

    secp256k1_pubkey P;
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_stealth, &P, &ephemPubkey[0], EC_COMPRESSED_SIZE))
        return errorN(1, "%s: secp256k1_ec_pubkey_parse P failed.", __func__);

    // dP
    if (!secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx_stealth, &P, scanSecret.begin()))
        return errorN(1, "%s: secp256k1_ec_pubkey_tweak_mul failed.", __func__);

    size_t len = 33;
    uint8_t tmp33[33];
    uint8_t tmp32[32];
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_stealth, tmp33, &len, &P, SECP256K1_EC_COMPRESSED); // Returns: 1 always.

    CSHA256().Write(tmp33, 33).Finalize(tmp32);

    if (!secp256k1_ec_seckey_verify(secp256k1_ctx_stealth, tmp32))
        return errorN(1, "%s: secp256k1_ec_seckey_verify failed.", __func__);

    secretOut = spendSecret;
    if (!secp256k1_ec_privkey_tweak_add(secp256k1_ctx_stealth, secretOut.begin_nc(), tmp32))
        return errorN(1, "%s: secp256k1_ec_privkey_tweak_add failed.", __func__);

    return 0;
};


int StealthSharedToSecretSpend(const CKey &sharedS, const CKey &spendSecret, CKey &secretOut)
{
    secretOut = spendSecret;
    if (!secp256k1_ec_privkey_tweak_add(secp256k1_ctx_stealth, secretOut.begin_nc(), sharedS.begin()))
        return errorN(1, "%s: secp256k1_ec_privkey_tweak_add failed.", __func__);

    if (!secp256k1_ec_seckey_verify(secp256k1_ctx_stealth, secretOut.begin())) // necessary?
        return errorN(1, "%s: secp256k1_ec_seckey_verify failed.", __func__);

    return 0;
};

int StealthSharedToPublicKey(const ec_point &pkSpend, const CKey &sharedS, ec_point &pkOut)
{
    if (pkSpend.size() != EC_COMPRESSED_SIZE)
        return errorN(1, "%s: sanity checks failed.", __func__);

    secp256k1_pubkey R;

    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx_stealth, &R, &pkSpend[0], EC_COMPRESSED_SIZE))
        return errorN(1, "%s: secp256k1_ec_pubkey_parse R failed.", __func__);

    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx_stealth, &R, sharedS.begin()))
        return errorN(1, "%s: secp256k1_ec_pubkey_tweak_add failed.", __func__);

    try {
        pkOut.resize(EC_COMPRESSED_SIZE);
    } catch (std::exception &e) {
        return errorN(8, "%s: pkOut.resize %u threw: %s.", __func__, EC_COMPRESSED_SIZE);
    };

    size_t len = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx_stealth, &pkOut[0], &len, &R, SECP256K1_EC_COMPRESSED); // Returns: 1 always.

    return 0;
};

bool IsStealthAddress(const std::string &encodedAddress)
{
    std::vector<uint8_t> raw;

    if (!DecodeBase58(encodedAddress, raw))
    {
        //LogPrintf("IsStealthAddress DecodeBase58 falied.\n");
        return false;
    };

    if (!VerifyChecksum(raw))
    {
        //LogPrintf("IsStealthAddress verify_checksum falied.\n");
        return false;
    };

    if (raw.size() < MIN_STEALTH_RAW_SIZE + 5)
    {
        //LogPrintf("IsStealthAddress too few bytes provided.\n");
        return false;
    };

    uint8_t* p = &raw[0];
    uint8_t version = *p++;

    if (version != Params().Base58Prefix(CChainParams::STEALTH_ADDRESS)[0])
    {
        //LogPrintf("IsStealthAddress version mismatch 0x%x != 0x%x.\n", version, stealth_version_byte);
        return false;
    };

    return true;
};

uint32_t FillStealthPrefix(uint8_t nBits, uint32_t nBitfield)
{
    uint32_t prefix, mask = SetStealthMask(nBits);
    GetStrongRandBytes((uint8_t*) &prefix, 4);

    prefix &= (~mask);
    prefix |= nBitfield & mask;
    return prefix;
};

bool ExtractStealthPrefix(const char *pPrefix, uint32_t &nPrefix)
{
    int base = 10;
    size_t len = strlen(pPrefix);
    if (len > 2
        && pPrefix[0] == '0')
    {
        if (pPrefix[1] == 'b')
        {
            pPrefix += 2;
            base = 2;
        } else
        if (pPrefix[1] == 'x' || pPrefix[1] == 'X')
        {
            pPrefix += 2;
            base = 16;
        };
    };

    char *pend;
    errno = 0;
    nPrefix = strtol(pPrefix, &pend, base);

    if (errno != 0 || !pend || *pend != '\0')
        return error("%s strtol failed.", __func__);
    return true;
};


int MakeStealthData(const std::string &sNarration, stealth_prefix prefix, const CKey &sShared, const CPubKey &pkEphem,
    std::vector<uint8_t> &vData, uint32_t &nStealthPrefix, std::string &sError)
{

    std::vector<uint8_t> vchNarr;
    if (sNarration.length() > 0)
    {
        if (vchNarr.size() > MAX_STEALTH_NARRATION_SIZE)
            return errorN(1, sError, __func__, "Encrypted narration is too long.");
    };

    vData.resize(34
        + (prefix.number_bits > 0 ? 5 : 0)
        + (vchNarr.size() + (vchNarr.size() > 0 ? 1 : 0)));

    size_t o = 0;
    vData[o++] = DO_STEALTH;
    memcpy(&vData[o], pkEphem.begin(), 33);
    o += 33;

    if (prefix.number_bits > 0)
    {
        vData[o++] = DO_STEALTH_PREFIX;
        nStealthPrefix = FillStealthPrefix(prefix.number_bits, prefix.bitfield);
        memcpy(&vData[o], &nStealthPrefix, 4);
        o+=4;
    };

    return 0;
};

int PrepareStealthOutput(const CStealthAddress &sx, const std::string &sNarration,
    CScript &scriptPubKey, std::vector<uint8_t> &vData, std::string &sError)
{
    CKey sShared, sEphem;
    ec_point pkSendTo;
    int k, nTries = 24;
    for (k = 0; k < nTries; ++k) // if StealthSecret fails try again with new ephem key
    {
        sEphem.MakeNewKey(true);
        if (StealthSecret(sEphem, sx.scan_pubkey, sx.spend_pubkey, sShared, pkSendTo) == 0)
            break;
    };
    if (k >= nTries)
        return errorN(1, sError, __func__, "Could not generate receiving public key.");
    CPubKey pkEphem = sEphem.GetPubKey();
    scriptPubKey = GetScriptForDestination(CPubKey(pkSendTo).GetID());

    uint32_t nStealthPrefix;
    if (0 != MakeStealthData(sNarration, sx.prefix, sShared, pkEphem, vData, nStealthPrefix, sError))
        return 1;
    return 0;
};

void ECC_Start_Stealth()
{
    assert(secp256k1_ctx_stealth == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    assert(ctx != nullptr);

    secp256k1_ctx_stealth = ctx;
};

void ECC_Stop_Stealth()
{
    secp256k1_context *ctx = secp256k1_ctx_stealth;
    secp256k1_ctx_stealth = nullptr;

    if (ctx)
    {
        secp256k1_context_destroy(ctx);
    };
};

/*
 *
 *
 *
 *
 *
 *
 *
 *
 */

#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

const uint8_t stealth_version_byte = 0x1F;
const uint8_t stealth_version_byte_segwit = 0x20;



bool CGhostAddress::SetEncoded(const std::string& encodedAddress)
{
    data_chunk raw;

    if (!DecodeBase58(encodedAddress, raw))
    {
        return false;
    };

    if (!VerifyChecksum(raw))
    {
        return false;
    };

    if (raw.size() < 1 + 1 + 33 + 1 + 33 + 1 + 1 + 4)
    {
        return false;
    };


    uint8_t* p = &raw[0];
    uint8_t version = *p++;

    if (version != stealth_version_byte)
    {
        return false;
    };

    options = *p++;

    scan_pubkey.resize(33);
    memcpy(&scan_pubkey[0], p, 33);
    p += 33;
    //uint8_t spend_pubkeys = *p++;
    p++;

    spend_pubkey.resize(33);
    memcpy(&spend_pubkey[0], p, 33);

    return true;
};

std::string CGhostAddress::Encoded() const
{
    // https://wiki.unsystem.net/index.php/DarkWallet/Stealth#Address_format
    // [version] [options] [scan_key] [N] ... [Nsigs] [prefix_length] ...

    data_chunk raw;
    raw.push_back(stealth_version_byte);

    raw.push_back(options);

    raw.insert(raw.end(), scan_pubkey.begin(), scan_pubkey.end());
    raw.push_back(1); // number of spend pubkeys
    raw.insert(raw.end(), spend_pubkey.begin(), spend_pubkey.end());
    raw.push_back(0); // number of signatures
    raw.push_back(0); // ?

    AppendChecksum(raw);

    return EncodeBase58(raw);
};

#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <random.cpp>
int GenerateRandomSecret(ec_secret& out)
{
    RandAddSeedPerfmon();

    static uint256 max = uint256S("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
    static uint256 min = uint256S("0x0000000000000000000000000000000000000000000000000000000000003E80"); // increase? min valid key is 1

    uint256 test;

    int i;
    // -- check max, try max 32 times
    for (i = 0; i < 32; ++i)
    {
        RAND_bytes((unsigned char*) test.begin(), 32);

        LogPrintf("GENSEED: %d\n %d\n%d\n", test.ToString(), max.ToString(), min.ToString());
        if (UintToArith256(test) > UintToArith256(min) && UintToArith256(test) < UintToArith256(max))
        {
            memcpy(&out.e[0], test.begin(), 32);
            break;
        };
    };

    if (i > 31)
    {
        printf("Error: GenerateRandomSecret failed to generate a valid key.\n");
        return 1;
    };

    return 0;
};

int SecretToPublicKey(const ec_secret& secret, ec_point& out)
{
    // -- public key = private * G
    int rv = 0;

    EC_GROUP *ecgrp = EC_GROUP_new_by_curve_name(NID_secp256k1);

    if (!ecgrp)
    {
        printf("SecretToPublicKey(): EC_GROUP_new_by_curve_name failed.\n");
        return 1;
    };

    BIGNUM* bnIn = BN_bin2bn(&secret.e[0], ec_secret_size, BN_new());
    if (!bnIn)
    {
        EC_GROUP_free(ecgrp);
        printf("SecretToPublicKey(): BN_bin2bn failed\n");
        return 1;
    };

    EC_POINT* pub = EC_POINT_new(ecgrp);


    EC_POINT_mul(ecgrp, pub, bnIn, NULL, NULL, NULL);

    BIGNUM* bnOut = EC_POINT_point2bn(ecgrp, pub, POINT_CONVERSION_COMPRESSED, BN_new(), NULL);
    if (!bnOut)
    {
        printf("SecretToPublicKey(): point2bn failed\n");
        rv = 1;
    } else
    {
        out.resize(ec_compressed_size);
        if (BN_num_bytes(bnOut) != (int) ec_compressed_size
            || BN_bn2bin(bnOut, &out[0]) != (int) ec_compressed_size)
        {
            printf("SecretToPublicKey(): bnOut incorrect length.\n");
            rv = 1;
        };

        BN_free(bnOut);
    };

    EC_GROUP_free(ecgrp);
    BN_free(bnIn);
    EC_POINT_free(pub);

    return rv;
};


int StealthSecret(ec_secret& secret, ec_point& pubkey, const ec_point& pkSpend, ec_secret& sharedSOut, ec_point& pkOut)
{
    /*

    send:
        secret = ephem_secret, pubkey = scan_pubkey

    receive:
        secret = scan_secret, pubkey = ephem_pubkey
        c = H(dP)

    Q = public scan key (EC point, 33 bytes)
    d = private scan key (integer, 32 bytes)
    R = public spend key
    f = private spend key
    Q = dG
    R = fG

    Sender (has Q and R, not d or f):

    P = eG
    c = H(eQ) = H(dP)
    R' = R + cG


    Recipient gets R' and P

    test 0 and infinity?
    */

    int rv = 0;
    std::vector<uint8_t> vchOutQ;

    BN_CTX* bnCtx   = NULL;
    BIGNUM* bnEphem = NULL;
    BIGNUM* bnQ     = NULL;
    EC_POINT* Q     = NULL;
    BIGNUM* bnOutQ  = NULL;
    BIGNUM* bnc     = NULL;
    EC_POINT* C     = NULL;
    BIGNUM* bnR     = NULL;
    EC_POINT* R     = NULL;
    EC_POINT* Rout  = NULL;
    BIGNUM* bnOutR  = NULL;

    EC_GROUP* ecgrp = EC_GROUP_new_by_curve_name(NID_secp256k1);

    if (!ecgrp)
    {
        return 1;
    };

    if (!(bnCtx = BN_CTX_new()))
    {
        rv = 1;
        goto End;
    };

    if (!(bnEphem = BN_bin2bn(&secret.e[0], ec_secret_size, BN_new())))
    {
        rv = 1;
        goto End;
    };

    if (!(bnQ = BN_bin2bn(&pubkey[0], pubkey.size(), BN_new())))
    {
        rv = 1;
        goto End;
    };

    if (!(Q = EC_POINT_bn2point(ecgrp, bnQ, NULL, bnCtx)))
    {
        rv = 1;
        goto End;
    };

    // -- eQ
    // EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
    // EC_POINT_mul calculates the value generator * n + q * m and stores the result in r. The value n may be NULL in which case the result is just q * m.
    if (!EC_POINT_mul(ecgrp, Q, NULL, Q, bnEphem, bnCtx))
    {
        rv = 1;
        goto End;
    };

    if (!(bnOutQ = EC_POINT_point2bn(ecgrp, Q, POINT_CONVERSION_COMPRESSED, BN_new(), bnCtx)))
    {
        rv = 1;
        goto End;
    };


    vchOutQ.resize(ec_compressed_size);
    if (BN_num_bytes(bnOutQ) != (int) ec_compressed_size
        || BN_bn2bin(bnOutQ, &vchOutQ[0]) != (int) ec_compressed_size)
    {
        rv = 1;
        goto End;
    };

    CSHA256().Write(&vchOutQ[0], vchOutQ.size()).Finalize(&sharedSOut.e[0]);

    if (!(bnc = BN_bin2bn(&sharedSOut.e[0], ec_secret_size, BN_new())))
    {
        rv = 1;
        goto End;
    };

    // -- cG
    if (!(C = EC_POINT_new(ecgrp)))
    {
        rv = 1;
        goto End;
    };

    if (!EC_POINT_mul(ecgrp, C, bnc, NULL, NULL, bnCtx))
    {
        rv = 1;
        goto End;
    };

    if (!(bnR = BN_bin2bn(&pkSpend[0], pkSpend.size(), BN_new())))
    {
        rv = 1;
        goto End;
    };


    if (!(R = EC_POINT_bn2point(ecgrp, bnR, NULL, bnCtx)))
    {
        rv = 1;
        goto End;
    };

    if (!EC_POINT_mul(ecgrp, C, bnc, NULL, NULL, bnCtx))
    {
        rv = 1;
        goto End;
    };

    if (!(Rout = EC_POINT_new(ecgrp)))
    {
        rv = 1;
        goto End;
    };

    if (!EC_POINT_add(ecgrp, Rout, R, C, bnCtx))
    {
        rv = 1;
        goto End;
    };

    if (!(bnOutR = EC_POINT_point2bn(ecgrp, Rout, POINT_CONVERSION_COMPRESSED, BN_new(), bnCtx)))
    {
        rv = 1;
        goto End;
    };


    pkOut.resize(ec_compressed_size);
    if (BN_num_bytes(bnOutR) != (int) ec_compressed_size
        || BN_bn2bin(bnOutR, &pkOut[0]) != (int) ec_compressed_size)
    {
        rv = 1;
        goto End;
    };

    End:
    if (bnOutR)     BN_free(bnOutR);
    if (Rout)       EC_POINT_free(Rout);
    if (R)          EC_POINT_free(R);
    if (bnR)        BN_free(bnR);
    if (C)          EC_POINT_free(C);
    if (bnc)        BN_free(bnc);
    if (bnOutQ)     BN_free(bnOutQ);
    if (Q)          EC_POINT_free(Q);
    if (bnQ)        BN_free(bnQ);
    if (bnEphem)    BN_free(bnEphem);
    if (bnCtx)      BN_CTX_free(bnCtx);
    EC_GROUP_free(ecgrp);

    return rv;
};


int StealthSecretSpend(ec_secret& scanSecret, ec_point& ephemPubkey, ec_secret& spendSecret, ec_secret& secretOut)
{
    /*

    c  = H(dP)
    R' = R + cG     [without decrypting wallet]
       = (f + c)G   [after decryption of wallet]
         Remember: mod curve.order, pad with 0x00s where necessary?
    */

    int rv = 0;
    std::vector<uint8_t> vchOutP;

    BN_CTX* bnCtx           = NULL;
    BIGNUM* bnScanSecret    = NULL;
    BIGNUM* bnP             = NULL;
    EC_POINT* P             = NULL;
    BIGNUM* bnOutP          = NULL;
    BIGNUM* bnc             = NULL;
    BIGNUM* bnOrder         = NULL;
    BIGNUM* bnSpend         = NULL;

    EC_GROUP* ecgrp = EC_GROUP_new_by_curve_name(NID_secp256k1);

    if (!ecgrp)
    {
        printf("StealthSecretSpend(): EC_GROUP_new_by_curve_name failed.\n");
        return 1;
    };

    if (!(bnCtx = BN_CTX_new()))
    {
        printf("StealthSecretSpend(): BN_CTX_new failed.\n");
        rv = 1;
        goto End;
    };

    if (!(bnScanSecret = BN_bin2bn(&scanSecret.e[0], ec_secret_size, BN_new())))
    {
        printf("StealthSecretSpend(): bnScanSecret BN_bin2bn failed.\n");
        rv = 1;
        goto End;
    };

    if (!(bnP = BN_bin2bn(&ephemPubkey[0], ephemPubkey.size(), BN_new())))
    {
        printf("StealthSecretSpend(): bnP BN_bin2bn failed\n");
        rv = 1;
        goto End;
    };

    if (!(P = EC_POINT_bn2point(ecgrp, bnP, NULL, bnCtx)))
    {
        printf("StealthSecretSpend(): P EC_POINT_bn2point failed\n");
        rv = 1;
        goto End;
    };

    // -- dP
    if (!EC_POINT_mul(ecgrp, P, NULL, P, bnScanSecret, bnCtx))
    {
        printf("StealthSecretSpend(): dP EC_POINT_mul failed\n");
        rv = 1;
        goto End;
    };

    if (!(bnOutP = EC_POINT_point2bn(ecgrp, P, POINT_CONVERSION_COMPRESSED, BN_new(), bnCtx)))
    {
        printf("StealthSecretSpend(): P EC_POINT_bn2point failed\n");
        rv = 1;
        goto End;
    };


    vchOutP.resize(ec_compressed_size);
    if (BN_num_bytes(bnOutP) != (int) ec_compressed_size
        || BN_bn2bin(bnOutP, &vchOutP[0]) != (int) ec_compressed_size)
    {
        printf("StealthSecretSpend(): bnOutP incorrect length.\n");
        rv = 1;
        goto End;
    };

    uint8_t hash1[32];

    CSHA256().Write(&vchOutP[0], vchOutP.size()).Finalize((uint8_t*)hash1);


    if (!(bnc = BN_bin2bn(&hash1[0], 32, BN_new())))
    {
        printf("StealthSecretSpend(): BN_bin2bn failed\n");
        rv = 1;
        goto End;
    };

    if (!(bnOrder = BN_new())
        || !EC_GROUP_get_order(ecgrp, bnOrder, bnCtx))
    {
        printf("StealthSecretSpend(): EC_GROUP_get_order failed\n");
        rv = 1;
        goto End;
    };

    if (!(bnSpend = BN_bin2bn(&spendSecret.e[0], ec_secret_size, BN_new())))
    {
        printf("StealthSecretSpend(): bnSpend BN_bin2bn failed.\n");
        rv = 1;
        goto End;
    };

    //if (!BN_add(r, a, b)) return 0;
    //return BN_nnmod(r, r, m, ctx);
    if (!BN_mod_add(bnSpend, bnSpend, bnc, bnOrder, bnCtx))
    {
        printf("StealthSecretSpend(): bnSpend BN_mod_add failed.\n");
        rv = 1;
        goto End;
    };

    if (BN_is_zero(bnSpend)) // possible?
    {
        printf("StealthSecretSpend(): bnSpend is zero.\n");
        rv = 1;
        goto End;
    };

    if (BN_num_bytes(bnSpend) != (int) ec_secret_size
        || BN_bn2bin(bnSpend, &secretOut.e[0]) != (int) ec_secret_size)
    {
        printf("StealthSecretSpend(): bnSpend incorrect length.\n");
        rv = 1;
        goto End;
    };

    End:
    if (bnSpend)        BN_free(bnSpend);
    if (bnOrder)        BN_free(bnOrder);
    if (bnc)            BN_free(bnc);
    if (bnOutP)         BN_free(bnOutP);
    if (P)              EC_POINT_free(P);
    if (bnP)            BN_free(bnP);
    if (bnScanSecret)   BN_free(bnScanSecret);
    if (bnCtx)          BN_CTX_free(bnCtx);
    EC_GROUP_free(ecgrp);

    return rv;
};


int StealthSharedToSecretSpend(ec_secret& sharedS, ec_secret& spendSecret, ec_secret& secretOut)
{

    int rv = 0;
    std::vector<uint8_t> vchOutP;

    BN_CTX* bnCtx           = NULL;
    BIGNUM* bnc             = NULL;
    BIGNUM* bnOrder         = NULL;
    BIGNUM* bnSpend         = NULL;

    EC_GROUP* ecgrp = EC_GROUP_new_by_curve_name(NID_secp256k1);

    if (!ecgrp)
    {
        printf("StealthSecretSpend(): EC_GROUP_new_by_curve_name failed.\n");
        return 1;
    };

    if (!(bnCtx = BN_CTX_new()))
    {
        printf("StealthSecretSpend(): BN_CTX_new failed.\n");
        rv = 1;
        goto End;
    };

    if (!(bnc = BN_bin2bn(&sharedS.e[0], ec_secret_size, BN_new())))
    {
        printf("StealthSecretSpend(): BN_bin2bn failed\n");
        rv = 1;
        goto End;
    };

    if (!(bnOrder = BN_new())
        || !EC_GROUP_get_order(ecgrp, bnOrder, bnCtx))
    {
        printf("StealthSecretSpend(): EC_GROUP_get_order failed\n");
        rv = 1;
        goto End;
    };

    if (!(bnSpend = BN_bin2bn(&spendSecret.e[0], ec_secret_size, BN_new())))
    {
        printf("StealthSecretSpend(): bnSpend BN_bin2bn failed.\n");
        rv = 1;
        goto End;
    };

    //if (!BN_add(r, a, b)) return 0;
    //return BN_nnmod(r, r, m, ctx);
    if (!BN_mod_add(bnSpend, bnSpend, bnc, bnOrder, bnCtx))
    {
        printf("StealthSecretSpend(): bnSpend BN_mod_add failed.\n");
        rv = 1;
        goto End;
    };

    if (BN_is_zero(bnSpend)) // possible?
    {
        printf("StealthSecretSpend(): bnSpend is zero.\n");
        rv = 1;
        goto End;
    };

    if (BN_num_bytes(bnSpend) != (int) ec_secret_size
        || BN_bn2bin(bnSpend, &secretOut.e[0]) != (int) ec_secret_size)
    {
        printf("StealthSecretSpend(): bnSpend incorrect length.\n");
        rv = 1;
        goto End;
    };

    End:
    if (bnSpend)        BN_free(bnSpend);
    if (bnOrder)        BN_free(bnOrder);
    if (bnc)            BN_free(bnc);
    if (bnCtx)          BN_CTX_free(bnCtx);
    EC_GROUP_free(ecgrp);

    return rv;
};

bool IsGhostAddress(const std::string& encodedAddress)
{
    data_chunk raw;

    if (!DecodeBase58(encodedAddress, raw))
    {
        return false;
    };

    if (!VerifyChecksum(raw))
    {
        return false;
    };

    if (raw.size() < 1 + 1 + 33 + 1 + 33 + 1 + 1 + 4)
    {
        return false;
    };


    uint8_t* p = &raw[0];
    uint8_t version = *p++;

    if (version != stealth_version_byte)
    {
        return false;
    };

    return true;
}
