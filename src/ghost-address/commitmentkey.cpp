// Copyright (c) 2017-2018 The NIX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ghost-address/commitmentkey.h>
#include <script/script.h>
#include <base58.h>
#include <ghost-address/lz4.h>
#include <ghost-address/keyutil.h>


/** All alphanumeric characters except for "0", "I", "O", and "l" */
static const char* pszBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

bool DecodeBase62(const char* psz, std::vector<unsigned char>& vch)
{
    // Skip leading spaces.
    while (*psz && isspace(*psz))
        psz++;
    // Skip and count leading '1's.
    int zeroes = 0;
    int length = 0;
    while (*psz == '1') {
        zeroes++;
        psz++;
    }
    // Allocate enough space in big-endian base256 representation.
    int size = strlen(psz) * 744 /1000 + 1; // log(62) / log(256), rounded up.
    std::vector<unsigned char> b256(size);
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base62 character
        const char* ch = strchr(pszBase62, *psz);
        if (ch == nullptr)
            return false;
        // Apply "b256 = b256 * 62 + ch".
        int carry = ch - pszBase62;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 62 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        assert(carry == 0);
        length = i;
        psz++;
    }
    // Skip trailing spaces.
    while (isspace(*psz))
        psz++;
    if (*psz != 0)
        return false;
    // Skip leading zeroes in b256.
    std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
    while (it != b256.end() && *it == 0)
        it++;
    // Copy result into output vector.
    vch.reserve(zeroes + (b256.end() - it));
    vch.assign(zeroes, 0x00);
    while (it != b256.end())
        vch.push_back(*(it++));
    return true;
}

std::string EncodeBase62(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base62 representation.
    int size = (pend - pbegin) * 138 / 100 + 1; // log(256) / log(62), rounded up.
    std::vector<unsigned char> b62(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b62 = b62 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b62.rbegin(); (carry != 0 || i < length) && (it != b62.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 62;
            carry /= 62;
        }

        assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base62 result.
    std::vector<unsigned char>::iterator it = b62.begin() + (size - length);
    while (it != b62.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b62.end() - it));
    str.assign(zeroes, '1');
    while (it != b62.end())
        str += pszBase62[*(it++)];
    return str;
}

std::string EncodeBase62(const std::vector<unsigned char>& vch)
{
    return EncodeBase62(vch.data(), vch.data() + vch.size());
}

bool DecodeBase62(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase62(str.c_str(), vchRet);
}

CommitmentKey::CommitmentKey(std::vector<unsigned char>& _pubCoinData):
    pubCoinData(_pubCoinData)
{
    Init();
}

void CommitmentKey::Init()
{
    pubCoinDataBase58 = EncodeBase58(pubCoinData);
    pubCoinScript = CScript() << OP_ZEROCOINMINT << pubCoinData.size() << pubCoinData;
}

int CommitmentKey::Compress()
{
    int size = pubCoinData.size();
    vector<char> buff;
    buff.resize(size*4);
    compressedSize = LZ4_compress_default((char*)pubCoinData.data(), buff.data(), size, buff.size());
    pubCoinDataCompressed = std::string(buff.begin(),buff.begin() + compressedSize);
    return compressedSize;
}

int CommitmentKey::Decompress()
{
    int size = pubCoinData.size();
    vector<char> buff;
    buff.resize(size*4);
    return LZ4_decompress_safe(pubCoinDataCompressed.c_str(), buff.data(), compressedSize, buff.size());
}


CommitmentKeyPack::CommitmentKeyPack(std::vector<unsigned char>& _pubCoinPack, bool fIn)
{
    //input key, have checksum
    if(fIn){
        DecodeBase58((char *)_pubCoinPack.data(), pubCoinPackData);
        pubCoinPackDataBase58 = std::string(_pubCoinPack.begin(), _pubCoinPack.end());
    }
    //output key, append checksum
    else{
        AppendChecksum(_pubCoinPack);
        pubCoinPackDataBase58 = EncodeBase58(_pubCoinPack);
        pubCoinPackData = _pubCoinPack;
    }

    if(IsValidPack()){
        //has valid checksum, store
        memcpy(&checksum, &(*(pubCoinPackData.end() - 4)), 4);

        //split key into convertable format
        //take out checksum
        std::string keyBunch(pubCoinPackData.begin(), pubCoinPackData.end() - 4);
        for(int i = 0; i < keyBunch.size(); i++){
            //find identifier of keysplit
            if(keyBunch[i] == '-'){
                std::vector<unsigned char> commitmentKey(keyBunch.begin(), keyBunch.begin()+i);
                pubCoinPack.push_back(CommitmentKey(commitmentKey));
                keyBunch.erase(keyBunch.begin(), keyBunch.begin()+i+1);
                i = 0;
            }
        }
    }
}

int CommitmentKeyPack::Compress()
{
    int size = pubCoinPack.size();
    vector<char> buff;
    buff.resize(size*4);
    compressedSize = LZ4_compress_default((char*)pubCoinPack.data(), buff.data(), size, buff.size());
    pubCoinPackCompressed = std::string(buff.begin(),buff.begin() + compressedSize);
    return compressedSize;
}

int CommitmentKeyPack::Decompress()
{
    int size = pubCoinPack.size();
    vector<char> buff;
    buff.resize(size*4);
    return LZ4_decompress_safe(pubCoinPackCompressed.c_str(), buff.data(), compressedSize, buff.size());
}

bool CommitmentKeyPack::IsValidPack()
{
    return VerifyChecksum(pubCoinPackData);
}
