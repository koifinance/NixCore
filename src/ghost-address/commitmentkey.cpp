// Copyright (c) 2017-2018 The NIX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <ghost-address/commitmentkey.h>
#include <script/script.h>
#include <base58.h>
#include <ghost-address/lz4.h>
#include <ghost-address/keyutil.h>
#include <crypto/sha256.h>


uint32_t CommitmentChecksum(uint8_t *p, uint32_t nBytes)
{
    if (!p || nBytes == 0)
        return 0;

    uint8_t hash1[32];
    CSHA256().Write(p, nBytes).Finalize((uint8_t*)hash1);
    uint8_t hash2[32];
    CSHA256().Write((uint8_t*)hash1, sizeof(hash1)).Finalize((uint8_t*)hash2);

    // Checksum is the 1st 4 bytes of the hash
    uint32_t checksum;
    memcpy(&checksum, &hash2[0], 4);

    return checksum;
}

void AppendCommitmentChecksum(std::vector<uint8_t> &data)
{
    uint32_t checksum = CommitmentChecksum(&data[0], data.size());

    std::vector<uint8_t> tmp(4);
    memcpy(&tmp[0], &checksum, 4);

    data.insert(data.end(), tmp.begin(), tmp.end());
}

bool VerifyCommitmentChecksum(const std::vector<uint8_t> &data, const uint32_t checksum)
{
    if (data.size() < 4)
        return false;

    return CommitmentChecksum((uint8_t*)&data[0], data.size()) == checksum;
}


/** All alphanumeric characters*/
static const char* pszBase61 = "023456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

bool DecodeBase61(const char* psz, std::vector<unsigned char>& vch)
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
    int size = strlen(psz) * 750 /1000 + 1; // log(61) / log(256), rounded up.
    std::vector<unsigned char> b256(size);
    // Process the characters.
    while (*psz && !isspace(*psz)) {
        // Decode base61 character
        const char* ch = strchr(pszBase61, *psz);
        if (ch == nullptr)
            return false;
        // Apply "b256 = b256 * 61 + ch".
        int carry = ch - pszBase61;
        int i = 0;
        for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
            carry += 61 * (*it);
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

std::string EncodeBase61(const unsigned char* pbegin, const unsigned char* pend)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base61 representation.
    int size = (pend - pbegin) * 140 / 100 + 1; // log(256) / log(61), rounded up.
    std::vector<unsigned char> b61(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b61 = b61 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b61.rbegin(); (carry != 0 || i < length) && (it != b61.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = carry % 61;
            carry /= 61;
        }

        assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base61 result.
    std::vector<unsigned char>::iterator it = b61.begin() + (size - length);
    while (it != b61.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b61.end() - it));
    str.assign(zeroes, '1');
    while (it != b61.end())
        str += pszBase61[*(it++)];
    return str;
}

std::string EncodeBase61(const std::vector<unsigned char>& vch)
{
    return EncodeBase61(vch.data(), vch.data() + vch.size());
}

bool DecodeBase61(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase61(str.c_str(), vchRet);
}

CommitmentKey::CommitmentKey(std::vector<unsigned char>& _pubCoinData):
    pubCoinData(_pubCoinData)
{
    Init();
}

void CommitmentKey::Init()
{
    pubCoinDataBase58 = EncodeBase61(pubCoinData);
    pubCoinScript = CScript() << OP_ZEROCOINMINT << pubCoinData.size() << pubCoinData;
}

/*
int CommitmentKey::Compress()
{
    int size = pubCoinData.size();
    std::vector<char> buff;
    buff.resize(size*4);
    compressedSize = LZ4_compress_default((char*)pubCoinData.data(), buff.data(), size, buff.size());
    pubCoinDataCompressed = std::string(buff.begin(),buff.begin() + compressedSize);
    return compressedSize;
}

int CommitmentKey::Decompress()
{
    int size = pubCoinData.size();
    std::vector<char> buff;
    buff.resize(size*4);
    return LZ4_decompress_safe(pubCoinDataCompressed.c_str(), buff.data(), compressedSize, buff.size());
}
*/

CommitmentKeyPack::CommitmentKeyPack(){
    SetNull();
}

/*
 * Commitment Key Pack raw format
 * C0 + ... Ci + 0xFFFFFF + CSize0(1byte) + ... CSizei + checksum(4bytes)
 */

CommitmentKeyPack::CommitmentKeyPack(std::string& _pubCoinPack)
{

    if(!DecodeBase61(_pubCoinPack, pubCoinPackData)){
        SetNull();
        return;
    }
    //check checksum
    if(!IsValidPack()){
        SetNull();
        return;
    }

    pubCoinPackDataBase58 = _pubCoinPack;

    int amountOfKeys = 0;
    std::vector<int> sizeOfKeys;

    //Get total keys included and their sizes
    for(int i = pubCoinPackData.size() - 4; i > 4; i--){
        //check for delimiter
        if(pubCoinPackData[i] == 0xFF && pubCoinPackData[i - 1] == 0xFF && pubCoinPackData[i - 2] == 0xFF){

            for(int k = i+1; k < pubCoinPackData.size() - 4; k++){
                amountOfKeys++;
                sizeOfKeys.push_back((int)pubCoinPackData[k]);
            }

            break;
        }
    }

    std::vector<unsigned char> pubCoinPackDataTemp = pubCoinPackData;

    for(int i = 0; i < amountOfKeys; i++){
        std::vector<unsigned char> commitmentKey(pubCoinPackDataTemp.begin(), pubCoinPackDataTemp.begin() + sizeOfKeys[i]);
        CommitmentKey pubKey(commitmentKey);
        pubCoinPack.push_back(CommitmentKey(commitmentKey));
        pubCoinPackScript.push_back(pubKey.GetPubCoinScript());
        pubCoinPackDataTemp.erase(pubCoinPackDataTemp.begin(), pubCoinPackDataTemp.begin() + + sizeOfKeys[i]);
    }

}

CommitmentKeyPack::CommitmentKeyPack(std::vector<std::vector<unsigned char>>& _pubCoinPack)
{
    if(_pubCoinPack.empty())
        return;

    SetNull();

    std::vector<unsigned char> pubCoinSizes;
    for(int i = 0; i < _pubCoinPack.size(); i++){
        pubCoinPackData.insert(pubCoinPackData.end(), _pubCoinPack[i].begin(), _pubCoinPack[i].end());
        pubCoinSizes.push_back(_pubCoinPack[i].size());
    }
    //Push back delimiter
    pubCoinPackData.push_back(0xFF);
    pubCoinPackData.push_back(0xFF);
    pubCoinPackData.push_back(0xFF);
    //Push back sizes
    for(int i = 0; i < pubCoinSizes.size(); i++)
        pubCoinPackData.push_back(pubCoinSizes[i]);

    //Insert checksum to ending
    AppendCommitmentChecksum(pubCoinPackData);

    pubCoinPackDataBase58 = EncodeBase61(pubCoinPackData);
}

/*
int CommitmentKeyPack::Compress()
{
    int size = pubCoinPack.size();
    std::vector<char> buff;
    buff.resize(size*4);
    compressedSize = LZ4_compress_default((char*)pubCoinPack.data(), buff.data(), size, buff.size());
    pubCoinPackCompressed = std::string(buff.begin(),buff.begin() + compressedSize);
    return compressedSize;
}

int CommitmentKeyPack::Decompress()
{
    int size = pubCoinPack.size();
    std::vector<char> buff;
    buff.resize(size*4);
    return LZ4_decompress_safe(pubCoinPackCompressed.c_str(), buff.data(), compressedSize, buff.size());
}
*/

bool CommitmentKeyPack::IsValidPack() const
{
    if(pubCoinPackData.size() < 4)
        return false;
    std::vector<uint8_t> checksumCheck(pubCoinPackData.begin(), pubCoinPackData.end() - 4);
    uint32_t checksum32;
    memcpy(&checksum32, &(*(pubCoinPackData.end() - 4)), 4);

    return VerifyCommitmentChecksum(checksumCheck, checksum32);
}
