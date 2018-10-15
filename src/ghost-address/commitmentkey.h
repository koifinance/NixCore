// Copyright (c) 2017-2018 The NIX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_PEDERSENKEY_H
#define NIX_PEDERSENKEY_H

#include <vector>
#include <string>
#include <script/script.h>
#include <inttypes.h>

#include <stdlib.h>
#include <stdio.h>
#include <util.h>
#include <serialize.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>


class CommitmentKey
{
private:
    CScript pubCoinScript;
    std::string pubCoinDataBase58;
    std::vector<unsigned char> pubCoinData;
    std::string pubCoinDataCompressed;
    int compressedSize;
public:
    CommitmentKey(std::vector<unsigned char>& _pubCoinData);

    void Init();
    //int Compress();
    //int Decompress();

    CScript GetPubCoinScript(){
        return pubCoinScript;
    }

    std::string GetPubCoinDataBase58(){
        return pubCoinDataBase58;
    }

    std::vector<unsigned char> GetPubCoinData(){
        return pubCoinData;
    }

    std::string GetPubCoinDataCompressed(){
        return pubCoinDataCompressed;
    }

    int GetCompressedSize(){
        return compressedSize;
    }
};


class CommitmentKeyPack
{
private:
    std::vector<CommitmentKey> pubCoinPack;
    std::vector<unsigned char> pubCoinPackData;
    std::vector<CScript> pubCoinPackScript;
    std::string pubCoinPackDataBase58;
    std::vector<unsigned char> checksum;
    std::string pubCoinPackCompressed;
    int compressedSize;

public:
    CommitmentKeyPack();
    CommitmentKeyPack(std::string& _pubCoinPack);
    CommitmentKeyPack(std::vector<std::vector<unsigned char>>& _pubCoinPack);

    void SetNull(){
        pubCoinPack.clear();
        pubCoinPackData.clear();
        pubCoinPackScript.clear();
        pubCoinPackDataBase58.clear();
        checksum.clear();
        pubCoinPackCompressed.clear();
        compressedSize = 0;
    }

    bool IsValidPack() const;
    //int Compress();
    //int Decompress();

    std::vector<CommitmentKey> GetPubCoinPack() const{
        return pubCoinPack;
    }

    std::vector<unsigned char> GetPubCoinPackData() const{
        return pubCoinPackData;
    }

    std::vector<CScript> GetPubCoinPackScript() const{
        return pubCoinPackScript;
    }

    std::string GetPubCoinPackDataBase58() const{
        return pubCoinPackDataBase58;
    }

    std::vector<unsigned char> GetCheckSum() const{
        return checksum;
    }

    std::string GetPubCoinPackCompressed() const{
        return pubCoinPackCompressed;
    }

    int GetCompressedSize() const{
        return compressedSize;
    }
};

std::string EncodeBase61(const std::vector<unsigned char>& vch);
bool DecodeBase61(const std::string& str, std::vector<unsigned char>& vchRet);
bool VerifyCommitmentChecksum(const std::vector<uint8_t> &data, const uint32_t checksum);
void AppendCommitmentChecksum(std::vector<uint8_t> &data);
uint32_t CommitmentChecksum(uint8_t *p, uint32_t nBytes);


#endif // NIX_PEDERSENKEY_H
