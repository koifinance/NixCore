// Copyright (c) 2017-2018 The NIX developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_PEDERSENKEY_H
#define NIX_PEDERSENKEY_H

#include <iostream>
#include <vector>
#include <script/script.h>

class CScript;

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
    int Compress();
    int Decompress();

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
    CommitmentKeyPack(std::string& _pubCoinPack);
    CommitmentKeyPack(std::vector<std::vector<unsigned char>>& _pubCoinPack);
    void Init();
    bool IsValidPack();
    int Compress();
    int Decompress();

    std::vector<CommitmentKey> GetPubCoinPack(){
        return pubCoinPack;
    }

    std::vector<unsigned char> GetPubCoinPackData(){
        return pubCoinPackData;
    }

    std::vector<CScript> GetPubCoinPackScript(){
        return pubCoinPackScript;
    }

    std::string GetPubCoinPackDataBase58(){
        return pubCoinPackDataBase58;
    }

    std::vector<unsigned char> GetCheckSum(){
        return checksum;
    }

    std::string GetPubCoinPackCompressed(){
        return pubCoinPackCompressed;
    }

    int GetCompressedSize(){
        return compressedSize;
    }
};

std::string EncodeBase61(const std::vector<unsigned char>& vch);
bool DecodeBase61(const std::string& str, std::vector<unsigned char>& vchRet);

#endif // NIX_PEDERSENKEY_H
