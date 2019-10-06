// Copyright (c) 2019 The NIX Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIGMA_MINT_H
#define SIGMA_MINT_H

#include <wallet/wallet.h>

//struct that is safe to store essential mint data, without holding any information that allows for actual spending (serial, randomness, private key)
class CSigmaMint
{
private:
    uint32_t nCount;
    uint256 hashSeed;
    uint256 hashSerial;
    GroupElement pubCoinValue;
    uint256 txid;
    int nHeight;
    int nId;
    int64_t denom;
    bool isUsed;
    bool watchOnly;

public:
    CSigmaMint();
    CSigmaMint(const uint32_t& nCount, const uint256& hashSeed, const uint256& hashSerial, const GroupElement& pubCoinValue);

    sigma::CoinDenomination GetDenomination() const {
        sigma::CoinDenomination value;
        sigma::IntegerToDenomination(denom, value);
        return value;
    }
    int64_t GetDenominationValue() const {
        return denom;
    }
    uint32_t GetCount() const { return nCount; }
    int GetHeight() const { return nHeight; }
    int GetId() const { return nId; }
    uint256 GetSeedHash() const { return hashSeed; }
    uint256 GetSerialHash() const { return hashSerial; }
    GroupElement GetPubcoinValue() const { return pubCoinValue; }
    uint256 GetPubCoinHash() const { return GetPubCoinValueHash(pubCoinValue); }
    uint256 GetTxHash() const { return txid; }
    bool IsWatchOnly() const {return watchOnly;}
    bool IsUsed() const { return isUsed; }
    void SetDenomination(const sigma::CoinDenomination value) {
        int64_t denom;
        sigma::DenominationToInteger(value, denom);
        this->denom = denom;
    };
    void SetDenominationValue(const int64_t& denom) { this->denom = denom; }
    void SetHeight(const int& nHeight) { this->nHeight = nHeight; }
    void SetId(const int& nId) { this->nId = nId; }
    void SetNull();
    void SetTxHash(const uint256& txid) { this->txid = txid; }
    void SetUsed(const bool isUsed) { this->isUsed = isUsed; }
    void SetPubcoinValue(const GroupElement pubCoinValue) { this->pubCoinValue = pubCoinValue; }
    void EnableWatchOnly() { this->watchOnly = true; }
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nCount);
        READWRITE(hashSeed);
        READWRITE(hashSerial);
        READWRITE(pubCoinValue);
        READWRITE(txid);
        READWRITE(nHeight);
        READWRITE(nId);
        READWRITE(denom);
        READWRITE(isUsed);
        if(watchOnly){
            READWRITE(watchOnly);
        }
    };
};

#endif //SIGMA_MINT_H
