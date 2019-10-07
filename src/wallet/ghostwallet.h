// Copyright (c) 2019 The NIX Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOSTWALLET_H
#define GHOSTWALLET_H

#include <map>
#include <uint256.h>
#include <zerocoin/sigma.h>
#include <key.h>

class CDeterministicMint;
class CWallet;
class CSigmaEntry;
class CSigmaTracker;
class CWalletDBWrapper;
class CSigmaMint;

/*****************************
       *  Mint Pool *
       *            *
*****************************/

class CMintPool : public std::map<uint256, uint32_t>
{
private:
    uint32_t nCountLastGenerated;
    uint32_t nCountLastRemoved;

public:
    CMintPool();
    explicit CMintPool(uint32_t nCount);
    void Add(const GroupElement& bnValue, const uint32_t& nCount);
    void Add(const std::pair<uint256, uint32_t>& pMint, bool fVerbose = false);
    bool Has(const GroupElement& bnValue);
    void Remove(const GroupElement& bnValue);
    void Remove(const uint256& hashPubcoin);
    std::pair<uint256, uint32_t> Get(const GroupElement& bnValue);
    std::list<std::pair<uint256, uint32_t> > List();
    void Reset();

    bool Front(std::pair<uint256, uint32_t>& pMint);
    bool Next(std::pair<uint256, uint32_t>& pMint);

    //The count of the next mint to generate will have be a mint that is already in the pool
    //therefore need to return the next value that has not been removed from the pool yet
    uint32_t CountOfLastRemoved() { return nCountLastRemoved; }

    //The next pool count returns the next count that will be added to the pool
    uint32_t CountOfLastGenerated() { return nCountLastGenerated; }
};

/*****************************
       *   Wallet   *
       *            *
*****************************/

class CGhostWallet
{
private:
    uint256 seedMaster;
    std::map<uint32_t, uint256> sigmaHash;
    uint32_t nCountLastUsed;
    CMintPool mintPool;
    CWallet *pwalletMain;

public:
    CGhostWallet(CWallet *pwalletMain);
    void AddToMintPool(const std::pair<uint256, uint32_t>& pMint, bool fVerbose);
    bool SetMasterSeed(const uint256& seedMaster, bool fResetCount = false);
    uint256 GetMasterSeed() { return seedMaster; }
    void SyncWithChain(bool fGenerateMintPool = true);
    void GenerateHDMint(sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CSigmaMint& dMint, bool fGenerateOnly = false);
    void GenerateMint(const uint32_t& nCount, const sigma::CoinDenomination denom, sigma::PrivateCoin& coin, CSigmaMint& dMint);
    void GetState(int& nCount, int& nLastGenerated);
    bool RegenerateMint(const CSigmaMint& dMint, CSigmaEntry& sigma);
    void GenerateMintPool(uint32_t nCountStart = 0, uint32_t nCountEnd = 0);
    bool LoadMintPoolFromDB();
    void RemoveMintsFromPool(const std::vector<uint256>& vPubcoinHashes);
    bool SetMintSeen(const GroupElement& bnValue, const int& nHeight, const uint256& txid, const sigma::CoinDenomination& denom);
    bool IsInMintPool(const GroupElement& bnValue) { return mintPool.Has(bnValue); }
    void Lock();
    void SeedToSigma(const uint512& seedZerocoin, GroupElement& bnValue, sigma::PrivateCoin& coin);
    bool CheckSeed(const CSigmaMint& dMint);
    std::list<std::pair<uint256, uint32_t>> getMintPoolList() {return mintPool.List();}

    // Count updating functions
    uint32_t GetCount();
    void SetCount(uint32_t nCount);
    void UpdateCountLocal();
    void UpdateCountDB();
    void UpdateCount();

//private:
    uint512 GetSigmaSeed(uint32_t n);
};

bool IsSerialInBlockchain(const Scalar& bnSerial, int& nHeightTx);
bool IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend);
bool IsSerialInBlockchain(const uint256& hashSerial, int& nHeightTx, uint256& txidSpend, CTransactionRef& tx);
bool TxOutToPublicCoin(const CTxOut& txout, sigma::PublicCoin& pubCoin, CValidationState& state);

#endif // GHOSTWALLET_H
