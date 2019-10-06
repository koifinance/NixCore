// Copyright (c) 2019 The NIX Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_SIGMA_H
#define NIX_SIGMA_H

#include <validation.h>
#include <consensus/validation.h>
#include <amount.h>
#include <coins.h>
#include <chain.h>
#include <chainparams.h>
#include <libzerocoin/Zerocoin.h>
#include <sigma/coin.h>
#include <sigma/coinspend.h>
#include <unordered_set>
#include <unordered_map>
#include <functional>
#include <net.h>

#define COINS_PER_ID 15000

// sigma parameters
extern sigma::Params *SParams;

class CBadTxIn : public std::exception
{
};

class CBadSequence : public CBadTxIn
{
};

//struct that is safe to store essential mint data, without holding any information that allows for actual spending (serial, randomness, private key)
struct CMintMeta
{
    int nHeight;
    int nId;
    GroupElement pubCoinValue;
    uint256 hashSerial;
    uint8_t nVersion;
    sigma::CoinDenomination denom;
    uint256 txid;
    bool isUsed;
    bool isArchived;
    bool isDeterministic;
    bool isSeedCorrect;
    bool watchOnly;
};

uint256 GetSerialHash(const Scalar& bnSerial);
uint256 GetPubCoinValueHash(const GroupElement& bnValue);

class CSigmaTxInfo {
public: 
    // all the sigma transactions encountered so far
    std::set<uint256> sTransactions;

    // Vector of <pubCoin> for all the mints.
    std::vector<sigma::PublicCoin> mints;

    // serial for every spend (map from serial to denomination)
    std::unordered_map<Scalar, int, sigma::CScalarHash> spentSerials;

    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CSigmaTxInfo(): fInfoIsComplete(false) {}

    // finalize everything
    void Complete();
};

secp_primitives::GroupElement ParseSigmaMintScript(const CScript& script);
std::pair<std::unique_ptr<sigma::CoinSpend>, uint32_t> ParseSigmaSpend(const CTxIn& in);

bool CheckSigmaTransaction(
  const CTransaction &tx,
    CValidationState &state,
    uint256 hashTx,
    bool isVerifyDB,
    int nHeight,
  bool isCheckWallet,
  CSigmaTxInfo *sigmaTxInfo);

void DisconnectTipSigma(CBlock &block, CBlockIndex *pindexDelete);

bool ConnectBlockSigma(
  CValidationState& state,
  const CChainParams& chainparams,
  CBlockIndex* pindexNew,
  const CBlock *pblock,
  bool fJustCheck=false);

bool SigmaBuildStateFromIndex(CChain *chain);

Scalar SigmaGetSpendSerialNumber(const CTransaction &tx, const CTxIn &txin);
CAmount GetSpendTransactionInput(const CTransaction &tx);
/*
 * State of minted/spent coins as extracted from the index
 */
class CSigmaState {
friend bool SigmaBuildStateFromIndex(CChain *, set<CBlockIndex *> &);
public:
    // First and last block where mint with given denomination and id was seen
    struct CoinGroupInfo {
        CoinGroupInfo() : firstBlock(NULL), lastBlock(NULL), nCoins(0) {}

        // first and last blocks having coins with given denomination and id minted
        CBlockIndex *firstBlock;
        CBlockIndex *lastBlock;
        // total number of minted coins with such parameters
        int nCoins;
    };

    struct CMintedCoinInfo {
        sigma::CoinDenomination denomination;

        // ID of coin group.
        int id;
        int nHeight;
    };

    struct pairhash {
      public:
        template <typename T, typename U>
          std::size_t operator()(const std::pair<T, U> &x) const
          {
            return std::hash<T>()(x.first) ^ std::hash<U>()(x.second);
          }
    };
public:
    CSigmaState();

    // Add mint, automatically assigning id to it. Returns id and previous accumulator value (if any)
    int AddMint(
        CBlockIndex *index,
        const sigma::PublicCoin& pubCoin);

    // Add serial to the list of used ones
    void AddSpend(const Scalar& serial);

    // Add everything from the block to the state
    void AddBlock(CBlockIndex *index);

    // Disconnect block from the chain rolling back mints and spends
    void RemoveBlock(CBlockIndex *index);

    // Query coin group with given denomination and id
    bool GetCoinGroupInfo(sigma::CoinDenomination denomination,
        int group_id, CoinGroupInfo &result);

    // Query if the coin serial was previously used
    bool IsUsedCoinSerial(const Scalar& coinSerial);
    bool IsUsedCoinSerialHash(Scalar &coinSerial, const uint256 &coinSerialHash);

    // Query if there is a coin with given pubCoin value
    bool HasCoin(const sigma::PublicCoin& pubCoin);
    bool HasCoinHash(GroupElement &pubCoinValue, const uint256 &pubCoinValueHash);

    // Given denomination and id returns latest accumulator value and corresponding block hash
    // Do not take into account coins with height more than maxHeight
    // Returns number of coins satisfying conditions
    int GetCoinSetForSpend(
        CChain *chain,
        int maxHeight,
        sigma::CoinDenomination denomination,
        int id,
        uint256& blockHash_out,
        std::vector<sigma::PublicCoin>& coins_out);

    // Return height of mint transaction and id of minted coin
    std::pair<int, int> GetMintedCoinHeightAndId(const sigma::PublicCoin& pubCoin);

    // Reset to initial values
    void Reset();

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddSpendToMempool(const Scalar& coinSerial);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const Scalar &coinSerial, uint256 txHash);

    // Add spend into the mempool.
    // Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const vector<Scalar> &coinSerials, uint256 txHash);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const Scalar& coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const Scalar& coinSerial);

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddMintToMempool(const sigma::PublicCoin& coinMint);

    // Add mint into the mempool.
    // Check if there is a coin with such value in either blockchain or mempool
    bool AddMintToMempool(const sigma::PublicCoin &coinMint, uint256 txHash);

    // Remove mint from the mempool.
    // Check if there is a coin with such value in either blockchain or mempool
    void RemoveMintFromMempool(const sigma::PublicCoin &coinMint);

    // Get conflicting tx hash by coin value number
    uint256 GetMempoolMintConflictingTxHash(const sigma::PublicCoin& coinMint);

    static CSigmaState* GetSigmaState();

    int GetLatestCoinID(sigma::CoinDenomination denomination) const;



private:
    // Collection of coin groups. Map from <denomination,id> to CoinGroupInfo structure
    std::unordered_map<pair<sigma::CoinDenomination, int>, CoinGroupInfo, pairhash> coinGroups;

    // Set of all minted pubCoin values, keyed by the public coin.
    // Used for checking if the given coin already exists.
    unordered_map<sigma::PublicCoin, CMintedCoinInfo, sigma::CPublicCoinHash> mintedPubCoins;

    // Latest IDs of coins by denomination
    std::unordered_map<sigma::CoinDenomination, int> latestCoinIds;

    // Set of all used coin serials.
    std::unordered_set<Scalar, sigma::CScalarHash> usedCoinSerials;

    // serials of spends currently in the mempool mapped to tx hashes
    std::unordered_map<Scalar, uint256, sigma::CScalarHash> mempoolCoinSerials;

    // values of mints currently in the mempool mapped to tx hashes
    unordered_map<sigma::PublicCoin,uint256, sigma::CPublicCoinHash> mempoolCoinMints;

};

bool IsSigmaAllowed();

bool SigmaGetMintTxHash(uint256& txHash, uint256 pubCoinValueHash);
bool SigmaGetMintTxHash(uint256& txHash, GroupElement pubCoinValue);

#endif // NIX_SIGMA_H
