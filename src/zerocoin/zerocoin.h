#ifndef ZEROCOIN_PARAM_H
#define ZEROCOIN_PARAM_H

#include "validation.h"
#include "consensus/validation.h"
#include "amount.h"
#include "coins.h"
#include "chain.h"
#include "chainparams.h"
#include "libzerocoin/Zerocoin.h"
#include <unordered_set>
#include <unordered_map>
#include <functional>

#define ZEROCOIN_MODULUS   "C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5"
#define ZEROCOIN_SEED   "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357"

// Zerocoin transaction info, added to the CBlock to ensure zerocoin mint/spend transactions got their info stored into
// index
// zerocoin parameters
extern libzerocoin::Params *ZCParams;

class CZerocoinTxInfo {
public:
    // all the zerocoin transactions encountered so far
    set<uint256> zcTransactions;
    // <denomination, pubCoin> for all the mints
    vector<pair<int,CBigNum> > mints;
    // serial for every spend
    map<CBigNum, int> spentSerials;
    // information about transactions in the block is complete
    bool fInfoIsComplete;

    CZerocoinTxInfo(): fInfoIsComplete(false) {}
    // finalize everything
    void Complete();
};

bool CheckDevFundInputs(const CTransaction &tx, CValidationState &state, int nHeight, bool fTestNet);
bool CheckZerocoinTransaction(const CTransaction &tx,
    CValidationState &state,
    uint256 hashTx,
    bool isVerifyDB,
    int nHeight,
    bool isCheckWallet,
    CZerocoinTxInfo *zerocoinTxInfo);

void DisconnectTipGhost(CBlock &block, CBlockIndex *pindexDelete);
bool ConnectBlockGhost(CValidationState &state, const CChainParams &chainparams, CBlockIndex *pindexNew, const CBlock *pblock);

int ZerocoinGetNHeight(const CBlockHeader &block);

bool ZerocoinBuildStateFromIndex(CChain *chain, set<CBlockIndex *> &changes);

CBigNum ZerocoinGetSpendSerialNumber(const CTransaction &tx, int i);

/*
 * State of minted/spent coins as extracted from the index
 */
class CZerocoinState {
friend bool ZerocoinBuildStateFromIndex(CChain *, set<CBlockIndex *> &);
public:
    // First and last block where mint (and hence accumulator update) with given denomination and id was seen
    struct CoinGroupInfo {
        CoinGroupInfo() : firstBlock(NULL), lastBlock(NULL), nCoins(0) {}

        // first and last blocks having coins with given denomination and id minted
        CBlockIndex *firstBlock;
        CBlockIndex *lastBlock;
        // total number of minted coins with such parameters
        int nCoins;
    };

private:
    // Custom hash for big numbers
    struct CBigNumHash {
        std::size_t operator()(const CBigNum &bn) const noexcept;
    };

    struct CMintedCoinInfo {
        int         denomination;
        int         id;
        int         nHeight;
    };

    // Collection of coin groups. Map from <denomination,id> to CoinGroupInfo structure
    map<pair<int, int>, CoinGroupInfo> coinGroups;
    // Set of all minted pubCoin values
    unordered_multimap<CBigNum,CMintedCoinInfo,CBigNumHash> mintedPubCoins;
    // Latest IDs of coins by denomination
    map<int, int> latestCoinIds;

public:
    CZerocoinState();

    // Set of all used coin serials. Allows multiple entries for the same coin serial for historical reasons
    unordered_multiset<CBigNum,CBigNumHash> usedCoinSerials;

    // serials of spends currently in the mempool mapped to tx hashes
    unordered_map<CBigNum,uint256,CBigNumHash> mempoolCoinSerials;
    // serials of mints currently in the mempool mapped to tx hashes
    unordered_map<CBigNum,uint256,CBigNumHash> mempoolCoinMints;

    // Add mint, automatically assigning id to it. Returns id and previous accumulator value (if any)
    int AddMint(CBlockIndex *index, int denomination, const CBigNum &pubCoin, CBigNum &previousAccValue);
    // Add serial to the list of used ones
    void AddSpend(const CBigNum &serial);

    // Add everything from the block to the state
    void AddBlock(CBlockIndex *index);
    // Disconnect block from the chain rolling back mints and spends
    void RemoveBlock(CBlockIndex *index);

    // Query coin group with given denomination and id
    bool GetCoinGroupInfo(int denomination, int id, CoinGroupInfo &result);

    // Query if the coin serial was previously used
    bool IsUsedCoinSerial(const CBigNum &coinSerial);
    // Query if there is a coin with given pubCoin value
    bool HasCoin(const CBigNum &pubCoin);

    // Given denomination and id returns latest accumulator value and corresponding block hash
    // Do not take into account coins with height more than maxHeight
    // Returns number of coins satisfying conditions
    int GetAccumulatorValueForSpend(CChain *chain, int maxHeight, int denomination, int id, CBigNum &accumulator, uint256 &blockHash);

    // Get witness
    libzerocoin::AccumulatorWitness GetWitnessForSpend(CChain *chain, int maxHeight, int denomination, int id, const CBigNum &pubCoin);

    // Return height of mint transaction and id of minted coin
    int GetMintedCoinHeightAndId(const CBigNum &pubCoin, int denomination, int &id);

    // Reset to initial values
    void Reset();

    // Test function
    bool TestValidity(CChain *chain);

    // Returns set of indices that changed
    set<CBlockIndex *> RecalculateAccumulators(CChain *chain);

    // Check if there is a conflicting tx in the blockchain or mempool
    bool CanAddSpendToMempool(const CBigNum &coinSerial);

    // Add spend into the mempool. Check if there is a coin with such serial in either blockchain or mempool
    bool AddSpendToMempool(const CBigNum &coinSerial, uint256 txHash);

    // Get conflicting tx hash by coin serial number
    uint256 GetMempoolConflictingTxHash(const CBigNum &coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)
    void RemoveSpendFromMempool(const CBigNum &coinSerial);

    // Remove spend from the mempool (usually as the result of adding tx to the block)

    static CZerocoinState *GetZerocoinState();

    uint64_t GetTotalZerocoins();

    // Check if there is a conflicting mint tx in the blockchain or mempool
    bool CanAddMintToMempool(const CBigNum &coinMint);

    // Add mint into the mempool. Check if there is a coin with such serial in either blockchain or mempool
    bool AddMintToMempool(const CBigNum &coinMint, uint256 txHash);

    // Get conflicting mint tx hash by coin pubkey number
    uint256 GetMempoolMintConflictingTxHash(const CBigNum &coinMint);

    // Remove mint from the mempool (usually as the result of adding tx to the block)
    void RemoveMintFromMempool(const CBigNum &coinMint);

};

uint64_t TotalGhosted();

#endif //ZEROCOIN_H
