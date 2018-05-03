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

#define ZEROCOIN_MODULUS   "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357"

// Zerocoin transaction info, added to the CBlock to ensure zerocoin mint/spend transactions got their info stored into
// index


class CZerocoinTxInfo {
public:
    // all the zerocoin transactions encountered so far
    set<uint256> zcTransactions;
    // <denomination, pubCoin> for all the mints
    vector<pair<int,CBigNum> > mints;
    // serial for every spend
    set<CBigNum> spentSerials;
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

bool ZerocoinBuildStateFromIndex(CChain *chain);

/*
 * State of minted/spent coins as extracted from the index
 */
class CZerocoinState {
friend bool ZerocoinBuildStateFromIndex(CChain *);
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
    // Set of all used coin serials. Allows multiple entries for the same coin serial for historical reasons
    unordered_multiset<CBigNum,CBigNumHash> usedCoinSerials;
    // Set of all minted pubCoin values
    unordered_multimap<CBigNum,CMintedCoinInfo,CBigNumHash> mintedPubCoins;
    // Latest IDs of coins by denomination
    map<int, int> latestCoinIds;

public:
    CZerocoinState();

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
    int GetAccumulatorValueForSpend(int maxHeight, int denomination, int id, CBigNum &accumulator, uint256 &blockHash);

    // Get witness
    libzerocoin::AccumulatorWitness GetWitnessForSpend(CChain *chain, int maxHeight, int denomination, int id, const CBigNum &pubCoin);

    // Return height of mint transaction and id of minted coin
    int GetMintedCoinHeightAndId(const CBigNum &pubCoin, int denomination, int &id);

    // Reset to initial values
    void Reset();

    static CZerocoinState *GetZerocoinState();
};

#endif //ZEROCOIN_H
