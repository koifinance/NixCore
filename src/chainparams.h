// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include <chainparamsbase.h>
#include <consensus/params.h>
#include <primitives/block.h>
#include <protocol.h>
#include <memory>
#include <vector>
#include <chain.h>

static const uint32_t CHAIN_NO_GENESIS = 444444;
static const uint32_t CHAIN_NO_STEALTH_SPEND = 444445; // used hardened

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
};

struct ChainTxData {
    int64_t nTime;
    int64_t nTxCount;
    double dTxRate;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,
        STEALTH_ADDRESS,
        EXT_KEY_HASH,
        EXT_ACC_HASH,
        EXT_PUBLIC_KEY_BTC,
        EXT_SECRET_KEY_BTC,
        PUBKEY_ADDRESS_256,
        SCRIPT_ADDRESS_256,
        MAX_BASE58_TYPES
    };

    //pos
    uint32_t GetModifierInterval() const { return nModifierInterval; }
    uint32_t GetTargetSpacing() const { return nTargetSpacing; }
    uint32_t GetTargetTimespan() const { return nTargetTimespan; }

    uint32_t GetStakeTimestampMask(int nHeight) const { return nStakeTimestampMask; }
    int64_t GetCoinYearReward(int64_t nTime) const;
    int64_t GetProofOfStakeReward(const CBlockIndex *pindexPrev, int64_t nFees, bool allowInitial = false) const;


    const Consensus::Params& GetConsensus() const { return consensus; }
    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; }
    int GetDefaultPort() const { return nDefaultPort; }

    int BIP44ID() const { return nBIP44ID; }
    const CBlock& GenesisBlock() const { return genesis; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    uint64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    /** Return the list of hostnames to look up for DNS seeds */
    const std::vector<std::string>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::vector<unsigned char>& Bech32Prefix(Base58Type type) const { return bech32Prefixes[type]; }
    const std::string& Bech32HRP() const { return bech32_hrp; }
    const std::vector<SeedSpec6>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }
    const ChainTxData& TxData() const { return chainTxData; }
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout);

    bool IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const;
    bool IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const;
    bool IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const;

    /** ghostnode code*/
    int64_t MaxTipAge() const { return nMaxTipAge; }
    int PoolMaxTransactions() const { return nPoolMaxTransactions; }
    int FulfilledRequestExpireTime() const { return nFulfilledRequestExpireTime; }
    std::string SporkPubKey() const { return strSporkPubKey; }
    std::string GhostnodePaymentPubKey() const { return strGhostnodePaymentsPubKey; }

protected:
    CChainParams() {}

    Consensus::Params consensus;
    CMessageHeader::MessageStartChars pchMessageStart;
    int nDefaultPort;
    int nBIP44ID;
    uint64_t nPruneAfterHeight;
    std::vector<std::string> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::vector<unsigned char> bech32Prefixes[MAX_BASE58_TYPES];
    std::string bech32_hrp;
    std::string strNetworkID;
    CBlock genesis;
    std::vector<SeedSpec6> vFixedSeeds;
    bool fDefaultConsistencyChecks;
    bool fRequireStandard;
    bool fMineBlocksOnDemand;
    CCheckpointData checkpointData;
    ChainTxData chainTxData;

    /** ghostnode params*/
    long nMaxTipAge;
    int nPoolMaxTransactions;
    int nFulfilledRequestExpireTime;
    std::string strSporkPubKey;
    std::string strGhostnodePaymentsPubKey;

public:
    /* POS params */
    uint32_t nModifierInterval;         // seconds to elapse before new modifier is computed
    uint32_t nTargetSpacing;            // targeted number of seconds between blocks
    uint32_t nTargetTimespan;
    uint32_t nStakeTimestampMask = (1 << 4) -1; // 4 bits, every kernel stake hash will change every 16 seconds
    int64_t nCoinYearReward = 1.5 * CENT; // 1.5% per year based on a 30% staking model
};

/**
 * Creates and returns a std::unique_ptr<CChainParams> of the chosen chain.
 * @returns a CChainParams* of the chosen chain.
 * @throws a std::runtime_error if the chain is not supported.
 */
std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain);

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams &Params();

/**
 * @returns CChainParams for the given BIP70 chain name.
 */
CChainParams& Params(const std::string& chain);

const CChainParams *pParams();

/**
 * Sets the params returned by Params() to those for the given BIP70 chain name.
 * @throws std::runtime_error when the chain is not supported.
 */
void SelectParams(const std::string& chain);

/**
 * Allows modifying the Version Bits regtest parameters.
 */
void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout);

#endif // BITCOIN_CHAINPARAMS_H
