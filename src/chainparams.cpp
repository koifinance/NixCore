// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>
#include <assert.h>
#include "arith_uint256.h"

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << nBits << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Chemical attack on Douma denied by Assad Regime 04/07/2018";
    const CScript genesisOutputScript = CScript();
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 1050000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x657dcc75c0dc8be8625fb43d91d6fe30c1bbc93fb6a333e4ca1eaa47f3da724f"); //genesis block
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 120;  //2 minute block time
        consensus.nPowTargetTimespan = consensus.nPowTargetSpacing; // Every block
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000a87058cbe368be6");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x9eea953a4e8ef299b93f308c8d49ea79c9997cc8a8ace93128fa4495aac16dc7"); //506067

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xb9;
        pchMessageStart[1] = 0xb4;
        pchMessageStart[2] = 0xbe;
        pchMessageStart[3] = 0xf9;
        nDefaultPort = 6214;
        nBIP44ID = 0x8000002C;
        nPruneAfterHeight = 0;

        //mine genesis block
        /*
        uint NONCE = 0;
        bool isValidGen = false;
        while(!isValidGen){
            genesis = CreateGenesisBlock(1522615406, NONCE, 0x1e0ffff0, 1, 0 * COIN);
            bool fNegative;
            bool fOverflow;
            arith_uint256 bnTarget;
            bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
            // Check range
            if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(consensus.powLimit))
                isValidGen = false;
            else
                isValidGen = true;
            // Check proof of work matches claimed amount
            if (UintToArith256(genesis.GetPoWHash(0)) > bnTarget)
                isValidGen = false;
            else
                isValidGen = true;

            if(!isValidGen)
                NONCE++;
        }
        */

        genesis = CreateGenesisBlock(1522615406, 71492, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //std::cout << consensus.hashGenesisBlock.ToString() << std::endl;
        //std::cout << genesis.hashMerkleRoot.ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x08c5e972b54a741384839612b104c3085161cc86c9f49ec2c79a9caa2072f117"));
        assert(genesis.hashMerkleRoot == uint256S("0xb112aed2be4b9d02a1d6a1465fa1416bb0e5a907e1ea21d08ee2469a1146eaaa"));


        vSeeds.emplace_back("ny.nixplatform.io");
        vSeeds.emplace_back("sf.nixplatform.io");
        vSeeds.emplace_back("ldn.nixplatform.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,53);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("nh","nh"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("nr","nr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("nl","nl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("nj","nj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("nx","nx"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("nen","nen"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("nex","nex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ns","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("nek","nek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("nea","nea"+3);

        bech32_hrp = "nix";

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                { 0, uint256S("0x08c5e972b54a741384839612b104c3085161cc86c9f49ec2c79a9caa2072f117")},
            }
        };

        chainTxData = ChainTxData{
            1522615406, // * UNIX timestamp of last known number of transactions
            0,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            1         // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 1050000;
        consensus.BIP16Height = 0; // 00000000040b4e986385315e14bee30ad876d8b47f748025b26683116d21aa65
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x09b9a8cecd64af042421115d4bbc9fbd85c2f6ae0cee2db13e463a2323ec1f9b");
        consensus.BIP65Height = 0; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 0; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 120;
        consensus.nPowTargetSpacing = 120;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100010");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000002e9e7b00e1f6dc5123a04aad68dd0f0968d8c7aa45f6640795c37b1"); //1135275

        pchMessageStart[0] = 0x09;
        pchMessageStart[1] = 0x07;
        pchMessageStart[2] = 0x0b;
        pchMessageStart[3] = 0x11;
        nDefaultPort = 16214;
        nBIP44ID = 0x80000001;
        nPruneAfterHeight = 1000;


        //mine genesis block
        /*
        uint NONCE = 0;
        bool isValidGen = false;
        while(!isValidGen){
            genesis = CreateGenesisBlock(1522615406, NONCE, 0x1e0ffff0, 1, 0 * COIN);
            bool fNegative;
            bool fOverflow;
            arith_uint256 bnTarget;
            bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
            // Check range
            if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(consensus.powLimit))
                isValidGen = false;
            else
                isValidGen = true;
            // Check proof of work matches claimed amount
            if (UintToArith256(genesis.GetPoWHash(0)) > bnTarget)
                isValidGen = false;
            else
                isValidGen = true;

            if(!isValidGen)
                NONCE++;
        }
        */

        genesis = CreateGenesisBlock(1522615406, 71492, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //std::cout << consensus.hashGenesisBlock.ToString() << std::endl;
        //std::cout << genesis.hashMerkleRoot.ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x08c5e972b54a741384839612b104c3085161cc86c9f49ec2c79a9caa2072f117"));
        assert(genesis.hashMerkleRoot == uint256S("0xb112aed2be4b9d02a1d6a1465fa1416bb0e5a907e1ea21d08ee2469a1146eaaa"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnetnode1.nixplatform.io");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("nh","nh"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("nr","nr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("nl","nl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("nj","nj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("nx","nx"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("nen","nen"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("nex","nex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ns","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("nek","nek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("nea","nea"+3);

        bech32_hrp = "tnix";

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
        vFixedSeeds.clear();

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {0, uint256S("0x08c5e972b54a741384839612b104c3085161cc86c9f49ec2c79a9caa2072f117")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 000000000000033cfa3c975eb83ecf2bb4aaedf68e6d279f6ed2b427c64caff9 (height 1260526)
            1516903490,
            17082348,
            0.09
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 1050000;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 5; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 5; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 16215;
        nBIP44ID = 0x80000001;
        nPruneAfterHeight = 1000;

        //mine genesis block
        /*
        uint NONCE = 0;
        bool isValidGen = false;
        while(!isValidGen){
            genesis = CreateGenesisBlock(1522615406, NONCE, 0x1e0ffff0, 1, 0 * COIN);
            bool fNegative;
            bool fOverflow;
            arith_uint256 bnTarget;
            bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);
            // Check range
            if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(consensus.powLimit))
                isValidGen = false;
            else
                isValidGen = true;
            // Check proof of work matches claimed amount
            if (UintToArith256(genesis.GetPoWHash(0)) > bnTarget)
                isValidGen = false;
            else
                isValidGen = true;

            if(!isValidGen)
                NONCE++;
        }
        */

        genesis = CreateGenesisBlock(1522615406, 71492, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        std::cout << consensus.hashGenesisBlock.ToString() << std::endl;
        std::cout << genesis.hashMerkleRoot.ToString() << std::endl;
        assert(consensus.hashGenesisBlock == uint256S("0x08c5e972b54a741384839612b104c3085161cc86c9f49ec2c79a9caa2072f117"));
        assert(genesis.hashMerkleRoot == uint256S("0xb112aed2be4b9d02a1d6a1465fa1416bb0e5a907e1ea21d08ee2469a1146eaaa"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0x08c5e972b54a741384839612b104c3085161cc86c9f49ec2c79a9caa2072f117")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        base58Prefixes[PUBKEY_ADDRESS_256] = {0x39};
        base58Prefixes[SCRIPT_ADDRESS_256] = {0x3d};
        base58Prefixes[STEALTH_ADDRESS]    = {0x14};
        base58Prefixes[EXT_KEY_HASH]       = {0x4b}; // X
        base58Prefixes[EXT_ACC_HASH]       = {0x17}; // A
        base58Prefixes[EXT_PUBLIC_KEY_BTC] = {0x04, 0x88, 0xB2, 0x1E}; // xpub
        base58Prefixes[EXT_SECRET_KEY_BTC] = {0x04, 0x88, 0xAD, 0xE4}; // xprv

        bech32Prefixes[PUBKEY_ADDRESS].assign       ("nh","nh"+2);
        bech32Prefixes[SCRIPT_ADDRESS].assign       ("nr","nr"+2);
        bech32Prefixes[PUBKEY_ADDRESS_256].assign   ("nl","nl"+2);
        bech32Prefixes[SCRIPT_ADDRESS_256].assign   ("nj","nj"+2);
        bech32Prefixes[SECRET_KEY].assign           ("nx","nx"+2);
        bech32Prefixes[EXT_PUBLIC_KEY].assign       ("nen","nen"+3);
        bech32Prefixes[EXT_SECRET_KEY].assign       ("nex","nex"+3);
        bech32Prefixes[STEALTH_ADDRESS].assign      ("ns","ps"+2);
        bech32Prefixes[EXT_KEY_HASH].assign         ("nek","nek"+3);
        bech32Prefixes[EXT_ACC_HASH].assign         ("nea","nea"+3);

        bech32_hrp = "nxrt";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams *pParams() {
    return globalChainParams.get();
};
std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn) const
{
    for (auto &hrp : bech32Prefixes)
    {
        if (vchPrefixIn == hrp)
            return true;
    };

    return false;
};

bool CChainParams::IsBech32Prefix(const std::vector<unsigned char> &vchPrefixIn, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k)
    {
        auto &hrp = bech32Prefixes[k];
        if (vchPrefixIn == hrp)
        {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        };
    };

    return false;
};

bool CChainParams::IsBech32Prefix(const char *ps, size_t slen, CChainParams::Base58Type &rtype) const
{
    for (size_t k = 0; k < MAX_BASE58_TYPES; ++k)
    {
        auto &hrp = bech32Prefixes[k];
        size_t hrplen = hrp.size();
        if (hrplen > 0
            && slen > hrplen
            && strncmp(ps, (const char*)&hrp[0], hrplen) == 0)
        {
            rtype = static_cast<CChainParams::Base58Type>(k);
            return true;
        };
    };

    return false;
};
