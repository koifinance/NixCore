#include <pos/miner.h>
#include <pos/kernel.h>
#include <miner.h>
#include <chainparams.h>
#include <utilmoneystr.h>

#include <fs.h>
#include <sync.h>
#include <net.h>
#include <validation.h>
#include <base58.h>
#include <crypto/sha256.h>

#include <wallet/wallet.h>
#include <ghostnode/ghostnodeman.h>

#include <fs.h>

#include <atomic>
#include <stdint.h>
#include <thread>
#include <condition_variable>

typedef CWallet* CWalletRef;
std::vector<StakeThread*> vStakeThreads;

void StakeThread::condWaitFor(int ms)
{
    std::unique_lock<std::mutex> lock(mtxMinerProc);
    fWakeMinerProc = false;
    condMinerProc.wait_for(lock, std::chrono::milliseconds(ms), [this] { return this->fWakeMinerProc; });
};

std::atomic<bool> fStopMinerProc(false);
std::atomic<bool> fTryToSync(false);
std::atomic<bool> fIsStaking(false);


int nMinStakeInterval = 0;  // min stake interval in seconds
int nMinerSleep = 500;
std::atomic<int64_t> nTimeLastStake(0);

extern double GetDifficulty(const CBlockIndex* blockindex = nullptr);

double GetPoSKernelPS()
{
    LOCK(cs_main);

    CBlockIndex *pindex = chainActive.Tip();
    CBlockIndex *pindexPrevStake = nullptr;

    int nBestHeight = pindex->nHeight;

    int nPoSInterval = 200; // blocks sampled
    double dStakeKernelsTriedAvg = 0;
    int nStakesHandled = 0, nStakesTime = 0;

    while (pindex && nStakesHandled < nPoSInterval)
    {
        if (pindex->IsProofOfStake())
        {
            if (pindexPrevStake)
            {
                dStakeKernelsTriedAvg += GetDifficulty(pindexPrevStake) * 4294967296.0;
                nStakesTime += pindexPrevStake->nTime - pindex->nTime;
                nStakesHandled++;
            }
            pindexPrevStake = pindex;
        }
        pindex = pindex->pprev;
    }

    double result = 0;

    if (nStakesTime)
        result = dStakeKernelsTriedAvg / nStakesTime;

    result *= Params().GetStakeTimestampMask(nBestHeight) + 1;

    return result;
}

bool CheckStake(CBlock *pblock)
{
    uint256 proofHash, hashTarget;
    uint256 hashBlock = pblock->GetHash();

    if (!pblock->IsProofOfStake())
        return error("%s: %s is not a proof-of-stake block.", __func__, hashBlock.GetHex());

    if (!CheckStakeUnique(*pblock, false)) // Check in SignBlock also
        return error("%s: %s CheckStakeUnique failed.", __func__, hashBlock.GetHex());

    BlockMap::const_iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return error("%s: %s prev block not found: %s.", __func__, hashBlock.GetHex(), pblock->hashPrevBlock.GetHex());

    if (!chainActive.Contains(mi->second))
        return error("%s: %s prev block in active chain: %s.", __func__, hashBlock.GetHex(), pblock->hashPrevBlock.GetHex());

    // verify hash target and signature of coinstake tx
    if (!CheckProofOfStake(mi->second, *pblock->vtx[0], pblock->nTime, pblock->nBits, proofHash, hashTarget))
        return error("%s: proof-of-stake checking failed.", __func__);

    // debug print
    LogPrintf("CheckStake(): New proof-of-stake block found  \n  hash: %s \nproofhash: %s  \ntarget: %s\n", hashBlock.GetHex(), proofHash.GetHex(), hashTarget.GetHex());
    if (LogAcceptCategory(BCLog::POS))
    {
        LogPrintf("block %s\n", pblock->ToString());
        LogPrintf("out %s\n", FormatMoney(pblock->vtx[0]->GetValueOut()));
    };

    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash()) // hashbestchain
            return error("%s: Generated block is stale.", __func__);
    }

    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    if (!ProcessNewBlock(Params(), shared_pblock, true, nullptr))
        return error("%s: Block not accepted.", __func__);

    return true;
}

void ShutdownThreadStakeMiner()
{
    if (vStakeThreads.size() < 1 // no thread created
        || fStopMinerProc)
        return;
    LogPrint(BCLog::POS, "ShutdownThreadStakeMiner\n");
    fStopMinerProc = true;

    for (auto t : vStakeThreads)
    {
        {
            std::lock_guard<std::mutex> lock(t->mtxMinerProc);
            t->fWakeMinerProc = true;
        }
        t->condMinerProc.notify_all();

        t->thread.join();
        delete t;
    };
    vStakeThreads.clear();
};

void WakeThreadStakeMiner(CWallet *pwallet)
{
    // Call when chain is synced, wallet unlocked or balance changed
    LogPrint(BCLog::POS, "WakeThreadStakeMiner thread %d\n", pwallet->nStakeThread);

    if (pwallet->nStakeThread >= vStakeThreads.size())
        return; // stake unit test
    StakeThread *t = vStakeThreads[pwallet->nStakeThread];
    pwallet->nLastCoinStakeSearchTime = 0;
    {
        std::lock_guard<std::mutex> lock(t->mtxMinerProc);
        t->fWakeMinerProc = true;
    }

    t->condMinerProc.notify_all();
};

bool ThreadStakeMinerStopped()
{
    return fStopMinerProc;
}

static inline void condWaitFor(size_t nThreadID, int ms)
{
    assert(vStakeThreads.size() > nThreadID);
    StakeThread *t = vStakeThreads[nThreadID];
    t->condWaitFor(ms);
};

void ThreadStakeMiner(size_t nThreadID, std::vector<CWalletRef> &vpwallets, size_t nStart, size_t nEnd)
{
    LogPrintf("Starting staking thread %d, %d wallet%s.\n", nThreadID, nEnd - nStart, (nEnd - nStart) > 1 ? "s" : "");

    int nBestHeight; // TODO: set from new block signal?
    int64_t nBestTime;

    if (!gArgs.GetBoolArg("-staking", true))
    {
        LogPrint(BCLog::POS, "%s: -staking is false.\n", __func__);
        return;
    };

    CScript coinbaseScript;
    while (!fStopMinerProc)
    {
        if (fReindex || fImporting)
        {
            fIsStaking = false;
            LogPrint(BCLog::POS, "%s: Block import/reindex.\n", __func__);
            condWaitFor(nThreadID, 30000);
            continue;
        };

        if (fTryToSync)
        {
            fTryToSync = false;

            if (g_connman->vNodes.size() < 3 || nBestHeight < GetNumBlocksOfPeers())
            {
                fIsStaking = false;
                LogPrint(BCLog::POS, "%s: TryToSync\n", __func__);
                condWaitFor(nThreadID, 30000);
                continue;
            };
        };

        //test pos on regtest
        if(Params().NetworkIDString() != CBaseChainParams::REGTEST){
            if (g_connman->vNodes.empty() || IsInitialBlockDownload())
            {
                fIsStaking = false;
                fTryToSync = true;
                LogPrint(BCLog::POS, "%s: IsInitialBlockDownload\n", __func__);
                condWaitFor(nThreadID, 2000);
                continue;
            }
        }


        {
            LOCK(cs_main);
            nBestHeight = chainActive.Height();
            nBestTime = chainActive.Tip()->nTime;
        }

        if (nBestHeight < GetNumBlocksOfPeers()-1)
        {
            fIsStaking = false;
            LogPrint(BCLog::POS, "%s: nBestHeight < GetNumBlocksOfPeers(), %d, %d\n", __func__, nBestHeight, GetNumBlocksOfPeers());
            condWaitFor(nThreadID, nMinerSleep * 4);
            continue;
        };

        if (nBestHeight + 1 < Params().GetConsensus().nPosHeightActivate)
        {
            fIsStaking = false;
            LogPrint(BCLog::POS, "%s: nBestHeight < nPosHeightActivate(), %d, %d\n", __func__, nBestHeight, GetNumBlocksOfPeers());
            condWaitFor(nThreadID, nMinerSleep * 4);
            continue;
        };

        if (nMinStakeInterval > 0 && nTimeLastStake + (int64_t)nMinStakeInterval > GetTime())
        {
            LogPrint(BCLog::POS, "%s: Rate limited to 1 / %d seconds.\n", __func__, nMinStakeInterval);
            condWaitFor(nThreadID, nMinStakeInterval * 500); // nMinStakeInterval / 2 seconds
            continue;
        };

        int64_t nTime = GetAdjustedTime();
        int64_t nMask = Params().GetStakeTimestampMask(nBestHeight+1);
        int64_t nSearchTime = nTime & ~nMask;
        if (nSearchTime <= nBestTime)
        {
            if (nTime < nBestTime)
            {
                LogPrint(BCLog::POS, "%s: Can't stake before last block time.\n", __func__);
                condWaitFor(nThreadID, std::min(1000 + (nBestTime - nTime) * 1000, (int64_t)30000));
                continue;
            };

            int64_t nNextSearch = nSearchTime + nMask;
            condWaitFor(nThreadID, std::min(nMinerSleep + (nNextSearch - nTime) * 1000, (int64_t)10000));
            continue;
        };

        std::unique_ptr<CBlockTemplate> pblocktemplate;

        size_t nWaitFor = 60000;
        for (size_t i = nStart; i < nEnd; ++i)
        {
            auto pwallet = vpwallets[i];

            if (nSearchTime <= pwallet->nLastCoinStakeSearchTime)
            {
                nWaitFor = std::min(nWaitFor, (size_t)nMinerSleep);
                continue;
            }

            if (pwallet->nStakeLimitHeight && nBestHeight >= pwallet->nStakeLimitHeight)
            {
                pwallet->nIsStaking = CWallet::NOT_STAKING_LIMITED;
                nWaitFor = std::min(nWaitFor, (size_t)30000);
                continue;
            }

            if (pwallet->IsLocked())
            {
                pwallet->nIsStaking = CWallet::NOT_STAKING_LOCKED;
                nWaitFor = std::min(nWaitFor, (size_t)30000);
                continue;
            }

            if (pwallet->IsCrypted() && !pwallet->fUnlockForStakingOnly)
            {
                pwallet->nIsStaking = CWallet::NOT_STAKING_NOT_UNLOCKED_FOR_STAKING_ONLY;
                nWaitFor = std::min(nWaitFor, (size_t)30000);
                continue;
            }

            if (pwallet->GetStakeableBalance() <= pwallet->nReserveBalance)
            {
                pwallet->nIsStaking = CWallet::NOT_STAKING_BALANCE;
                nWaitFor = std::min(nWaitFor, (size_t)60000);
                pwallet->nLastCoinStakeSearchTime = nSearchTime + 60;
                LogPrint(BCLog::POS, "%s: Wallet %d, low balance.\n", __func__, i);
                continue;
            }

            if (!pblocktemplate.get())
            {
                pblocktemplate = BlockAssembler(Params()).CreateNewBlock(coinbaseScript);
                if (!pblocktemplate.get())
                {
                    fIsStaking = false;
                    nWaitFor = std::min(nWaitFor, (size_t)nMinerSleep);
                    LogPrint(BCLog::POS, "%s: Couldn't create new block.\n", __func__);
                    continue;
                }

            }

            pwallet->nIsStaking = CWallet::IS_STAKING;
            nWaitFor = nMinerSleep;
            fIsStaking = true;
            if (pwallet->SignBlock(pblocktemplate.get(), nBestHeight+1, nSearchTime))
            {
                CBlock *pblock = &pblocktemplate->block;
                if (CheckStake(pblock))
                {
                     nTimeLastStake = GetTime();
                     break;
                };
            } else
            {
                int coinbaseMaturity = chainActive.Height() >= Params().GetConsensus().nCoinMaturityReductionHeight ?
                            COINBASE_MATURITY_V2 : COINBASE_MATURITY;

                bool fTestNet = (Params().NetworkIDString() == CBaseChainParams::TESTNET);
                if(fTestNet)
                    coinbaseMaturity = COINBASE_MATURITY_TESTNET;

                int nRequiredDepth = (int)(coinbaseMaturity-1);
                if (pwallet->deepestTxnDepth < nRequiredDepth-4)
                {
                    pwallet->nIsStaking = CWallet::NOT_STAKING_DEPTH;
                    size_t nSleep = (nRequiredDepth - pwallet->deepestTxnDepth) / 4;
                    nWaitFor = std::min(nWaitFor, (size_t)(nSleep * 1000));
                    pwallet->nLastCoinStakeSearchTime = nSearchTime + nSleep;
                    LogPrint(BCLog::POS, "%s: Wallet %d, no outputs with required depth, sleeping for %ds.\n", __func__, i, nSleep);
                    continue;
                };
            };
        };

        condWaitFor(nThreadID, nWaitFor);
    };
};

