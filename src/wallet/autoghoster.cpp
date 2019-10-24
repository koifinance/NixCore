// Copyright (c) 2018-2020 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/autoghoster.h>
#include <chainparams.h>
#include <utilmoneystr.h>
#include <random.h>

#include <fs.h>
#include <sync.h>
#include <net.h>
#include <validation.h>
#include <base58.h>
#include <crypto/sha256.h>

#include <wallet/wallet.h>
#include <wallet/coincontrol.h>
#include <ghostnode/ghostnodeman.h>

#include <fs.h>

#include <atomic>
#include <stdint.h>
#include <thread>
#include <condition_variable>
#include <sstream>

typedef CWallet* CWalletRef;
std::vector<AutoGhosterThread*> vAutoGhosterThreads;

void AutoGhosterThread::condWaitFor(int ms)
{
    std::unique_lock<std::mutex> lock(mtxGhostProc);
    fWakeGhostProc = false;
    condGhostProc.wait_for(lock, std::chrono::milliseconds(ms), [this] { return this->fWakeGhostProc; });
}

std::atomic<bool> fStopGhostProc(false);

int64_t nGhostSleep = (60 + GetRandInt(300));
std::atomic<int64_t> nTimeLastGhosted(GetTime());


void ShutdownThreadAutoGhoster()
{
    if (vAutoGhosterThreads.size() < 1  || fStopGhostProc)
        return;
    LogPrintf("ShutdownThreadAutoGhoster\n");
    fStopGhostProc = true;
    for (auto t : vAutoGhosterThreads)
    {
        {
            std::lock_guard<std::mutex> lock(t->mtxGhostProc);
            t->fWakeGhostProc = true;
        }
        t->condGhostProc.notify_all();

        t->thread.join();
        delete t;
    };
    vAutoGhosterThreads.clear();
};

void WakeThreadAutoGhoster(CWallet *pwallet)
{
    // Call when chain is synced, wallet unlocked or balance changed
    LogPrintf("WakeThreadStakeMiner thread %d\n", pwallet->nAutoGhosterThread);
    nTimeLastGhosted = GetTime();
    nGhostSleep = (60 + GetRandInt(300));
    if (pwallet->nAutoGhosterThread >= vAutoGhosterThreads.size())
        return;
    AutoGhosterThread *t = vAutoGhosterThreads[pwallet->nAutoGhosterThread];
    {
        std::lock_guard<std::mutex> lock(t->mtxGhostProc);
        t->fWakeGhostProc = true;
    }

    t->condGhostProc.notify_all();
}

bool ThreadAutoGhosterStopped()
{
    return fStopGhostProc;
}

static inline void condWaitFor(size_t nThreadID, int ms)
{
    assert(vAutoGhosterThreads.size() > nThreadID);
    AutoGhosterThread *t = vAutoGhosterThreads[nThreadID];
    t->condWaitFor(ms);
}

void ThreadAutoGhoster(size_t nThreadID, std::vector<CWalletRef> &vpwallets, size_t nStart, size_t nEnd)
{
    LogPrintf("Starting ghosting thread %d, %d wallet%s %llf, %llf, %llf.\n", nThreadID, nEnd - nStart, (nEnd - nStart) > 1 ? "s" : "", nTimeLastGhosted, nGhostSleep, GetTime());
    if (!gArgs.GetBoolArg("-autoghost", false))
    {
        LogPrintf("%s: -autoghost is false.\n", __func__);
        return;
    };

    while (!fStopGhostProc)
    {
        if (fReindex || fImporting)
        {
            LogPrintf("%s: Block import/reindex.\n", __func__);
            condWaitFor(nThreadID, 10000);
            continue;
        };

        if (g_connman->vNodes.empty() || IsInitialBlockDownload())
        {
            LogPrintf("%s: IsInitialBlockDownload\n", __func__);
            condWaitFor(nThreadID, 10000);
            continue;
        }


        if (nTimeLastGhosted + nGhostSleep > GetTime())
        {
            LogPrintf("%s: timer not expired yet %llf\n", __func__, nGhostSleep);
            int64_t waitFor = nTimeLastGhosted + nGhostSleep - GetTime();
            condWaitFor(nThreadID, waitFor * 1000);
            continue;
        };

        std::unique_ptr<CBlockTemplate> pblocktemplate;

        for (size_t i = nStart; i < nEnd; ++i)
        {
            auto pwallet = vpwallets[i];

            if (pwallet->IsLocked())
            {
                pwallet->nIsAutoGhosting = CWallet::NOT_GHOSTING_LOCKED;
                LogPrintf("%s: wallet locked, check again in 10 seconds\n", __func__);
                condWaitFor(nThreadID, 10000);
                continue;
            }

            std::vector<COutput> vecOutputs;
            std::vector<COutPoint> vLockedOutpts;
            LOCK2(cs_main, pwallet->cs_wallet);
            //minimum amount we can ghost (0.1 denom * 0.25% fee)
            CAmount minGhostAmount = (0.1 * COIN * 0.0025);
            pwallet->AvailableCoins(vecOutputs);
            pwallet->ListLockedCoins(vLockedOutpts);
            pwallet->nIsAutoGhosting = CWallet::NOT_GHOSTING;
            // shuffle the outputs
            std::random_shuffle(vecOutputs.begin(), vecOutputs.end());
            for (const COutput& out : vecOutputs) {
                COutPoint selectedInput(out.tx->tx->GetHash(), out.i);

                if(out.tx->tx->vout[out.i].nValue < minGhostAmount)
                    continue;

                // do not spend locked coins, choose another output
                bool isLocked = false;
                for(const COutPoint& ind : vLockedOutpts){
                    if(selectedInput.n == ind.n && selectedInput.hash == ind.hash){
                        isLocked = true;
                        break;
                    }
                }

                if(!isLocked){
                    pwallet->nIsAutoGhosting = CWallet::IS_GHOSTING;
                    g_coincontrol.SetNull();
                    g_coincontrol.Select(selectedInput);
                    double decAmount = (out.tx->tx->vout[out.i].nValue/COIN) * 0.9975;
                    std::ostringstream strs;
                    strs << decAmount;
                    std::string decString = strs.str();
                    LogPrintf("Starting GhostModeMintSigma for %s.\n", decString);
                    // if it does not work, try again
                    if(pwallet->GhostModeMintSigma(decString))
                        break;
                }

            }
        };

        // set sleep timer in ms
        nGhostSleep = (60 + GetRandInt(300));
        // set last ghosted to now
        nTimeLastGhosted = GetTime();
        LogPrintf("ThreadAutoGhoster sleeping for %llf.\n", nGhostSleep);
        // sleep for timer length
        condWaitFor(nThreadID, nGhostSleep * 1000);
    };
}
