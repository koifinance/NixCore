#ifndef NIX_POS_MINER_H
#define NIX_POS_MINER_H

#include <primitives/block.h>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <vector>

class CWallet;

class StakeThread
{
public:
    void condWaitFor(int ms);

    StakeThread() {};
    std::thread thread;
    std::condition_variable condMinerProc;
    std::mutex mtxMinerProc;
    std::string sName;
    bool fWakeMinerProc = false;
};

extern std::vector<StakeThread*> vStakeThreads;

extern std::atomic<bool> fIsStaking;

extern int nMinStakeInterval;
extern int nMinerSleep;

double GetPoSKernelPS();

bool CheckStake(CBlock *pblock);

void ShutdownThreadStakeMiner();
void WakeThreadStakeMiner(CWallet *pwallet);
bool ThreadStakeMinerStopped(); // replace interruption_point

void ThreadStakeMiner(size_t nThreadID, std::vector<CWallet*> &vpwallets, size_t nStart, size_t nEnd);

#endif // NIX_POS_MINER_H

