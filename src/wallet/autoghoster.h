#ifndef NIX_AUTOGHOSTER_H
#define NIX_AUTOGHOSTER_H

#include <primitives/block.h>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <vector>

class CWallet;

class AutoGhosterThread
{
public:
    void condWaitFor(int ms);

    AutoGhosterThread() {};
    std::thread thread;
    std::condition_variable condGhostProc;
    std::mutex mtxGhostProc;
    std::string sName;
    bool fWakeGhostProc = false;
};

extern std::vector<AutoGhosterThread*> vAutoGhosterThreads;
extern int64_t nGhostSleep;

void ShutdownThreadAutoGhoster();
void WakeThreadAutoGhoster(CWallet *pwallet);
bool ThreadAutoGhosterStopped(); // replace interruption_point

void ThreadAutoGhoster(size_t nThreadID, std::vector<CWallet*> &vpwallets, size_t nStart, size_t nEnd);

#endif // NIX_AUTOGHOSTER_H

