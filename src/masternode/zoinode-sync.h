// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef ZOINODE_SYNC_H
#define ZOINODE_SYNC_H

#include "chain.h"
#include "net.h"
#include  "utiltime.h"
#include <univalue.h>

class CZoinodeSync;

static const int ZOINODE_SYNC_FAILED          = -1;
static const int ZOINODE_SYNC_INITIAL         = 0;
static const int ZOINODE_SYNC_SPORKS          = 1;
static const int ZOINODE_SYNC_LIST            = 2;
static const int ZOINODE_SYNC_MNW             = 3;
static const int ZOINODE_SYNC_FINISHED        = 999;

static const int ZOINODE_SYNC_TICK_SECONDS    = 6;
static const int ZOINODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2.5 minutes so 30 seconds should be fine

static const int ZOINODE_SYNC_ENOUGH_PEERS    = 6;  //Mainnet PARAMS
//static const int ZOINODE_SYNC_ENOUGH_PEERS    = 1;  //Testnet PARAMS

extern CZoinodeSync zoinodeSync;

//
// CZoinodeSync : Sync zoinode assets in stages
//

class CZoinodeSync
{
private:
    // Keep track of current asset
    int nRequestedZoinodeAssets;
    // Count peers we've requested the asset from
    int nRequestedZoinodeAttempt;

    // Time when current zoinode asset sync started
    int64_t nTimeAssetSyncStarted;

    // Last time when we received some zoinode asset ...
    int64_t nTimeLastZoinodeList;
    int64_t nTimeLastPaymentVote;
    int64_t nTimeLastGovernanceItem;
    // ... or failed
    int64_t nTimeLastFailure;

    // How many times we failed
    int nCountFailures;

    // Keep track of current block index
    const CBlockIndex *pCurrentBlockIndex;

    bool CheckNodeHeight(CNode* pnode, bool fDisconnectStuckNodes = false);
    void Fail();
    void ClearFulfilledRequests();

public:
    CZoinodeSync() { Reset(); }

    void AddedZoinodeList() { nTimeLastZoinodeList = GetTime(); }
    void AddedPaymentVote() { nTimeLastPaymentVote = GetTime(); }
    void AddedGovernanceItem() { nTimeLastGovernanceItem = GetTime(); }

    void SendGovernanceSyncRequest(CNode* pnode);

    bool IsFailed() { return nRequestedZoinodeAssets == ZOINODE_SYNC_FAILED; }
    bool IsBlockchainSynced(bool fBlockAccepted = false);
    bool IsZoinodeListSynced() { return nRequestedZoinodeAssets > ZOINODE_SYNC_LIST; }
    bool IsWinnersListSynced() { return nRequestedZoinodeAssets > ZOINODE_SYNC_MNW; }
    bool IsSynced() { return nRequestedZoinodeAssets == ZOINODE_SYNC_FINISHED; }

    int GetAssetID() { return nRequestedZoinodeAssets; }
    int GetAttempt() { return nRequestedZoinodeAttempt; }
    std::string GetAssetName();
    std::string GetSyncStatus();

    void Reset();
    void SwitchToNextAsset();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    void ProcessTick();

    void UpdatedBlockTip(const CBlockIndex *pindex);
};

#endif
