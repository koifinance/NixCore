// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef GHOSTNODE_SYNC_H
#define GHOSTNODE_SYNC_H

#include "chain.h"
#include "net.h"
#include  "utiltime.h"
#include <univalue.h>

class CGhostnodeSync;

static const int GHOSTNODE_SYNC_FAILED          = -1;
static const int GHOSTNODE_SYNC_INITIAL         = 0;
static const int GHOSTNODE_SYNC_SPORKS          = 1;
static const int GHOSTNODE_SYNC_LIST            = 2;
static const int GHOSTNODE_SYNC_MNW             = 3;
static const int GHOSTNODE_SYNC_FINISHED        = 999;

static const int GHOSTNODE_SYNC_TICK_SECONDS    = 6;
static const int GHOSTNODE_SYNC_TIMEOUT_SECONDS = 30; // our blocks are 2 minutes so 30 seconds should be fine

static const int GHOSTNODE_SYNC_ENOUGH_PEERS    = 6;  //Mainnet PARAMS
static const int GHOSTNODE_SYNC_ENOUGH_PEERS_TESTNET    = 1;  //Testnet PARAMS

extern CGhostnodeSync ghostnodeSync;

//
// CGhostnodeSync : Sync ghostnode assets in stages
//

class CGhostnodeSync
{
private:
    // Keep track of current asset
    int nRequestedGhostnodeAssets;
    // Count peers we've requested the asset from
    int nRequestedGhostnodeAttempt;

    // Time when current ghostnode asset sync started
    int64_t nTimeAssetSyncStarted;

    // Last time when we received some ghostnode asset ...
    int64_t nTimeLastGhostnodeList;
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
    CGhostnodeSync() { Reset(); }

    void AddedGhostnodeList() { nTimeLastGhostnodeList = GetTime(); }
    void AddedPaymentVote() { nTimeLastPaymentVote = GetTime(); }
    void AddedGovernanceItem() { nTimeLastGovernanceItem = GetTime(); }

    void SendGovernanceSyncRequest(CNode* pnode);

    bool IsFailed() { return nRequestedGhostnodeAssets == GHOSTNODE_SYNC_FAILED; }
    bool IsBlockchainSynced(bool fBlockAccepted = false);
    bool IsGhostnodeListSynced() { return nRequestedGhostnodeAssets > GHOSTNODE_SYNC_LIST; }
    bool IsWinnersListSynced() { return nRequestedGhostnodeAssets > GHOSTNODE_SYNC_MNW; }
    bool IsSynced(int nHeight) { return (nHeight >= 6) ? nRequestedGhostnodeAssets == GHOSTNODE_SYNC_FINISHED : true; }

    int GetAssetID() { return nRequestedGhostnodeAssets; }
    int GetAttempt() { return nRequestedGhostnodeAttempt; }
    std::string GetAssetName();
    std::string GetSyncStatus();

    void Reset();
    void SwitchToNextAsset();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    void ProcessTick();

    void UpdatedBlockTip(const CBlockIndex *pindex);
};

#endif
