// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeghostnode.h"
#include "checkpoints.h"
#include "validation.h"
#include "ghostnode.h"
#include "ghostnode-payments.h"
#include "ghostnode-sync.h"
#include "ghostnodeman.h"
#include "netfulfilledman.h"
#include "spork.h"
#include "util.h"
#include "boost/foreach.hpp"
#include "netmessagemaker.h"

class CGhostnodeSync;

CGhostnodeSync ghostnodeSync;

bool CGhostnodeSync::CheckNodeHeight(CNode *pnode, bool fDisconnectStuckNodes) {
    CNodeStateStats stats;
    if (!GetNodeStateStats(pnode->GetId(), stats) || stats.nCommonHeight == -1 || stats.nSyncHeight == -1) return false; // not enough info about this peer

    // Check blocks and headers, allow a small error margin of 1 block
    if (pCurrentBlockIndex->nHeight - 1 > stats.nCommonHeight) {
        // This peer probably stuck, don't sync any additional data from it
        if (fDisconnectStuckNodes) {
            // Disconnect to free this connection slot for another peer.
            pnode->fDisconnect = true;
            //LogPrint("CGhostnodeSync::CheckNodeHeight -- disconnecting from stuck peer, nHeight=%d, nCommonHeight=%d, peer=%d\n",
                      //pCurrentBlockIndex->nHeight, stats.nCommonHeight, pnode->GetId());
        } else {
            //LogPrint("CGhostnodeSync::CheckNodeHeight -- skipping stuck peer, nHeight=%d, nCommonHeight=%d, peer=%d\n",
                      //pCurrentBlockIndex->nHeight, stats.nCommonHeight, pnode->GetId());
        }
        return false;
    } else if (pCurrentBlockIndex->nHeight < stats.nSyncHeight - 1) {
        // This peer announced more headers than we have blocks currently
        //LogPrint("CGhostnodeSync::CheckNodeHeight -- skipping peer, who announced more headers than we have blocks currently, nHeight=%d, nSyncHeight=%d, peer=%d\n",
                  //pCurrentBlockIndex->nHeight, stats.nSyncHeight, pnode->GetId());
        return false;
    }

    return true;
}

bool CGhostnodeSync::IsBlockchainSynced(bool fBlockAccepted) {
    static bool fBlockchainSynced = false;
    static int64_t nTimeLastProcess = GetTime();
    static int nSkipped = 0;
    static bool fFirstBlockAccepted = false;

    if(chainActive.Height() <= Params().GetConsensus().nGhostnodeInitialize)
        return true;
    // if the last call to this function was more than 60 minutes ago (client was in sleep mode) reset the sync process
    if (GetTime() - nTimeLastProcess > 60 * 60) {
        //LogPrint("CGhostnodeSync::IsBlockchainSynced time-check fBlockchainSynced=%s\n", fBlockchainSynced);
        Reset();
        fBlockchainSynced = false;
    }

    if (!pCurrentBlockIndex || !pindexBestHeader || fImporting || fReindex) return false;

    if (fBlockAccepted) {
        // this should be only triggered while we are still syncing
        if (!IsSynced(chainActive.Height())) {
            // we are trying to download smth, reset blockchain sync status
            fFirstBlockAccepted = true;
            fBlockchainSynced = false;
            nTimeLastProcess = GetTime();
            return false;
        }
    } else {
        // skip if we already checked less than 1 tick ago
        if (GetTime() - nTimeLastProcess < GHOSTNODE_SYNC_TICK_SECONDS) {
            nSkipped++;
            return fBlockchainSynced;
        }
    }

    //LogPrint("ghostnode-sync", "CGhostnodeSync::IsBlockchainSynced -- state before check: %ssynced, skipped %d times\n", fBlockchainSynced ? "" : "not ", nSkipped);

    nTimeLastProcess = GetTime();
    nSkipped = 0;

    if (fBlockchainSynced){
        return true;
    }

    if (fCheckpointsEnabled && pCurrentBlockIndex->nHeight < Checkpoints::GetTotalBlocksEstimate(Params().Checkpoints())) {
        return false;
    }

    std::vector < CNode * > vNodesCopy = g_connman->CopyNodeVector();
    bool fTestNet = (Params().NetworkIDString() == CBaseChainParams::TESTNET);
    int enough_peers = GHOSTNODE_SYNC_ENOUGH_PEERS;
    if(fTestNet)
        enough_peers = GHOSTNODE_SYNC_ENOUGH_PEERS_TESTNET;

    // We have enough peers and assume most of them are synced
    if (vNodesCopy.size() >= enough_peers) {
        // Check to see how many of our peers are (almost) at the same height as we are
        int nNodesAtSameHeight = 0;
        BOOST_FOREACH(CNode * pnode, vNodesCopy)
        {
            // Make sure this peer is presumably at the same height
            if (!CheckNodeHeight(pnode)) {
                continue;
            }
            nNodesAtSameHeight++;
            // if we have decent number of such peers, most likely we are synced now
            if (nNodesAtSameHeight >= enough_peers) {
                //LogPrint("CGhostnodeSync::IsBlockchainSynced -- found enough peers on the same height as we are, done\n");
                fBlockchainSynced = true;
                g_connman->ReleaseNodeVector(vNodesCopy);
                return true;
            }
        }
    }
    g_connman->ReleaseNodeVector(vNodesCopy);

    // wait for at least one new block to be accepted
    if (!fFirstBlockAccepted) return false;

    // same as !IsInitialBlockDownload() but no cs_main needed here
    int64_t nMaxBlockTime = std::max(pCurrentBlockIndex->GetBlockTime(), pindexBestHeader->GetBlockTime());
    fBlockchainSynced = pindexBestHeader->nHeight - pCurrentBlockIndex->nHeight < 24 * 6 &&
                        GetTime() - nMaxBlockTime < Params().MaxTipAge();
    return fBlockchainSynced;
}

void CGhostnodeSync::Fail() {
    nTimeLastFailure = GetTime();
    nRequestedGhostnodeAssets = GHOSTNODE_SYNC_FAILED;
}

void CGhostnodeSync::Reset() {
    nRequestedGhostnodeAssets = GHOSTNODE_SYNC_INITIAL;
    nRequestedGhostnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
    nTimeLastGhostnodeList = GetTime();
    nTimeLastPaymentVote = GetTime();
    nTimeLastGovernanceItem = GetTime();
    nTimeLastFailure = 0;
    nCountFailures = 0;
}

std::string CGhostnodeSync::GetAssetName() {
    switch (nRequestedGhostnodeAssets) {
        case (GHOSTNODE_SYNC_INITIAL):
            return "GHOSTNODE_SYNC_INITIAL";
        case (GHOSTNODE_SYNC_SPORKS):
            return "GHOSTNODE_SYNC_SPORKS";
        case (GHOSTNODE_SYNC_LIST):
            return "GHOSTNODE_SYNC_LIST";
        case (GHOSTNODE_SYNC_MNW):
            return "GHOSTNODE_SYNC_MNW";
        case (GHOSTNODE_SYNC_FAILED):
            return "GHOSTNODE_SYNC_FAILED";
        case GHOSTNODE_SYNC_FINISHED:
            return "GHOSTNODE_SYNC_FINISHED";
        default:
            return "UNKNOWN";
    }
}

void CGhostnodeSync::SwitchToNextAsset() {
    switch (nRequestedGhostnodeAssets) {
        case (GHOSTNODE_SYNC_FAILED):
            throw std::runtime_error("Can't switch to next asset from failed, should use Reset() first!");
            break;
        case (GHOSTNODE_SYNC_INITIAL):
            ClearFulfilledRequests();
            nRequestedGhostnodeAssets = GHOSTNODE_SYNC_SPORKS;
            //LogPrint("CGhostnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case (GHOSTNODE_SYNC_SPORKS):
            nTimeLastGhostnodeList = GetTime();
            nRequestedGhostnodeAssets = GHOSTNODE_SYNC_LIST;
            //LogPrint("CGhostnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;
        case (GHOSTNODE_SYNC_LIST):
            nTimeLastPaymentVote = GetTime();
            nRequestedGhostnodeAssets = GHOSTNODE_SYNC_MNW;
            //LogPrint("CGhostnodeSync::SwitchToNextAsset -- Starting %s\n", GetAssetName());
            break;

        case (GHOSTNODE_SYNC_MNW):
            nTimeLastGovernanceItem = GetTime();
            //LogPrint("CGhostnodeSync::SwitchToNextAsset -- Sync has finished\n");
            nRequestedGhostnodeAssets = GHOSTNODE_SYNC_FINISHED;
            break;
    }
    nRequestedGhostnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
}

std::string CGhostnodeSync::GetSyncStatus() {
    switch (ghostnodeSync.nRequestedGhostnodeAssets) {
        case GHOSTNODE_SYNC_INITIAL:
            return _("Synchronization pending...");
        case GHOSTNODE_SYNC_SPORKS:
            return _("Synchronizing sporks...");
        case GHOSTNODE_SYNC_LIST:
            return _("Synchronizing ghostnodes...");
        case GHOSTNODE_SYNC_MNW:
            return _("Synchronizing ghostnode payments...");
        case GHOSTNODE_SYNC_FAILED:
            return _("Synchronization failed");
        case GHOSTNODE_SYNC_FINISHED:
            return _("Synchronization finished");
        default:
            return "";
    }
}

void CGhostnodeSync::ProcessMessage(CNode *pfrom, std::string &strCommand, CDataStream &vRecv) {
    if (strCommand == NetMsgType::SYNCSTATUSCOUNT) { //Sync status count

        //do not care about stats if sync process finished or failed
        if (IsSynced(chainActive.Height())|| IsFailed()) return;

        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        //LogPrint("SYNCSTATUSCOUNT -- got inventory count: nItemID=%d  nCount=%d  peer=%d\n", nItemID, nCount, pfrom->GetId());
    }
}

void CGhostnodeSync::ClearFulfilledRequests() {
    TRY_LOCK(g_connman->cs_vNodes, lockRecv);
    if (!lockRecv) return;

    BOOST_FOREACH(CNode * pnode, g_connman->vNodes)
    {
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "spork-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "ghostnode-list-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "ghostnode-payment-sync");
        netfulfilledman.RemoveFulfilledRequest(pnode->addr, "full-sync");
    }
}

void CGhostnodeSync::ProcessTick() {
    static int nTick = 0;
    if (nTick++ % GHOSTNODE_SYNC_TICK_SECONDS != 0) return;
    if (!pCurrentBlockIndex) return;

    //the actual count of ghostnodes we have currently
    int nMnCount = mnodeman.CountGhostnodes();

    //LogPrint("ProcessTick", "CGhostnodeSync::ProcessTick -- nTick %d nMnCount %d\n", nTick, nMnCount);

    // INITIAL SYNC SETUP / LOG REPORTING
    double nSyncProgress = double(nRequestedGhostnodeAttempt + (nRequestedGhostnodeAssets - 1) * 8) / (8 * 4);
    //LogPrint("ProcessTick", "CGhostnodeSync::ProcessTick -- nTick %d nRequestedGhostnodeAssets %d nRequestedGhostnodeAttempt %d nSyncProgress %f\n", nTick, nRequestedGhostnodeAssets, nRequestedGhostnodeAttempt, nSyncProgress);
    uiInterface.NotifyAdditionalDataSyncProgressChanged(pCurrentBlockIndex->nHeight, nSyncProgress);

    // RESET SYNCING INCASE OF FAILURE
    {
        if (IsSynced(chainActive.Height())) {
            /*
                Resync if we lost all ghostnodes from sleep/wake or failed to sync originally
            */
            if (nMnCount == 0) {
                //LogPrint("CGhostnodeSync::ProcessTick -- WARNING: not enough data, restarting sync\n");
                Reset();
            } else {
                std::vector < CNode * > vNodesCopy = g_connman->CopyNodeVector();
                g_connman->ReleaseNodeVector(vNodesCopy);
                return;
            }
        }

        //try syncing again
        if (IsFailed()) {
            if (nTimeLastFailure + (1 * 60) < GetTime()) { // 1 minute cooldown after failed sync
                Reset();
            }
            return;
        }
    }

    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !IsBlockchainSynced() && nRequestedGhostnodeAssets > GHOSTNODE_SYNC_SPORKS) {
        nTimeLastGhostnodeList = GetTime();
        nTimeLastPaymentVote = GetTime();
        nTimeLastGovernanceItem = GetTime();
        return;
    }
    if (nRequestedGhostnodeAssets == GHOSTNODE_SYNC_INITIAL || (nRequestedGhostnodeAssets == GHOSTNODE_SYNC_SPORKS && IsBlockchainSynced())) {
        SwitchToNextAsset();
    }

    std::vector < CNode * > vNodesCopy = g_connman->CopyNodeVector();

    BOOST_FOREACH(CNode * pnode, vNodesCopy)
    {
        // Don't try to sync any data from outbound "ghostnode" connections -
        // they are temporary and should be considered unreliable for a sync process.
        // Inbound connection this early is most likely a "ghostnode" connection
        // initialted from another node, so skip it too.
        if (pnode->fGhostnode || (fGhostNode && pnode->fInbound)) continue;

        // QUICK MODE (REGTEST ONLY!)
        if (Params().NetworkIDString() == CBaseChainParams::REGTEST) {
            if (nRequestedGhostnodeAttempt <= 2) {
                const CNetMsgMaker msgMaker(pnode->GetSendVersion());
                g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS)); //get current network sporks
            } else if (nRequestedGhostnodeAttempt < 4) {
                mnodeman.DsegUpdate(pnode);
            } else if (nRequestedGhostnodeAttempt < 6) {
                int nMnCount = mnodeman.CountGhostnodes();
                const CNetMsgMaker msgMaker(pnode->GetSendVersion());
                g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GHOSTNODEPAYMENTSYNC,nMnCount)); //sync payment votes
            } else {
                nRequestedGhostnodeAssets = GHOSTNODE_SYNC_FINISHED;
            }
            nRequestedGhostnodeAttempt++;
            g_connman->ReleaseNodeVector(vNodesCopy);
            return;
        }

        // NORMAL NETWORK MODE - TESTNET/MAINNET
        {
            if (netfulfilledman.HasFulfilledRequest(pnode->addr, "full-sync")) {
                // We already fully synced from this node recently,
                // disconnect to free this connection slot for another peer.
                pnode->fDisconnect = true;
                //LogPrint("CGhostnodeSync::ProcessTick -- disconnecting from recently synced peer %d\n", pnode->GetId());
                continue;
            }

            // SPORK : ALWAYS ASK FOR SPORKS AS WE SYNC (we skip this mode now)

            if (!netfulfilledman.HasFulfilledRequest(pnode->addr, "spork-sync")) {
                // only request once from each peer
                netfulfilledman.AddFulfilledRequest(pnode->addr, "spork-sync");
                // get current network sporks
                const CNetMsgMaker msgMaker(pnode->GetSendVersion());
                g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GETSPORKS));
                //LogPrint("CGhostnodeSync::ProcessTick -- nTick %d nRequestedGhostnodeAssets %d -- requesting sporks from peer %d\n", nTick, nRequestedGhostnodeAssets, pnode->GetId());
                continue; // always get sporks first, switch to the next node without waiting for the next tick
            }

            // MNLIST : SYNC GHOSTNODE LIST FROM OTHER CONNECTED CLIENTS

            if (nRequestedGhostnodeAssets == GHOSTNODE_SYNC_LIST) {
                // check for timeout first
                if (nTimeLastGhostnodeList < GetTime() - GHOSTNODE_SYNC_TIMEOUT_SECONDS) {
                    //LogPrint("CGhostnodeSync::ProcessTick -- nTick %d nRequestedGhostnodeAssets %d -- timeout\n", nTick, nRequestedGhostnodeAssets);
                    if (nRequestedGhostnodeAttempt == 0) {
                        //LogPrint("CGhostnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // there is no way we can continue without ghostnode list, fail here and try later
                        Fail();
                        g_connman->ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset();
                    g_connman->ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "ghostnode-list-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "ghostnode-list-sync");

                if (pnode->nVersion < mnpayments.GetMinGhostnodePaymentsProto()) continue;
                nRequestedGhostnodeAttempt++;

                mnodeman.DsegUpdate(pnode);

                g_connman->ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

            // MNW : SYNC GHOSTNODE PAYMENT VOTES FROM OTHER CONNECTED CLIENTS

            if (nRequestedGhostnodeAssets == GHOSTNODE_SYNC_MNW) {
                //LogPrint("mnpayments", "CGhostnodeSync::ProcessTick -- nTick %d nRequestedGhostnodeAssets %d nTimeLastPaymentVote %lld GetTime() %lld diff %lld\n", nTick, nRequestedGhostnodeAssets, nTimeLastPaymentVote, GetTime(), GetTime() - nTimeLastPaymentVote);
                // check for timeout first
                // This might take a lot longer than GHOSTNODE_SYNC_TIMEOUT_SECONDS minutes due to new blocks,
                // but that should be OK and it should timeout eventually.
                if (nTimeLastPaymentVote < GetTime() - GHOSTNODE_SYNC_TIMEOUT_SECONDS) {
                    //LogPrint("CGhostnodeSync::ProcessTick -- nTick %d nRequestedGhostnodeAssets %d -- timeout\n", nTick, nRequestedGhostnodeAssets);
                    if (nRequestedGhostnodeAttempt == 0) {
                        //LogPrint("CGhostnodeSync::ProcessTick -- ERROR: failed to sync %s\n", GetAssetName());
                        // probably not a good idea to proceed without winner list
                        Fail();
                        g_connman->ReleaseNodeVector(vNodesCopy);
                        return;
                    }
                    SwitchToNextAsset();
                    g_connman->ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // check for data
                // if mnpayments already has enough blocks and votes, switch to the next asset
                // try to fetch data from at least two peers though
                if (nRequestedGhostnodeAttempt > 1 && mnpayments.IsEnoughData()) {
                    //LogPrint("CGhostnodeSync::ProcessTick -- nTick %d nRequestedGhostnodeAssets %d -- found enough data\n", nTick, nRequestedGhostnodeAssets);
                    SwitchToNextAsset();
                    g_connman->ReleaseNodeVector(vNodesCopy);
                    return;
                }

                // only request once from each peer
                if (netfulfilledman.HasFulfilledRequest(pnode->addr, "ghostnode-payment-sync")) continue;
                netfulfilledman.AddFulfilledRequest(pnode->addr, "ghostnode-payment-sync");

                if (pnode->nVersion < mnpayments.GetMinGhostnodePaymentsProto()) continue;
                nRequestedGhostnodeAttempt++;

                // ask node for all payment votes it has (new nodes will only return votes for future payments)
                const CNetMsgMaker msgMaker(pnode->GetSendVersion());
                g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GHOSTNODEPAYMENTSYNC, mnpayments.GetStorageLimit()));
                // ask node for missing pieces only (old nodes will not be asked)
                mnpayments.RequestLowDataPaymentBlocks(pnode);

                g_connman->ReleaseNodeVector(vNodesCopy);
                return; //this will cause each peer to get one request each six seconds for the various assets we need
            }

        }
    }
    // looped through all nodes, release them
    g_connman->ReleaseNodeVector(vNodesCopy);
}

void CGhostnodeSync::UpdatedBlockTip(const CBlockIndex *pindex) {
    pCurrentBlockIndex = pindex;
}
