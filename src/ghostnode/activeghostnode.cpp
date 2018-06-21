// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeghostnode.h"
#include "ghostnode.h"
#include "ghostnode-sync.h"
#include "ghostnodeman.h"
#include "protocol.h"
#include "boost/foreach.hpp"

// Keep track of the active Ghostnode
CActiveGhostnode activeGhostnode;

void CActiveGhostnode::ManageState() {
    //LogPrint("ghostnode", "CActiveGhostnode::ManageState -- Start\n");
    if (!fGhostNode) {
        //LogPrint("ghostnode", "CActiveGhostnode::ManageState -- Not a ghostnode, returning\n");
        return;
    }

    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !ghostnodeSync.IsBlockchainSynced()) {
        nState = ACTIVE_GHOSTNODE_SYNC_IN_PROCESS;
        //LogPrint("CActiveGhostnode::ManageState -- %s: %s\n", GetStateString(), GetStatus());
        return;
    }

    if (nState == ACTIVE_GHOSTNODE_SYNC_IN_PROCESS) {
        nState = ACTIVE_GHOSTNODE_INITIAL;
    }

    //LogPrint("ghostnode", "CActiveGhostnode::ManageState -- status = %s, type = %s, pinger enabled = %d\n",
             //GetStatus(), GetTypeString(), fPingerEnabled);

    if (eType == GHOSTNODE_UNKNOWN) {
        ManageStateInitial();
    }

    if (eType == GHOSTNODE_REMOTE) {
        ManageStateRemote();
    } else if (eType == GHOSTNODE_LOCAL) {
        // Try Remote Start first so the started local ghostnode can be restarted without recreate ghostnode broadcast.
        ManageStateRemote();
        if (nState != ACTIVE_GHOSTNODE_STARTED)
            ManageStateLocal();
    }

    SendGhostnodePing();
}

std::string CActiveGhostnode::GetStateString() const {
    switch (nState) {
        case ACTIVE_GHOSTNODE_INITIAL:
            return "INITIAL";
        case ACTIVE_GHOSTNODE_SYNC_IN_PROCESS:
            return "SYNC_IN_PROCESS";
        case ACTIVE_GHOSTNODE_INPUT_TOO_NEW:
            return "INPUT_TOO_NEW";
        case ACTIVE_GHOSTNODE_NOT_CAPABLE:
            return "NOT_CAPABLE";
        case ACTIVE_GHOSTNODE_STARTED:
            return "STARTED";
        default:
            return "UNKNOWN";
    }
}

std::string CActiveGhostnode::GetStatus() const {
    switch (nState) {
        case ACTIVE_GHOSTNODE_INITIAL:
            return "Node just started, not yet activated";
        case ACTIVE_GHOSTNODE_SYNC_IN_PROCESS:
            return "Sync in progress. Must wait until sync is complete to start Ghostnode";
        case ACTIVE_GHOSTNODE_INPUT_TOO_NEW:
            return strprintf("Ghostnode input must have at least %d confirmations",
                             Params().GetConsensus().nGhostnodeMinimumConfirmations);
        case ACTIVE_GHOSTNODE_NOT_CAPABLE:
            return "Not capable ghostnode: " + strNotCapableReason;
        case ACTIVE_GHOSTNODE_STARTED:
            return "Ghostnode successfully started";
        default:
            return "Unknown";
    }
}

std::string CActiveGhostnode::GetTypeString() const {
    std::string strType;
    switch (eType) {
        case GHOSTNODE_UNKNOWN:
            strType = "UNKNOWN";
            break;
        case GHOSTNODE_REMOTE:
            strType = "REMOTE";
            break;
        case GHOSTNODE_LOCAL:
            strType = "LOCAL";
            break;
        default:
            strType = "UNKNOWN";
            break;
    }
    return strType;
}

bool CActiveGhostnode::SendGhostnodePing() {
    if (!fPingerEnabled) {
        //LogPrint("ghostnode",
                 //"CActiveGhostnode::SendGhostnodePing -- %s: ghostnode ping service is disabled, skipping...\n",
                 //GetStateString());
        return false;
    }

    if (!mnodeman.Has(vin)) {
        strNotCapableReason = "Ghostnode not in ghostnode list";
        nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
        //LogPrint("CActiveGhostnode::SendGhostnodePing -- %s: %s\n", GetStateString(), strNotCapableReason);
        return false;
    }

    CGhostnodePing mnp(vin);
    if (!mnp.Sign(keyGhostnode, pubKeyGhostnode)) {
        //LogPrint("CActiveGhostnode::SendGhostnodePing -- ERROR: Couldn't sign Ghostnode Ping\n");
        return false;
    }

    // Update lastPing for our ghostnode in Ghostnode list
    if (mnodeman.IsGhostnodePingedWithin(vin, GHOSTNODE_MIN_MNP_SECONDS, mnp.sigTime)) {
        //LogPrint("CActiveGhostnode::SendGhostnodePing -- Too early to send Ghostnode Ping\n");
        return false;
    }

    mnodeman.SetGhostnodeLastPing(vin, mnp);

    //LogPrint("CActiveGhostnode::SendGhostnodePing -- Relaying ping, collateral=%s\n", vin.ToString());
    mnp.Relay();

    return true;
}

void CActiveGhostnode::ManageStateInitial() {
    //LogPrint("ghostnode", "CActiveGhostnode::ManageStateInitial -- status = %s, type = %s, pinger enabled = %d\n",
             //GetStatus(), GetTypeString(), fPingerEnabled);

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
        strNotCapableReason = "Ghostnode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    bool fFoundLocal = false;
    {
        LOCK(g_connman->cs_vNodes);

        // First try to find whatever local address is specified by externalip option
        fFoundLocal = GetLocal(service) && CGhostnode::IsValidNetAddr(service);
        if (!fFoundLocal) {
            // nothing and no live connections, can't do anything for now
            if (g_connman->vNodes.empty()) {
                nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
                strNotCapableReason = "Can't detect valid external address. Will retry when there are some connections available.";
                //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
                return;
            }
            // We have some peers, let's try to find our local address from one of them
            BOOST_FOREACH(CNode * pnode, g_connman->vNodes)
            {
                if (pnode->fSuccessfullyConnected && pnode->addr.IsIPv4()) {
                    fFoundLocal = GetLocal(service, &pnode->addr) && CGhostnode::IsValidNetAddr(service);
                    if (fFoundLocal) break;
                }
            }
        }
    }

    if (!fFoundLocal) {
        nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
        strNotCapableReason = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort) {
            nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Invalid port: %u - only %d is supported on mainnet.", service.GetPort(),
                                            mainnetDefaultPort);
            //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    } else if (service.GetPort() == mainnetDefaultPort) {
        nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
        strNotCapableReason = strprintf("Invalid port: %u - %d is only supported on mainnet.", service.GetPort(),
                                        mainnetDefaultPort);
        //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    //LogPrint("CActiveGhostnode::ManageStateInitial -- Checking inbound connection to '%s'\n", service.ToString());
    //TODO
    if (!g_connman->ConnectNode(CAddress(service, NODE_NETWORK), NULL, false, true)) {
        nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
        strNotCapableReason = "Could not connect to " + service.ToString();
        //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Default to REMOTE
    eType = GHOSTNODE_REMOTE;

    // Check if wallet funds are available
    if (!vpwallets.front()) {
        //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: Wallet not available\n", GetStateString());
        return;
    }

    if (vpwallets.front()->IsLocked()) {
        //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: Wallet is locked\n", GetStateString());
        return;
    }

    if (vpwallets.front()->GetBalance() < GHOSTNODE_COIN_REQUIRED * COIN) {
        //LogPrint("CActiveGhostnode::ManageStateInitial -- %s: Wallet balance is < 40000 NIX\n", GetStateString());
        return;
    }

    // Choose coins to use
    CPubKey pubKeyCollateral;
    CKey keyCollateral;

    // If collateral is found switch to LOCAL mode

    if (vpwallets.front()->GetGhostnodeVinAndKeys(vin, pubKeyCollateral, keyCollateral)) {
        eType = GHOSTNODE_LOCAL;
    }

    //LogPrint("ghostnode", "CActiveGhostnode::ManageStateInitial -- End status = %s, type = %s, pinger enabled = %d\n",
            // GetStatus(), GetTypeString(), fPingerEnabled);
}

void CActiveGhostnode::ManageStateRemote() {
    //LogPrint("ghostnode",
             "CActiveGhostnode::ManageStateRemote -- Start status = %s, type = %s, pinger enabled = %d, pubKeyGhostnode.GetID() = %s\n",
             //GetStatus(), fPingerEnabled, GetTypeString(), pubKeyGhostnode.GetID().ToString());

    mnodeman.CheckGhostnode(pubKeyGhostnode);
    ghostnode_info_t infoMn = mnodeman.GetGhostnodeInfo(pubKeyGhostnode);
    if (infoMn.fInfoValid) {
        if (infoMn.nProtocolVersion != PROTOCOL_VERSION) {
            nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
            strNotCapableReason = "Invalid protocol version";
            //LogPrint("CActiveGhostnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (service != infoMn.addr) {
            nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
            // //LogPrint("service: %s\n", service.ToString());
            // //LogPrint("infoMn.addr: %s\n", infoMn.addr.ToString());
            strNotCapableReason = "Broadcasted IP doesn't match our external address. Make sure you issued a new broadcast if IP of this ghostnode changed recently.";
            //LogPrint("CActiveGhostnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (!CGhostnode::IsValidStateForAutoStart(infoMn.nActiveState)) {
            nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Ghostnode in %s state", CGhostnode::StateToString(infoMn.nActiveState));
            //LogPrint("CActiveGhostnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (nState != ACTIVE_GHOSTNODE_STARTED) {
            //LogPrint("CActiveGhostnode::ManageStateRemote -- STARTED!\n");
            vin = infoMn.vin;
            service = infoMn.addr;
            fPingerEnabled = true;
            nState = ACTIVE_GHOSTNODE_STARTED;
        }
    } else {
        nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
        strNotCapableReason = "Ghostnode not in ghostnode list";
        //LogPrint("CActiveGhostnode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
    }
}

void CActiveGhostnode::ManageStateLocal() {
    //LogPrint("ghostnode", "CActiveGhostnode::ManageStateLocal -- status = %s, type = %s, pinger enabled = %d\n",
             //GetStatus(), GetTypeString(), fPingerEnabled);
    if (nState == ACTIVE_GHOSTNODE_STARTED) {
        return;
    }

    // Choose coins to use
    CPubKey pubKeyCollateral;
    CKey keyCollateral;

    if (vpwallets.front()->GetGhostnodeVinAndKeys(vin, pubKeyCollateral, keyCollateral)) {
        int nInputAge = GetInputAge(vin);
        if (nInputAge < Params().GetConsensus().nGhostnodeMinimumConfirmations) {
            nState = ACTIVE_GHOSTNODE_INPUT_TOO_NEW;
            strNotCapableReason = strprintf(_("%s - %d confirmations"), GetStatus(), nInputAge);
            //LogPrint("CActiveGhostnode::ManageStateLocal -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }

        {
            LOCK(vpwallets.front()->cs_wallet);
            vpwallets.front()->LockCoin(vin.prevout);
        }

        CGhostnodeBroadcast mnb;
        std::string strError;
        if (!CGhostnodeBroadcast::Create(vin, service, keyCollateral, pubKeyCollateral, keyGhostnode,
                                     pubKeyGhostnode, strError, mnb)) {
            nState = ACTIVE_GHOSTNODE_NOT_CAPABLE;
            strNotCapableReason = "Error creating mastenode broadcast: " + strError;
            //LogPrint("CActiveGhostnode::ManageStateLocal -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }

        fPingerEnabled = true;
        nState = ACTIVE_GHOSTNODE_STARTED;

        //update to ghostnode list
        //LogPrint("CActiveGhostnode::ManageStateLocal -- Update Ghostnode List\n");
        mnodeman.UpdateGhostnodeList(mnb);
        mnodeman.NotifyGhostnodeUpdates();

        //send to all peers
        //LogPrint("CActiveGhostnode::ManageStateLocal -- Relay broadcast, vin=%s\n", vin.ToString());
        mnb.RelayGhostNode();
    }
}
