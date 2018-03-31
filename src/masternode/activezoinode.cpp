// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activezoinode.h"
#include "zoinode.h"
#include "zoinode-sync.h"
#include "zoinodeman.h"
#include "protocol.h"

extern CWallet *pwalletMain;

// Keep track of the active Zoinode
CActiveZoinode activeZoinode;

void CActiveZoinode::ManageState() {
    LogPrint("zoinode", "CActiveZoinode::ManageState -- Start\n");
    if (!fZoiNode) {
        LogPrint("zoinode", "CActiveZoinode::ManageState -- Not a zoinode, returning\n");
        return;
    }

    if (Params().NetworkIDString() != CBaseChainParams::REGTEST && !zoinodeSync.IsBlockchainSynced()) {
        nState = ACTIVE_ZOINODE_SYNC_IN_PROCESS;
        LogPrintf("CActiveZoinode::ManageState -- %s: %s\n", GetStateString(), GetStatus());
        return;
    }

    if (nState == ACTIVE_ZOINODE_SYNC_IN_PROCESS) {
        nState = ACTIVE_ZOINODE_INITIAL;
    }

    LogPrint("zoinode", "CActiveZoinode::ManageState -- status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);

    if (eType == ZOINODE_UNKNOWN) {
        ManageStateInitial();
    }

    if (eType == ZOINODE_REMOTE) {
        ManageStateRemote();
    } else if (eType == ZOINODE_LOCAL) {
        // Try Remote Start first so the started local zoinode can be restarted without recreate zoinode broadcast.
        ManageStateRemote();
        if (nState != ACTIVE_ZOINODE_STARTED)
            ManageStateLocal();
    }

    SendZoinodePing();
}

std::string CActiveZoinode::GetStateString() const {
    switch (nState) {
        case ACTIVE_ZOINODE_INITIAL:
            return "INITIAL";
        case ACTIVE_ZOINODE_SYNC_IN_PROCESS:
            return "SYNC_IN_PROCESS";
        case ACTIVE_ZOINODE_INPUT_TOO_NEW:
            return "INPUT_TOO_NEW";
        case ACTIVE_ZOINODE_NOT_CAPABLE:
            return "NOT_CAPABLE";
        case ACTIVE_ZOINODE_STARTED:
            return "STARTED";
        default:
            return "UNKNOWN";
    }
}

std::string CActiveZoinode::GetStatus() const {
    switch (nState) {
        case ACTIVE_ZOINODE_INITIAL:
            return "Node just started, not yet activated";
        case ACTIVE_ZOINODE_SYNC_IN_PROCESS:
            return "Sync in progress. Must wait until sync is complete to start Zoinode";
        case ACTIVE_ZOINODE_INPUT_TOO_NEW:
            return strprintf("Zoinode input must have at least %d confirmations",
                             Params().GetConsensus().nZoinodeMinimumConfirmations);
        case ACTIVE_ZOINODE_NOT_CAPABLE:
            return "Not capable zoinode: " + strNotCapableReason;
        case ACTIVE_ZOINODE_STARTED:
            return "Zoinode successfully started";
        default:
            return "Unknown";
    }
}

std::string CActiveZoinode::GetTypeString() const {
    std::string strType;
    switch (eType) {
        case ZOINODE_UNKNOWN:
            strType = "UNKNOWN";
            break;
        case ZOINODE_REMOTE:
            strType = "REMOTE";
            break;
        case ZOINODE_LOCAL:
            strType = "LOCAL";
            break;
        default:
            strType = "UNKNOWN";
            break;
    }
    return strType;
}

bool CActiveZoinode::SendZoinodePing() {
    if (!fPingerEnabled) {
        LogPrint("zoinode",
                 "CActiveZoinode::SendZoinodePing -- %s: zoinode ping service is disabled, skipping...\n",
                 GetStateString());
        return false;
    }

    if (!mnodeman.Has(vin)) {
        strNotCapableReason = "Zoinode not in zoinode list";
        nState = ACTIVE_ZOINODE_NOT_CAPABLE;
        LogPrintf("CActiveZoinode::SendZoinodePing -- %s: %s\n", GetStateString(), strNotCapableReason);
        return false;
    }

    CZoinodePing mnp(vin);
    if (!mnp.Sign(keyZoinode, pubKeyZoinode)) {
        LogPrintf("CActiveZoinode::SendZoinodePing -- ERROR: Couldn't sign Zoinode Ping\n");
        return false;
    }

    // Update lastPing for our zoinode in Zoinode list
    if (mnodeman.IsZoinodePingedWithin(vin, ZOINODE_MIN_MNP_SECONDS, mnp.sigTime)) {
        LogPrintf("CActiveZoinode::SendZoinodePing -- Too early to send Zoinode Ping\n");
        return false;
    }

    mnodeman.SetZoinodeLastPing(vin, mnp);

    LogPrintf("CActiveZoinode::SendZoinodePing -- Relaying ping, collateral=%s\n", vin.ToString());
    mnp.Relay();

    return true;
}

void CActiveZoinode::ManageStateInitial() {
    LogPrint("zoinode", "CActiveZoinode::ManageStateInitial -- status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);

    // Check that our local network configuration is correct
    if (!fListen) {
        // listen option is probably overwritten by smth else, no good
        nState = ACTIVE_ZOINODE_NOT_CAPABLE;
        strNotCapableReason = "Zoinode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("CActiveZoinode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    bool fFoundLocal = false;
    {
        LOCK(cs_vNodes);

        // First try to find whatever local address is specified by externalip option
        fFoundLocal = GetLocal(service) && CZoinode::IsValidNetAddr(service);
        if (!fFoundLocal) {
            // nothing and no live connections, can't do anything for now
            if (vNodes.empty()) {
                nState = ACTIVE_ZOINODE_NOT_CAPABLE;
                strNotCapableReason = "Can't detect valid external address. Will retry when there are some connections available.";
                LogPrintf("CActiveZoinode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
                return;
            }
            // We have some peers, let's try to find our local address from one of them
            BOOST_FOREACH(CNode * pnode, vNodes)
            {
                if (pnode->fSuccessfullyConnected && pnode->addr.IsIPv4()) {
                    fFoundLocal = GetLocal(service, &pnode->addr) && CZoinode::IsValidNetAddr(service);
                    if (fFoundLocal) break;
                }
            }
        }
    }

    if (!fFoundLocal) {
        nState = ACTIVE_ZOINODE_NOT_CAPABLE;
        strNotCapableReason = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        LogPrintf("CActiveZoinode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort) {
            nState = ACTIVE_ZOINODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Invalid port: %u - only %d is supported on mainnet.", service.GetPort(),
                                            mainnetDefaultPort);
            LogPrintf("CActiveZoinode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
    } else if (service.GetPort() == mainnetDefaultPort) {
        nState = ACTIVE_ZOINODE_NOT_CAPABLE;
        strNotCapableReason = strprintf("Invalid port: %u - %d is only supported on mainnet.", service.GetPort(),
                                        mainnetDefaultPort);
        LogPrintf("CActiveZoinode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    LogPrintf("CActiveZoinode::ManageStateInitial -- Checking inbound connection to '%s'\n", service.ToString());
    //TODO
    if (!ConnectNode(CAddress(service, NODE_NETWORK), NULL, false, true)) {
        nState = ACTIVE_ZOINODE_NOT_CAPABLE;
        strNotCapableReason = "Could not connect to " + service.ToString();
        LogPrintf("CActiveZoinode::ManageStateInitial -- %s: %s\n", GetStateString(), strNotCapableReason);
        return;
    }

    // Default to REMOTE
    eType = ZOINODE_REMOTE;

    // Check if wallet funds are available
    if (!pwalletMain) {
        LogPrintf("CActiveZoinode::ManageStateInitial -- %s: Wallet not available\n", GetStateString());
        return;
    }

    if (pwalletMain->IsLocked()) {
        LogPrintf("CActiveZoinode::ManageStateInitial -- %s: Wallet is locked\n", GetStateString());
        return;
    }

    if (pwalletMain->GetBalance() < ZOINODE_COIN_REQUIRED * COIN) {
        LogPrintf("CActiveZoinode::ManageStateInitial -- %s: Wallet balance is < 1000 XZC\n", GetStateString());
        return;
    }

    // Choose coins to use
    CPubKey pubKeyCollateral;
    CKey keyCollateral;

    // If collateral is found switch to LOCAL mode

    if (pwalletMain->GetZoinodeVinAndKeys(vin, pubKeyCollateral, keyCollateral)) {
        eType = ZOINODE_LOCAL;
    }

    LogPrint("zoinode", "CActiveZoinode::ManageStateInitial -- End status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);
}

void CActiveZoinode::ManageStateRemote() {
    LogPrint("zoinode",
             "CActiveZoinode::ManageStateRemote -- Start status = %s, type = %s, pinger enabled = %d, pubKeyZoinode.GetID() = %s\n",
             GetStatus(), fPingerEnabled, GetTypeString(), pubKeyZoinode.GetID().ToString());

    mnodeman.CheckZoinode(pubKeyZoinode);
    zoinode_info_t infoMn = mnodeman.GetZoinodeInfo(pubKeyZoinode);
    if (infoMn.fInfoValid) {
        if (infoMn.nProtocolVersion != PROTOCOL_VERSION) {
            nState = ACTIVE_ZOINODE_NOT_CAPABLE;
            strNotCapableReason = "Invalid protocol version";
            LogPrintf("CActiveZoinode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (service != infoMn.addr) {
            nState = ACTIVE_ZOINODE_NOT_CAPABLE;
            // LogPrintf("service: %s\n", service.ToString());
            // LogPrintf("infoMn.addr: %s\n", infoMn.addr.ToString());
            strNotCapableReason = "Broadcasted IP doesn't match our external address. Make sure you issued a new broadcast if IP of this zoinode changed recently.";
            LogPrintf("CActiveZoinode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (!CZoinode::IsValidStateForAutoStart(infoMn.nActiveState)) {
            nState = ACTIVE_ZOINODE_NOT_CAPABLE;
            strNotCapableReason = strprintf("Zoinode in %s state", CZoinode::StateToString(infoMn.nActiveState));
            LogPrintf("CActiveZoinode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }
        if (nState != ACTIVE_ZOINODE_STARTED) {
            LogPrintf("CActiveZoinode::ManageStateRemote -- STARTED!\n");
            vin = infoMn.vin;
            service = infoMn.addr;
            fPingerEnabled = true;
            nState = ACTIVE_ZOINODE_STARTED;
        }
    } else {
        nState = ACTIVE_ZOINODE_NOT_CAPABLE;
        strNotCapableReason = "Zoinode not in zoinode list";
        LogPrintf("CActiveZoinode::ManageStateRemote -- %s: %s\n", GetStateString(), strNotCapableReason);
    }
}

void CActiveZoinode::ManageStateLocal() {
    LogPrint("zoinode", "CActiveZoinode::ManageStateLocal -- status = %s, type = %s, pinger enabled = %d\n",
             GetStatus(), GetTypeString(), fPingerEnabled);
    if (nState == ACTIVE_ZOINODE_STARTED) {
        return;
    }

    // Choose coins to use
    CPubKey pubKeyCollateral;
    CKey keyCollateral;

    if (pwalletMain->GetZoinodeVinAndKeys(vin, pubKeyCollateral, keyCollateral)) {
        int nInputAge = GetInputAge(vin);
        if (nInputAge < Params().GetConsensus().nZoinodeMinimumConfirmations) {
            nState = ACTIVE_ZOINODE_INPUT_TOO_NEW;
            strNotCapableReason = strprintf(_("%s - %d confirmations"), GetStatus(), nInputAge);
            LogPrintf("CActiveZoinode::ManageStateLocal -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }

        {
            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(vin.prevout);
        }

        CZoinodeBroadcast mnb;
        std::string strError;
        if (!CZoinodeBroadcast::Create(vin, service, keyCollateral, pubKeyCollateral, keyZoinode,
                                     pubKeyZoinode, strError, mnb)) {
            nState = ACTIVE_ZOINODE_NOT_CAPABLE;
            strNotCapableReason = "Error creating mastenode broadcast: " + strError;
            LogPrintf("CActiveZoinode::ManageStateLocal -- %s: %s\n", GetStateString(), strNotCapableReason);
            return;
        }

        fPingerEnabled = true;
        nState = ACTIVE_ZOINODE_STARTED;

        //update to zoinode list
        LogPrintf("CActiveZoinode::ManageStateLocal -- Update Zoinode List\n");
        mnodeman.UpdateZoinodeList(mnb);
        mnodeman.NotifyZoinodeUpdates();

        //send to all peers
        LogPrintf("CActiveZoinode::ManageStateLocal -- Relay broadcast, vin=%s\n", vin.ToString());
        mnb.RelayZoiNode();
    }
}
