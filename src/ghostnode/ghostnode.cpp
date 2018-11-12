// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeghostnode.h"
#include "consensus/validation.h"
#include "darksend.h"
#include "init.h"
#include "ghostnode.h"
#include "ghostnode-payments.h"
#include "ghostnode-sync.h"
#include "ghostnodeman.h"
#include "util.h"
#include "netbase.h"

#include <boost/lexical_cast.hpp>


CGhostnode::CGhostnode() :
        vin(),
        addr(),
        pubKeyCollateralAddress(),
        pubKeyGhostnode(),
        lastPing(),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(GHOSTNODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(PROTOCOL_VERSION),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CGhostnode::CGhostnode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyGhostnodeNew, int nProtocolVersionIn) :
        vin(vinNew),
        addr(addrNew),
        pubKeyCollateralAddress(pubKeyCollateralAddressNew),
        pubKeyGhostnode(pubKeyGhostnodeNew),
        lastPing(),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(GHOSTNODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(nProtocolVersionIn),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CGhostnode::CGhostnode(const CGhostnode &other) :
        vin(other.vin),
        addr(other.addr),
        pubKeyCollateralAddress(other.pubKeyCollateralAddress),
        pubKeyGhostnode(other.pubKeyGhostnode),
        lastPing(other.lastPing),
        vchSig(other.vchSig),
        sigTime(other.sigTime),
        nLastDsq(other.nLastDsq),
        nTimeLastChecked(other.nTimeLastChecked),
        nTimeLastPaid(other.nTimeLastPaid),
        nTimeLastWatchdogVote(other.nTimeLastWatchdogVote),
        nActiveState(other.nActiveState),
        nCacheCollateralBlock(other.nCacheCollateralBlock),
        nBlockLastPaid(other.nBlockLastPaid),
        nProtocolVersion(other.nProtocolVersion),
        nPoSeBanScore(other.nPoSeBanScore),
        nPoSeBanHeight(other.nPoSeBanHeight),
        fAllowMixingTx(other.fAllowMixingTx),
        fUnitTest(other.fUnitTest) {}

CGhostnode::CGhostnode(const CGhostnodeBroadcast &mnb) :
        vin(mnb.vin),
        addr(mnb.addr),
        pubKeyCollateralAddress(mnb.pubKeyCollateralAddress),
        pubKeyGhostnode(mnb.pubKeyGhostnode),
        lastPing(mnb.lastPing),
        vchSig(mnb.vchSig),
        sigTime(mnb.sigTime),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(mnb.sigTime),
        nActiveState(mnb.nActiveState),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(mnb.nProtocolVersion),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

//CSporkManager sporkManager;
//
// When a new ghostnode broadcast is sent, update our information
//
bool CGhostnode::UpdateFromNewBroadcast(CGhostnodeBroadcast &mnb) {
    if (mnb.sigTime <= sigTime && !mnb.fRecovery) return false;

    pubKeyGhostnode = mnb.pubKeyGhostnode;
    sigTime = mnb.sigTime;
    vchSig = mnb.vchSig;
    nProtocolVersion = mnb.nProtocolVersion;
    addr = mnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if (mnb.lastPing == CGhostnodePing() || (mnb.lastPing != CGhostnodePing() && mnb.lastPing.CheckAndUpdate(this, true, nDos))) {
        lastPing = mnb.lastPing;
        mnodeman.mapSeenGhostnodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Ghostnode privkey...
    if (fGhostNode && pubKeyGhostnode == activeGhostnode.pubKeyGhostnode) {
        nPoSeBanScore = -GHOSTNODE_POSE_BAN_MAX_SCORE;
        if (nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeGhostnode.ManageState();
        } else {
            // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
            // but also do not ban the node we get this message from
            //LogPrint("CGhostnode::UpdateFromNewBroadcast -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", nProtocolVersion, PROTOCOL_VERSION);
            return false;
        }
    }
    return true;
}

//
// Deterministically calculate a given "score" for a Ghostnode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
arith_uint256 CGhostnode::CalculateScore(const uint256 &blockHash) {
    uint256 aux = ArithToUint256(UintToArith256(vin.prevout.hash) + vin.prevout.n);

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << blockHash;
    arith_uint256 hash2 = UintToArith256(ss.GetHash());

    CHashWriter ss2(SER_GETHASH, PROTOCOL_VERSION);
    ss2 << blockHash;
    ss2 << aux;
    arith_uint256 hash3 = UintToArith256(ss2.GetHash());

    return (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);
}

void CGhostnode::Check(bool fForce) {
    LOCK(cs);

    if (ShutdownRequested()) return;

    if (!fForce && (GetTime() - nTimeLastChecked < GHOSTNODE_CHECK_SECONDS)) return;
    nTimeLastChecked = GetTime();

    //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state\n", vin.prevout.ToStringShort(), GetStateString());

    //once spent, stop doing the checks
    if (IsOutpointSpent()) return;

    int nHeight = 0;
    if (!fUnitTest) {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) return;

        Coin coin;
        if (!pcoinsTip->GetCoin(vin.prevout, coin) ||
            /*(unsigned int) vin.prevout.n >= coin.out || */
            coin.out.IsNull()) {
            nActiveState = GHOSTNODE_OUTPOINT_SPENT;
            //LogPrint("ghostnode", "CGhostnode::Check -- Failed to find Ghostnode UTXO, ghostnode=%s\n", vin.prevout.ToStringShort());
            return;
        }

        nHeight = chainActive.Height();
    }

    if (IsPoSeBanned()) {
        if (nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Ghostnode still will be on the edge and can be banned back easily if it keeps ignoring mnverify
        // or connect attempts. Will require few mnverify messages to strengthen its position in mn list.
        //LogPrint("CGhostnode::Check -- Ghostnode %s is unbanned and back in list now\n", vin.prevout.ToStringShort());
        DecreasePoSeBanScore();
    } else if (nPoSeBanScore >= GHOSTNODE_POSE_BAN_MAX_SCORE) {
        nActiveState = GHOSTNODE_POSE_BAN;
        // ban for the whole payment cycle
        nPoSeBanHeight = nHeight + mnodeman.size();
        //LogPrint("CGhostnode::Check -- Ghostnode %s is banned till block %d now\n", vin.prevout.ToStringShort(), nPoSeBanHeight);
        return;
    }

    int nActiveStatePrev = nActiveState;
    bool fOurGhostnode = fGhostNode && activeGhostnode.pubKeyGhostnode == pubKeyGhostnode;

    // ghostnode doesn't meet payment protocol requirements ...
    bool fRequireUpdate = nProtocolVersion < mnpayments.GetMinGhostnodePaymentsProto() ||
                          // or it's our own node and we just updated it to the new protocol but we are still waiting for activation ...
                          (fOurGhostnode && nProtocolVersion < PROTOCOL_VERSION);

    if (fRequireUpdate) {
        nActiveState = GHOSTNODE_UPDATE_REQUIRED;
        if (nActiveStatePrev != nActiveState) {
            //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    // keep old ghostnodes on start, give them a chance to receive updates...
    bool fWaitForPing = !ghostnodeSync.IsGhostnodeListSynced() && !IsPingedWithin(GHOSTNODE_MIN_MNP_SECONDS);

    if (fWaitForPing && !fOurGhostnode) {
        // ...but if it was already expired before the initial check - return right away
        if (IsExpired() || IsWatchdogExpired() || IsNewStartRequired()) {
            //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state, waiting for ping\n", vin.prevout.ToStringShort(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own ghostnode
    if (!fWaitForPing || fOurGhostnode) {

        if (!IsPingedWithin(GHOSTNODE_NEW_START_REQUIRED_SECONDS)) {
            nActiveState = GHOSTNODE_NEW_START_REQUIRED;
            if (nActiveStatePrev != nActiveState) {
                //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        bool fWatchdogActive = ghostnodeSync.IsSynced(chainActive.Height()) && mnodeman.IsWatchdogActive();
        bool fWatchdogExpired = (fWatchdogActive && ((GetTime() - nTimeLastWatchdogVote) > GHOSTNODE_WATCHDOG_MAX_SECONDS));

//        //LogPrint("ghostnode", "CGhostnode::Check -- outpoint=%s, nTimeLastWatchdogVote=%d, GetTime()=%d, fWatchdogExpired=%d\n",
//                vin.prevout.ToStringShort(), nTimeLastWatchdogVote, GetTime(), fWatchdogExpired);

        if (fWatchdogExpired) {
            nActiveState = GHOSTNODE_WATCHDOG_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        if (!IsPingedWithin(GHOSTNODE_EXPIRATION_SECONDS)) {
            nActiveState = GHOSTNODE_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    if (lastPing.sigTime - sigTime < GHOSTNODE_MIN_MNP_SECONDS) {
        nActiveState = GHOSTNODE_PRE_ENABLED;
        if (nActiveStatePrev != nActiveState) {
            //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    nActiveState = GHOSTNODE_ENABLED; // OK
    if (nActiveStatePrev != nActiveState) {
        //LogPrint("ghostnode", "CGhostnode::Check -- Ghostnode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
    }
}

bool CGhostnode::IsValidNetAddr() {
    return IsValidNetAddr(addr);
}

bool CGhostnode::IsValidForPayment() {
    if (nActiveState == GHOSTNODE_ENABLED) {
        return true;
    }
//    if(!sporkManager.IsSporkActive(SPORK_14_REQUIRE_SENTINEL_FLAG) &&
//       (nActiveState == GHOSTNODE_WATCHDOG_EXPIRED)) {
//        return true;
//    }

    return false;
}

bool CGhostnode::IsValidNetAddr(CService addrIn) {
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
           (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

ghostnode_info_t CGhostnode::GetInfo() {
    ghostnode_info_t info;
    info.vin = vin;
    info.addr = addr;
    info.pubKeyCollateralAddress = pubKeyCollateralAddress;
    info.pubKeyGhostnode = pubKeyGhostnode;
    info.sigTime = sigTime;
    info.nLastDsq = nLastDsq;
    info.nTimeLastChecked = nTimeLastChecked;
    info.nTimeLastPaid = nTimeLastPaid;
    info.nTimeLastWatchdogVote = nTimeLastWatchdogVote;
    info.nTimeLastPing = lastPing.sigTime;
    info.nActiveState = nActiveState;
    info.nProtocolVersion = nProtocolVersion;
    info.fInfoValid = true;
    return info;
}

std::string CGhostnode::StateToString(int nStateIn) {
    switch (nStateIn) {
        case GHOSTNODE_PRE_ENABLED:
            return "PRE_ENABLED";
        case GHOSTNODE_ENABLED:
            return "ENABLED";
        case GHOSTNODE_EXPIRED:
            return "EXPIRED";
        case GHOSTNODE_OUTPOINT_SPENT:
            return "OUTPOINT_SPENT";
        case GHOSTNODE_UPDATE_REQUIRED:
            return "UPDATE_REQUIRED";
        case GHOSTNODE_WATCHDOG_EXPIRED:
            return "WATCHDOG_EXPIRED";
        case GHOSTNODE_NEW_START_REQUIRED:
            return "NEW_START_REQUIRED";
        case GHOSTNODE_POSE_BAN:
            return "POSE_BAN";
        default:
            return "UNKNOWN";
    }
}

std::string CGhostnode::GetStateString() const {
    return StateToString(nActiveState);
}

std::string CGhostnode::GetStatus() const {
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

std::string CGhostnode::ToString() const {
    std::string str;
    str += "ghostnode{";
    str += addr.ToString();
    str += " ";
    str += std::to_string(nProtocolVersion);
    str += " ";
    str += vin.prevout.ToStringShort();
    str += " ";
    str += CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString();
    str += " ";
    str += std::to_string(lastPing == CGhostnodePing() ? sigTime : lastPing.sigTime);
    str += " ";
    str += std::to_string(lastPing == CGhostnodePing() ? 0 : lastPing.sigTime - sigTime);
    str += " ";
    str += std::to_string(nBlockLastPaid);
    str += "}\n";
    return str;
}

int CGhostnode::GetCollateralAge() {
    int nHeight;
    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain || !chainActive.Tip()) return -1;
        nHeight = chainActive.Height();
    }

    if (nCacheCollateralBlock == 0) {
        int nInputAge = GetInputAge(vin);
        if (nInputAge > 0) {
            nCacheCollateralBlock = nHeight - nInputAge;
        } else {
            return nInputAge;
        }
    }

    return nHeight - nCacheCollateralBlock;
}

void CGhostnode::UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack) {
    if (!pindex) {
        //LogPrint("CGhostnode::UpdateLastPaid pindex is NULL\n");
        return;
    }

    const CBlockIndex *BlockReading = pindex;

    CScript mnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());
    //LogPrint("ghostnode", "CGhostnode::UpdateLastPaidBlock -- searching for block with payment to %s\n", vin.prevout.ToStringShort());

    LOCK(cs_mapGhostnodeBlocks);

    for (int i = 0; BlockReading && BlockReading->nHeight > nBlockLastPaid && i < nMaxBlocksToScanBack; i++) {
//        //LogPrint("mnpayments.mapGhostnodeBlocks.count(BlockReading->nHeight)=%s\n", mnpayments.mapGhostnodeBlocks.count(BlockReading->nHeight));
//        //LogPrint("mnpayments.mapGhostnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)=%s\n", mnpayments.mapGhostnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2));
        if (mnpayments.mapGhostnodeBlocks.count(BlockReading->nHeight) &&
            mnpayments.mapGhostnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)) {
            // //LogPrint("i=%s, BlockReading->nHeight=%s\n", i, BlockReading->nHeight);
            CBlock block;
            if (!ReadBlockFromDisk(block, BlockReading, Params().GetConsensus())) // shouldn't really happen
            {
                //LogPrint("ReadBlockFromDisk failed\n");
                continue;
            }

            CAmount nGhostnodePayment = GetGhostnodePayment(BlockReading->nHeight, block.vtx[0]->GetValueOut());

            BOOST_FOREACH(CTxOut txout, block.vtx[0]->vout)
            if (mnpayee == txout.scriptPubKey && nGhostnodePayment == txout.nValue) {
                nBlockLastPaid = BlockReading->nHeight;
                nTimeLastPaid = BlockReading->nTime;
                //LogPrint("ghostnode", "CGhostnode::UpdateLastPaidBlock -- searching for block with payment to %s -- found new %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
                return;
            }
        }

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    // Last payment for this ghostnode wasn't found in latest mnpayments blocks
    // or it was found in mnpayments blocks but wasn't found in the blockchain.
    // //LogPrint("ghostnode", "CGhostnode::UpdateLastPaidBlock -- searching for block with payment to %s -- keeping old %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
}

bool CGhostnodeBroadcast::Create(std::string strService, std::string strKeyGhostnode, std::string strTxHash, std::string strOutputIndex, std::string &strErrorRet, CGhostnodeBroadcast &mnbRet, bool fOffline) {
    //LogPrint("CGhostnodeBroadcast::Create\n");
    CTxIn txin;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyGhostnodeNew;
    CKey keyGhostnodeNew;
    //need correct blocks to send ping
    if (!fOffline && !ghostnodeSync.IsBlockchainSynced()) {
        strErrorRet = "Sync in progress. Must wait until sync is complete to start Ghostnode";
        //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    //TODO
    if (!darkSendSigner.GetKeysFromSecret(strKeyGhostnode, keyGhostnodeNew, pubKeyGhostnodeNew)) {
        strErrorRet = strprintf("Invalid ghostnode key %s", strKeyGhostnode);
        //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!vpwallets.front()->GetGhostnodeVinAndKeys(txin, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
        strErrorRet = strprintf("Could not allocate txin %s:%s for ghostnode %s", strTxHash, strOutputIndex, strService);
        //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }


    CService addr;
    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (!Lookup(strService.c_str(), addr, mainnetDefaultPort, false)) {
        return InitError(strprintf(_("CGhostnodeBroadcast Create(): Invalid ghostnode broadcast: '%s'"), strService));
    }

    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != mainnetDefaultPort) {
            strErrorRet = strprintf("Invalid port %u for ghostnode %s, only %d is supported on mainnet.", addr.GetPort(), strService, mainnetDefaultPort);
            //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
            return false;
        }
    } else if (addr.GetPort() == mainnetDefaultPort) {
        strErrorRet = strprintf("Invalid port %u for ghostnode %s, %d is the only supported on mainnet.", addr.GetPort(), strService, mainnetDefaultPort);
        //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    return Create(txin, addr, keyCollateralAddressNew, pubKeyCollateralAddressNew, keyGhostnodeNew, pubKeyGhostnodeNew, strErrorRet, mnbRet);
}

bool CGhostnodeBroadcast::Create(CTxIn txin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyGhostnodeNew, CPubKey pubKeyGhostnodeNew, std::string &strErrorRet, CGhostnodeBroadcast &mnbRet) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    //LogPrint("ghostnode", "CGhostnodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeyGhostnodeNew.GetID() = %s\n",
             //CBitcoinAddress(pubKeyCollateralAddressNew.GetID()).ToString(),
             //pubKeyGhostnodeNew.GetID().ToString());


    CGhostnodePing mnp(txin);
    if (!mnp.Sign(keyGhostnodeNew, pubKeyGhostnodeNew)) {
        strErrorRet = strprintf("Failed to sign ping, ghostnode=%s", txin.prevout.ToStringShort());
        //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CGhostnodeBroadcast();
        return false;
    }

    mnbRet = CGhostnodeBroadcast(service, txin, pubKeyCollateralAddressNew, pubKeyGhostnodeNew, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr()) {
        strErrorRet = strprintf("Invalid IP address, ghostnode=%s", txin.prevout.ToStringShort());
        //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CGhostnodeBroadcast();
        return false;
    }

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew)) {
        strErrorRet = strprintf("Failed to sign broadcast, ghostnode=%s", txin.prevout.ToStringShort());
        //LogPrint("CGhostnodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CGhostnodeBroadcast();
        return false;
    }

    return true;
}

bool CGhostnodeBroadcast::SimpleCheck(int &nDos) {
    nDos = 0;

    // make sure addr is valid
    if (!IsValidNetAddr()) {
        //LogPrint("CGhostnodeBroadcast::SimpleCheck -- Invalid addr, rejected: ghostnode=%s  addr=%s\n",
                  //vin.prevout.ToStringShort(), addr.ToString());
        return false;
    }

    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        //LogPrint("CGhostnodeBroadcast::SimpleCheck -- Signature rejected, too far into the future: ghostnode=%s\n", vin.prevout.ToStringShort());
        nDos = 1;
        return false;
    }

    // empty ping or incorrect sigTime/unknown blockhash
    if (lastPing == CGhostnodePing() || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = GHOSTNODE_EXPIRED;
    }

    if (nProtocolVersion < mnpayments.GetMinGhostnodePaymentsProto()) {
        //LogPrint("CGhostnodeBroadcast::SimpleCheck -- ignoring outdated Ghostnode: ghostnode=%s  nProtocolVersion=%d\n", vin.prevout.ToStringShort(), nProtocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if (pubkeyScript.size() != 25) {
        //LogPrint("CGhostnodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyGhostnode.GetID());

    if (pubkeyScript2.size() != 25) {
        //LogPrint("CGhostnodeBroadcast::SimpleCheck -- pubKeyGhostnode has the wrong size\n");
        nDos = 100;
        return false;
    }

    if (!vin.scriptSig.empty()) {
        //LogPrint("CGhostnodeBroadcast::SimpleCheck -- Ignore Not Empty ScriptSig %s\n", vin.ToString());
        nDos = 100;
        return false;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != mainnetDefaultPort) return false;
    } else if (addr.GetPort() == mainnetDefaultPort) return false;

    return true;
}

bool CGhostnodeBroadcast::Update(CGhostnode *pmn, int &nDos) {
    nDos = 0;

    if (pmn->sigTime == sigTime && !fRecovery) {
        // mapSeenGhostnodeBroadcast in CGhostnodeMan::CheckMnbAndUpdateGhostnodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if (pmn->sigTime > sigTime) {
        //LogPrint("CGhostnodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Ghostnode %s %s\n",
                  //sigTime, pmn->sigTime, vin.prevout.ToStringShort(), addr.ToString());
        return false;
    }

    pmn->Check();

    // ghostnode is banned by PoSe
    if (pmn->IsPoSeBanned()) {
        //LogPrint("CGhostnodeBroadcast::Update -- Banned by PoSe, ghostnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if (pmn->pubKeyCollateralAddress != pubKeyCollateralAddress) {
        //LogPrint("CGhostnodeBroadcast::Update -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        //LogPrint("CGhostnodeBroadcast::Update -- CheckSignature() failed, ghostnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // if ther was no ghostnode broadcast recently or if it matches our Ghostnode privkey...
    if (!pmn->IsBroadcastedWithin(GHOSTNODE_MIN_MNB_SECONDS) || (fGhostNode && pubKeyGhostnode == activeGhostnode.pubKeyGhostnode)) {
        // take the newest entry
        //LogPrint("CGhostnodeBroadcast::Update -- Got UPDATED Ghostnode entry: addr=%s\n", addr.ToString());
        if (pmn->UpdateFromNewBroadcast((*this))) {
            pmn->Check();
            RelayGhostNode();
        }
        ghostnodeSync.AddedGhostnodeList();
    }

    return true;
}

bool CGhostnodeBroadcast::CheckOutpoint(int &nDos) {
    // we are a ghostnode with the same vin (i.e. already activated) and this mnb is ours (matches our Ghostnode privkey)
    // so nothing to do here for us
    if (fGhostNode && vin.prevout == activeGhostnode.vin.prevout && pubKeyGhostnode == activeGhostnode.pubKeyGhostnode) {
        return false;
    }

    if (!CheckSignature(nDos)) {
        //LogPrint("CGhostnodeBroadcast::CheckOutpoint -- CheckSignature() failed, ghostnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            // not mnb fault, let it to be checked again later
            //LogPrint("ghostnode", "CGhostnodeBroadcast::CheckOutpoint -- Failed to aquire lock, addr=%s", addr.ToString());
            mnodeman.mapSeenGhostnodeBroadcast.erase(GetHash());
            return false;
        }

        /*
        CCoins coins;
        if (!pcoinsTip->GetCoins(vin.prevout.hash, coins) ||
            (unsigned int) vin.prevout.n >= coins.vout.size() ||
            coins.vout[vin.prevout.n].IsNull()) {
            //LogPrint("ghostnode", "CGhostnodeBroadcast::CheckOutpoint -- Failed to find Ghostnode UTXO, ghostnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
        */

        Coin coin;
        if (!pcoinsTip->GetCoin(vin.prevout, coin) ||
            /*(unsigned int) vin.prevout.n >= coin.out || */
            coin.out.IsNull()) {
            //LogPrint("ghostnode", "CGhostnode::Check -- Failed to find Ghostnode UTXO, ghostnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
        if (coin.out.nValue != GHOSTNODE_COIN_REQUIRED * COIN) {
            //LogPrint("ghostnode", "CGhostnodeBroadcast::CheckOutpoint -- Failed to find Ghostnode UTXO, ghostnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
        if (chainActive.Height() - coin.nHeight + 1 < Params().GetConsensus().nGhostnodeMinimumConfirmations) {
            //LogPrint("CGhostnodeBroadcast::CheckOutpoint -- Ghostnode UTXO must have at least %d confirmations, ghostnode=%s\n",
                      //Params().GetConsensus().nGhostnodeMinimumConfirmations, vin.prevout.ToStringShort());
            // maybe we miss few blocks, let this mnb to be checked again later
            mnodeman.mapSeenGhostnodeBroadcast.erase(GetHash());
            return false;
        }
    }

    //LogPrint("ghostnode", "CGhostnodeBroadcast::CheckOutpoint -- Ghostnode UTXO verified\n");

    // make sure the vout that was signed is related to the transaction that spawned the Ghostnode
    //  - this is expensive, so it's only done once per Ghostnode
    if (!darkSendSigner.IsVinAssociatedWithPubkey(vin, pubKeyCollateralAddress)) {
        //LogPrint("CGhostnodeMan::CheckOutpoint -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 40000 NIX tx got nGhostnodeMinimumConfirmations
    uint256 hashBlock = uint256();
    CTransactionRef tx2;
    GetTransaction(vin.prevout.hash, tx2, Params().GetConsensus(), hashBlock, true);
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex *pMNIndex = (*mi).second; // block for 40k NIX tx -> 1 confirmation
            CBlockIndex *pConfIndex = chainActive[pMNIndex->nHeight + Params().GetConsensus().nGhostnodeMinimumConfirmations - 1]; // block where tx got nGhostnodeMinimumConfirmations
            if (pConfIndex->GetBlockTime() > sigTime) {
                //LogPrint("CGhostnodeBroadcast::CheckOutpoint -- Bad sigTime %d (%d conf block is at %d) for Ghostnode %s %s\n",
                          //sigTime, Params().GetConsensus().nGhostnodeMinimumConfirmations, pConfIndex->GetBlockTime(), vin.prevout.ToStringShort(), addr.ToString());
                return false;
            }
        }
    }

    return true;
}

bool CGhostnodeBroadcast::Sign(CKey &keyCollateralAddress) {
    std::string strError;
    std::string strMessage;

    sigTime = GetAdjustedTime();

    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                 pubKeyCollateralAddress.GetID().ToString() + pubKeyGhostnode.GetID().ToString() +
                 boost::lexical_cast<std::string>(nProtocolVersion);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, keyCollateralAddress)) {
        //LogPrint("CGhostnodeBroadcast::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
        //LogPrint("CGhostnodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CGhostnodeBroadcast::CheckSignature(int &nDos) {
    std::string strMessage;
    std::string strError = "";
    nDos = 0;

    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                 pubKeyCollateralAddress.GetID().ToString() + pubKeyGhostnode.GetID().ToString() +
                 boost::lexical_cast<std::string>(nProtocolVersion);

    //LogPrint("ghostnode", "CGhostnodeBroadcast::CheckSignature -- strMessage: %s  pubKeyCollateralAddress address: %s  sig: %s\n", strMessage, CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString(), EncodeBase64(&vchSig[0], vchSig.size()));

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
        //LogPrint("CGhostnodeBroadcast::CheckSignature -- Got bad Ghostnode announce signature, error: %s\n", strError);
        nDos = 100;
        return false;
    }

    return true;
}

void CGhostnodeBroadcast::RelayGhostNode() {
    //LogPrint("CGhostnodeBroadcast::RelayGhostNode\n");
    CInv inv(MSG_GHOSTNODE_ANNOUNCE, GetHash());
    g_connman->RelayInv(inv);
}

CGhostnodePing::CGhostnodePing(CTxIn &vinNew) {
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    vin = vinNew;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    vchSig = std::vector < unsigned char > ();
}

bool CGhostnodePing::Sign(CKey &keyGhostnode, CPubKey &pubKeyGhostnode) {
    std::string strError;
    std::string strGhostNodeSignMessage;

    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, keyGhostnode)) {
        //LogPrint("CGhostnodePing::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyGhostnode, vchSig, strMessage, strError)) {
        //LogPrint("CGhostnodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CGhostnodePing::CheckSignature(CPubKey &pubKeyGhostnode, int &nDos) {
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string strError = "";
    nDos = 0;

    if (!darkSendSigner.VerifyMessage(pubKeyGhostnode, vchSig, strMessage, strError)) {
        //LogPrint("CGhostnodePing::CheckSignature -- Got bad Ghostnode ping signature, ghostnode=%s, error: %s\n", vin.prevout.ToStringShort(), strError);
        nDos = 33;
        return false;
    }
    return true;
}

bool CGhostnodePing::SimpleCheck(int &nDos) {
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        //LogPrint("CGhostnodePing::SimpleCheck -- Signature rejected, too far into the future, ghostnode=%s\n", vin.prevout.ToStringShort());
        nDos = 1;
        return false;
    }

    {
//        LOCK(cs_main);
        AssertLockHeld(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if (mi == mapBlockIndex.end()) {
            //LogPrint("ghostnode", "CGhostnodePing::SimpleCheck -- Ghostnode ping is invalid, unknown block hash: ghostnode=%s blockHash=%s\n", vin.prevout.ToStringShort(), blockHash.ToString());
            // maybe we stuck or forked so we shouldn't ban this node, just fail to accept this ping
            // TODO: or should we also request this block?
            return false;
        }
    }
    //LogPrint("ghostnode", "CGhostnodePing::SimpleCheck -- Ghostnode ping verified: ghostnode=%s  blockHash=%s  sigTime=%d\n", vin.prevout.ToStringShort(), blockHash.ToString(), sigTime);
    return true;
}

bool CGhostnodePing::CheckAndUpdate(CGhostnode *pmn, bool fFromNewBroadcast, int &nDos) {
    // don't ban by default
    nDos = 0;

    if (!SimpleCheck(nDos)) {
        return false;
    }

    if (pmn == NULL) {
        //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- Couldn't find Ghostnode entry, ghostnode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    if (!fFromNewBroadcast) {
        if (pmn->IsUpdateRequired()) {
            //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- ghostnode protocol is outdated, ghostnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }

        if (pmn->IsNewStartRequired()) {
            //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- ghostnode is completely expired, new start is required, ghostnode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
    }

    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if ((*mi).second && (*mi).second->nHeight < chainActive.Height() - 24) {
            //LogPrint("CGhostnodePing::CheckAndUpdate -- Ghostnode ping is invalid, block hash is too old: ghostnode=%s  blockHash=%s\n", vin.prevout.ToStringShort(), blockHash.ToString());
            // nDos = 1;
            return false;
        }
    }

    //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- New ping: ghostnode=%s  blockHash=%s  sigTime=%d\n", vin.prevout.ToStringShort(), blockHash.ToString(), sigTime);

    // //LogPrint("mnping - Found corresponding mn for vin: %s\n", vin.prevout.ToStringShort());
    // update only if there is no known ping for this ghostnode or
    // last ping was more then GHOSTNODE_MIN_MNP_SECONDS-60 ago comparing to this one
    if (pmn->IsPingedWithin(GHOSTNODE_MIN_MNP_SECONDS - 60, sigTime)) {
        //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- Ghostnode ping arrived too early, ghostnode=%s\n", vin.prevout.ToStringShort());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }

    if (!CheckSignature(pmn->pubKeyGhostnode, nDos)) return false;

    // so, ping seems to be ok

    // if we are still syncing and there was no known ping for this mn for quite a while
    // (NOTE: assuming that GHOSTNODE_EXPIRATION_SECONDS/2 should be enough to finish mn list sync)
    if (!ghostnodeSync.IsGhostnodeListSynced() && !pmn->IsPingedWithin(GHOSTNODE_EXPIRATION_SECONDS / 2)) {
        // let's bump sync timeout
        //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- bumping sync timeout, ghostnode=%s\n", vin.prevout.ToStringShort());
        ghostnodeSync.AddedGhostnodeList();
    }

    // let's store this ping as the last one
    //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- Ghostnode ping accepted, ghostnode=%s\n", vin.prevout.ToStringShort());
    pmn->lastPing = *this;

    // and update ghostnodeman.mapSeenGhostnodeBroadcast.lastPing which is probably outdated
    CGhostnodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if (mnodeman.mapSeenGhostnodeBroadcast.count(hash)) {
        mnodeman.mapSeenGhostnodeBroadcast[hash].second.lastPing = *this;
    }

    pmn->Check(true); // force update, ignoring cache
    if (!pmn->IsEnabled()) return false;

    //LogPrint("ghostnode", "CGhostnodePing::CheckAndUpdate -- Ghostnode ping acceepted and relayed, ghostnode=%s\n", vin.prevout.ToStringShort());
    Relay();

    return true;
}

void CGhostnodePing::Relay() {
    CInv inv(MSG_GHOSTNODE_PING, GetHash());
    g_connman->RelayInv(inv);
}

void CGhostnode::UpdateWatchdogVoteTime() {
    LOCK(cs);
    nTimeLastWatchdogVote = GetTime();
}
