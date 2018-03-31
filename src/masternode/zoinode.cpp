// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activezoinode.h"
#include "consensus/validation.h"
#include "darksend.h"
#include "init.h"
//#include "governance.h"
#include "zoinode.h"
#include "zoinode-payments.h"
#include "zoinode-sync.h"
#include "zoinodeman.h"
#include "util.h"

#include <boost/lexical_cast.hpp>


CZoinode::CZoinode() :
        vin(),
        addr(),
        pubKeyCollateralAddress(),
        pubKeyZoinode(),
        lastPing(),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(ZOINODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(PROTOCOL_VERSION),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CZoinode::CZoinode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyZoinodeNew, int nProtocolVersionIn) :
        vin(vinNew),
        addr(addrNew),
        pubKeyCollateralAddress(pubKeyCollateralAddressNew),
        pubKeyZoinode(pubKeyZoinodeNew),
        lastPing(),
        vchSig(),
        sigTime(GetAdjustedTime()),
        nLastDsq(0),
        nTimeLastChecked(0),
        nTimeLastPaid(0),
        nTimeLastWatchdogVote(0),
        nActiveState(ZOINODE_ENABLED),
        nCacheCollateralBlock(0),
        nBlockLastPaid(0),
        nProtocolVersion(nProtocolVersionIn),
        nPoSeBanScore(0),
        nPoSeBanHeight(0),
        fAllowMixingTx(true),
        fUnitTest(false) {}

CZoinode::CZoinode(const CZoinode &other) :
        vin(other.vin),
        addr(other.addr),
        pubKeyCollateralAddress(other.pubKeyCollateralAddress),
        pubKeyZoinode(other.pubKeyZoinode),
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

CZoinode::CZoinode(const CZoinodeBroadcast &mnb) :
        vin(mnb.vin),
        addr(mnb.addr),
        pubKeyCollateralAddress(mnb.pubKeyCollateralAddress),
        pubKeyZoinode(mnb.pubKeyZoinode),
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
// When a new zoinode broadcast is sent, update our information
//
bool CZoinode::UpdateFromNewBroadcast(CZoinodeBroadcast &mnb) {
    if (mnb.sigTime <= sigTime && !mnb.fRecovery) return false;

    pubKeyZoinode = mnb.pubKeyZoinode;
    sigTime = mnb.sigTime;
    vchSig = mnb.vchSig;
    nProtocolVersion = mnb.nProtocolVersion;
    addr = mnb.addr;
    nPoSeBanScore = 0;
    nPoSeBanHeight = 0;
    nTimeLastChecked = 0;
    int nDos = 0;
    if (mnb.lastPing == CZoinodePing() || (mnb.lastPing != CZoinodePing() && mnb.lastPing.CheckAndUpdate(this, true, nDos))) {
        lastPing = mnb.lastPing;
        mnodeman.mapSeenZoinodePing.insert(std::make_pair(lastPing.GetHash(), lastPing));
    }
    // if it matches our Zoinode privkey...
    if (fZoiNode && pubKeyZoinode == activeZoinode.pubKeyZoinode) {
        nPoSeBanScore = -ZOINODE_POSE_BAN_MAX_SCORE;
        if (nProtocolVersion == PROTOCOL_VERSION) {
            // ... and PROTOCOL_VERSION, then we've been remotely activated ...
            activeZoinode.ManageState();
        } else {
            // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
            // but also do not ban the node we get this message from
            LogPrintf("CZoinode::UpdateFromNewBroadcast -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", nProtocolVersion, PROTOCOL_VERSION);
            return false;
        }
    }
    return true;
}

//
// Deterministically calculate a given "score" for a Zoinode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
arith_uint256 CZoinode::CalculateScore(const uint256 &blockHash) {
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

void CZoinode::Check(bool fForce) {
    LOCK(cs);

    if (ShutdownRequested()) return;

    if (!fForce && (GetTime() - nTimeLastChecked < ZOINODE_CHECK_SECONDS)) return;
    nTimeLastChecked = GetTime();

    LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state\n", vin.prevout.ToStringShort(), GetStateString());

    //once spent, stop doing the checks
    if (IsOutpointSpent()) return;

    int nHeight = 0;
    if (!fUnitTest) {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) return;

        CCoins coins;
        if (!pcoinsTip->GetCoins(vin.prevout.hash, coins) ||
            (unsigned int) vin.prevout.n >= coins.vout.size() ||
            coins.vout[vin.prevout.n].IsNull()) {
            nActiveState = ZOINODE_OUTPOINT_SPENT;
            LogPrint("zoinode", "CZoinode::Check -- Failed to find Zoinode UTXO, zoinode=%s\n", vin.prevout.ToStringShort());
            return;
        }

        nHeight = chainActive.Height();
    }

    if (IsPoSeBanned()) {
        if (nHeight < nPoSeBanHeight) return; // too early?
        // Otherwise give it a chance to proceed further to do all the usual checks and to change its state.
        // Zoinode still will be on the edge and can be banned back easily if it keeps ignoring mnverify
        // or connect attempts. Will require few mnverify messages to strengthen its position in mn list.
        LogPrintf("CZoinode::Check -- Zoinode %s is unbanned and back in list now\n", vin.prevout.ToStringShort());
        DecreasePoSeBanScore();
    } else if (nPoSeBanScore >= ZOINODE_POSE_BAN_MAX_SCORE) {
        nActiveState = ZOINODE_POSE_BAN;
        // ban for the whole payment cycle
        nPoSeBanHeight = nHeight + mnodeman.size();
        LogPrintf("CZoinode::Check -- Zoinode %s is banned till block %d now\n", vin.prevout.ToStringShort(), nPoSeBanHeight);
        return;
    }

    int nActiveStatePrev = nActiveState;
    bool fOurZoinode = fZoiNode && activeZoinode.pubKeyZoinode == pubKeyZoinode;

    // zoinode doesn't meet payment protocol requirements ...
    bool fRequireUpdate = nProtocolVersion < mnpayments.GetMinZoinodePaymentsProto() ||
                          // or it's our own node and we just updated it to the new protocol but we are still waiting for activation ...
                          (fOurZoinode && nProtocolVersion < PROTOCOL_VERSION);

    if (fRequireUpdate) {
        nActiveState = ZOINODE_UPDATE_REQUIRED;
        if (nActiveStatePrev != nActiveState) {
            LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    // keep old zoinodes on start, give them a chance to receive updates...
    bool fWaitForPing = !zoinodeSync.IsZoinodeListSynced() && !IsPingedWithin(ZOINODE_MIN_MNP_SECONDS);

    if (fWaitForPing && !fOurZoinode) {
        // ...but if it was already expired before the initial check - return right away
        if (IsExpired() || IsWatchdogExpired() || IsNewStartRequired()) {
            LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state, waiting for ping\n", vin.prevout.ToStringShort(), GetStateString());
            return;
        }
    }

    // don't expire if we are still in "waiting for ping" mode unless it's our own zoinode
    if (!fWaitForPing || fOurZoinode) {

        if (!IsPingedWithin(ZOINODE_NEW_START_REQUIRED_SECONDS)) {
            nActiveState = ZOINODE_NEW_START_REQUIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        bool fWatchdogActive = zoinodeSync.IsSynced() && mnodeman.IsWatchdogActive();
        bool fWatchdogExpired = (fWatchdogActive && ((GetTime() - nTimeLastWatchdogVote) > ZOINODE_WATCHDOG_MAX_SECONDS));

//        LogPrint("zoinode", "CZoinode::Check -- outpoint=%s, nTimeLastWatchdogVote=%d, GetTime()=%d, fWatchdogExpired=%d\n",
//                vin.prevout.ToStringShort(), nTimeLastWatchdogVote, GetTime(), fWatchdogExpired);

        if (fWatchdogExpired) {
            nActiveState = ZOINODE_WATCHDOG_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }

        if (!IsPingedWithin(ZOINODE_EXPIRATION_SECONDS)) {
            nActiveState = ZOINODE_EXPIRED;
            if (nActiveStatePrev != nActiveState) {
                LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
            }
            return;
        }
    }

    if (lastPing.sigTime - sigTime < ZOINODE_MIN_MNP_SECONDS) {
        nActiveState = ZOINODE_PRE_ENABLED;
        if (nActiveStatePrev != nActiveState) {
            LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
        }
        return;
    }

    nActiveState = ZOINODE_ENABLED; // OK
    if (nActiveStatePrev != nActiveState) {
        LogPrint("zoinode", "CZoinode::Check -- Zoinode %s is in %s state now\n", vin.prevout.ToStringShort(), GetStateString());
    }
}

bool CZoinode::IsValidNetAddr() {
    return IsValidNetAddr(addr);
}

bool CZoinode::IsValidForPayment() {
    if (nActiveState == ZOINODE_ENABLED) {
        return true;
    }
//    if(!sporkManager.IsSporkActive(SPORK_14_REQUIRE_SENTINEL_FLAG) &&
//       (nActiveState == ZOINODE_WATCHDOG_EXPIRED)) {
//        return true;
//    }

    return false;
}

bool CZoinode::IsValidNetAddr(CService addrIn) {
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
           (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

zoinode_info_t CZoinode::GetInfo() {
    zoinode_info_t info;
    info.vin = vin;
    info.addr = addr;
    info.pubKeyCollateralAddress = pubKeyCollateralAddress;
    info.pubKeyZoinode = pubKeyZoinode;
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

std::string CZoinode::StateToString(int nStateIn) {
    switch (nStateIn) {
        case ZOINODE_PRE_ENABLED:
            return "PRE_ENABLED";
        case ZOINODE_ENABLED:
            return "ENABLED";
        case ZOINODE_EXPIRED:
            return "EXPIRED";
        case ZOINODE_OUTPOINT_SPENT:
            return "OUTPOINT_SPENT";
        case ZOINODE_UPDATE_REQUIRED:
            return "UPDATE_REQUIRED";
        case ZOINODE_WATCHDOG_EXPIRED:
            return "WATCHDOG_EXPIRED";
        case ZOINODE_NEW_START_REQUIRED:
            return "NEW_START_REQUIRED";
        case ZOINODE_POSE_BAN:
            return "POSE_BAN";
        default:
            return "UNKNOWN";
    }
}

std::string CZoinode::GetStateString() const {
    return StateToString(nActiveState);
}

std::string CZoinode::GetStatus() const {
    // TODO: return smth a bit more human readable here
    return GetStateString();
}

std::string CZoinode::ToString() const {
    std::string str;
    str += "zoinode{";
    str += addr.ToString();
    str += " ";
    str += std::to_string(nProtocolVersion);
    str += " ";
    str += vin.prevout.ToStringShort();
    str += " ";
    str += CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString();
    str += " ";
    str += std::to_string(lastPing == CZoinodePing() ? sigTime : lastPing.sigTime);
    str += " ";
    str += std::to_string(lastPing == CZoinodePing() ? 0 : lastPing.sigTime - sigTime);
    str += " ";
    str += std::to_string(nBlockLastPaid);
    str += "}\n";
    return str;
}

int CZoinode::GetCollateralAge() {
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

void CZoinode::UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack) {
    if (!pindex) {
        LogPrintf("CZoinode::UpdateLastPaid pindex is NULL\n");
        return;
    }

    const CBlockIndex *BlockReading = pindex;

    CScript mnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());
    LogPrint("zoinode", "CZoinode::UpdateLastPaidBlock -- searching for block with payment to %s\n", vin.prevout.ToStringShort());

    LOCK(cs_mapZoinodeBlocks);

    for (int i = 0; BlockReading && BlockReading->nHeight > nBlockLastPaid && i < nMaxBlocksToScanBack; i++) {
//        LogPrintf("mnpayments.mapZoinodeBlocks.count(BlockReading->nHeight)=%s\n", mnpayments.mapZoinodeBlocks.count(BlockReading->nHeight));
//        LogPrintf("mnpayments.mapZoinodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)=%s\n", mnpayments.mapZoinodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2));
        if (mnpayments.mapZoinodeBlocks.count(BlockReading->nHeight) &&
            mnpayments.mapZoinodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)) {
            // LogPrintf("i=%s, BlockReading->nHeight=%s\n", i, BlockReading->nHeight);
            CBlock block;
            if (!ReadBlockFromDisk(block, BlockReading, Params().GetConsensus())) // shouldn't really happen
            {
                LogPrintf("ReadBlockFromDisk failed\n");
                continue;
            }

            CAmount nZoinodePayment = GetZoinodePayment(BlockReading->nHeight, block.vtx[0].GetValueOut());

            BOOST_FOREACH(CTxOut txout, block.vtx[0].vout)
            if (mnpayee == txout.scriptPubKey && nZoinodePayment == txout.nValue) {
                nBlockLastPaid = BlockReading->nHeight;
                nTimeLastPaid = BlockReading->nTime;
                LogPrint("zoinode", "CZoinode::UpdateLastPaidBlock -- searching for block with payment to %s -- found new %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
                return;
            }
        }

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    // Last payment for this zoinode wasn't found in latest mnpayments blocks
    // or it was found in mnpayments blocks but wasn't found in the blockchain.
    // LogPrint("zoinode", "CZoinode::UpdateLastPaidBlock -- searching for block with payment to %s -- keeping old %d\n", vin.prevout.ToStringShort(), nBlockLastPaid);
}

bool CZoinodeBroadcast::Create(std::string strService, std::string strKeyZoinode, std::string strTxHash, std::string strOutputIndex, std::string &strErrorRet, CZoinodeBroadcast &mnbRet, bool fOffline) {
    LogPrintf("CZoinodeBroadcast::Create\n");
    CTxIn txin;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyZoinodeNew;
    CKey keyZoinodeNew;
    //need correct blocks to send ping
    if (!fOffline && !zoinodeSync.IsBlockchainSynced()) {
        strErrorRet = "Sync in progress. Must wait until sync is complete to start Zoinode";
        LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    //TODO
    if (!darkSendSigner.GetKeysFromSecret(strKeyZoinode, keyZoinodeNew, pubKeyZoinodeNew)) {
        strErrorRet = strprintf("Invalid zoinode key %s", strKeyZoinode);
        LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    if (!pwalletMain->GetZoinodeVinAndKeys(txin, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
        strErrorRet = strprintf("Could not allocate txin %s:%s for zoinode %s", strTxHash, strOutputIndex, strService);
        LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    CService service = CService(strService);
    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (service.GetPort() != mainnetDefaultPort) {
            strErrorRet = strprintf("Invalid port %u for zoinode %s, only %d is supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort);
            LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
            return false;
        }
    } else if (service.GetPort() == mainnetDefaultPort) {
        strErrorRet = strprintf("Invalid port %u for zoinode %s, %d is the only supported on mainnet.", service.GetPort(), strService, mainnetDefaultPort);
        LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
        return false;
    }

    return Create(txin, CService(strService), keyCollateralAddressNew, pubKeyCollateralAddressNew, keyZoinodeNew, pubKeyZoinodeNew, strErrorRet, mnbRet);
}

bool CZoinodeBroadcast::Create(CTxIn txin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyZoinodeNew, CPubKey pubKeyZoinodeNew, std::string &strErrorRet, CZoinodeBroadcast &mnbRet) {
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    LogPrint("zoinode", "CZoinodeBroadcast::Create -- pubKeyCollateralAddressNew = %s, pubKeyZoinodeNew.GetID() = %s\n",
             CBitcoinAddress(pubKeyCollateralAddressNew.GetID()).ToString(),
             pubKeyZoinodeNew.GetID().ToString());


    CZoinodePing mnp(txin);
    if (!mnp.Sign(keyZoinodeNew, pubKeyZoinodeNew)) {
        strErrorRet = strprintf("Failed to sign ping, zoinode=%s", txin.prevout.ToStringShort());
        LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CZoinodeBroadcast();
        return false;
    }

    mnbRet = CZoinodeBroadcast(service, txin, pubKeyCollateralAddressNew, pubKeyZoinodeNew, PROTOCOL_VERSION);

    if (!mnbRet.IsValidNetAddr()) {
        strErrorRet = strprintf("Invalid IP address, zoinode=%s", txin.prevout.ToStringShort());
        LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CZoinodeBroadcast();
        return false;
    }

    mnbRet.lastPing = mnp;
    if (!mnbRet.Sign(keyCollateralAddressNew)) {
        strErrorRet = strprintf("Failed to sign broadcast, zoinode=%s", txin.prevout.ToStringShort());
        LogPrintf("CZoinodeBroadcast::Create -- %s\n", strErrorRet);
        mnbRet = CZoinodeBroadcast();
        return false;
    }

    return true;
}

bool CZoinodeBroadcast::SimpleCheck(int &nDos) {
    nDos = 0;

    // make sure addr is valid
    if (!IsValidNetAddr()) {
        LogPrintf("CZoinodeBroadcast::SimpleCheck -- Invalid addr, rejected: zoinode=%s  addr=%s\n",
                  vin.prevout.ToStringShort(), addr.ToString());
        return false;
    }

    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CZoinodeBroadcast::SimpleCheck -- Signature rejected, too far into the future: zoinode=%s\n", vin.prevout.ToStringShort());
        nDos = 1;
        return false;
    }

    // empty ping or incorrect sigTime/unknown blockhash
    if (lastPing == CZoinodePing() || !lastPing.SimpleCheck(nDos)) {
        // one of us is probably forked or smth, just mark it as expired and check the rest of the rules
        nActiveState = ZOINODE_EXPIRED;
    }

    if (nProtocolVersion < mnpayments.GetMinZoinodePaymentsProto()) {
        LogPrintf("CZoinodeBroadcast::SimpleCheck -- ignoring outdated Zoinode: zoinode=%s  nProtocolVersion=%d\n", vin.prevout.ToStringShort(), nProtocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if (pubkeyScript.size() != 25) {
        LogPrintf("CZoinodeBroadcast::SimpleCheck -- pubKeyCollateralAddress has the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyZoinode.GetID());

    if (pubkeyScript2.size() != 25) {
        LogPrintf("CZoinodeBroadcast::SimpleCheck -- pubKeyZoinode has the wrong size\n");
        nDos = 100;
        return false;
    }

    if (!vin.scriptSig.empty()) {
        LogPrintf("CZoinodeBroadcast::SimpleCheck -- Ignore Not Empty ScriptSig %s\n", vin.ToString());
        nDos = 100;
        return false;
    }

    int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != mainnetDefaultPort) return false;
    } else if (addr.GetPort() == mainnetDefaultPort) return false;

    return true;
}

bool CZoinodeBroadcast::Update(CZoinode *pmn, int &nDos) {
    nDos = 0;

    if (pmn->sigTime == sigTime && !fRecovery) {
        // mapSeenZoinodeBroadcast in CZoinodeMan::CheckMnbAndUpdateZoinodeList should filter legit duplicates
        // but this still can happen if we just started, which is ok, just do nothing here.
        return false;
    }

    // this broadcast is older than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    if (pmn->sigTime > sigTime) {
        LogPrintf("CZoinodeBroadcast::Update -- Bad sigTime %d (existing broadcast is at %d) for Zoinode %s %s\n",
                  sigTime, pmn->sigTime, vin.prevout.ToStringShort(), addr.ToString());
        return false;
    }

    pmn->Check();

    // zoinode is banned by PoSe
    if (pmn->IsPoSeBanned()) {
        LogPrintf("CZoinodeBroadcast::Update -- Banned by PoSe, zoinode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // IsVnAssociatedWithPubkey is validated once in CheckOutpoint, after that they just need to match
    if (pmn->pubKeyCollateralAddress != pubKeyCollateralAddress) {
        LogPrintf("CZoinodeBroadcast::Update -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CZoinodeBroadcast::Update -- CheckSignature() failed, zoinode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    // if ther was no zoinode broadcast recently or if it matches our Zoinode privkey...
    if (!pmn->IsBroadcastedWithin(ZOINODE_MIN_MNB_SECONDS) || (fZoiNode && pubKeyZoinode == activeZoinode.pubKeyZoinode)) {
        // take the newest entry
        LogPrintf("CZoinodeBroadcast::Update -- Got UPDATED Zoinode entry: addr=%s\n", addr.ToString());
        if (pmn->UpdateFromNewBroadcast((*this))) {
            pmn->Check();
            RelayZoiNode();
        }
        zoinodeSync.AddedZoinodeList();
    }

    return true;
}

bool CZoinodeBroadcast::CheckOutpoint(int &nDos) {
    // we are a zoinode with the same vin (i.e. already activated) and this mnb is ours (matches our Zoinode privkey)
    // so nothing to do here for us
    if (fZoiNode && vin.prevout == activeZoinode.vin.prevout && pubKeyZoinode == activeZoinode.pubKeyZoinode) {
        return false;
    }

    if (!CheckSignature(nDos)) {
        LogPrintf("CZoinodeBroadcast::CheckOutpoint -- CheckSignature() failed, zoinode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            // not mnb fault, let it to be checked again later
            LogPrint("zoinode", "CZoinodeBroadcast::CheckOutpoint -- Failed to aquire lock, addr=%s", addr.ToString());
            mnodeman.mapSeenZoinodeBroadcast.erase(GetHash());
            return false;
        }

        CCoins coins;
        if (!pcoinsTip->GetCoins(vin.prevout.hash, coins) ||
            (unsigned int) vin.prevout.n >= coins.vout.size() ||
            coins.vout[vin.prevout.n].IsNull()) {
            LogPrint("zoinode", "CZoinodeBroadcast::CheckOutpoint -- Failed to find Zoinode UTXO, zoinode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
        if (coins.vout[vin.prevout.n].nValue != ZOINODE_COIN_REQUIRED * COIN) {
            LogPrint("zoinode", "CZoinodeBroadcast::CheckOutpoint -- Zoinode UTXO should have 25000 ZOI, zoinode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
        if (chainActive.Height() - coins.nHeight + 1 < Params().GetConsensus().nZoinodeMinimumConfirmations) {
            LogPrintf("CZoinodeBroadcast::CheckOutpoint -- Zoinode UTXO must have at least %d confirmations, zoinode=%s\n",
                      Params().GetConsensus().nZoinodeMinimumConfirmations, vin.prevout.ToStringShort());
            // maybe we miss few blocks, let this mnb to be checked again later
            mnodeman.mapSeenZoinodeBroadcast.erase(GetHash());
            return false;
        }
    }

    LogPrint("zoinode", "CZoinodeBroadcast::CheckOutpoint -- Zoinode UTXO verified\n");

    // make sure the vout that was signed is related to the transaction that spawned the Zoinode
    //  - this is expensive, so it's only done once per Zoinode
    if (!darkSendSigner.IsVinAssociatedWithPubkey(vin, pubKeyCollateralAddress)) {
        LogPrintf("CZoinodeMan::CheckOutpoint -- Got mismatched pubKeyCollateralAddress and vin\n");
        nDos = 33;
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 25000 ZOI tx got nZoinodeMinimumConfirmations
    uint256 hashBlock = uint256();
    CTransaction tx2;
    GetTransaction(vin.prevout.hash, tx2, Params().GetConsensus(), hashBlock, true);
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second) {
            CBlockIndex *pMNIndex = (*mi).second; // block for 25000 ZOI tx -> 1 confirmation
            CBlockIndex *pConfIndex = chainActive[pMNIndex->nHeight + Params().GetConsensus().nZoinodeMinimumConfirmations - 1]; // block where tx got nZoinodeMinimumConfirmations
            if (pConfIndex->GetBlockTime() > sigTime) {
                LogPrintf("CZoinodeBroadcast::CheckOutpoint -- Bad sigTime %d (%d conf block is at %d) for Zoinode %s %s\n",
                          sigTime, Params().GetConsensus().nZoinodeMinimumConfirmations, pConfIndex->GetBlockTime(), vin.prevout.ToStringShort(), addr.ToString());
                return false;
            }
        }
    }

    return true;
}

bool CZoinodeBroadcast::Sign(CKey &keyCollateralAddress) {
    std::string strError;
    std::string strMessage;

    sigTime = GetAdjustedTime();

    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                 pubKeyCollateralAddress.GetID().ToString() + pubKeyZoinode.GetID().ToString() +
                 boost::lexical_cast<std::string>(nProtocolVersion);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, keyCollateralAddress)) {
        LogPrintf("CZoinodeBroadcast::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
        LogPrintf("CZoinodeBroadcast::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CZoinodeBroadcast::CheckSignature(int &nDos) {
    std::string strMessage;
    std::string strError = "";
    nDos = 0;

    strMessage = addr.ToString() + boost::lexical_cast<std::string>(sigTime) +
                 pubKeyCollateralAddress.GetID().ToString() + pubKeyZoinode.GetID().ToString() +
                 boost::lexical_cast<std::string>(nProtocolVersion);

    LogPrint("zoinode", "CZoinodeBroadcast::CheckSignature -- strMessage: %s  pubKeyCollateralAddress address: %s  sig: %s\n", strMessage, CBitcoinAddress(pubKeyCollateralAddress.GetID()).ToString(), EncodeBase64(&vchSig[0], vchSig.size()));

    if (!darkSendSigner.VerifyMessage(pubKeyCollateralAddress, vchSig, strMessage, strError)) {
        LogPrintf("CZoinodeBroadcast::CheckSignature -- Got bad Zoinode announce signature, error: %s\n", strError);
        nDos = 100;
        return false;
    }

    return true;
}

void CZoinodeBroadcast::RelayZoiNode() {
    LogPrintf("CZoinodeBroadcast::RelayZoiNode\n");
    CInv inv(MSG_ZOINODE_ANNOUNCE, GetHash());
    RelayInv(inv);
}

CZoinodePing::CZoinodePing(CTxIn &vinNew) {
    LOCK(cs_main);
    if (!chainActive.Tip() || chainActive.Height() < 12) return;

    vin = vinNew;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    vchSig = std::vector < unsigned char > ();
}

bool CZoinodePing::Sign(CKey &keyZoinode, CPubKey &pubKeyZoinode) {
    std::string strError;
    std::string strZoiNodeSignMessage;

    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, keyZoinode)) {
        LogPrintf("CZoinodePing::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!darkSendSigner.VerifyMessage(pubKeyZoinode, vchSig, strMessage, strError)) {
        LogPrintf("CZoinodePing::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CZoinodePing::CheckSignature(CPubKey &pubKeyZoinode, int &nDos) {
    std::string strMessage = vin.ToString() + blockHash.ToString() + boost::lexical_cast<std::string>(sigTime);
    std::string strError = "";
    nDos = 0;

    if (!darkSendSigner.VerifyMessage(pubKeyZoinode, vchSig, strMessage, strError)) {
        LogPrintf("CZoinodePing::CheckSignature -- Got bad Zoinode ping signature, zoinode=%s, error: %s\n", vin.prevout.ToStringShort(), strError);
        nDos = 33;
        return false;
    }
    return true;
}

bool CZoinodePing::SimpleCheck(int &nDos) {
    // don't ban by default
    nDos = 0;

    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrintf("CZoinodePing::SimpleCheck -- Signature rejected, too far into the future, zoinode=%s\n", vin.prevout.ToStringShort());
        nDos = 1;
        return false;
    }

    {
//        LOCK(cs_main);
        AssertLockHeld(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if (mi == mapBlockIndex.end()) {
            LogPrint("zoinode", "CZoinodePing::SimpleCheck -- Zoinode ping is invalid, unknown block hash: zoinode=%s blockHash=%s\n", vin.prevout.ToStringShort(), blockHash.ToString());
            // maybe we stuck or forked so we shouldn't ban this node, just fail to accept this ping
            // TODO: or should we also request this block?
            return false;
        }
    }
    LogPrint("zoinode", "CZoinodePing::SimpleCheck -- Zoinode ping verified: zoinode=%s  blockHash=%s  sigTime=%d\n", vin.prevout.ToStringShort(), blockHash.ToString(), sigTime);
    return true;
}

bool CZoinodePing::CheckAndUpdate(CZoinode *pmn, bool fFromNewBroadcast, int &nDos) {
    // don't ban by default
    nDos = 0;

    if (!SimpleCheck(nDos)) {
        return false;
    }

    if (pmn == NULL) {
        LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- Couldn't find Zoinode entry, zoinode=%s\n", vin.prevout.ToStringShort());
        return false;
    }

    if (!fFromNewBroadcast) {
        if (pmn->IsUpdateRequired()) {
            LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- zoinode protocol is outdated, zoinode=%s\n", vin.prevout.ToStringShort());
            return false;
        }

        if (pmn->IsNewStartRequired()) {
            LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- zoinode is completely expired, new start is required, zoinode=%s\n", vin.prevout.ToStringShort());
            return false;
        }
    }

    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(blockHash);
        if ((*mi).second && (*mi).second->nHeight < chainActive.Height() - 24) {
            LogPrintf("CZoinodePing::CheckAndUpdate -- Zoinode ping is invalid, block hash is too old: zoinode=%s  blockHash=%s\n", vin.prevout.ToStringShort(), blockHash.ToString());
            // nDos = 1;
            return false;
        }
    }

    LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- New ping: zoinode=%s  blockHash=%s  sigTime=%d\n", vin.prevout.ToStringShort(), blockHash.ToString(), sigTime);

    // LogPrintf("mnping - Found corresponding mn for vin: %s\n", vin.prevout.ToStringShort());
    // update only if there is no known ping for this zoinode or
    // last ping was more then ZOINODE_MIN_MNP_SECONDS-60 ago comparing to this one
    if (pmn->IsPingedWithin(ZOINODE_MIN_MNP_SECONDS - 60, sigTime)) {
        LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- Zoinode ping arrived too early, zoinode=%s\n", vin.prevout.ToStringShort());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }

    if (!CheckSignature(pmn->pubKeyZoinode, nDos)) return false;

    // so, ping seems to be ok

    // if we are still syncing and there was no known ping for this mn for quite a while
    // (NOTE: assuming that ZOINODE_EXPIRATION_SECONDS/2 should be enough to finish mn list sync)
    if (!zoinodeSync.IsZoinodeListSynced() && !pmn->IsPingedWithin(ZOINODE_EXPIRATION_SECONDS / 2)) {
        // let's bump sync timeout
        LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- bumping sync timeout, zoinode=%s\n", vin.prevout.ToStringShort());
        zoinodeSync.AddedZoinodeList();
    }

    // let's store this ping as the last one
    LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- Zoinode ping accepted, zoinode=%s\n", vin.prevout.ToStringShort());
    pmn->lastPing = *this;

    // and update zoinodeman.mapSeenZoinodeBroadcast.lastPing which is probably outdated
    CZoinodeBroadcast mnb(*pmn);
    uint256 hash = mnb.GetHash();
    if (mnodeman.mapSeenZoinodeBroadcast.count(hash)) {
        mnodeman.mapSeenZoinodeBroadcast[hash].second.lastPing = *this;
    }

    pmn->Check(true); // force update, ignoring cache
    if (!pmn->IsEnabled()) return false;

    LogPrint("zoinode", "CZoinodePing::CheckAndUpdate -- Zoinode ping acceepted and relayed, zoinode=%s\n", vin.prevout.ToStringShort());
    Relay();

    return true;
}

void CZoinodePing::Relay() {
    CInv inv(MSG_ZOINODE_PING, GetHash());
    RelayInv(inv);
}

//void CZoinode::AddGovernanceVote(uint256 nGovernanceObjectHash)
//{
//    if(mapGovernanceObjectsVotedOn.count(nGovernanceObjectHash)) {
//        mapGovernanceObjectsVotedOn[nGovernanceObjectHash]++;
//    } else {
//        mapGovernanceObjectsVotedOn.insert(std::make_pair(nGovernanceObjectHash, 1));
//    }
//}

//void CZoinode::RemoveGovernanceObject(uint256 nGovernanceObjectHash)
//{
//    std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.find(nGovernanceObjectHash);
//    if(it == mapGovernanceObjectsVotedOn.end()) {
//        return;
//    }
//    mapGovernanceObjectsVotedOn.erase(it);
//}

void CZoinode::UpdateWatchdogVoteTime() {
    LOCK(cs);
    nTimeLastWatchdogVote = GetTime();
}

/**
*   FLAG GOVERNANCE ITEMS AS DIRTY
*
*   - When zoinode come and go on the network, we must flag the items they voted on to recalc it's cached flags
*
*/
//void CZoinode::FlagGovernanceItemsAsDirty()
//{
//    std::vector<uint256> vecDirty;
//    {
//        std::map<uint256, int>::iterator it = mapGovernanceObjectsVotedOn.begin();
//        while(it != mapGovernanceObjectsVotedOn.end()) {
//            vecDirty.push_back(it->first);
//            ++it;
//        }
//    }
//    for(size_t i = 0; i < vecDirty.size(); ++i) {
//        zoinodeman.AddDirtyGovernanceObjectHash(vecDirty[i]);
//    }
//}
