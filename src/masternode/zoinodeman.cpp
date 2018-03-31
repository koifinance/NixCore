// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activezoinode.h"
#include "addrman.h"
#include "darksend.h"
//#include "governance.h"
#include "zoinode-payments.h"
#include "zoinode-sync.h"
#include "zoinodeman.h"
#include "netfulfilledman.h"
#include "util.h"
//#include "random.h"

/** Zoinode manager */
CZoinodeMan mnodeman;

const std::string CZoinodeMan::SERIALIZATION_VERSION_STRING = "CZoinodeMan-Version-4";

struct CompareLastPaidBlock
{
    bool operator()(const std::pair<int, CZoinode*>& t1,
                    const std::pair<int, CZoinode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

struct CompareScoreMN
{
    bool operator()(const std::pair<int64_t, CZoinode*>& t1,
                    const std::pair<int64_t, CZoinode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

CZoinodeIndex::CZoinodeIndex()
    : nSize(0),
      mapIndex(),
      mapReverseIndex()
{}

bool CZoinodeIndex::Get(int nIndex, CTxIn& vinZoinode) const
{
    rindex_m_cit it = mapReverseIndex.find(nIndex);
    if(it == mapReverseIndex.end()) {
        return false;
    }
    vinZoinode = it->second;
    return true;
}

int CZoinodeIndex::GetZoinodeIndex(const CTxIn& vinZoinode) const
{
    index_m_cit it = mapIndex.find(vinZoinode);
    if(it == mapIndex.end()) {
        return -1;
    }
    return it->second;
}

void CZoinodeIndex::AddZoinodeVIN(const CTxIn& vinZoinode)
{
    index_m_it it = mapIndex.find(vinZoinode);
    if(it != mapIndex.end()) {
        return;
    }
    int nNextIndex = nSize;
    mapIndex[vinZoinode] = nNextIndex;
    mapReverseIndex[nNextIndex] = vinZoinode;
    ++nSize;
}

void CZoinodeIndex::Clear()
{
    mapIndex.clear();
    mapReverseIndex.clear();
    nSize = 0;
}
struct CompareByAddr

{
    bool operator()(const CZoinode* t1,
                    const CZoinode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

void CZoinodeIndex::RebuildIndex()
{
    nSize = mapIndex.size();
    for(index_m_it it = mapIndex.begin(); it != mapIndex.end(); ++it) {
        mapReverseIndex[it->second] = it->first;
    }
}

CZoinodeMan::CZoinodeMan() : cs(),
  vZoinodes(),
  mAskedUsForZoinodeList(),
  mWeAskedForZoinodeList(),
  mWeAskedForZoinodeListEntry(),
  mWeAskedForVerification(),
  mMnbRecoveryRequests(),
  mMnbRecoveryGoodReplies(),
  listScheduledMnbRequestConnections(),
  nLastIndexRebuildTime(0),
  indexZoinodes(),
  indexZoinodesOld(),
  fIndexRebuilt(false),
  fZoinodesAdded(false),
  fZoinodesRemoved(false),
//  vecDirtyGovernanceObjectHashes(),
  nLastWatchdogVoteTime(0),
  mapSeenZoinodeBroadcast(),
  mapSeenZoinodePing(),
  nDsqCount(0)
{}

bool CZoinodeMan::Add(CZoinode &mn)
{
    LOCK(cs);

    CZoinode *pmn = Find(mn.vin);
    if (pmn == NULL) {
        LogPrint("zoinode", "CZoinodeMan::Add -- Adding new Zoinode: addr=%s, %i now\n", mn.addr.ToString(), size() + 1);
        vZoinodes.push_back(mn);
        indexZoinodes.AddZoinodeVIN(mn.vin);
        fZoinodesAdded = true;
        return true;
    }

    return false;
}

void CZoinodeMan::AskForMN(CNode* pnode, const CTxIn &vin)
{
    if(!pnode) return;

    LOCK(cs);

    std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it1 = mWeAskedForZoinodeListEntry.find(vin.prevout);
    if (it1 != mWeAskedForZoinodeListEntry.end()) {
        std::map<CNetAddr, int64_t>::iterator it2 = it1->second.find(pnode->addr);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            LogPrintf("CZoinodeMan::AskForMN -- Asking same peer %s for missing zoinode entry again: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
        } else {
            // we already asked for this outpoint but not this node
            LogPrintf("CZoinodeMan::AskForMN -- Asking new peer %s for missing zoinode entry: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
        }
    } else {
        // we never asked any node for this outpoint
        LogPrintf("CZoinodeMan::AskForMN -- Asking peer %s for missing zoinode entry for the first time: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
    }
    mWeAskedForZoinodeListEntry[vin.prevout][pnode->addr] = GetTime() + DSEG_UPDATE_SECONDS;

    pnode->PushMessage(NetMsgType::DSEG, vin);
}

void CZoinodeMan::Check()
{
    LOCK(cs);

//    LogPrint("zoinode", "CZoinodeMan::Check -- nLastWatchdogVoteTime=%d, IsWatchdogActive()=%d\n", nLastWatchdogVoteTime, IsWatchdogActive());

    BOOST_FOREACH(CZoinode& mn, vZoinodes) {
        mn.Check();
    }
}

void CZoinodeMan::CheckAndRemove()
{
    if(!zoinodeSync.IsZoinodeListSynced()) return;

    LogPrintf("CZoinodeMan::CheckAndRemove\n");

    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckMnbAndUpdateZoinodeList()
        LOCK2(cs_main, cs);

        Check();

        // Remove spent zoinodes, prepare structures and make requests to reasure the state of inactive ones
        std::vector<CZoinode>::iterator it = vZoinodes.begin();
        std::vector<std::pair<int, CZoinode> > vecZoinodeRanks;
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES zoinode entries at a time
        int nAskForMnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        while(it != vZoinodes.end()) {
            CZoinodeBroadcast mnb = CZoinodeBroadcast(*it);
            uint256 hash = mnb.GetHash();
            // If collateral was spent ...
            if ((*it).IsOutpointSpent()) {
                LogPrint("zoinode", "CZoinodeMan::CheckAndRemove -- Removing Zoinode: %s  addr=%s  %i now\n", (*it).GetStateString(), (*it).addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenZoinodeBroadcast.erase(hash);
                mWeAskedForZoinodeListEntry.erase((*it).vin.prevout);

                // and finally remove it from the list
//                it->FlagGovernanceItemsAsDirty();
                it = vZoinodes.erase(it);
                fZoinodesRemoved = true;
            } else {
                bool fAsk = pCurrentBlockIndex &&
                            (nAskForMnbRecovery > 0) &&
                            zoinodeSync.IsSynced() &&
                            it->IsNewStartRequired() &&
                            !IsMnbRecoveryRequested(hash);
                if(fAsk) {
                    // this mn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CNetAddr> setRequested;
                    // calulate only once and only when it's needed
                    if(vecZoinodeRanks.empty()) {
                        int nRandomBlockHeight = GetRandInt(pCurrentBlockIndex->nHeight);
                        vecZoinodeRanks = GetZoinodeRanks(nRandomBlockHeight);
                    }
                    bool fAskedForMnbRecovery = false;
                    // ask first MNB_RECOVERY_QUORUM_TOTAL zoinodes we can connect to and we haven't asked recently
                    for(int i = 0; setRequested.size() < MNB_RECOVERY_QUORUM_TOTAL && i < (int)vecZoinodeRanks.size(); i++) {
                        // avoid banning
                        if(mWeAskedForZoinodeListEntry.count(it->vin.prevout) && mWeAskedForZoinodeListEntry[it->vin.prevout].count(vecZoinodeRanks[i].second.addr)) continue;
                        // didn't ask recently, ok to ask now
                        CService addr = vecZoinodeRanks[i].second.addr;
                        setRequested.insert(addr);
                        listScheduledMnbRequestConnections.push_back(std::make_pair(addr, hash));
                        fAskedForMnbRecovery = true;
                    }
                    if(fAskedForMnbRecovery) {
                        LogPrint("zoinode", "CZoinodeMan::CheckAndRemove -- Recovery initiated, zoinode=%s\n", it->vin.prevout.ToStringShort());
                        nAskForMnbRecovery--;
                    }
                    // wait for mnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mMnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for ZOINODE_NEW_START_REQUIRED zoinodes
        LogPrint("zoinode", "CZoinodeMan::CheckAndRemove -- mMnbRecoveryGoodReplies size=%d\n", (int)mMnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CZoinodeBroadcast> >::iterator itMnbReplies = mMnbRecoveryGoodReplies.begin();
        while(itMnbReplies != mMnbRecoveryGoodReplies.end()){
            if(mMnbRecoveryRequests[itMnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if(itMnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this mn doesn't require new mnb, reprocess one of new mnbs
                    LogPrint("zoinode", "CZoinodeMan::CheckAndRemove -- reprocessing mnb, zoinode=%s\n", itMnbReplies->second[0].vin.prevout.ToStringShort());
                    // mapSeenZoinodeBroadcast.erase(itMnbReplies->first);
                    int nDos;
                    itMnbReplies->second[0].fRecovery = true;
                    CheckMnbAndUpdateZoinodeList(NULL, itMnbReplies->second[0], nDos);
                }
                LogPrint("zoinode", "CZoinodeMan::CheckAndRemove -- removing mnb recovery reply, zoinode=%s, size=%d\n", itMnbReplies->second[0].vin.prevout.ToStringShort(), (int)itMnbReplies->second.size());
                mMnbRecoveryGoodReplies.erase(itMnbReplies++);
            } else {
                ++itMnbReplies;
            }
        }
    }
    {
        // no need for cm_main below
        LOCK(cs);

        std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > >::iterator itMnbRequest = mMnbRecoveryRequests.begin();
        while(itMnbRequest != mMnbRecoveryRequests.end()){
            // Allow this mnb to be re-verified again after MNB_RECOVERY_RETRY_SECONDS seconds
            // if mn is still in ZOINODE_NEW_START_REQUIRED state.
            if(GetTime() - itMnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mMnbRecoveryRequests.erase(itMnbRequest++);
            } else {
                ++itMnbRequest;
            }
        }

        // check who's asked for the Zoinode list
        std::map<CNetAddr, int64_t>::iterator it1 = mAskedUsForZoinodeList.begin();
        while(it1 != mAskedUsForZoinodeList.end()){
            if((*it1).second < GetTime()) {
                mAskedUsForZoinodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Zoinode list
        it1 = mWeAskedForZoinodeList.begin();
        while(it1 != mWeAskedForZoinodeList.end()){
            if((*it1).second < GetTime()){
                mWeAskedForZoinodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Zoinodes we've asked for
        std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it2 = mWeAskedForZoinodeListEntry.begin();
        while(it2 != mWeAskedForZoinodeListEntry.end()){
            std::map<CNetAddr, int64_t>::iterator it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if(it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if(it2->second.empty()) {
                mWeAskedForZoinodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        std::map<CNetAddr, CZoinodeVerification>::iterator it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if(it3->second.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenZoinodeBroadcast entries here, clean them on mnb updates!

        // remove expired mapSeenZoinodePing
        std::map<uint256, CZoinodePing>::iterator it4 = mapSeenZoinodePing.begin();
        while(it4 != mapSeenZoinodePing.end()){
            if((*it4).second.IsExpired()) {
                LogPrint("zoinode", "CZoinodeMan::CheckAndRemove -- Removing expired Zoinode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenZoinodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenZoinodeVerification
        std::map<uint256, CZoinodeVerification>::iterator itv2 = mapSeenZoinodeVerification.begin();
        while(itv2 != mapSeenZoinodeVerification.end()){
            if((*itv2).second.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS){
                LogPrint("zoinode", "CZoinodeMan::CheckAndRemove -- Removing expired Zoinode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenZoinodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        LogPrintf("CZoinodeMan::CheckAndRemove -- %s\n", ToString());

        if(fZoinodesRemoved) {
            CheckAndRebuildZoinodeIndex();
        }
    }

    if(fZoinodesRemoved) {
        NotifyZoinodeUpdates();
    }
}

void CZoinodeMan::Clear()
{
    LOCK(cs);
    vZoinodes.clear();
    mAskedUsForZoinodeList.clear();
    mWeAskedForZoinodeList.clear();
    mWeAskedForZoinodeListEntry.clear();
    mapSeenZoinodeBroadcast.clear();
    mapSeenZoinodePing.clear();
    nDsqCount = 0;
    nLastWatchdogVoteTime = 0;
    indexZoinodes.Clear();
    indexZoinodesOld.Clear();
}

int CZoinodeMan::CountZoinodes(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinZoinodePaymentsProto() : nProtocolVersion;

    BOOST_FOREACH(CZoinode& mn, vZoinodes) {
        if(mn.nProtocolVersion < nProtocolVersion) continue;
        nCount++;
    }

    return nCount;
}

int CZoinodeMan::CountEnabled(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinZoinodePaymentsProto() : nProtocolVersion;

    BOOST_FOREACH(CZoinode& mn, vZoinodes) {
        if(mn.nProtocolVersion < nProtocolVersion || !mn.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

/* Only IPv4 zoinodes are allowed in 12.1, saving this for later
int CZoinodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    BOOST_FOREACH(CZoinode& mn, vZoinodes)
        if ((nNetworkType == NET_IPV4 && mn.addr.IsIPv4()) ||
            (nNetworkType == NET_TOR  && mn.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && mn.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}
*/

void CZoinodeMan::DsegUpdate(CNode* pnode)
{
    LOCK(cs);

    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForZoinodeList.find(pnode->addr);
            if(it != mWeAskedForZoinodeList.end() && GetTime() < (*it).second) {
                LogPrintf("CZoinodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", pnode->addr.ToString());
                return;
            }
        }
    }
    
    pnode->PushMessage(NetMsgType::DSEG, CTxIn());
    int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
    mWeAskedForZoinodeList[pnode->addr] = askAgain;

    LogPrint("zoinode", "CZoinodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CZoinode* CZoinodeMan::Find(const CScript &payee)
{
    LOCK(cs);

    BOOST_FOREACH(CZoinode& mn, vZoinodes)
    {
        if(GetScriptForDestination(mn.pubKeyCollateralAddress.GetID()) == payee)
            return &mn;
    }
    return NULL;
}

CZoinode* CZoinodeMan::Find(const CTxIn &vin)
{
    LOCK(cs);

    BOOST_FOREACH(CZoinode& mn, vZoinodes)
    {
        if(mn.vin.prevout == vin.prevout)
            return &mn;
    }
    return NULL;
}

CZoinode* CZoinodeMan::Find(const CPubKey &pubKeyZoinode)
{
    LOCK(cs);

    BOOST_FOREACH(CZoinode& mn, vZoinodes)
    {
        if(mn.pubKeyZoinode == pubKeyZoinode)
            return &mn;
    }
    return NULL;
}

bool CZoinodeMan::Get(const CPubKey& pubKeyZoinode, CZoinode& zoinode)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    CZoinode* pMN = Find(pubKeyZoinode);
    if(!pMN)  {
        return false;
    }
    zoinode = *pMN;
    return true;
}

bool CZoinodeMan::Get(const CTxIn& vin, CZoinode& zoinode)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    if(!pMN)  {
        return false;
    }
    zoinode = *pMN;
    return true;
}

zoinode_info_t CZoinodeMan::GetZoinodeInfo(const CTxIn& vin)
{
    zoinode_info_t info;
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    if(!pMN)  {
        return info;
    }
    info = pMN->GetInfo();
    return info;
}

zoinode_info_t CZoinodeMan::GetZoinodeInfo(const CPubKey& pubKeyZoinode)
{
    zoinode_info_t info;
    LOCK(cs);
    CZoinode* pMN = Find(pubKeyZoinode);
    if(!pMN)  {
        return info;
    }
    info = pMN->GetInfo();
    return info;
}

bool CZoinodeMan::Has(const CTxIn& vin)
{
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    return (pMN != NULL);
}

char* CZoinodeMan::GetNotQualifyReason(CZoinode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount)
{
    if (!mn.IsValidForPayment()) {
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'not valid for payment'");
        return reasonStr;
    }
    // //check protocol version
    if (mn.nProtocolVersion < mnpayments.GetMinZoinodePaymentsProto()) {
        // LogPrintf("Invalid nProtocolVersion!\n");
        // LogPrintf("mn.nProtocolVersion=%s!\n", mn.nProtocolVersion);
        // LogPrintf("mnpayments.GetMinZoinodePaymentsProto=%s!\n", mnpayments.GetMinZoinodePaymentsProto());
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'Invalid nProtocolVersion', nProtocolVersion=%d", mn.nProtocolVersion);
        return reasonStr;
    }
    //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
    if (mnpayments.IsScheduled(mn, nBlockHeight)) {
        // LogPrintf("mnpayments.IsScheduled!\n");
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'is scheduled'");
        return reasonStr;
    }
    //it's too new, wait for a cycle
    if (fFilterSigTime && mn.sigTime + (nMnCount * 2.6 * 60) > GetAdjustedTime()) {
        // LogPrintf("it's too new, wait for a cycle!\n");
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'too new', sigTime=%s, will be qualifed after=%s",
                DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime).c_str(), DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime + (nMnCount * 2.6 * 60)).c_str());
        return reasonStr;
    }
    //make sure it has at least as many confirmations as there are zoinodes
    if (mn.GetCollateralAge() < nMnCount) {
        // LogPrintf("mn.GetCollateralAge()=%s!\n", mn.GetCollateralAge());
        // LogPrintf("nMnCount=%s!\n", nMnCount);
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'collateralAge < znCount', collateralAge=%d, znCount=%d", mn.GetCollateralAge(), nMnCount);
        return reasonStr;
    }
    return NULL;
}

//
// Deterministically select the oldest/best zoinode to pay on the network
//
CZoinode* CZoinodeMan::GetNextZoinodeInQueueForPayment(bool fFilterSigTime, int& nCount)
{
    if(!pCurrentBlockIndex) {
        nCount = 0;
        return NULL;
    }
    return GetNextZoinodeInQueueForPayment(pCurrentBlockIndex->nHeight, fFilterSigTime, nCount);
}

CZoinode* CZoinodeMan::GetNextZoinodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount)
{
    // Need LOCK2 here to ensure consistent locking order because the GetBlockHash call below locks cs_main
    LOCK2(cs_main,cs);

    CZoinode *pBestZoinode = NULL;
    std::vector<std::pair<int, CZoinode*> > vecZoinodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */
    int nMnCount = CountEnabled();
    int index = 0;
    BOOST_FOREACH(CZoinode &mn, vZoinodes)
    {
        index += 1;
        // LogPrintf("index=%s, mn=%s\n", index, mn.ToString());
        /*if (!mn.IsValidForPayment()) {
            LogPrint("zoinodeman", "Zoinode, %s, addr(%s), not-qualified: 'not valid for payment'\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString());
            continue;
        }
        // //check protocol version
        if (mn.nProtocolVersion < mnpayments.GetMinZoinodePaymentsProto()) {
            // LogPrintf("Invalid nProtocolVersion!\n");
            // LogPrintf("mn.nProtocolVersion=%s!\n", mn.nProtocolVersion);
            // LogPrintf("mnpayments.GetMinZoinodePaymentsProto=%s!\n", mnpayments.GetMinZoinodePaymentsProto());
            LogPrint("zoinodeman", "Zoinode, %s, addr(%s), not-qualified: 'invalid nProtocolVersion'\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString());
            continue;
        }
        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (mnpayments.IsScheduled(mn, nBlockHeight)) {
            // LogPrintf("mnpayments.IsScheduled!\n");
            LogPrint("zoinodeman", "Zoinode, %s, addr(%s), not-qualified: 'IsScheduled'\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString());
            continue;
        }
        //it's too new, wait for a cycle
        if (fFilterSigTime && mn.sigTime + (nMnCount * 2.6 * 60) > GetAdjustedTime()) {
            // LogPrintf("it's too new, wait for a cycle!\n");
            LogPrint("zoinodeman", "Zoinode, %s, addr(%s), not-qualified: 'it's too new, wait for a cycle!', sigTime=%s, will be qualifed after=%s\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString(), DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime).c_str(), DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime + (nMnCount * 2.6 * 60)).c_str());
            continue;
        }
        //make sure it has at least as many confirmations as there are zoinodes
        if (mn.GetCollateralAge() < nMnCount) {
            // LogPrintf("mn.GetCollateralAge()=%s!\n", mn.GetCollateralAge());
            // LogPrintf("nMnCount=%s!\n", nMnCount);
            LogPrint("zoinodeman", "Zoinode, %s, addr(%s), not-qualified: 'mn.GetCollateralAge() < nMnCount', CollateralAge=%d, nMnCount=%d\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString(), mn.GetCollateralAge(), nMnCount);
            continue;
        }*/
        char* reasonStr = GetNotQualifyReason(mn, nBlockHeight, fFilterSigTime, nMnCount);
        if (reasonStr != NULL) {
            LogPrint("zoinodeman", "Zoinode, %s, addr(%s), qualify %s\n",
                     mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString(), reasonStr);
            delete [] reasonStr;
            continue;
        }
        vecZoinodeLastPaid.push_back(std::make_pair(mn.GetLastPaidBlock(), &mn));
    }
    nCount = (int)vecZoinodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if(fFilterSigTime && nCount < nMnCount / 3) {
        // LogPrintf("Need Return, nCount=%s, nMnCount/3=%s\n", nCount, nMnCount/3);
        return GetNextZoinodeInQueueForPayment(nBlockHeight, false, nCount);
    }

    // Sort them low to high
    sort(vecZoinodeLastPaid.begin(), vecZoinodeLastPaid.end(), CompareLastPaidBlock());

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight - 101)) {
        LogPrintf("CZoinode::GetNextZoinodeInQueueForPayment -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight - 101);
        return NULL;
    }
    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = nMnCount/10;
    int nCountTenth = 0;
    arith_uint256 nHighest = 0;
    BOOST_FOREACH (PAIRTYPE(int, CZoinode*)& s, vecZoinodeLastPaid){
        arith_uint256 nScore = s.second->CalculateScore(blockHash);
        if(nScore > nHighest){
            nHighest = nScore;
            pBestZoinode = s.second;
        }
        nCountTenth++;
        if(nCountTenth >= nTenthNetwork) break;
    }
    return pBestZoinode;
}

CZoinode* CZoinodeMan::FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion)
{
    LOCK(cs);

    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinZoinodePaymentsProto() : nProtocolVersion;

    int nCountEnabled = CountEnabled(nProtocolVersion);
    int nCountNotExcluded = nCountEnabled - vecToExclude.size();

    LogPrintf("CZoinodeMan::FindRandomNotInVec -- %d enabled zoinodes, %d zoinodes to choose from\n", nCountEnabled, nCountNotExcluded);
    if(nCountNotExcluded < 1) return NULL;

    // fill a vector of pointers
    std::vector<CZoinode*> vpZoinodesShuffled;
    BOOST_FOREACH(CZoinode &mn, vZoinodes) {
        vpZoinodesShuffled.push_back(&mn);
    }

    InsecureRand insecureRand;
    // shuffle pointers
    std::random_shuffle(vpZoinodesShuffled.begin(), vpZoinodesShuffled.end(), insecureRand);
    bool fExclude;

    // loop through
    BOOST_FOREACH(CZoinode* pmn, vpZoinodesShuffled) {
        if(pmn->nProtocolVersion < nProtocolVersion || !pmn->IsEnabled()) continue;
        fExclude = false;
        BOOST_FOREACH(const CTxIn &txinToExclude, vecToExclude) {
            if(pmn->vin.prevout == txinToExclude.prevout) {
                fExclude = true;
                break;
            }
        }
        if(fExclude) continue;
        // found the one not in vecToExclude
        LogPrint("zoinode", "CZoinodeMan::FindRandomNotInVec -- found, zoinode=%s\n", pmn->vin.prevout.ToStringShort());
        return pmn;
    }

    LogPrint("zoinode", "CZoinodeMan::FindRandomNotInVec -- failed\n");
    return NULL;
}

int CZoinodeMan::GetZoinodeRank(const CTxIn& vin, int nBlockHeight, int nMinProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CZoinode*> > vecZoinodeScores;

    //make sure we know about this block
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, nBlockHeight)) return -1;

    LOCK(cs);

    // scan for winner
    BOOST_FOREACH(CZoinode& mn, vZoinodes) {
        if(mn.nProtocolVersion < nMinProtocol) continue;
        if(fOnlyActive) {
            if(!mn.IsEnabled()) continue;
        }
        else {
            if(!mn.IsValidForPayment()) continue;
        }
        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecZoinodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecZoinodeScores.rbegin(), vecZoinodeScores.rend(), CompareScoreMN());

    int nRank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CZoinode*)& scorePair, vecZoinodeScores) {
        nRank++;
        if(scorePair.second->vin.prevout == vin.prevout) return nRank;
    }

    return -1;
}

std::vector<std::pair<int, CZoinode> > CZoinodeMan::GetZoinodeRanks(int nBlockHeight, int nMinProtocol)
{
    std::vector<std::pair<int64_t, CZoinode*> > vecZoinodeScores;
    std::vector<std::pair<int, CZoinode> > vecZoinodeRanks;

    //make sure we know about this block
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, nBlockHeight)) return vecZoinodeRanks;

    LOCK(cs);

    // scan for winner
    BOOST_FOREACH(CZoinode& mn, vZoinodes) {

        if(mn.nProtocolVersion < nMinProtocol || !mn.IsEnabled()) continue;

        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecZoinodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecZoinodeScores.rbegin(), vecZoinodeScores.rend(), CompareScoreMN());

    int nRank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CZoinode*)& s, vecZoinodeScores) {
        nRank++;
        vecZoinodeRanks.push_back(std::make_pair(nRank, *s.second));
    }

    return vecZoinodeRanks;
}

CZoinode* CZoinodeMan::GetZoinodeByRank(int nRank, int nBlockHeight, int nMinProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CZoinode*> > vecZoinodeScores;

    LOCK(cs);

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight)) {
        LogPrintf("CZoinode::GetZoinodeByRank -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight);
        return NULL;
    }

    // Fill scores
    BOOST_FOREACH(CZoinode& mn, vZoinodes) {

        if(mn.nProtocolVersion < nMinProtocol) continue;
        if(fOnlyActive && !mn.IsEnabled()) continue;

        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecZoinodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecZoinodeScores.rbegin(), vecZoinodeScores.rend(), CompareScoreMN());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CZoinode*)& s, vecZoinodeScores){
        rank++;
        if(rank == nRank) {
            return s.second;
        }
    }

    return NULL;
}

void CZoinodeMan::ProcessZoinodeConnections()
{
    //we don't care about this for regtest
    if(Params().NetworkIDString() == CBaseChainParams::REGTEST) return;

    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes) {
        if(pnode->fZoinode) {
            if(darkSendPool.pSubmittedToZoinode != NULL && pnode->addr == darkSendPool.pSubmittedToZoinode->addr) continue;
            // LogPrintf("Closing Zoinode connection: peer=%d, addr=%s\n", pnode->id, pnode->addr.ToString());
            pnode->fDisconnect = true;
        }
    }
}

std::pair<CService, std::set<uint256> > CZoinodeMan::PopScheduledMnbRequestConnection()
{
    LOCK(cs);
    if(listScheduledMnbRequestConnections.empty()) {
        return std::make_pair(CService(), std::set<uint256>());
    }

    std::set<uint256> setResult;

    listScheduledMnbRequestConnections.sort();
    std::pair<CService, uint256> pairFront = listScheduledMnbRequestConnections.front();

    // squash hashes from requests with the same CService as the first one into setResult
    std::list< std::pair<CService, uint256> >::iterator it = listScheduledMnbRequestConnections.begin();
    while(it != listScheduledMnbRequestConnections.end()) {
        if(pairFront.first == it->first) {
            setResult.insert(it->second);
            it = listScheduledMnbRequestConnections.erase(it);
        } else {
            // since list is sorted now, we can be sure that there is no more hashes left
            // to ask for from this addr
            break;
        }
    }
    return std::make_pair(pairFront.first, setResult);
}


void CZoinodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{

//    LogPrint("zoinode", "CZoinodeMan::ProcessMessage, strCommand=%s\n", strCommand);
    if(fLiteMode) return; // disable all Dash specific functionality
    if(!zoinodeSync.IsBlockchainSynced()) return;

    if (strCommand == NetMsgType::MNANNOUNCE) { //Zoinode Broadcast
        CZoinodeBroadcast mnb;
        vRecv >> mnb;

        pfrom->setAskFor.erase(mnb.GetHash());

        LogPrintf("MNANNOUNCE -- Zoinode announce, zoinode=%s\n", mnb.vin.prevout.ToStringShort());

        int nDos = 0;

        if (CheckMnbAndUpdateZoinodeList(pfrom, mnb, nDos)) {
            // use announced Zoinode as a peer
            addrman.Add(CAddress(mnb.addr, NODE_NETWORK), pfrom->addr, 2*60*60);
        } else if(nDos > 0) {
            Misbehaving(pfrom->GetId(), nDos);
        }

        if(fZoinodesAdded) {
            NotifyZoinodeUpdates();
        }
    } else if (strCommand == NetMsgType::MNPING) { //Zoinode Ping

        CZoinodePing mnp;
        vRecv >> mnp;

        uint256 nHash = mnp.GetHash();

        pfrom->setAskFor.erase(nHash);

        LogPrint("zoinode", "MNPING -- Zoinode ping, zoinode=%s\n", mnp.vin.prevout.ToStringShort());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if(mapSeenZoinodePing.count(nHash)) return; //seen
        mapSeenZoinodePing.insert(std::make_pair(nHash, mnp));

        LogPrint("zoinode", "MNPING -- Zoinode ping, zoinode=%s new\n", mnp.vin.prevout.ToStringShort());

        // see if we have this Zoinode
        CZoinode* pmn = mnodeman.Find(mnp.vin);

        // too late, new MNANNOUNCE is required
        if(pmn && pmn->IsNewStartRequired()) return;

        int nDos = 0;
        if(mnp.CheckAndUpdate(pmn, false, nDos)) return;

        if(nDos > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDos);
        } else if(pmn != NULL) {
            // nothing significant failed, mn is a known one too
            return;
        }

        // something significant is broken or mn is unknown,
        // we might have to ask for a zoinode entry once
        AskForMN(pfrom, mnp.vin);

    } else if (strCommand == NetMsgType::DSEG) { //Get Zoinode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after zoinode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!zoinodeSync.IsSynced()) return;

        CTxIn vin;
        vRecv >> vin;

        LogPrint("zoinode", "DSEG -- Zoinode list, zoinode=%s\n", vin.prevout.ToStringShort());

        LOCK(cs);

        if(vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if(!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator i = mAskedUsForZoinodeList.find(pfrom->addr);
                if (i != mAskedUsForZoinodeList.end()){
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        Misbehaving(pfrom->GetId(), 34);
                        LogPrintf("DSEG -- peer already asked me for the list, peer=%d\n", pfrom->id);
                        return;
                    }
                }
                int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
                mAskedUsForZoinodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok

        int nInvCount = 0;

        BOOST_FOREACH(CZoinode& mn, vZoinodes) {
            if (vin != CTxIn() && vin != mn.vin) continue; // asked for specific vin but we are not there yet
            if (mn.addr.IsRFC1918() || mn.addr.IsLocal()) continue; // do not send local network zoinode
            if (mn.IsUpdateRequired()) continue; // do not send outdated zoinodes

            LogPrint("zoinode", "DSEG -- Sending Zoinode entry: zoinode=%s  addr=%s\n", mn.vin.prevout.ToStringShort(), mn.addr.ToString());
            CZoinodeBroadcast mnb = CZoinodeBroadcast(mn);
            uint256 hash = mnb.GetHash();
            pfrom->PushInventory(CInv(MSG_ZOINODE_ANNOUNCE, hash));
            pfrom->PushInventory(CInv(MSG_ZOINODE_PING, mn.lastPing.GetHash()));
            nInvCount++;

            if (!mapSeenZoinodeBroadcast.count(hash)) {
                mapSeenZoinodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));
            }

            if (vin == mn.vin) {
                LogPrintf("DSEG -- Sent 1 Zoinode inv to peer %d\n", pfrom->id);
                return;
            }
        }

        if(vin == CTxIn()) {
            pfrom->PushMessage(NetMsgType::SYNCSTATUSCOUNT, ZOINODE_SYNC_LIST, nInvCount);
            LogPrintf("DSEG -- Sent %d Zoinode invs to peer %d\n", nInvCount, pfrom->id);
            return;
        }
        // smth weird happen - someone asked us for vin we have no idea about?
        LogPrint("zoinode", "DSEG -- No invs sent to peer %d\n", pfrom->id);

    } else if (strCommand == NetMsgType::MNVERIFY) { // Zoinode Verify

        // Need LOCK2 here to ensure consistent locking order because the all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CZoinodeVerification mnv;
        vRecv >> mnv;

        if(mnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, mnv);
        } else if (mnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some zoinode
            ProcessVerifyReply(pfrom, mnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some zoinode which verified another one
            ProcessVerifyBroadcast(pfrom, mnv);
        }
    }
}

// Verification of zoinodes via unique direct requests.

void CZoinodeMan::DoFullVerificationStep()
{
    if(activeZoinode.vin == CTxIn()) return;
    if(!zoinodeSync.IsSynced()) return;

    std::vector<std::pair<int, CZoinode> > vecZoinodeRanks = GetZoinodeRanks(pCurrentBlockIndex->nHeight - 1, MIN_POSE_PROTO_VERSION);

    // Need LOCK2 here to ensure consistent locking order because the SendVerifyRequest call below locks cs_main
    // through GetHeight() signal in ConnectNode
    LOCK2(cs_main, cs);

    int nCount = 0;

    int nMyRank = -1;
    int nRanksTotal = (int)vecZoinodeRanks.size();

    // send verify requests only if we are in top MAX_POSE_RANK
    std::vector<std::pair<int, CZoinode> >::iterator it = vecZoinodeRanks.begin();
    while(it != vecZoinodeRanks.end()) {
        if(it->first > MAX_POSE_RANK) {
            LogPrint("zoinode", "CZoinodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                        (int)MAX_POSE_RANK);
            return;
        }
        if(it->second.vin == activeZoinode.vin) {
            nMyRank = it->first;
            LogPrint("zoinode", "CZoinodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d zoinodes\n",
                        nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
        ++it;
    }

    // edge case: list is too short and this zoinode is not enabled
    if(nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS zoinodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if(nOffset >= (int)vecZoinodeRanks.size()) return;

    std::vector<CZoinode*> vSortedByAddr;
    BOOST_FOREACH(CZoinode& mn, vZoinodes) {
        vSortedByAddr.push_back(&mn);
    }

    sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    it = vecZoinodeRanks.begin() + nOffset;
    while(it != vecZoinodeRanks.end()) {
        if(it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            LogPrint("zoinode", "CZoinodeMan::DoFullVerificationStep -- Already %s%s%s zoinode %s address %s, skipping...\n",
                        it->second.IsPoSeVerified() ? "verified" : "",
                        it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
                        it->second.IsPoSeBanned() ? "banned" : "",
                        it->second.vin.prevout.ToStringShort(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if(nOffset >= (int)vecZoinodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        LogPrint("zoinode", "CZoinodeMan::DoFullVerificationStep -- Verifying zoinode %s rank %d/%d address %s\n",
                    it->second.vin.prevout.ToStringShort(), it->first, nRanksTotal, it->second.addr.ToString());
        if(SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr)) {
            nCount++;
            if(nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if(nOffset >= (int)vecZoinodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }

    LogPrint("zoinode", "CZoinodeMan::DoFullVerificationStep -- Sent verification requests to %d zoinodes\n", nCount);
}

// This function tries to find zoinodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CZoinodeMan::CheckSameAddr()
{
    if(!zoinodeSync.IsSynced() || vZoinodes.empty()) return;

    std::vector<CZoinode*> vBan;
    std::vector<CZoinode*> vSortedByAddr;

    {
        LOCK(cs);

        CZoinode* pprevZoinode = NULL;
        CZoinode* pverifiedZoinode = NULL;

        BOOST_FOREACH(CZoinode& mn, vZoinodes) {
            vSortedByAddr.push_back(&mn);
        }

        sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        BOOST_FOREACH(CZoinode* pmn, vSortedByAddr) {
            // check only (pre)enabled zoinodes
            if(!pmn->IsEnabled() && !pmn->IsPreEnabled()) continue;
            // initial step
            if(!pprevZoinode) {
                pprevZoinode = pmn;
                pverifiedZoinode = pmn->IsPoSeVerified() ? pmn : NULL;
                continue;
            }
            // second+ step
            if(pmn->addr == pprevZoinode->addr) {
                if(pverifiedZoinode) {
                    // another zoinode with the same ip is verified, ban this one
                    vBan.push_back(pmn);
                } else if(pmn->IsPoSeVerified()) {
                    // this zoinode with the same ip is verified, ban previous one
                    vBan.push_back(pprevZoinode);
                    // and keep a reference to be able to ban following zoinodes with the same ip
                    pverifiedZoinode = pmn;
                }
            } else {
                pverifiedZoinode = pmn->IsPoSeVerified() ? pmn : NULL;
            }
            pprevZoinode = pmn;
        }
    }

    // ban duplicates
    BOOST_FOREACH(CZoinode* pmn, vBan) {
        LogPrintf("CZoinodeMan::CheckSameAddr -- increasing PoSe ban score for zoinode %s\n", pmn->vin.prevout.ToStringShort());
        pmn->IncreasePoSeBanScore();
    }
}

bool CZoinodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<CZoinode*>& vSortedByAddr)
{
    if(netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        LogPrint("zoinode", "CZoinodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    CNode* pnode = ConnectNode(addr, NULL, false, true);
    if(pnode == NULL) {
        LogPrintf("CZoinodeMan::SendVerifyRequest -- can't connect to node to verify it, addr=%s\n", addr.ToString());
        return false;
    }

    netfulfilledman.AddFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request");
    // use random nonce, store it and require node to reply with correct one later
    CZoinodeVerification mnv(addr, GetRandInt(999999), pCurrentBlockIndex->nHeight - 1);
    mWeAskedForVerification[addr] = mnv;
    LogPrintf("CZoinodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", mnv.nonce, addr.ToString());
    pnode->PushMessage(NetMsgType::MNVERIFY, mnv);

    return true;
}

void CZoinodeMan::SendVerifyReply(CNode* pnode, CZoinodeVerification& mnv)
{
    // only zoinodes can sign this, why would someone ask regular node?
    if(!fZoiNode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply")) {
//        // peer should not ask us that often
        LogPrintf("ZoinodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        LogPrintf("ZoinodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

    std::string strMessage = strprintf("%s%d%s", activeZoinode.service.ToString(), mnv.nonce, blockHash.ToString());

    if(!darkSendSigner.SignMessage(strMessage, mnv.vchSig1, activeZoinode.keyZoinode)) {
        LogPrintf("ZoinodeMan::SendVerifyReply -- SignMessage() failed\n");
        return;
    }

    std::string strError;

    if(!darkSendSigner.VerifyMessage(activeZoinode.pubKeyZoinode, mnv.vchSig1, strMessage, strError)) {
        LogPrintf("ZoinodeMan::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
        return;
    }

    pnode->PushMessage(NetMsgType::MNVERIFY, mnv);
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply");
}

void CZoinodeMan::ProcessVerifyReply(CNode* pnode, CZoinodeVerification& mnv)
{
    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if(!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        LogPrintf("CZoinodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nonce for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nonce != mnv.nonce) {
        LogPrintf("CZoinodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nonce, mnv.nonce, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nBlockHeight != mnv.nBlockHeight) {
        LogPrintf("CZoinodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                    mWeAskedForVerification[pnode->addr].nBlockHeight, mnv.nBlockHeight, pnode->id);
        Misbehaving(pnode->id, 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("ZoinodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

//    // we already verified this address, why node is spamming?
    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done")) {
        LogPrintf("CZoinodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->id, 20);
        return;
    }

    {
        LOCK(cs);

        CZoinode* prealZoinode = NULL;
        std::vector<CZoinode*> vpZoinodesToBan;
        std::vector<CZoinode>::iterator it = vZoinodes.begin();
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(), mnv.nonce, blockHash.ToString());
        while(it != vZoinodes.end()) {
            if(CAddress(it->addr, NODE_NETWORK) == pnode->addr) {
                if(darkSendSigner.VerifyMessage(it->pubKeyZoinode, mnv.vchSig1, strMessage1, strError)) {
                    // found it!
                    prealZoinode = &(*it);
                    if(!it->IsPoSeVerified()) {
                        it->DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done");

                    // we can only broadcast it if we are an activated zoinode
                    if(activeZoinode.vin == CTxIn()) continue;
                    // update ...
                    mnv.addr = it->addr;
                    mnv.vin1 = it->vin;
                    mnv.vin2 = activeZoinode.vin;
                    std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                            mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());
                    // ... and sign it
                    if(!darkSendSigner.SignMessage(strMessage2, mnv.vchSig2, activeZoinode.keyZoinode)) {
                        LogPrintf("ZoinodeMan::ProcessVerifyReply -- SignMessage() failed\n");
                        return;
                    }

                    std::string strError;

                    if(!darkSendSigner.VerifyMessage(activeZoinode.pubKeyZoinode, mnv.vchSig2, strMessage2, strError)) {
                        LogPrintf("ZoinodeMan::ProcessVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
                        return;
                    }

                    mWeAskedForVerification[pnode->addr] = mnv;
                    mnv.Relay();

                } else {
                    vpZoinodesToBan.push_back(&(*it));
                }
            }
            ++it;
        }
        // no real zoinode found?...
        if(!prealZoinode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            LogPrintf("CZoinodeMan::ProcessVerifyReply -- ERROR: no real zoinode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->id, 20);
            return;
        }
        LogPrintf("CZoinodeMan::ProcessVerifyReply -- verified real zoinode %s for addr %s\n",
                    prealZoinode->vin.prevout.ToStringShort(), pnode->addr.ToString());
        // increase ban score for everyone else
        BOOST_FOREACH(CZoinode* pmn, vpZoinodesToBan) {
            pmn->IncreasePoSeBanScore();
            LogPrint("zoinode", "CZoinodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        prealZoinode->vin.prevout.ToStringShort(), pnode->addr.ToString(), pmn->nPoSeBanScore);
        }
        LogPrintf("CZoinodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake zoinodes, addr %s\n",
                    (int)vpZoinodesToBan.size(), pnode->addr.ToString());
    }
}

void CZoinodeMan::ProcessVerifyBroadcast(CNode* pnode, const CZoinodeVerification& mnv)
{
    std::string strError;

    if(mapSeenZoinodeVerification.find(mnv.GetHash()) != mapSeenZoinodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenZoinodeVerification[mnv.GetHash()] = mnv;

    // we don't care about history
    if(mnv.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS) {
        LogPrint("zoinode", "ZoinodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                    pCurrentBlockIndex->nHeight, mnv.nBlockHeight, pnode->id);
        return;
    }

    if(mnv.vin1.prevout == mnv.vin2.prevout) {
        LogPrint("zoinode", "ZoinodeMan::ProcessVerifyBroadcast -- ERROR: same vins %s, peer=%d\n",
                    mnv.vin1.prevout.ToStringShort(), pnode->id);
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->id, 100);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        LogPrintf("ZoinodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->id);
        return;
    }

    int nRank = GetZoinodeRank(mnv.vin2, mnv.nBlockHeight, MIN_POSE_PROTO_VERSION);

    if (nRank == -1) {
        LogPrint("zoinode", "CZoinodeMan::ProcessVerifyBroadcast -- Can't calculate rank for zoinode %s\n",
                    mnv.vin2.prevout.ToStringShort());
        return;
    }

    if(nRank > MAX_POSE_RANK) {
        LogPrint("zoinode", "CZoinodeMan::ProcessVerifyBroadcast -- Mastrernode %s is not in top %d, current rank %d, peer=%d\n",
                    mnv.vin2.prevout.ToStringShort(), (int)MAX_POSE_RANK, nRank, pnode->id);
        return;
    }

    {
        LOCK(cs);

        std::string strMessage1 = strprintf("%s%d%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString());
        std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());

        CZoinode* pmn1 = Find(mnv.vin1);
        if(!pmn1) {
            LogPrintf("CZoinodeMan::ProcessVerifyBroadcast -- can't find zoinode1 %s\n", mnv.vin1.prevout.ToStringShort());
            return;
        }

        CZoinode* pmn2 = Find(mnv.vin2);
        if(!pmn2) {
            LogPrintf("CZoinodeMan::ProcessVerifyBroadcast -- can't find zoinode2 %s\n", mnv.vin2.prevout.ToStringShort());
            return;
        }

        if(pmn1->addr != mnv.addr) {
            LogPrintf("CZoinodeMan::ProcessVerifyBroadcast -- addr %s do not match %s\n", mnv.addr.ToString(), pnode->addr.ToString());
            return;
        }

        if(darkSendSigner.VerifyMessage(pmn1->pubKeyZoinode, mnv.vchSig1, strMessage1, strError)) {
            LogPrintf("ZoinodeMan::ProcessVerifyBroadcast -- VerifyMessage() for zoinode1 failed, error: %s\n", strError);
            return;
        }

        if(darkSendSigner.VerifyMessage(pmn2->pubKeyZoinode, mnv.vchSig2, strMessage2, strError)) {
            LogPrintf("ZoinodeMan::ProcessVerifyBroadcast -- VerifyMessage() for zoinode2 failed, error: %s\n", strError);
            return;
        }

        if(!pmn1->IsPoSeVerified()) {
            pmn1->DecreasePoSeBanScore();
        }
        mnv.Relay();

        LogPrintf("CZoinodeMan::ProcessVerifyBroadcast -- verified zoinode %s for addr %s\n",
                    pmn1->vin.prevout.ToStringShort(), pnode->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        BOOST_FOREACH(CZoinode& mn, vZoinodes) {
            if(mn.addr != mnv.addr || mn.vin.prevout == mnv.vin1.prevout) continue;
            mn.IncreasePoSeBanScore();
            nCount++;
            LogPrint("zoinode", "CZoinodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        mn.vin.prevout.ToStringShort(), mn.addr.ToString(), mn.nPoSeBanScore);
        }
        LogPrintf("CZoinodeMan::ProcessVerifyBroadcast -- PoSe score incresed for %d fake zoinodes, addr %s\n",
                    nCount, pnode->addr.ToString());
    }
}

std::string CZoinodeMan::ToString() const
{
    std::ostringstream info;

    info << "Zoinodes: " << (int)vZoinodes.size() <<
            ", peers who asked us for Zoinode list: " << (int)mAskedUsForZoinodeList.size() <<
            ", peers we asked for Zoinode list: " << (int)mWeAskedForZoinodeList.size() <<
            ", entries in Zoinode list we asked for: " << (int)mWeAskedForZoinodeListEntry.size() <<
            ", zoinode index size: " << indexZoinodes.GetSize() <<
            ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}

void CZoinodeMan::UpdateZoinodeList(CZoinodeBroadcast mnb)
{
    try {
        LogPrintf("CZoinodeMan::UpdateZoinodeList\n");
        LOCK2(cs_main, cs);
        mapSeenZoinodePing.insert(std::make_pair(mnb.lastPing.GetHash(), mnb.lastPing));
        mapSeenZoinodeBroadcast.insert(std::make_pair(mnb.GetHash(), std::make_pair(GetTime(), mnb)));

        LogPrintf("CZoinodeMan::UpdateZoinodeList -- zoinode=%s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());

        CZoinode *pmn = Find(mnb.vin);
        if (pmn == NULL) {
            CZoinode mn(mnb);
            if (Add(mn)) {
                zoinodeSync.AddedZoinodeList();
            }
        } else {
            CZoinodeBroadcast mnbOld = mapSeenZoinodeBroadcast[CZoinodeBroadcast(*pmn).GetHash()].second;
            if (pmn->UpdateFromNewBroadcast(mnb)) {
                zoinodeSync.AddedZoinodeList();
                mapSeenZoinodeBroadcast.erase(mnbOld.GetHash());
            }
        }
    } catch (const std::exception &e) {
        PrintExceptionContinue(&e, "UpdateZoinodeList");
    }
}

bool CZoinodeMan::CheckMnbAndUpdateZoinodeList(CNode* pfrom, CZoinodeBroadcast mnb, int& nDos)
{
    // Need LOCK2 here to ensure consistent locking order because the SimpleCheck call below locks cs_main
    LOCK(cs_main);

    {
        LOCK(cs);
        nDos = 0;
        LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- zoinode=%s\n", mnb.vin.prevout.ToStringShort());

        uint256 hash = mnb.GetHash();
        if (mapSeenZoinodeBroadcast.count(hash) && !mnb.fRecovery) { //seen
            LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- zoinode=%s seen\n", mnb.vin.prevout.ToStringShort());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if (GetTime() - mapSeenZoinodeBroadcast[hash].first > ZOINODE_NEW_START_REQUIRED_SECONDS - ZOINODE_MIN_MNP_SECONDS * 2) {
                LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- zoinode=%s seen update\n", mnb.vin.prevout.ToStringShort());
                mapSeenZoinodeBroadcast[hash].first = GetTime();
                zoinodeSync.AddedZoinodeList();
            }
            // did we ask this node for it?
            if (pfrom && IsMnbRecoveryRequested(hash) && GetTime() < mMnbRecoveryRequests[hash].first) {
                LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- mnb=%s seen request\n", hash.ToString());
                if (mMnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- mnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same mnb multiple times in recovery mode
                    mMnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if (mnb.lastPing.sigTime > mapSeenZoinodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CZoinode mnTemp = CZoinode(mnb);
                        mnTemp.Check();
                        LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- mnb=%s seen request, addr=%s, better lastPing: %d min ago, projected mn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetTime() - mnb.lastPing.sigTime) / 60, mnTemp.GetStateString());
                        if (mnTemp.IsValidStateForAutoStart(mnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- zoinode=%s seen good\n", mnb.vin.prevout.ToStringShort());
                            mMnbRecoveryGoodReplies[hash].push_back(mnb);
                        }
                    }
                }
            }
            return true;
        }
        mapSeenZoinodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));

        LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- zoinode=%s new\n", mnb.vin.prevout.ToStringShort());

        if (!mnb.SimpleCheck(nDos)) {
            LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- SimpleCheck() failed, zoinode=%s\n", mnb.vin.prevout.ToStringShort());
            return false;
        }

        // search Zoinode list
        CZoinode *pmn = Find(mnb.vin);
        if (pmn) {
            CZoinodeBroadcast mnbOld = mapSeenZoinodeBroadcast[CZoinodeBroadcast(*pmn).GetHash()].second;
            if (!mnb.Update(pmn, nDos)) {
                LogPrint("zoinode", "CZoinodeMan::CheckMnbAndUpdateZoinodeList -- Update() failed, zoinode=%s\n", mnb.vin.prevout.ToStringShort());
                return false;
            }
            if (hash != mnbOld.GetHash()) {
                mapSeenZoinodeBroadcast.erase(mnbOld.GetHash());
            }
        }
    } // end of LOCK(cs);

    if(mnb.CheckOutpoint(nDos)) {
        Add(mnb);
        zoinodeSync.AddedZoinodeList();
        // if it matches our Zoinode privkey...
        if(fZoiNode && mnb.pubKeyZoinode == activeZoinode.pubKeyZoinode) {
            mnb.nPoSeBanScore = -ZOINODE_POSE_BAN_MAX_SCORE;
            if(mnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                LogPrintf("CZoinodeMan::CheckMnbAndUpdateZoinodeList -- Got NEW Zoinode entry: zoinode=%s  sigTime=%lld  addr=%s\n",
                            mnb.vin.prevout.ToStringShort(), mnb.sigTime, mnb.addr.ToString());
                activeZoinode.ManageState();
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                LogPrintf("CZoinodeMan::CheckMnbAndUpdateZoinodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", mnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        mnb.RelayZoiNode();
    } else {
        LogPrintf("CZoinodeMan::CheckMnbAndUpdateZoinodeList -- Rejected Zoinode entry: %s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());
        return false;
    }

    return true;
}

void CZoinodeMan::UpdateLastPaid()
{
    LOCK(cs);
    if(fLiteMode) return;
    if(!pCurrentBlockIndex) {
        // LogPrintf("CZoinodeMan::UpdateLastPaid, pCurrentBlockIndex=NULL\n");
        return;
    }

    static bool IsFirstRun = true;
    // Do full scan on first run or if we are not a zoinode
    // (MNs should update this info on every block, so limited scan should be enough for them)
    int nMaxBlocksToScanBack = (IsFirstRun || !fZoiNode) ? mnpayments.GetStorageLimit() : LAST_PAID_SCAN_BLOCKS;

    LogPrint("mnpayments", "CZoinodeMan::UpdateLastPaid -- nHeight=%d, nMaxBlocksToScanBack=%d, IsFirstRun=%s\n",
                             pCurrentBlockIndex->nHeight, nMaxBlocksToScanBack, IsFirstRun ? "true" : "false");

    BOOST_FOREACH(CZoinode& mn, vZoinodes) {
        mn.UpdateLastPaid(pCurrentBlockIndex, nMaxBlocksToScanBack);
    }

    // every time is like the first time if winners list is not synced
    IsFirstRun = !zoinodeSync.IsWinnersListSynced();
}

void CZoinodeMan::CheckAndRebuildZoinodeIndex()
{
    LOCK(cs);

    if(GetTime() - nLastIndexRebuildTime < MIN_INDEX_REBUILD_TIME) {
        return;
    }

    if(indexZoinodes.GetSize() <= MAX_EXPECTED_INDEX_SIZE) {
        return;
    }

    if(indexZoinodes.GetSize() <= int(vZoinodes.size())) {
        return;
    }

    indexZoinodesOld = indexZoinodes;
    indexZoinodes.Clear();
    for(size_t i = 0; i < vZoinodes.size(); ++i) {
        indexZoinodes.AddZoinodeVIN(vZoinodes[i].vin);
    }

    fIndexRebuilt = true;
    nLastIndexRebuildTime = GetTime();
}

void CZoinodeMan::UpdateWatchdogVoteTime(const CTxIn& vin)
{
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->UpdateWatchdogVoteTime();
    nLastWatchdogVoteTime = GetTime();
}

bool CZoinodeMan::IsWatchdogActive()
{
    LOCK(cs);
    // Check if any zoinodes have voted recently, otherwise return false
    return (GetTime() - nLastWatchdogVoteTime) <= ZOINODE_WATCHDOG_MAX_SECONDS;
}

void CZoinodeMan::CheckZoinode(const CTxIn& vin, bool fForce)
{
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->Check(fForce);
}

void CZoinodeMan::CheckZoinode(const CPubKey& pubKeyZoinode, bool fForce)
{
    LOCK(cs);
    CZoinode* pMN = Find(pubKeyZoinode);
    if(!pMN)  {
        return;
    }
    pMN->Check(fForce);
}

int CZoinodeMan::GetZoinodeState(const CTxIn& vin)
{
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    if(!pMN)  {
        return CZoinode::ZOINODE_NEW_START_REQUIRED;
    }
    return pMN->nActiveState;
}

int CZoinodeMan::GetZoinodeState(const CPubKey& pubKeyZoinode)
{
    LOCK(cs);
    CZoinode* pMN = Find(pubKeyZoinode);
    if(!pMN)  {
        return CZoinode::ZOINODE_NEW_START_REQUIRED;
    }
    return pMN->nActiveState;
}

bool CZoinodeMan::IsZoinodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    if(!pMN) {
        return false;
    }
    return pMN->IsPingedWithin(nSeconds, nTimeToCheckAt);
}

void CZoinodeMan::SetZoinodeLastPing(const CTxIn& vin, const CZoinodePing& mnp)
{
    LOCK(cs);
    CZoinode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->lastPing = mnp;
    mapSeenZoinodePing.insert(std::make_pair(mnp.GetHash(), mnp));

    CZoinodeBroadcast mnb(*pMN);
    uint256 hash = mnb.GetHash();
    if(mapSeenZoinodeBroadcast.count(hash)) {
        mapSeenZoinodeBroadcast[hash].second.lastPing = mnp;
    }
}

void CZoinodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    pCurrentBlockIndex = pindex;
    LogPrint("zoinode", "CZoinodeMan::UpdatedBlockTip -- pCurrentBlockIndex->nHeight=%d\n", pCurrentBlockIndex->nHeight);

    CheckSameAddr();

    if(fZoiNode) {
        // normal wallet does not need to update this every block, doing update on rpc call should be enough
        UpdateLastPaid();
    }
}

void CZoinodeMan::NotifyZoinodeUpdates()
{
    // Avoid double locking
    bool fZoinodesAddedLocal = false;
    bool fZoinodesRemovedLocal = false;
    {
        LOCK(cs);
        fZoinodesAddedLocal = fZoinodesAdded;
        fZoinodesRemovedLocal = fZoinodesRemoved;
    }

    if(fZoinodesAddedLocal) {
//        governance.CheckZoinodeOrphanObjects();
//        governance.CheckZoinodeOrphanVotes();
    }
    if(fZoinodesRemovedLocal) {
//        governance.UpdateCachesAndClean();
    }

    LOCK(cs);
    fZoinodesAdded = false;
    fZoinodesRemoved = false;
}
