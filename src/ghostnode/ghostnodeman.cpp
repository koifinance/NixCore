// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeghostnode.h"
#include "addrman.h"
#include "darksend.h"
#include "ghostnode-payments.h"
#include "ghostnode-sync.h"
#include "ghostnodeman.h"
#include "netfulfilledman.h"
#include "util.h"
#include "netmessagemaker.h"

/** Ghostnode manager */
CGhostnodeMan mnodeman;

const std::string CGhostnodeMan::SERIALIZATION_VERSION_STRING = "CGhostnodeMan-Version-4";

struct CompareLastPaidBlock
{
    bool operator()(const std::pair<int, CGhostnode*>& t1,
                    const std::pair<int, CGhostnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

struct CompareScoreMN
{
    bool operator()(const std::pair<int64_t, CGhostnode*>& t1,
                    const std::pair<int64_t, CGhostnode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vin < t2.second->vin);
    }
};

CGhostnodeIndex::CGhostnodeIndex()
    : nSize(0),
      mapIndex(),
      mapReverseIndex()
{}

bool CGhostnodeIndex::Get(int nIndex, CTxIn& vinGhostnode) const
{
    rindex_m_cit it = mapReverseIndex.find(nIndex);
    if(it == mapReverseIndex.end()) {
        return false;
    }
    vinGhostnode = it->second;
    return true;
}

int CGhostnodeIndex::GetGhostnodeIndex(const CTxIn& vinGhostnode) const
{
    index_m_cit it = mapIndex.find(vinGhostnode);
    if(it == mapIndex.end()) {
        return -1;
    }
    return it->second;
}

void CGhostnodeIndex::AddGhostnodeVIN(const CTxIn& vinGhostnode)
{
    index_m_it it = mapIndex.find(vinGhostnode);
    if(it != mapIndex.end()) {
        return;
    }
    int nNextIndex = nSize;
    mapIndex[vinGhostnode] = nNextIndex;
    mapReverseIndex[nNextIndex] = vinGhostnode;
    ++nSize;
}

void CGhostnodeIndex::Clear()
{
    mapIndex.clear();
    mapReverseIndex.clear();
    nSize = 0;
}
struct CompareByAddr

{
    bool operator()(const CGhostnode* t1,
                    const CGhostnode* t2) const
    {
        return t1->addr < t2->addr;
    }
};

void CGhostnodeIndex::RebuildIndex()
{
    nSize = mapIndex.size();
    for(index_m_it it = mapIndex.begin(); it != mapIndex.end(); ++it) {
        mapReverseIndex[it->second] = it->first;
    }
}

CGhostnodeMan::CGhostnodeMan() : cs(),
  vGhostnodes(),
  mAskedUsForGhostnodeList(),
  mWeAskedForGhostnodeList(),
  mWeAskedForGhostnodeListEntry(),
  mWeAskedForVerification(),
  mMnbRecoveryRequests(),
  mMnbRecoveryGoodReplies(),
  listScheduledMnbRequestConnections(),
  nLastIndexRebuildTime(0),
  indexGhostnodes(),
  indexGhostnodesOld(),
  fIndexRebuilt(false),
  fGhostnodesAdded(false),
  fGhostnodesRemoved(false),
//  vecDirtyGovernanceObjectHashes(),
  nLastWatchdogVoteTime(0),
  mapSeenGhostnodeBroadcast(),
  mapSeenGhostnodePing(),
  nDsqCount(0)
{}

bool CGhostnodeMan::Add(CGhostnode &mn)
{
    LOCK(cs);

    CGhostnode *pmn = Find(mn.vin);
    if (pmn == NULL) {
        //LogPrint("ghostnode", "CGhostnodeMan::Add -- Adding new Ghostnode: addr=%s, %i now\n", mn.addr.ToString(), size() + 1);
        vGhostnodes.push_back(mn);
        indexGhostnodes.AddGhostnodeVIN(mn.vin);
        fGhostnodesAdded = true;
        return true;
    }

    return false;
}

void CGhostnodeMan::AskForMN(CNode* pnode, const CTxIn &vin)
{
    if(!pnode) return;

    LOCK(cs);

    std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it1 = mWeAskedForGhostnodeListEntry.find(vin.prevout);
    if (it1 != mWeAskedForGhostnodeListEntry.end()) {
        std::map<CNetAddr, int64_t>::iterator it2 = it1->second.find(pnode->addr);
        if (it2 != it1->second.end()) {
            if (GetTime() < it2->second) {
                // we've asked recently, should not repeat too often or we could get banned
                return;
            }
            // we asked this node for this outpoint but it's ok to ask again already
            //LogPrint("CGhostnodeMan::AskForMN -- Asking same peer %s for missing ghostnode entry again: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
        } else {
            // we already asked for this outpoint but not this node
            //LogPrint("CGhostnodeMan::AskForMN -- Asking new peer %s for missing ghostnode entry: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
        }
    } else {
        // we never asked any node for this outpoint
        //LogPrint("CGhostnodeMan::AskForMN -- Asking peer %s for missing ghostnode entry for the first time: %s\n", pnode->addr.ToString(), vin.prevout.ToStringShort());
    }
    mWeAskedForGhostnodeListEntry[vin.prevout][pnode->addr] = GetTime() + DSEG_UPDATE_SECONDS;

    const CNetMsgMaker msgMaker(pnode->GetSendVersion());
    g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::DSEG,vin));
}

void CGhostnodeMan::Check()
{
    LOCK(cs);

//    //LogPrint("ghostnode", "CGhostnodeMan::Check -- nLastWatchdogVoteTime=%d, IsWatchdogActive()=%d\n", nLastWatchdogVoteTime, IsWatchdogActive());

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
        mn.Check();
    }
}

void CGhostnodeMan::CheckAndRemove()
{
    if(!ghostnodeSync.IsGhostnodeListSynced()) return;

    //LogPrint("CGhostnodeMan::CheckAndRemove\n");

    {
        // Need LOCK2 here to ensure consistent locking order because code below locks cs_main
        // in CheckMnbAndUpdateGhostnodeList()
        LOCK2(cs_main, cs);

        Check();

        // Remove spent ghostnodes, prepare structures and make requests to reasure the state of inactive ones
        std::vector<CGhostnode>::iterator it = vGhostnodes.begin();
        std::vector<std::pair<int, CGhostnode> > vecGhostnodeRanks;
        // ask for up to MNB_RECOVERY_MAX_ASK_ENTRIES ghostnode entries at a time
        int nAskForMnbRecovery = MNB_RECOVERY_MAX_ASK_ENTRIES;
        while(it != vGhostnodes.end()) {
            CGhostnodeBroadcast mnb = CGhostnodeBroadcast(*it);
            uint256 hash = mnb.GetHash();
            // If collateral was spent ...
            if ((*it).IsOutpointSpent()) {
                //LogPrint("ghostnode", "CGhostnodeMan::CheckAndRemove -- Removing Ghostnode: %s  addr=%s  %i now\n", (*it).GetStateString(), (*it).addr.ToString(), size() - 1);

                // erase all of the broadcasts we've seen from this txin, ...
                mapSeenGhostnodeBroadcast.erase(hash);
                mWeAskedForGhostnodeListEntry.erase((*it).vin.prevout);

                // and finally remove it from the list
//                it->FlagGovernanceItemsAsDirty();
                it = vGhostnodes.erase(it);
                fGhostnodesRemoved = true;
            } else {
                bool fAsk = pCurrentBlockIndex &&
                            (nAskForMnbRecovery > 0) &&
                            ghostnodeSync.IsSynced(chainActive.Height()) &&
                            it->IsNewStartRequired() &&
                            !IsMnbRecoveryRequested(hash);
                if(fAsk) {
                    // this mn is in a non-recoverable state and we haven't asked other nodes yet
                    std::set<CNetAddr> setRequested;
                    // calulate only once and only when it's needed
                    if(vecGhostnodeRanks.empty()) {
                        int nRandomBlockHeight = GetRandInt(pCurrentBlockIndex->nHeight);
                        vecGhostnodeRanks = GetGhostnodeRanks(nRandomBlockHeight);
                    }
                    bool fAskedForMnbRecovery = false;
                    // ask first MNB_RECOVERY_QUORUM_TOTAL ghostnodes we can connect to and we haven't asked recently
                    for(int i = 0; setRequested.size() < MNB_RECOVERY_QUORUM_TOTAL && i < (int)vecGhostnodeRanks.size(); i++) {
                        // avoid banning
                        if(mWeAskedForGhostnodeListEntry.count(it->vin.prevout) && mWeAskedForGhostnodeListEntry[it->vin.prevout].count(vecGhostnodeRanks[i].second.addr)) continue;
                        // didn't ask recently, ok to ask now
                        CService addr = vecGhostnodeRanks[i].second.addr;
                        setRequested.insert(addr);
                        listScheduledMnbRequestConnections.push_back(std::make_pair(addr, hash));
                        fAskedForMnbRecovery = true;
                    }
                    if(fAskedForMnbRecovery) {
                        //LogPrint("ghostnode", "CGhostnodeMan::CheckAndRemove -- Recovery initiated, ghostnode=%s\n", it->vin.prevout.ToStringShort());
                        nAskForMnbRecovery--;
                    }
                    // wait for mnb recovery replies for MNB_RECOVERY_WAIT_SECONDS seconds
                    mMnbRecoveryRequests[hash] = std::make_pair(GetTime() + MNB_RECOVERY_WAIT_SECONDS, setRequested);
                }
                ++it;
            }
        }

        // proces replies for GHOSTNODE_NEW_START_REQUIRED ghostnodes
        //LogPrint("ghostnode", "CGhostnodeMan::CheckAndRemove -- mMnbRecoveryGoodReplies size=%d\n", (int)mMnbRecoveryGoodReplies.size());
        std::map<uint256, std::vector<CGhostnodeBroadcast> >::iterator itMnbReplies = mMnbRecoveryGoodReplies.begin();
        while(itMnbReplies != mMnbRecoveryGoodReplies.end()){
            if(mMnbRecoveryRequests[itMnbReplies->first].first < GetTime()) {
                // all nodes we asked should have replied now
                if(itMnbReplies->second.size() >= MNB_RECOVERY_QUORUM_REQUIRED) {
                    // majority of nodes we asked agrees that this mn doesn't require new mnb, reprocess one of new mnbs
                    //LogPrint("ghostnode", "CGhostnodeMan::CheckAndRemove -- reprocessing mnb, ghostnode=%s\n", itMnbReplies->second[0].vin.prevout.ToStringShort());
                    // mapSeenGhostnodeBroadcast.erase(itMnbReplies->first);
                    int nDos;
                    itMnbReplies->second[0].fRecovery = true;
                    CheckMnbAndUpdateGhostnodeList(NULL, itMnbReplies->second[0], nDos);
                }
                //LogPrint("ghostnode", "CGhostnodeMan::CheckAndRemove -- removing mnb recovery reply, ghostnode=%s, size=%d\n", itMnbReplies->second[0].vin.prevout.ToStringShort(), (int)itMnbReplies->second.size());
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
            // if mn is still in GHOSTNODE_NEW_START_REQUIRED state.
            if(GetTime() - itMnbRequest->second.first > MNB_RECOVERY_RETRY_SECONDS) {
                mMnbRecoveryRequests.erase(itMnbRequest++);
            } else {
                ++itMnbRequest;
            }
        }

        // check who's asked for the Ghostnode list
        std::map<CNetAddr, int64_t>::iterator it1 = mAskedUsForGhostnodeList.begin();
        while(it1 != mAskedUsForGhostnodeList.end()){
            if((*it1).second < GetTime()) {
                mAskedUsForGhostnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check who we asked for the Ghostnode list
        it1 = mWeAskedForGhostnodeList.begin();
        while(it1 != mWeAskedForGhostnodeList.end()){
            if((*it1).second < GetTime()){
                mWeAskedForGhostnodeList.erase(it1++);
            } else {
                ++it1;
            }
        }

        // check which Ghostnodes we've asked for
        std::map<COutPoint, std::map<CNetAddr, int64_t> >::iterator it2 = mWeAskedForGhostnodeListEntry.begin();
        while(it2 != mWeAskedForGhostnodeListEntry.end()){
            std::map<CNetAddr, int64_t>::iterator it3 = it2->second.begin();
            while(it3 != it2->second.end()){
                if(it3->second < GetTime()){
                    it2->second.erase(it3++);
                } else {
                    ++it3;
                }
            }
            if(it2->second.empty()) {
                mWeAskedForGhostnodeListEntry.erase(it2++);
            } else {
                ++it2;
            }
        }

        std::map<CNetAddr, CGhostnodeVerification>::iterator it3 = mWeAskedForVerification.begin();
        while(it3 != mWeAskedForVerification.end()){
            if(it3->second.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS) {
                mWeAskedForVerification.erase(it3++);
            } else {
                ++it3;
            }
        }

        // NOTE: do not expire mapSeenGhostnodeBroadcast entries here, clean them on mnb updates!

        // remove expired mapSeenGhostnodePing
        std::map<uint256, CGhostnodePing>::iterator it4 = mapSeenGhostnodePing.begin();
        while(it4 != mapSeenGhostnodePing.end()){
            if((*it4).second.IsExpired()) {
                //LogPrint("ghostnode", "CGhostnodeMan::CheckAndRemove -- Removing expired Ghostnode ping: hash=%s\n", (*it4).second.GetHash().ToString());
                mapSeenGhostnodePing.erase(it4++);
            } else {
                ++it4;
            }
        }

        // remove expired mapSeenGhostnodeVerification
        std::map<uint256, CGhostnodeVerification>::iterator itv2 = mapSeenGhostnodeVerification.begin();
        while(itv2 != mapSeenGhostnodeVerification.end()){
            if((*itv2).second.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS){
                //LogPrint("ghostnode", "CGhostnodeMan::CheckAndRemove -- Removing expired Ghostnode verification: hash=%s\n", (*itv2).first.ToString());
                mapSeenGhostnodeVerification.erase(itv2++);
            } else {
                ++itv2;
            }
        }

        //LogPrint("CGhostnodeMan::CheckAndRemove -- %s\n", ToString());

        if(fGhostnodesRemoved) {
            CheckAndRebuildGhostnodeIndex();
        }
    }

    if(fGhostnodesRemoved) {
        NotifyGhostnodeUpdates();
    }
}

void CGhostnodeMan::Clear()
{
    LOCK(cs);
    vGhostnodes.clear();
    mAskedUsForGhostnodeList.clear();
    mWeAskedForGhostnodeList.clear();
    mWeAskedForGhostnodeListEntry.clear();
    mapSeenGhostnodeBroadcast.clear();
    mapSeenGhostnodePing.clear();
    nDsqCount = 0;
    nLastWatchdogVoteTime = 0;
    indexGhostnodes.Clear();
    indexGhostnodesOld.Clear();
}

int CGhostnodeMan::CountGhostnodes(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinGhostnodePaymentsProto() : nProtocolVersion;

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
        if(mn.nProtocolVersion < nProtocolVersion) continue;
        nCount++;
    }

    return nCount;
}

int CGhostnodeMan::CountEnabled(int nProtocolVersion)
{
    LOCK(cs);
    int nCount = 0;
    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinGhostnodePaymentsProto() : nProtocolVersion;

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
        if(mn.nProtocolVersion < nProtocolVersion || !mn.IsEnabled()) continue;
        nCount++;
    }

    return nCount;
}

/* Only IPv4 ghostnodes are allowed in 12.1, saving this for later
int CGhostnodeMan::CountByIP(int nNetworkType)
{
    LOCK(cs);
    int nNodeCount = 0;

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes)
        if ((nNetworkType == NET_IPV4 && mn.addr.IsIPv4()) ||
            (nNetworkType == NET_TOR  && mn.addr.IsTor())  ||
            (nNetworkType == NET_IPV6 && mn.addr.IsIPv6())) {
                nNodeCount++;
        }

    return nNodeCount;
}
*/

void CGhostnodeMan::DsegUpdate(CNode* pnode)
{
    LOCK(cs);

    if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForGhostnodeList.find(pnode->addr);
            if(it != mWeAskedForGhostnodeList.end() && GetTime() < (*it).second) {
                //LogPrint("CGhostnodeMan::DsegUpdate -- we already asked %s for the list; skipping...\n", pnode->addr.ToString());
                return;
            }
        }
    }
    
    const CNetMsgMaker msgMaker(pnode->GetSendVersion());
    g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::DSEG, CTxIn()));
    int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
    mWeAskedForGhostnodeList[pnode->addr] = askAgain;

    //LogPrint("ghostnode", "CGhostnodeMan::DsegUpdate -- asked %s for the list\n", pnode->addr.ToString());
}

CGhostnode* CGhostnodeMan::Find(const CScript &payee)
{
    LOCK(cs);

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes)
    {
        if(GetScriptForDestination(mn.pubKeyCollateralAddress.GetID()) == payee)
            return &mn;
    }
    return NULL;
}

CGhostnode* CGhostnodeMan::Find(const CTxIn &vin)
{
    LOCK(cs);

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes)
    {
        if(mn.vin.prevout == vin.prevout)
            return &mn;
    }
    return NULL;
}

CGhostnode* CGhostnodeMan::Find(const CPubKey &pubKeyGhostnode)
{
    LOCK(cs);

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes)
    {
        if(mn.pubKeyGhostnode == pubKeyGhostnode)
            return &mn;
    }
    return NULL;
}

bool CGhostnodeMan::Get(const CPubKey& pubKeyGhostnode, CGhostnode& ghostnode)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    CGhostnode* pMN = Find(pubKeyGhostnode);
    if(!pMN)  {
        return false;
    }
    ghostnode = *pMN;
    return true;
}

bool CGhostnodeMan::Get(const CTxIn& vin, CGhostnode& ghostnode)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    if(!pMN)  {
        return false;
    }
    ghostnode = *pMN;
    return true;
}

ghostnode_info_t CGhostnodeMan::GetGhostnodeInfo(const CTxIn& vin)
{
    ghostnode_info_t info;
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    if(!pMN)  {
        return info;
    }
    info = pMN->GetInfo();
    return info;
}

ghostnode_info_t CGhostnodeMan::GetGhostnodeInfo(const CPubKey& pubKeyGhostnode)
{
    ghostnode_info_t info;
    LOCK(cs);
    CGhostnode* pMN = Find(pubKeyGhostnode);
    if(!pMN)  {
        return info;
    }
    info = pMN->GetInfo();
    return info;
}

bool CGhostnodeMan::Has(const CTxIn& vin)
{
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    return (pMN != NULL);
}

char* CGhostnodeMan::GetNotQualifyReason(CGhostnode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount)
{
    if (!mn.IsValidForPayment()) {
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'not valid for payment'");
        return reasonStr;
    }
    // //check protocol version
    if (mn.nProtocolVersion < mnpayments.GetMinGhostnodePaymentsProto()) {
        // //LogPrint("Invalid nProtocolVersion!\n");
        // //LogPrint("mn.nProtocolVersion=%s!\n", mn.nProtocolVersion);
        // //LogPrint("mnpayments.GetMinGhostnodePaymentsProto=%s!\n", mnpayments.GetMinGhostnodePaymentsProto());
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'Invalid nProtocolVersion', nProtocolVersion=%d", mn.nProtocolVersion);
        return reasonStr;
    }
    //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
    if (mnpayments.IsScheduled(mn, nBlockHeight)) {
        // //LogPrint("mnpayments.IsScheduled!\n");
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'is scheduled'");
        return reasonStr;
    }
    //it's too new, wait for a cycle
    if (fFilterSigTime && mn.sigTime + (nMnCount * 2.6 * 60) > GetAdjustedTime()) {
        // //LogPrint("it's too new, wait for a cycle!\n");
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'too new', sigTime=%s, will be qualifed after=%s",
                DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime).c_str(), DateTimeStrFormat("%Y-%m-%d %H:%M UTC", mn.sigTime + (nMnCount * 2.6 * 60)).c_str());
        return reasonStr;
    }
    //make sure it has at least as many confirmations as there are ghostnodes
    if (mn.GetCollateralAge() < nMnCount) {
        // //LogPrint("mn.GetCollateralAge()=%s!\n", mn.GetCollateralAge());
        // //LogPrint("nMnCount=%s!\n", nMnCount);
        char* reasonStr = new char[256];
        sprintf(reasonStr, "false: 'collateralAge < znCount', collateralAge=%d, znCount=%d", mn.GetCollateralAge(), nMnCount);
        return reasonStr;
    }
    return NULL;
}

//
// Deterministically select the oldest/best ghostnode to pay on the network
//
CGhostnode* CGhostnodeMan::GetNextGhostnodeInQueueForPayment(bool fFilterSigTime, int& nCount)
{
    if(!pCurrentBlockIndex) {
        nCount = 0;
        return NULL;
    }
    return GetNextGhostnodeInQueueForPayment(pCurrentBlockIndex->nHeight, fFilterSigTime, nCount);
}

CGhostnode* CGhostnodeMan::GetNextGhostnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount)
{
    // Need LOCK2 here to ensure consistent locking order because the GetBlockHash call below locks cs_main
    LOCK2(cs_main,cs);

    CGhostnode *pBestGhostnode = NULL;
    std::vector<std::pair<int, CGhostnode*> > vecGhostnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */
    //LogPrintf("\nGhostnode InQueueForPayment \n");
    int nMnCount = CountEnabled();
    int index = 0;
    BOOST_FOREACH(CGhostnode &mn, vGhostnodes)
    {
        index += 1;

        char* reasonStr = GetNotQualifyReason(mn, nBlockHeight, fFilterSigTime, nMnCount);
        if (reasonStr != NULL) {
            //LogPrint("ghostnodeman", "Ghostnode, %s, addr(%s), qualify %s\n",
                     //mn.vin.prevout.ToStringShort(), CBitcoinAddress(mn.pubKeyCollateralAddress.GetID()).ToString(), reasonStr);
            delete [] reasonStr;
            continue;
        }
        //LogPrintf("\nNODE Last Paid\n");
        vecGhostnodeLastPaid.push_back(std::make_pair(mn.GetLastPaidBlock(), &mn));
    }
    nCount = (int)vecGhostnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if(fFilterSigTime && nCount < nMnCount / 3) {
        LogPrintf("Need Return, nCount=%s, nMnCount/3=%s\n", nCount, nMnCount/3);
        return GetNextGhostnodeInQueueForPayment(nBlockHeight, false, nCount);
    }

    // Sort them low to high
    sort(vecGhostnodeLastPaid.begin(), vecGhostnodeLastPaid.end(), CompareLastPaidBlock());

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight - 100)) {
        LogPrintf("CGhostnode::GetNextGhostnodeInQueueForPayment -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", (nBlockHeight - 100));
        return NULL;
    }
    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nTenthNetwork = nMnCount/10;
    int nCountTenth = 0;
    arith_uint256 nHighest = 0;
    BOOST_FOREACH (PAIRTYPE(int, CGhostnode*)& s, vecGhostnodeLastPaid){
        arith_uint256 nScore = s.second->CalculateScore(blockHash);
        if(nScore > nHighest){
            nHighest = nScore;
            pBestGhostnode = s.second;
        }
        nCountTenth++;
        if(nCountTenth >= nTenthNetwork) break;
    }
    return pBestGhostnode;
}

CGhostnode* CGhostnodeMan::FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion)
{
    LOCK(cs);

    nProtocolVersion = nProtocolVersion == -1 ? mnpayments.GetMinGhostnodePaymentsProto() : nProtocolVersion;

    int nCountEnabled = CountEnabled(nProtocolVersion);
    int nCountNotExcluded = nCountEnabled - vecToExclude.size();

    //LogPrint("CGhostnodeMan::FindRandomNotInVec -- %d enabled ghostnodes, %d ghostnodes to choose from\n", nCountEnabled, nCountNotExcluded);
    if(nCountNotExcluded < 1) return NULL;

    // fill a vector of pointers
    std::vector<CGhostnode*> vpGhostnodesShuffled;
    BOOST_FOREACH(CGhostnode &mn, vGhostnodes) {
        vpGhostnodesShuffled.push_back(&mn);
    }

    InsecureRand insecureRand;
    // shuffle pointers
    std::random_shuffle(vpGhostnodesShuffled.begin(), vpGhostnodesShuffled.end(), insecureRand);
    bool fExclude;

    // loop through
    BOOST_FOREACH(CGhostnode* pmn, vpGhostnodesShuffled) {
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
        //LogPrint("ghostnode", "CGhostnodeMan::FindRandomNotInVec -- found, ghostnode=%s\n", pmn->vin.prevout.ToStringShort());
        return pmn;
    }

    //LogPrint("ghostnode", "CGhostnodeMan::FindRandomNotInVec -- failed\n");
    return NULL;
}

int CGhostnodeMan::GetGhostnodeRank(const CTxIn& vin, int nBlockHeight, int nMinProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CGhostnode*> > vecGhostnodeScores;

    //make sure we know about this block
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, nBlockHeight)) return -1;

    LOCK(cs);

    // scan for winner
    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
        if(mn.nProtocolVersion < nMinProtocol) continue;
        if(fOnlyActive) {
            if(!mn.IsEnabled()) continue;
        }
        else {
            if(!mn.IsValidForPayment()) continue;
        }
        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecGhostnodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecGhostnodeScores.rbegin(), vecGhostnodeScores.rend(), CompareScoreMN());

    int nRank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CGhostnode*)& scorePair, vecGhostnodeScores) {
        nRank++;
        if(scorePair.second->vin.prevout == vin.prevout) return nRank;
    }

    return -1;
}

std::vector<std::pair<int, CGhostnode> > CGhostnodeMan::GetGhostnodeRanks(int nBlockHeight, int nMinProtocol)
{
    std::vector<std::pair<int64_t, CGhostnode*> > vecGhostnodeScores;
    std::vector<std::pair<int, CGhostnode> > vecGhostnodeRanks;

    //make sure we know about this block
    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, nBlockHeight)) return vecGhostnodeRanks;

    LOCK(cs);

    // scan for winner
    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {

        if(mn.nProtocolVersion < nMinProtocol || !mn.IsEnabled()) continue;

        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecGhostnodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecGhostnodeScores.rbegin(), vecGhostnodeScores.rend(), CompareScoreMN());

    int nRank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CGhostnode*)& s, vecGhostnodeScores) {
        nRank++;
        vecGhostnodeRanks.push_back(std::make_pair(nRank, *s.second));
    }

    return vecGhostnodeRanks;
}

CGhostnode* CGhostnodeMan::GetGhostnodeByRank(int nRank, int nBlockHeight, int nMinProtocol, bool fOnlyActive)
{
    std::vector<std::pair<int64_t, CGhostnode*> > vecGhostnodeScores;

    LOCK(cs);

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight)) {
        //LogPrint("CGhostnode::GetGhostnodeByRank -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", nBlockHeight);
        return NULL;
    }

    // Fill scores
    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {

        if(mn.nProtocolVersion < nMinProtocol) continue;
        if(fOnlyActive && !mn.IsEnabled()) continue;

        int64_t nScore = mn.CalculateScore(blockHash).GetCompact(false);

        vecGhostnodeScores.push_back(std::make_pair(nScore, &mn));
    }

    sort(vecGhostnodeScores.rbegin(), vecGhostnodeScores.rend(), CompareScoreMN());

    int rank = 0;
    BOOST_FOREACH (PAIRTYPE(int64_t, CGhostnode*)& s, vecGhostnodeScores){
        rank++;
        if(rank == nRank) {
            return s.second;
        }
    }

    return NULL;
}

void CGhostnodeMan::ProcessGhostnodeConnections()
{
    //we don't care about this for regtest
    if(Params().NetworkIDString() == CBaseChainParams::REGTEST) return;

    g_connman->ForEachNode([](CNode* pnode){
        if(!(darkSendPool.pSubmittedToGhostnode != NULL && pnode->addr == darkSendPool.pSubmittedToGhostnode->addr))
            if(pnode->fGhostnode) {
                // //LogPrint("Closing Ghostnode connection: peer=%d, addr=%s\n", pnode->GetId(), pnode->addr.ToString());
                pnode->fDisconnect = true;
            }
    });
    /*
    BOOST_FOREACH(CNode* pnode, g_connman->vNodes) {
        if(pnode->fGhostnode) {
            if(darkSendPool.pSubmittedToGhostnode != NULL && pnode->addr == darkSendPool.pSubmittedToGhostnode->addr) continue;
            // //LogPrint("Closing Ghostnode connection: peer=%d, addr=%s\n", pnode->GetId(), pnode->addr.ToString());
            pnode->fDisconnect = true;
        }
    }
    */
}

std::pair<CService, std::set<uint256> > CGhostnodeMan::PopScheduledMnbRequestConnection()
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


void CGhostnodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{

//    //LogPrint("ghostnode", "CGhostnodeMan::ProcessMessage, strCommand=%s\n", strCommand);
    if(fLiteMode) return; // disable all Dash specific functionality
    if(!ghostnodeSync.IsBlockchainSynced()) return;

    if (strCommand == NetMsgType::MNANNOUNCE) { //Ghostnode Broadcast
        CGhostnodeBroadcast mnb;
        vRecv >> mnb;

        pfrom->setAskFor.erase(mnb.GetHash());

        //LogPrint("MNANNOUNCE -- Ghostnode announce, ghostnode=%s\n", mnb.vin.prevout.ToStringShort());

        int nDos = 0;

        if (CheckMnbAndUpdateGhostnodeList(pfrom, mnb, nDos)) {
            // use announced Ghostnode as a peer
            g_connman->addrman.Add(CAddress(mnb.addr, NODE_NETWORK), pfrom->addr, 2*60*60);
        } else if(nDos > 0) {
            Misbehaving(pfrom->GetId(), nDos);
        }

        if(fGhostnodesAdded) {
            NotifyGhostnodeUpdates();
        }
    } else if (strCommand == NetMsgType::MNPING) { //Ghostnode Ping

        CGhostnodePing mnp;
        vRecv >> mnp;

        uint256 nHash = mnp.GetHash();

        pfrom->setAskFor.erase(nHash);

        //LogPrint("ghostnode", "MNPING -- Ghostnode ping, ghostnode=%s\n", mnp.vin.prevout.ToStringShort());

        // Need LOCK2 here to ensure consistent locking order because the CheckAndUpdate call below locks cs_main
        LOCK2(cs_main, cs);

        if(mapSeenGhostnodePing.count(nHash)) return; //seen
        mapSeenGhostnodePing.insert(std::make_pair(nHash, mnp));

        //LogPrint("ghostnode", "MNPING -- Ghostnode ping, ghostnode=%s new\n", mnp.vin.prevout.ToStringShort());

        // see if we have this Ghostnode
        CGhostnode* pmn = mnodeman.Find(mnp.vin);

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
        // we might have to ask for a ghostnode entry once
        AskForMN(pfrom, mnp.vin);

    } else if (strCommand == NetMsgType::DSEG) { //Get Ghostnode list or specific entry
        // Ignore such requests until we are fully synced.
        // We could start processing this after ghostnode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!ghostnodeSync.IsSynced(chainActive.Height())) return;

        CTxIn vin;
        vRecv >> vin;

        //LogPrint("ghostnode", "DSEG -- Ghostnode list, ghostnode=%s\n", vin.prevout.ToStringShort());

        LOCK(cs);

        if(vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if(!isLocal && Params().NetworkIDString() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator i = mAskedUsForGhostnodeList.find(pfrom->addr);
                if (i != mAskedUsForGhostnodeList.end()){
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        Misbehaving(pfrom->GetId(), 34);
                        //LogPrint("DSEG -- peer already asked me for the list, peer=%d\n", pfrom->GetId());
                        return;
                    }
                }
                int64_t askAgain = GetTime() + DSEG_UPDATE_SECONDS;
                mAskedUsForGhostnodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok

        int nInvCount = 0;

        BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
            if (vin != CTxIn() && vin != mn.vin) continue; // asked for specific vin but we are not there yet
            if (mn.addr.IsRFC1918() || mn.addr.IsLocal()) continue; // do not send local network ghostnode
            if (mn.IsUpdateRequired()) continue; // do not send outdated ghostnodes

            //LogPrint("ghostnode", "DSEG -- Sending Ghostnode entry: ghostnode=%s  addr=%s\n", mn.vin.prevout.ToStringShort(), mn.addr.ToString());
            CGhostnodeBroadcast mnb = CGhostnodeBroadcast(mn);
            uint256 hash = mnb.GetHash();
            pfrom->PushInventory(CInv(MSG_GHOSTNODE_ANNOUNCE, hash));
            pfrom->PushInventory(CInv(MSG_GHOSTNODE_PING, mn.lastPing.GetHash()));
            nInvCount++;

            if (!mapSeenGhostnodeBroadcast.count(hash)) {
                mapSeenGhostnodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));
            }

            if (vin == mn.vin) {
                //LogPrint("DSEG -- Sent 1 Ghostnode inv to peer %d\n", pfrom->GetId());
                return;
            }
        }

        if(vin == CTxIn()) {
            const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
            g_connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, GHOSTNODE_SYNC_LIST, nInvCount));
            //LogPrint("DSEG -- Sent %d Ghostnode invs to peer %d\n", nInvCount, pfrom->GetId());
            return;
        }
        // smth weird happen - someone asked us for vin we have no idea about?
        //LogPrint("ghostnode", "DSEG -- No invs sent to peer %d\n", pfrom->GetId());

    } else if (strCommand == NetMsgType::MNVERIFY) { // Ghostnode Verify

        // Need LOCK2 here to ensure consistent locking order because the all functions below call GetBlockHash which locks cs_main
        LOCK2(cs_main, cs);

        CGhostnodeVerification mnv;
        vRecv >> mnv;

        if(mnv.vchSig1.empty()) {
            // CASE 1: someone asked me to verify myself /IP we are using/
            SendVerifyReply(pfrom, mnv);
        } else if (mnv.vchSig2.empty()) {
            // CASE 2: we _probably_ got verification we requested from some ghostnode
            ProcessVerifyReply(pfrom, mnv);
        } else {
            // CASE 3: we _probably_ got verification broadcast signed by some ghostnode which verified another one
            ProcessVerifyBroadcast(pfrom, mnv);
        }
    }
}

// Verification of ghostnodes via unique direct requests.

void CGhostnodeMan::DoFullVerificationStep()
{
    if(activeGhostnode.vin == CTxIn()) return;
    if(!ghostnodeSync.IsSynced(chainActive.Height())) return;

    std::vector<std::pair<int, CGhostnode> > vecGhostnodeRanks = GetGhostnodeRanks(pCurrentBlockIndex->nHeight - 1, MIN_POSE_PROTO_VERSION);

    {
    LOCK(cs);

    int nCount = 0;

    int nMyRank = -1;
    int nRanksTotal = (int)vecGhostnodeRanks.size();

    // send verify requests only if we are in top MAX_POSE_RANK
    std::vector<std::pair<int, CGhostnode> >::iterator it = vecGhostnodeRanks.begin();
    while(it != vecGhostnodeRanks.end()) {
        if(it->first > MAX_POSE_RANK) {
            //LogPrint("ghostnode", "CGhostnodeMan::DoFullVerificationStep -- Must be in top %d to send verify request\n",
                    //    (int)MAX_POSE_RANK);
            return;
        }
        if(it->second.vin == activeGhostnode.vin) {
            nMyRank = it->first;
            //LogPrint("ghostnode", "CGhostnodeMan::DoFullVerificationStep -- Found self at rank %d/%d, verifying up to %d ghostnodes\n",
                    //    nMyRank, nRanksTotal, (int)MAX_POSE_CONNECTIONS);
            break;
        }
        ++it;
    }

    // edge case: list is too short and this ghostnode is not enabled
    if(nMyRank == -1) return;

    // send verify requests to up to MAX_POSE_CONNECTIONS ghostnodes
    // starting from MAX_POSE_RANK + nMyRank and using MAX_POSE_CONNECTIONS as a step
    int nOffset = MAX_POSE_RANK + nMyRank - 1;
    if(nOffset >= (int)vecGhostnodeRanks.size()) return;

    std::vector<CGhostnode*> vSortedByAddr;
    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
        vSortedByAddr.push_back(&mn);
    }

    sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

    it = vecGhostnodeRanks.begin() + nOffset;
    while(it != vecGhostnodeRanks.end()) {
        if(it->second.IsPoSeVerified() || it->second.IsPoSeBanned()) {
            //LogPrint("ghostnode", "CGhostnodeMan::DoFullVerificationStep -- Already %s%s%s ghostnode %s address %s, skipping...\n",
//                        it->second.IsPoSeVerified() ? "verified" : "",
//                        it->second.IsPoSeVerified() && it->second.IsPoSeBanned() ? " and " : "",
//                        it->second.IsPoSeBanned() ? "banned" : "",
//                        it->second.vin.prevout.ToStringShort(), it->second.addr.ToString());
            nOffset += MAX_POSE_CONNECTIONS;
            if(nOffset >= (int)vecGhostnodeRanks.size()) break;
            it += MAX_POSE_CONNECTIONS;
            continue;
        }
        //LogPrint("ghostnode", "CGhostnodeMan::DoFullVerificationStep -- Verifying ghostnode %s rank %d/%d address %s\n",
                 //   it->second.vin.prevout.ToStringShort(), it->first, nRanksTotal, it->second.addr.ToString());
        if(SendVerifyRequest(CAddress(it->second.addr, NODE_NETWORK), vSortedByAddr)) {
            nCount++;
            if(nCount >= MAX_POSE_CONNECTIONS) break;
        }
        nOffset += MAX_POSE_CONNECTIONS;
        if(nOffset >= (int)vecGhostnodeRanks.size()) break;
        it += MAX_POSE_CONNECTIONS;
    }
    }
    //LogPrint("ghostnode", "CGhostnodeMan::DoFullVerificationStep -- Sent verification requests to %d ghostnodes\n", nCount);
}

// This function tries to find ghostnodes with the same addr,
// find a verified one and ban all the other. If there are many nodes
// with the same addr but none of them is verified yet, then none of them are banned.
// It could take many times to run this before most of the duplicate nodes are banned.

void CGhostnodeMan::CheckSameAddr()
{
    if(!ghostnodeSync.IsSynced(chainActive.Height()) || vGhostnodes.empty()) return;

    std::vector<CGhostnode*> vBan;
    std::vector<CGhostnode*> vSortedByAddr;

    {
        LOCK(cs);

        CGhostnode* pprevGhostnode = NULL;
        CGhostnode* pverifiedGhostnode = NULL;

        BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
            vSortedByAddr.push_back(&mn);
        }

        sort(vSortedByAddr.begin(), vSortedByAddr.end(), CompareByAddr());

        BOOST_FOREACH(CGhostnode* pmn, vSortedByAddr) {
            // check only (pre)enabled ghostnodes
            if(!pmn->IsEnabled() && !pmn->IsPreEnabled()) continue;
            // initial step
            if(!pprevGhostnode) {
                pprevGhostnode = pmn;
                pverifiedGhostnode = pmn->IsPoSeVerified() ? pmn : NULL;
                continue;
            }
            // second+ step
            if(pmn->addr == pprevGhostnode->addr) {
                if(pverifiedGhostnode) {
                    // another ghostnode with the same ip is verified, ban this one
                    vBan.push_back(pmn);
                } else if(pmn->IsPoSeVerified()) {
                    // this ghostnode with the same ip is verified, ban previous one
                    vBan.push_back(pprevGhostnode);
                    // and keep a reference to be able to ban following ghostnodes with the same ip
                    pverifiedGhostnode = pmn;
                }
            } else {
                pverifiedGhostnode = pmn->IsPoSeVerified() ? pmn : NULL;
            }
            pprevGhostnode = pmn;
        }
    }

    // ban duplicates
    BOOST_FOREACH(CGhostnode* pmn, vBan) {
        //LogPrint("CGhostnodeMan::CheckSameAddr -- increasing PoSe ban score for ghostnode %s\n", pmn->vin.prevout.ToStringShort());
        pmn->IncreasePoSeBanScore();
    }
}

bool CGhostnodeMan::SendVerifyRequest(const CAddress& addr, const std::vector<CGhostnode*>& vSortedByAddr)
{
    if(netfulfilledman.HasFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        // we already asked for verification, not a good idea to do this too often, skip it
        //LogPrint("ghostnode", "CGhostnodeMan::SendVerifyRequest -- too many requests, skipping... addr=%s\n", addr.ToString());
        return false;
    }

    CNode* pnode = g_connman->ConnectNode(addr, NULL, false, true);
    if(pnode == NULL) {
        //LogPrint("CGhostnodeMan::SendVerifyRequest -- can't connect to node to verify it, addr=%s\n", addr.ToString());
        return false;
    }

    netfulfilledman.AddFulfilledRequest(addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request");
    // use random nonce, store it and require node to reply with correct one later
    CGhostnodeVerification mnv(addr, GetRandInt(999999), pCurrentBlockIndex->nHeight - 1);
    mWeAskedForVerification[addr] = mnv;
    //LogPrint("CGhostnodeMan::SendVerifyRequest -- verifying node using nonce %d addr=%s\n", mnv.nonce, addr.ToString());
    const CNetMsgMaker msgMaker(pnode->GetSendVersion());
    g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, mnv));


    return true;
}

void CGhostnodeMan::SendVerifyReply(CNode* pnode, CGhostnodeVerification& mnv)
{
    // only ghostnodes can sign this, why would someone ask regular node?
    if(!fGhostNode) {
        // do not ban, malicious node might be using my IP
        // and trying to confuse the node which tries to verify it
        return;
    }

    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply")) {
//        // peer should not ask us that often
        //LogPrint("GhostnodeMan::SendVerifyReply -- ERROR: peer already asked me recently, peer=%d\n", pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        //LogPrint("GhostnodeMan::SendVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    std::string strMessage = strprintf("%s%d%s", activeGhostnode.service.ToString(), mnv.nonce, blockHash.ToString());

    if(!darkSendSigner.SignMessage(strMessage, mnv.vchSig1, activeGhostnode.keyGhostnode)) {
        //LogPrint("GhostnodeMan::SendVerifyReply -- SignMessage() failed\n");
        return;
    }

    std::string strError;

    if(!darkSendSigner.VerifyMessage(activeGhostnode.pubKeyGhostnode, mnv.vchSig1, strMessage, strError)) {
        //LogPrint("GhostnodeMan::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
        return;
    }

    const CNetMsgMaker msgMaker(pnode->GetSendVersion());
    g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::MNVERIFY, mnv));
    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-reply");
}

void CGhostnodeMan::ProcessVerifyReply(CNode* pnode, CGhostnodeVerification& mnv)
{
    std::string strError;

    // did we even ask for it? if that's the case we should have matching fulfilled request
    if(!netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-request")) {
        //LogPrint("CGhostnodeMan::ProcessVerifyReply -- ERROR: we didn't ask for verification of %s, peer=%d\n", pnode->addr.ToString(), pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    // Received nonce for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nonce != mnv.nonce) {
        //LogPrint("CGhostnodeMan::ProcessVerifyReply -- ERROR: wrong nounce: requested=%d, received=%d, peer=%d\n",
                   // mWeAskedForVerification[pnode->addr].nonce, mnv.nonce, pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    // Received nBlockHeight for a known address must match the one we sent
    if(mWeAskedForVerification[pnode->addr].nBlockHeight != mnv.nBlockHeight) {
        //LogPrint("CGhostnodeMan::ProcessVerifyReply -- ERROR: wrong nBlockHeight: requested=%d, received=%d, peer=%d\n",
                   // mWeAskedForVerification[pnode->addr].nBlockHeight, mnv.nBlockHeight, pnode->GetId());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        //LogPrint("GhostnodeMan::ProcessVerifyReply -- can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

//    // we already verified this address, why node is spamming?
    if(netfulfilledman.HasFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done")) {
        //LogPrint("CGhostnodeMan::ProcessVerifyReply -- ERROR: already verified %s recently\n", pnode->addr.ToString());
        Misbehaving(pnode->GetId(), 20);
        return;
    }

    {
        LOCK(cs);

        CGhostnode* prealGhostnode = NULL;
        std::vector<CGhostnode*> vpGhostnodesToBan;
        std::vector<CGhostnode>::iterator it = vGhostnodes.begin();
        std::string strMessage1 = strprintf("%s%d%s", pnode->addr.ToString(), mnv.nonce, blockHash.ToString());
        while(it != vGhostnodes.end()) {
            if(CAddress(it->addr, NODE_NETWORK) == pnode->addr) {
                if(darkSendSigner.VerifyMessage(it->pubKeyGhostnode, mnv.vchSig1, strMessage1, strError)) {
                    // found it!
                    prealGhostnode = &(*it);
                    if(!it->IsPoSeVerified()) {
                        it->DecreasePoSeBanScore();
                    }
                    netfulfilledman.AddFulfilledRequest(pnode->addr, strprintf("%s", NetMsgType::MNVERIFY)+"-done");

                    // we can only broadcast it if we are an activated ghostnode
                    if(activeGhostnode.vin == CTxIn()) continue;
                    // update ...
                    mnv.addr = it->addr;
                    mnv.vin1 = it->vin;
                    mnv.vin2 = activeGhostnode.vin;
                    std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                            mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());
                    // ... and sign it
                    if(!darkSendSigner.SignMessage(strMessage2, mnv.vchSig2, activeGhostnode.keyGhostnode)) {
                        //LogPrint("GhostnodeMan::ProcessVerifyReply -- SignMessage() failed\n");
                        return;
                    }

                    std::string strError;

                    if(!darkSendSigner.VerifyMessage(activeGhostnode.pubKeyGhostnode, mnv.vchSig2, strMessage2, strError)) {
                        //LogPrint("GhostnodeMan::ProcessVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
                        return;
                    }

                    mWeAskedForVerification[pnode->addr] = mnv;
                    mnv.Relay();

                } else {
                    vpGhostnodesToBan.push_back(&(*it));
                }
            }
            ++it;
        }
        // no real ghostnode found?...
        if(!prealGhostnode) {
            // this should never be the case normally,
            // only if someone is trying to game the system in some way or smth like that
            //LogPrint("CGhostnodeMan::ProcessVerifyReply -- ERROR: no real ghostnode found for addr %s\n", pnode->addr.ToString());
            Misbehaving(pnode->GetId(), 20);
            return;
        }
        //LogPrint("CGhostnodeMan::ProcessVerifyReply -- verified real ghostnode %s for addr %s\n",
                   // prealGhostnode->vin.prevout.ToStringShort(), pnode->addr.ToString());
        // increase ban score for everyone else
        BOOST_FOREACH(CGhostnode* pmn, vpGhostnodesToBan) {
            pmn->IncreasePoSeBanScore();
            //LogPrint("ghostnode", "CGhostnodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                        //prealGhostnode->vin.prevout.ToStringShort(), pnode->addr.ToString(), pmn->nPoSeBanScore);
        }
        //LogPrint("CGhostnodeMan::ProcessVerifyBroadcast -- PoSe score increased for %d fake ghostnodes, addr %s\n",
                   // (int)vpGhostnodesToBan.size(), pnode->addr.ToString());
    }
}

void CGhostnodeMan::ProcessVerifyBroadcast(CNode* pnode, const CGhostnodeVerification& mnv)
{
    std::string strError;

    if(mapSeenGhostnodeVerification.find(mnv.GetHash()) != mapSeenGhostnodeVerification.end()) {
        // we already have one
        return;
    }
    mapSeenGhostnodeVerification[mnv.GetHash()] = mnv;

    // we don't care about history
    if(mnv.nBlockHeight < pCurrentBlockIndex->nHeight - MAX_POSE_BLOCKS) {
        //LogPrint("ghostnode", "GhostnodeMan::ProcessVerifyBroadcast -- Outdated: current block %d, verification block %d, peer=%d\n",
                  //  pCurrentBlockIndex->nHeight, mnv.nBlockHeight, pnode->GetId());
        return;
    }

    if(mnv.vin1.prevout == mnv.vin2.prevout) {
        //LogPrint("ghostnode", "GhostnodeMan::ProcessVerifyBroadcast -- ERROR: same vins %s, peer=%d\n",
                   // mnv.vin1.prevout.ToStringShort(), pnode->GetId());
        // that was NOT a good idea to cheat and verify itself,
        // ban the node we received such message from
        Misbehaving(pnode->GetId(), 100);
        return;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, mnv.nBlockHeight)) {
        // this shouldn't happen...
        //LogPrint("GhostnodeMan::ProcessVerifyBroadcast -- Can't get block hash for unknown block height %d, peer=%d\n", mnv.nBlockHeight, pnode->GetId());
        return;
    }

    int nRank = GetGhostnodeRank(mnv.vin2, mnv.nBlockHeight, MIN_POSE_PROTO_VERSION);

    if (nRank == -1) {
        //LogPrint("ghostnode", "CGhostnodeMan::ProcessVerifyBroadcast -- Can't calculate rank for ghostnode %s\n",
                  //  mnv.vin2.prevout.ToStringShort());
        return;
    }

    if(nRank > MAX_POSE_RANK) {
        //LogPrint("ghostnode", "CGhostnodeMan::ProcessVerifyBroadcast -- Mastrernode %s is not in top %d, current rank %d, peer=%d\n",
                  //  mnv.vin2.prevout.ToStringShort(), (int)MAX_POSE_RANK, nRank, pnode->GetId());
        return;
    }

    {
        LOCK(cs);

        std::string strMessage1 = strprintf("%s%d%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString());
        std::string strMessage2 = strprintf("%s%d%s%s%s", mnv.addr.ToString(), mnv.nonce, blockHash.ToString(),
                                mnv.vin1.prevout.ToStringShort(), mnv.vin2.prevout.ToStringShort());

        CGhostnode* pmn1 = Find(mnv.vin1);
        if(!pmn1) {
            //LogPrint("CGhostnodeMan::ProcessVerifyBroadcast -- can't find ghostnode1 %s\n", mnv.vin1.prevout.ToStringShort());
            return;
        }

        CGhostnode* pmn2 = Find(mnv.vin2);
        if(!pmn2) {
            //LogPrint("CGhostnodeMan::ProcessVerifyBroadcast -- can't find ghostnode2 %s\n", mnv.vin2.prevout.ToStringShort());
            return;
        }

        if(pmn1->addr != mnv.addr) {
            //LogPrint("CGhostnodeMan::ProcessVerifyBroadcast -- addr %s do not match %s\n", mnv.addr.ToString(), pnode->addr.ToString());
            return;
        }

        if(darkSendSigner.VerifyMessage(pmn1->pubKeyGhostnode, mnv.vchSig1, strMessage1, strError)) {
            //LogPrint("GhostnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for ghostnode1 failed, error: %s\n", strError);
            return;
        }

        if(darkSendSigner.VerifyMessage(pmn2->pubKeyGhostnode, mnv.vchSig2, strMessage2, strError)) {
            //LogPrint("GhostnodeMan::ProcessVerifyBroadcast -- VerifyMessage() for ghostnode2 failed, error: %s\n", strError);
            return;
        }

        if(!pmn1->IsPoSeVerified()) {
            pmn1->DecreasePoSeBanScore();
        }
        mnv.Relay();

        //LogPrint("CGhostnodeMan::ProcessVerifyBroadcast -- verified ghostnode %s for addr %s\n",
                   // pmn1->vin.prevout.ToStringShort(), pnode->addr.ToString());

        // increase ban score for everyone else with the same addr
        int nCount = 0;
        BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
            if(mn.addr != mnv.addr || mn.vin.prevout == mnv.vin1.prevout) continue;
            mn.IncreasePoSeBanScore();
            nCount++;
            //LogPrint("ghostnode", "CGhostnodeMan::ProcessVerifyBroadcast -- increased PoSe ban score for %s addr %s, new score %d\n",
                      //  mn.vin.prevout.ToStringShort(), mn.addr.ToString(), mn.nPoSeBanScore);
        }
        //LogPrint("CGhostnodeMan::ProcessVerifyBroadcast -- PoSe score incresed for %d fake ghostnodes, addr %s\n",
                    //nCount, pnode->addr.ToString());
    }
}

std::string CGhostnodeMan::ToString() const
{
    std::ostringstream info;

    info << "Ghostnodes: " << (int)vGhostnodes.size() <<
            ", peers who asked us for Ghostnode list: " << (int)mAskedUsForGhostnodeList.size() <<
            ", peers we asked for Ghostnode list: " << (int)mWeAskedForGhostnodeList.size() <<
            ", entries in Ghostnode list we asked for: " << (int)mWeAskedForGhostnodeListEntry.size() <<
            ", ghostnode index size: " << indexGhostnodes.GetSize() <<
            ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}

void CGhostnodeMan::UpdateGhostnodeList(CGhostnodeBroadcast mnb)
{
    try {
        //LogPrint("CGhostnodeMan::UpdateGhostnodeList\n");
        LOCK2(cs_main, cs);
        mapSeenGhostnodePing.insert(std::make_pair(mnb.lastPing.GetHash(), mnb.lastPing));
        mapSeenGhostnodeBroadcast.insert(std::make_pair(mnb.GetHash(), std::make_pair(GetTime(), mnb)));

        //LogPrint("CGhostnodeMan::UpdateGhostnodeList -- ghostnode=%s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());

        CGhostnode *pmn = Find(mnb.vin);
        if (pmn == NULL) {
            CGhostnode mn(mnb);
            if (Add(mn)) {
                ghostnodeSync.AddedGhostnodeList();
            }
        } else {
            CGhostnodeBroadcast mnbOld = mapSeenGhostnodeBroadcast[CGhostnodeBroadcast(*pmn).GetHash()].second;
            if (pmn->UpdateFromNewBroadcast(mnb)) {
                ghostnodeSync.AddedGhostnodeList();
                mapSeenGhostnodeBroadcast.erase(mnbOld.GetHash());
            }
        }
    } catch (const std::exception &e) {
        PrintExceptionContinue(&e, "UpdateGhostnodeList");
    }
}

bool CGhostnodeMan::CheckMnbAndUpdateGhostnodeList(CNode* pfrom, CGhostnodeBroadcast mnb, int& nDos)
{
    // Need LOCK2 here to ensure consistent locking order because the SimpleCheck call below locks cs_main
    LOCK(cs_main);

    {
        LOCK(cs);
        nDos = 0;
        //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- ghostnode=%s\n", mnb.vin.prevout.ToStringShort());

        uint256 hash = mnb.GetHash();
        if (mapSeenGhostnodeBroadcast.count(hash) && !mnb.fRecovery) { //seen
            //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- ghostnode=%s seen\n", mnb.vin.prevout.ToStringShort());
            // less then 2 pings left before this MN goes into non-recoverable state, bump sync timeout
            if (GetTime() - mapSeenGhostnodeBroadcast[hash].first > GHOSTNODE_NEW_START_REQUIRED_SECONDS - GHOSTNODE_MIN_MNP_SECONDS * 2) {
                //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- ghostnode=%s seen update\n", mnb.vin.prevout.ToStringShort());
                mapSeenGhostnodeBroadcast[hash].first = GetTime();
                ghostnodeSync.AddedGhostnodeList();
            }
            // did we ask this node for it?
            if (pfrom && IsMnbRecoveryRequested(hash) && GetTime() < mMnbRecoveryRequests[hash].first) {
                //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- mnb=%s seen request\n", hash.ToString());
                if (mMnbRecoveryRequests[hash].second.count(pfrom->addr)) {
                    //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- mnb=%s seen request, addr=%s\n", hash.ToString(), pfrom->addr.ToString());
                    // do not allow node to send same mnb multiple times in recovery mode
                    mMnbRecoveryRequests[hash].second.erase(pfrom->addr);
                    // does it have newer lastPing?
                    if (mnb.lastPing.sigTime > mapSeenGhostnodeBroadcast[hash].second.lastPing.sigTime) {
                        // simulate Check
                        CGhostnode mnTemp = CGhostnode(mnb);
                        mnTemp.Check();
                        //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- mnb=%s seen request, addr=%s, better lastPing: %d min ago, projected mn state: %s\n", hash.ToString(), pfrom->addr.ToString(), (GetTime() - mnb.lastPing.sigTime) / 60, mnTemp.GetStateString());
                        if (mnTemp.IsValidStateForAutoStart(mnTemp.nActiveState)) {
                            // this node thinks it's a good one
                            //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- ghostnode=%s seen good\n", mnb.vin.prevout.ToStringShort());
                            mMnbRecoveryGoodReplies[hash].push_back(mnb);
                        }
                    }
                }
            }
            return true;
        }
        mapSeenGhostnodeBroadcast.insert(std::make_pair(hash, std::make_pair(GetTime(), mnb)));

        //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- ghostnode=%s new\n", mnb.vin.prevout.ToStringShort());

        if (!mnb.SimpleCheck(nDos)) {
            //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- SimpleCheck() failed, ghostnode=%s\n", mnb.vin.prevout.ToStringShort());
            return false;
        }

        // search Ghostnode list
        CGhostnode *pmn = Find(mnb.vin);
        if (pmn) {
            CGhostnodeBroadcast mnbOld = mapSeenGhostnodeBroadcast[CGhostnodeBroadcast(*pmn).GetHash()].second;
            if (!mnb.Update(pmn, nDos)) {
                //LogPrint("ghostnode", "CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- Update() failed, ghostnode=%s\n", mnb.vin.prevout.ToStringShort());
                return false;
            }
            if (hash != mnbOld.GetHash()) {
                mapSeenGhostnodeBroadcast.erase(mnbOld.GetHash());
            }
        }
    } // end of LOCK(cs);

    if(mnb.CheckOutpoint(nDos)) {
        Add(mnb);
        ghostnodeSync.AddedGhostnodeList();
        // if it matches our Ghostnode privkey...
        if(fGhostNode && mnb.pubKeyGhostnode == activeGhostnode.pubKeyGhostnode) {
            mnb.nPoSeBanScore = -GHOSTNODE_POSE_BAN_MAX_SCORE;
            if(mnb.nProtocolVersion == PROTOCOL_VERSION) {
                // ... and PROTOCOL_VERSION, then we've been remotely activated ...
                //LogPrint("CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- Got NEW Ghostnode entry: ghostnode=%s  sigTime=%lld  addr=%s\n",
                            //mnb.vin.prevout.ToStringShort(), mnb.sigTime, mnb.addr.ToString());
                activeGhostnode.ManageState();
            } else {
                // ... otherwise we need to reactivate our node, do not add it to the list and do not relay
                // but also do not ban the node we get this message from
                //LogPrint("CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- wrong PROTOCOL_VERSION, re-activate your MN: message nProtocolVersion=%d  PROTOCOL_VERSION=%d\n", mnb.nProtocolVersion, PROTOCOL_VERSION);
                return false;
            }
        }
        mnb.RelayGhostNode();
    } else {
        //LogPrint("CGhostnodeMan::CheckMnbAndUpdateGhostnodeList -- Rejected Ghostnode entry: %s  addr=%s\n", mnb.vin.prevout.ToStringShort(), mnb.addr.ToString());
        return false;
    }

    return true;
}

void CGhostnodeMan::UpdateLastPaid()
{
    LOCK(cs);
    if(fLiteMode) return;
    if(!pCurrentBlockIndex) {
        // //LogPrint("CGhostnodeMan::UpdateLastPaid, pCurrentBlockIndex=NULL\n");
        return;
    }

    static bool IsFirstRun = true;
    // Do full scan on first run or if we are not a ghostnode
    // (MNs should update this info on every block, so limited scan should be enough for them)
    int nMaxBlocksToScanBack = (IsFirstRun || !fGhostNode) ? mnpayments.GetStorageLimit() : LAST_PAID_SCAN_BLOCKS;

    //LogPrint("mnpayments", "CGhostnodeMan::UpdateLastPaid -- nHeight=%d, nMaxBlocksToScanBack=%d, IsFirstRun=%s\n",
                            // pCurrentBlockIndex->nHeight, nMaxBlocksToScanBack, IsFirstRun ? "true" : "false");

    BOOST_FOREACH(CGhostnode& mn, vGhostnodes) {
        mn.UpdateLastPaid(pCurrentBlockIndex, nMaxBlocksToScanBack);
    }

    // every time is like the first time if winners list is not synced
    IsFirstRun = !ghostnodeSync.IsWinnersListSynced();
}

void CGhostnodeMan::CheckAndRebuildGhostnodeIndex()
{
    LOCK(cs);

    if(GetTime() - nLastIndexRebuildTime < MIN_INDEX_REBUILD_TIME) {
        return;
    }

    if(indexGhostnodes.GetSize() <= MAX_EXPECTED_INDEX_SIZE) {
        return;
    }

    if(indexGhostnodes.GetSize() <= int(vGhostnodes.size())) {
        return;
    }

    indexGhostnodesOld = indexGhostnodes;
    indexGhostnodes.Clear();
    for(size_t i = 0; i < vGhostnodes.size(); ++i) {
        indexGhostnodes.AddGhostnodeVIN(vGhostnodes[i].vin);
    }

    fIndexRebuilt = true;
    nLastIndexRebuildTime = GetTime();
}

void CGhostnodeMan::UpdateWatchdogVoteTime(const CTxIn& vin)
{
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->UpdateWatchdogVoteTime();
    nLastWatchdogVoteTime = GetTime();
}

bool CGhostnodeMan::IsWatchdogActive()
{
    LOCK(cs);
    // Check if any ghostnodes have voted recently, otherwise return false
    return (GetTime() - nLastWatchdogVoteTime) <= GHOSTNODE_WATCHDOG_MAX_SECONDS;
}

void CGhostnodeMan::CheckGhostnode(const CTxIn& vin, bool fForce)
{
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->Check(fForce);
}

void CGhostnodeMan::CheckGhostnode(const CPubKey& pubKeyGhostnode, bool fForce)
{
    LOCK(cs);
    CGhostnode* pMN = Find(pubKeyGhostnode);
    if(!pMN)  {
        return;
    }
    pMN->Check(fForce);
}

int CGhostnodeMan::GetGhostnodeState(const CTxIn& vin)
{
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    if(!pMN)  {
        return CGhostnode::GHOSTNODE_NEW_START_REQUIRED;
    }
    return pMN->nActiveState;
}

int CGhostnodeMan::GetGhostnodeState(const CPubKey& pubKeyGhostnode)
{
    LOCK(cs);
    CGhostnode* pMN = Find(pubKeyGhostnode);
    if(!pMN)  {
        return CGhostnode::GHOSTNODE_NEW_START_REQUIRED;
    }
    return pMN->nActiveState;
}

bool CGhostnodeMan::IsGhostnodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt)
{
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    if(!pMN) {
        return false;
    }
    return pMN->IsPingedWithin(nSeconds, nTimeToCheckAt);
}

void CGhostnodeMan::SetGhostnodeLastPing(const CTxIn& vin, const CGhostnodePing& mnp)
{
    LOCK(cs);
    CGhostnode* pMN = Find(vin);
    if(!pMN)  {
        return;
    }
    pMN->lastPing = mnp;
    mapSeenGhostnodePing.insert(std::make_pair(mnp.GetHash(), mnp));

    CGhostnodeBroadcast mnb(*pMN);
    uint256 hash = mnb.GetHash();
    if(mapSeenGhostnodeBroadcast.count(hash)) {
        mapSeenGhostnodeBroadcast[hash].second.lastPing = mnp;
    }
}

void CGhostnodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    pCurrentBlockIndex = pindex;
    //LogPrint("ghostnode", "CGhostnodeMan::UpdatedBlockTip -- pCurrentBlockIndex->nHeight=%d\n", pCurrentBlockIndex->nHeight);

    CheckSameAddr();

    if(fGhostNode) {
        // normal wallet does not need to update this every block, doing update on rpc call should be enough
        UpdateLastPaid();
    }
}

void CGhostnodeMan::NotifyGhostnodeUpdates()
{
    // Avoid double locking
    bool fGhostnodesAddedLocal = false;
    bool fGhostnodesRemovedLocal = false;
    {
        LOCK(cs);
        fGhostnodesAddedLocal = fGhostnodesAdded;
        fGhostnodesRemovedLocal = fGhostnodesRemoved;
    }

    if(fGhostnodesAddedLocal) {
//        governance.CheckGhostnodeOrphanObjects();
//        governance.CheckGhostnodeOrphanVotes();
    }
    if(fGhostnodesRemovedLocal) {
//        governance.UpdateCachesAndClean();
    }

    LOCK(cs);
    fGhostnodesAdded = false;
    fGhostnodesRemoved = false;
}
