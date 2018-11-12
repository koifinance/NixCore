// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOSTNODEMAN_H
#define GHOSTNODEMAN_H

#include "ghostnode.h"
#include "sync.h"

using namespace std;

class CGhostnodeMan;

extern CGhostnodeMan mnodeman;

/**
 * Provides a forward and reverse index between MN vin's and integers.
 *
 * This mapping is normally add-only and is expected to be permanent
 * It is only rebuilt if the size of the index exceeds the expected maximum number
 * of MN's and the current number of known MN's.
 *
 * The external interface to this index is provided via delegation by CGhostnodeMan
 */
class CGhostnodeIndex
{
public: // Types
    typedef std::map<CTxIn,int> index_m_t;

    typedef index_m_t::iterator index_m_it;

    typedef index_m_t::const_iterator index_m_cit;

    typedef std::map<int,CTxIn> rindex_m_t;

    typedef rindex_m_t::iterator rindex_m_it;

    typedef rindex_m_t::const_iterator rindex_m_cit;

private:
    int                  nSize;

    index_m_t            mapIndex;

    rindex_m_t           mapReverseIndex;

public:
    CGhostnodeIndex();

    int GetSize() const {
        return nSize;
    }

    /// Retrieve ghostnode vin by index
    bool Get(int nIndex, CTxIn& vinGhostnode) const;

    /// Get index of a ghostnode vin
    int GetGhostnodeIndex(const CTxIn& vinGhostnode) const;

    void AddGhostnodeVIN(const CTxIn& vinGhostnode);

    void Clear();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(mapIndex);
        if(ser_action.ForRead()) {
            RebuildIndex();
        }
    }

private:
    void RebuildIndex();

};

class CGhostnodeMan
{
public:
    typedef std::map<CTxIn,int> index_m_t;

    typedef index_m_t::iterator index_m_it;

    typedef index_m_t::const_iterator index_m_cit;

private:
    static const int MAX_EXPECTED_INDEX_SIZE = 30000;

    /// Only allow 1 index rebuild per hour
    static const int64_t MIN_INDEX_REBUILD_TIME = 3600;

    static const std::string SERIALIZATION_VERSION_STRING;

    static const int DSEG_UPDATE_SECONDS        = 3 * 60 * 60;

    static const int LAST_PAID_SCAN_BLOCKS      = 100;

    static const int MIN_POSE_PROTO_VERSION     = 70203;
    static const int MAX_POSE_CONNECTIONS       = 10;
    static const int MAX_POSE_RANK              = 10;
    static const int MAX_POSE_BLOCKS            = 10;

    static const int MNB_RECOVERY_QUORUM_TOTAL      = 10;
    static const int MNB_RECOVERY_QUORUM_REQUIRED   = 6;
    static const int MNB_RECOVERY_MAX_ASK_ENTRIES   = 10;
    static const int MNB_RECOVERY_WAIT_SECONDS      = 60;
    static const int MNB_RECOVERY_RETRY_SECONDS     = 3 * 60 * 60;


    // Keep track of current block index
    const CBlockIndex *pCurrentBlockIndex;

    // map to hold all MNs
    std::vector<CGhostnode> vGhostnodes;
    // who's asked for the Ghostnode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForGhostnodeList;
    // who we asked for the Ghostnode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForGhostnodeList;
    // which Ghostnodes we've asked for
    std::map<COutPoint, std::map<CNetAddr, int64_t> > mWeAskedForGhostnodeListEntry;
    // who we asked for the ghostnode verification
    std::map<CNetAddr, CGhostnodeVerification> mWeAskedForVerification;

    // these maps are used for ghostnode recovery from GHOSTNODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CGhostnodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    int64_t nLastIndexRebuildTime;

    CGhostnodeIndex indexGhostnodes;

    CGhostnodeIndex indexGhostnodesOld;

    /// Set when index has been rebuilt, clear when read
    bool fIndexRebuilt;

    /// Set when ghostnodes are added, cleared when CGovernanceManager is notified
    bool fGhostnodesAdded;

    /// Set when ghostnodes are removed, cleared when CGovernanceManager is notified
    bool fGhostnodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CGhostnodeSync;

public:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CGhostnodeBroadcast> > mapSeenGhostnodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CGhostnodePing> mapSeenGhostnodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CGhostnodeVerification> mapSeenGhostnodeVerification;
    // keep track of dsq count to prevent ghostnodes from gaming darksend queue
    int64_t nDsqCount;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING; 
            READWRITE(strVersion);
        }

        READWRITE(vGhostnodes);
        READWRITE(mAskedUsForGhostnodeList);
        READWRITE(mWeAskedForGhostnodeList);
        READWRITE(mWeAskedForGhostnodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenGhostnodeBroadcast);
        READWRITE(mapSeenGhostnodePing);
        READWRITE(indexGhostnodes);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CGhostnodeMan();

    /// Add an entry
    bool Add(CGhostnode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const CTxIn &vin);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    /// Check all Ghostnodes
    void Check();

    /// Check all Ghostnodes and remove inactive
    void CheckAndRemove();

    /// Clear Ghostnode vector
    void Clear();

    /// Count Ghostnodes filtered by nProtocolVersion.
    /// Ghostnode nProtocolVersion should match or be above the one specified in param here.
    int CountGhostnodes(int nProtocolVersion = -1);
    /// Count enabled Ghostnodes filtered by nProtocolVersion.
    /// Ghostnode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Ghostnodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode);

    /// Find an entry
    CGhostnode* Find(const CScript &payee);
    CGhostnode* Find(const CTxIn& vin);
    CGhostnode* Find(const CPubKey& pubKeyGhostnode);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const CPubKey& pubKeyGhostnode, CGhostnode& ghostnode);
    bool Get(const CTxIn& vin, CGhostnode& ghostnode);

    /// Retrieve ghostnode vin by index
    bool Get(int nIndex, CTxIn& vinGhostnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexGhostnodes.Get(nIndex, vinGhostnode);
    }

    bool GetIndexRebuiltFlag() {
        LOCK(cs);
        return fIndexRebuilt;
    }

    /// Get index of a ghostnode vin
    int GetGhostnodeIndex(const CTxIn& vinGhostnode) {
        LOCK(cs);
        return indexGhostnodes.GetGhostnodeIndex(vinGhostnode);
    }

    /// Get old index of a ghostnode vin
    int GetGhostnodeIndexOld(const CTxIn& vinGhostnode) {
        LOCK(cs);
        return indexGhostnodesOld.GetGhostnodeIndex(vinGhostnode);
    }

    /// Get ghostnode VIN for an old index value
    bool GetGhostnodeVinForIndexOld(int nGhostnodeIndex, CTxIn& vinGhostnodeOut) {
        LOCK(cs);
        return indexGhostnodesOld.Get(nGhostnodeIndex, vinGhostnodeOut);
    }

    /// Get index of a ghostnode vin, returning rebuild flag
    int GetGhostnodeIndex(const CTxIn& vinGhostnode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexGhostnodes.GetGhostnodeIndex(vinGhostnode);
    }

    void ClearOldGhostnodeIndex() {
        LOCK(cs);
        indexGhostnodesOld.Clear();
        fIndexRebuilt = false;
    }

    bool Has(const CTxIn& vin);

    ghostnode_info_t GetGhostnodeInfo(const CTxIn& vin);

    ghostnode_info_t GetGhostnodeInfo(const CPubKey& pubKeyGhostnode);

    char* GetNotQualifyReason(CGhostnode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount);

    /// Find an entry in the ghostnode list that is next to be paid
    CGhostnode* GetNextGhostnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);
    /// Same as above but use current block height
    CGhostnode* GetNextGhostnodeInQueueForPayment(bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CGhostnode* FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion = -1);

    std::vector<CGhostnode> GetFullGhostnodeVector() { return vGhostnodes; }

    std::vector<std::pair<int, CGhostnode> > GetGhostnodeRanks(int nBlockHeight = -1, int nMinProtocol=0);
    int GetGhostnodeRank(const CTxIn &vin, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);
    CGhostnode* GetGhostnodeByRank(int nRank, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);

    void ProcessGhostnodeConnections();
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void DoFullVerificationStep();
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CGhostnode*>& vSortedByAddr);
    void SendVerifyReply(CNode* pnode, CGhostnodeVerification& mnv);
    void ProcessVerifyReply(CNode* pnode, CGhostnodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CGhostnodeVerification& mnv);

    /// Return the number of (unique) Ghostnodes
    int size() { return vGhostnodes.size(); }

    std::string ToString() const;

    /// Update ghostnode list and maps using provided CGhostnodeBroadcast
    void UpdateGhostnodeList(CGhostnodeBroadcast mnb);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateGhostnodeList(CNode* pfrom, CGhostnodeBroadcast mnb, int& nDos);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid();

    void CheckAndRebuildGhostnodeIndex();

    void AddDirtyGovernanceObjectHash(const uint256& nHash)
    {
        LOCK(cs);
        vecDirtyGovernanceObjectHashes.push_back(nHash);
    }

    std::vector<uint256> GetAndClearDirtyGovernanceObjectHashes()
    {
        LOCK(cs);
        std::vector<uint256> vecTmp = vecDirtyGovernanceObjectHashes;
        vecDirtyGovernanceObjectHashes.clear();
        return vecTmp;;
    }

    bool IsWatchdogActive();
    void UpdateWatchdogVoteTime(const CTxIn& vin);
    bool AddGovernanceVote(const CTxIn& vin, uint256 nGovernanceObjectHash);
    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void CheckGhostnode(const CTxIn& vin, bool fForce = false);
    void CheckGhostnode(const CPubKey& pubKeyGhostnode, bool fForce = false);

    int GetGhostnodeState(const CTxIn& vin);
    int GetGhostnodeState(const CPubKey& pubKeyGhostnode);

    bool IsGhostnodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetGhostnodeLastPing(const CTxIn& vin, const CGhostnodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    /**
     * Called to notify CGovernanceManager that the ghostnode index has been updated.
     * Must be called while not holding the CGhostnodeMan::cs mutex
     */
    void NotifyGhostnodeUpdates();
};

#endif
