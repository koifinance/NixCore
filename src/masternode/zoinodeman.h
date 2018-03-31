// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZOINODEMAN_H
#define ZOINODEMAN_H

#include "zoinode.h"
#include "sync.h"

using namespace std;

class CZoinodeMan;

extern CZoinodeMan mnodeman;

/**
 * Provides a forward and reverse index between MN vin's and integers.
 *
 * This mapping is normally add-only and is expected to be permanent
 * It is only rebuilt if the size of the index exceeds the expected maximum number
 * of MN's and the current number of known MN's.
 *
 * The external interface to this index is provided via delegation by CZoinodeMan
 */
class CZoinodeIndex
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
    CZoinodeIndex();

    int GetSize() const {
        return nSize;
    }

    /// Retrieve zoinode vin by index
    bool Get(int nIndex, CTxIn& vinZoinode) const;

    /// Get index of a zoinode vin
    int GetZoinodeIndex(const CTxIn& vinZoinode) const;

    void AddZoinodeVIN(const CTxIn& vinZoinode);

    void Clear();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(mapIndex);
        if(ser_action.ForRead()) {
            RebuildIndex();
        }
    }

private:
    void RebuildIndex();

};

class CZoinodeMan
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


    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    // Keep track of current block index
    const CBlockIndex *pCurrentBlockIndex;

    // map to hold all MNs
    std::vector<CZoinode> vZoinodes;
    // who's asked for the Zoinode list and the last time
    std::map<CNetAddr, int64_t> mAskedUsForZoinodeList;
    // who we asked for the Zoinode list and the last time
    std::map<CNetAddr, int64_t> mWeAskedForZoinodeList;
    // which Zoinodes we've asked for
    std::map<COutPoint, std::map<CNetAddr, int64_t> > mWeAskedForZoinodeListEntry;
    // who we asked for the zoinode verification
    std::map<CNetAddr, CZoinodeVerification> mWeAskedForVerification;

    // these maps are used for zoinode recovery from ZOINODE_NEW_START_REQUIRED state
    std::map<uint256, std::pair< int64_t, std::set<CNetAddr> > > mMnbRecoveryRequests;
    std::map<uint256, std::vector<CZoinodeBroadcast> > mMnbRecoveryGoodReplies;
    std::list< std::pair<CService, uint256> > listScheduledMnbRequestConnections;

    int64_t nLastIndexRebuildTime;

    CZoinodeIndex indexZoinodes;

    CZoinodeIndex indexZoinodesOld;

    /// Set when index has been rebuilt, clear when read
    bool fIndexRebuilt;

    /// Set when zoinodes are added, cleared when CGovernanceManager is notified
    bool fZoinodesAdded;

    /// Set when zoinodes are removed, cleared when CGovernanceManager is notified
    bool fZoinodesRemoved;

    std::vector<uint256> vecDirtyGovernanceObjectHashes;

    int64_t nLastWatchdogVoteTime;

    friend class CZoinodeSync;

public:
    // Keep track of all broadcasts I've seen
    std::map<uint256, std::pair<int64_t, CZoinodeBroadcast> > mapSeenZoinodeBroadcast;
    // Keep track of all pings I've seen
    std::map<uint256, CZoinodePing> mapSeenZoinodePing;
    // Keep track of all verifications I've seen
    std::map<uint256, CZoinodeVerification> mapSeenZoinodeVerification;
    // keep track of dsq count to prevent zoinodes from gaming darksend queue
    int64_t nDsqCount;


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING; 
            READWRITE(strVersion);
        }

        READWRITE(vZoinodes);
        READWRITE(mAskedUsForZoinodeList);
        READWRITE(mWeAskedForZoinodeList);
        READWRITE(mWeAskedForZoinodeListEntry);
        READWRITE(mMnbRecoveryRequests);
        READWRITE(mMnbRecoveryGoodReplies);
        READWRITE(nLastWatchdogVoteTime);
        READWRITE(nDsqCount);

        READWRITE(mapSeenZoinodeBroadcast);
        READWRITE(mapSeenZoinodePing);
        READWRITE(indexZoinodes);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    CZoinodeMan();

    /// Add an entry
    bool Add(CZoinode &mn);

    /// Ask (source) node for mnb
    void AskForMN(CNode *pnode, const CTxIn &vin);
    void AskForMnb(CNode *pnode, const uint256 &hash);

    /// Check all Zoinodes
    void Check();

    /// Check all Zoinodes and remove inactive
    void CheckAndRemove();

    /// Clear Zoinode vector
    void Clear();

    /// Count Zoinodes filtered by nProtocolVersion.
    /// Zoinode nProtocolVersion should match or be above the one specified in param here.
    int CountZoinodes(int nProtocolVersion = -1);
    /// Count enabled Zoinodes filtered by nProtocolVersion.
    /// Zoinode nProtocolVersion should match or be above the one specified in param here.
    int CountEnabled(int nProtocolVersion = -1);

    /// Count Zoinodes by network type - NET_IPV4, NET_IPV6, NET_TOR
    // int CountByIP(int nNetworkType);

    void DsegUpdate(CNode* pnode);

    /// Find an entry
    CZoinode* Find(const CScript &payee);
    CZoinode* Find(const CTxIn& vin);
    CZoinode* Find(const CPubKey& pubKeyZoinode);

    /// Versions of Find that are safe to use from outside the class
    bool Get(const CPubKey& pubKeyZoinode, CZoinode& zoinode);
    bool Get(const CTxIn& vin, CZoinode& zoinode);

    /// Retrieve zoinode vin by index
    bool Get(int nIndex, CTxIn& vinZoinode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexZoinodes.Get(nIndex, vinZoinode);
    }

    bool GetIndexRebuiltFlag() {
        LOCK(cs);
        return fIndexRebuilt;
    }

    /// Get index of a zoinode vin
    int GetZoinodeIndex(const CTxIn& vinZoinode) {
        LOCK(cs);
        return indexZoinodes.GetZoinodeIndex(vinZoinode);
    }

    /// Get old index of a zoinode vin
    int GetZoinodeIndexOld(const CTxIn& vinZoinode) {
        LOCK(cs);
        return indexZoinodesOld.GetZoinodeIndex(vinZoinode);
    }

    /// Get zoinode VIN for an old index value
    bool GetZoinodeVinForIndexOld(int nZoinodeIndex, CTxIn& vinZoinodeOut) {
        LOCK(cs);
        return indexZoinodesOld.Get(nZoinodeIndex, vinZoinodeOut);
    }

    /// Get index of a zoinode vin, returning rebuild flag
    int GetZoinodeIndex(const CTxIn& vinZoinode, bool& fIndexRebuiltOut) {
        LOCK(cs);
        fIndexRebuiltOut = fIndexRebuilt;
        return indexZoinodes.GetZoinodeIndex(vinZoinode);
    }

    void ClearOldZoinodeIndex() {
        LOCK(cs);
        indexZoinodesOld.Clear();
        fIndexRebuilt = false;
    }

    bool Has(const CTxIn& vin);

    zoinode_info_t GetZoinodeInfo(const CTxIn& vin);

    zoinode_info_t GetZoinodeInfo(const CPubKey& pubKeyZoinode);

    char* GetNotQualifyReason(CZoinode& mn, int nBlockHeight, bool fFilterSigTime, int nMnCount);

    /// Find an entry in the zoinode list that is next to be paid
    CZoinode* GetNextZoinodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nCount);
    /// Same as above but use current block height
    CZoinode* GetNextZoinodeInQueueForPayment(bool fFilterSigTime, int& nCount);

    /// Find a random entry
    CZoinode* FindRandomNotInVec(const std::vector<CTxIn> &vecToExclude, int nProtocolVersion = -1);

    std::vector<CZoinode> GetFullZoinodeVector() { return vZoinodes; }

    std::vector<std::pair<int, CZoinode> > GetZoinodeRanks(int nBlockHeight = -1, int nMinProtocol=0);
    int GetZoinodeRank(const CTxIn &vin, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);
    CZoinode* GetZoinodeByRank(int nRank, int nBlockHeight, int nMinProtocol=0, bool fOnlyActive=true);

    void ProcessZoinodeConnections();
    std::pair<CService, std::set<uint256> > PopScheduledMnbRequestConnection();

    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

    void DoFullVerificationStep();
    void CheckSameAddr();
    bool SendVerifyRequest(const CAddress& addr, const std::vector<CZoinode*>& vSortedByAddr);
    void SendVerifyReply(CNode* pnode, CZoinodeVerification& mnv);
    void ProcessVerifyReply(CNode* pnode, CZoinodeVerification& mnv);
    void ProcessVerifyBroadcast(CNode* pnode, const CZoinodeVerification& mnv);

    /// Return the number of (unique) Zoinodes
    int size() { return vZoinodes.size(); }

    std::string ToString() const;

    /// Update zoinode list and maps using provided CZoinodeBroadcast
    void UpdateZoinodeList(CZoinodeBroadcast mnb);
    /// Perform complete check and only then update list and maps
    bool CheckMnbAndUpdateZoinodeList(CNode* pfrom, CZoinodeBroadcast mnb, int& nDos);
    bool IsMnbRecoveryRequested(const uint256& hash) { return mMnbRecoveryRequests.count(hash); }

    void UpdateLastPaid();

    void CheckAndRebuildZoinodeIndex();

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

    void CheckZoinode(const CTxIn& vin, bool fForce = false);
    void CheckZoinode(const CPubKey& pubKeyZoinode, bool fForce = false);

    int GetZoinodeState(const CTxIn& vin);
    int GetZoinodeState(const CPubKey& pubKeyZoinode);

    bool IsZoinodePingedWithin(const CTxIn& vin, int nSeconds, int64_t nTimeToCheckAt = -1);
    void SetZoinodeLastPing(const CTxIn& vin, const CZoinodePing& mnp);

    void UpdatedBlockTip(const CBlockIndex *pindex);

    /**
     * Called to notify CGovernanceManager that the zoinode index has been updated.
     * Must be called while not holding the CZoinodeMan::cs mutex
     */
    void NotifyZoinodeUpdates();

};

#endif
