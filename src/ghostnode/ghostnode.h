// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOSTNODE_H
#define GHOSTNODE_H

#include "key.h"
#include "validation.h"
#include "net.h"
#include "spork.h"
#include "timedata.h"
#include "utiltime.h"

class CGhostnode;
class CGhostnodeBroadcast;
class CGhostnodePing;

static const int GHOSTNODE_CHECK_SECONDS               =   5;
static const int GHOSTNODE_MIN_MNB_SECONDS             =   5 * 60; //BROADCAST_TIME
static const int GHOSTNODE_MIN_MNP_SECONDS             =  10 * 60; //PRE_ENABLE_TIME
static const int GHOSTNODE_EXPIRATION_SECONDS          =  65 * 60;
static const int GHOSTNODE_WATCHDOG_MAX_SECONDS        = 120 * 60;
static const int GHOSTNODE_NEW_START_REQUIRED_SECONDS  = 180 * 60;
static const int GHOSTNODE_COIN_REQUIRED  = 40000;

static const int GHOSTNODE_POSE_BAN_MAX_SCORE          = 5;
//
// The Ghostnode Ping Class : Contains a different serialize method for sending pings from ghostnodes throughout the network
//

class CGhostnodePing
{
public:
    CTxIn vin;
    uint256 blockHash;
    int64_t sigTime; //mnb message times
    std::vector<unsigned char> vchSig;
    //removed stop

    CGhostnodePing() :
        vin(),
        blockHash(),
        sigTime(0),
        vchSig()
        {}

    CGhostnodePing(CTxIn& vinNew);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vin);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
    }

    void swap(CGhostnodePing& first, CGhostnodePing& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.blockHash, second.blockHash);
        swap(first.sigTime, second.sigTime);
        swap(first.vchSig, second.vchSig);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << sigTime;
        return ss.GetHash();
    }

    bool IsExpired() { return GetTime() - sigTime > GHOSTNODE_NEW_START_REQUIRED_SECONDS; }

    bool Sign(CKey& keyGhostnode, CPubKey& pubKeyGhostnode);
    bool CheckSignature(CPubKey& pubKeyGhostnode, int &nDos);
    bool SimpleCheck(int& nDos);
    bool CheckAndUpdate(CGhostnode* pmn, bool fFromNewBroadcast, int& nDos);
    void Relay();

    CGhostnodePing& operator=(CGhostnodePing from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CGhostnodePing& a, const CGhostnodePing& b)
    {
        return a.vin == b.vin && a.blockHash == b.blockHash;
    }
    friend bool operator!=(const CGhostnodePing& a, const CGhostnodePing& b)
    {
        return !(a == b);
    }

};

struct ghostnode_info_t
{
    ghostnode_info_t()
        : vin(),
          addr(),
          pubKeyCollateralAddress(),
          pubKeyGhostnode(),
          sigTime(0),
          nLastDsq(0),
          nTimeLastChecked(0),
          nTimeLastPaid(0),
          nTimeLastWatchdogVote(0),
          nTimeLastPing(0),
          nActiveState(0),
          nProtocolVersion(0),
          fInfoValid(false)
        {}

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeyGhostnode;
    int64_t sigTime; //mnb message time
    int64_t nLastDsq; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked;
    int64_t nTimeLastPaid;
    int64_t nTimeLastWatchdogVote;
    int64_t nTimeLastPing;
    int nActiveState;
    int nProtocolVersion;
    bool fInfoValid;
};

//
// The Ghostnode Class. For managing the Darksend process. It contains the input of the 1000DRK, signature to prove
// it's the one who own that ip address and code for calculating the payment election.
//
class CGhostnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

public:
    enum state {
        GHOSTNODE_PRE_ENABLED,
        GHOSTNODE_ENABLED,
        GHOSTNODE_EXPIRED,
        GHOSTNODE_OUTPOINT_SPENT,
        GHOSTNODE_UPDATE_REQUIRED,
        GHOSTNODE_WATCHDOG_EXPIRED,
        GHOSTNODE_NEW_START_REQUIRED,
        GHOSTNODE_POSE_BAN
    };

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeyGhostnode;
    CGhostnodePing lastPing;
    std::vector<unsigned char> vchSig;
    int64_t sigTime; //mnb message time
    int64_t nLastDsq; //the dsq count from the last dsq broadcast of this node
    int64_t nTimeLastChecked;
    int64_t nTimeLastPaid;
    int64_t nTimeLastWatchdogVote;
    int nActiveState;
    int nCacheCollateralBlock;
    int nBlockLastPaid;
    int nProtocolVersion;
    int nPoSeBanScore;
    int nPoSeBanHeight;
    bool fAllowMixingTx;
    bool fUnitTest;

    // KEEP TRACK OF GOVERNANCE ITEMS EACH GHOSTNODE HAS VOTE UPON FOR RECALCULATION
    std::map<uint256, int> mapGovernanceObjectsVotedOn;

    CGhostnode();
    CGhostnode(const CGhostnode& other);
    CGhostnode(const CGhostnodeBroadcast& mnb);
    CGhostnode(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyGhostnodeNew, int nProtocolVersionIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyGhostnode);
        READWRITE(lastPing);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nLastDsq);
        READWRITE(nTimeLastChecked);
        READWRITE(nTimeLastPaid);
        READWRITE(nTimeLastWatchdogVote);
        READWRITE(nActiveState);
        READWRITE(nCacheCollateralBlock);
        READWRITE(nBlockLastPaid);
        READWRITE(nProtocolVersion);
        READWRITE(nPoSeBanScore);
        READWRITE(nPoSeBanHeight);
        READWRITE(fAllowMixingTx);
        READWRITE(fUnitTest);
        READWRITE(mapGovernanceObjectsVotedOn);
    }

    void swap(CGhostnode& first, CGhostnode& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.addr, second.addr);
        swap(first.pubKeyCollateralAddress, second.pubKeyCollateralAddress);
        swap(first.pubKeyGhostnode, second.pubKeyGhostnode);
        swap(first.lastPing, second.lastPing);
        swap(first.vchSig, second.vchSig);
        swap(first.sigTime, second.sigTime);
        swap(first.nLastDsq, second.nLastDsq);
        swap(first.nTimeLastChecked, second.nTimeLastChecked);
        swap(first.nTimeLastPaid, second.nTimeLastPaid);
        swap(first.nTimeLastWatchdogVote, second.nTimeLastWatchdogVote);
        swap(first.nActiveState, second.nActiveState);
        swap(first.nCacheCollateralBlock, second.nCacheCollateralBlock);
        swap(first.nBlockLastPaid, second.nBlockLastPaid);
        swap(first.nProtocolVersion, second.nProtocolVersion);
        swap(first.nPoSeBanScore, second.nPoSeBanScore);
        swap(first.nPoSeBanHeight, second.nPoSeBanHeight);
        swap(first.fAllowMixingTx, second.fAllowMixingTx);
        swap(first.fUnitTest, second.fUnitTest);
        swap(first.mapGovernanceObjectsVotedOn, second.mapGovernanceObjectsVotedOn);
    }

    // CALCULATE A RANK AGAINST OF GIVEN BLOCK
    arith_uint256 CalculateScore(const uint256& blockHash);

    bool UpdateFromNewBroadcast(CGhostnodeBroadcast& mnb);

    void Check(bool fForce = false);

    bool IsBroadcastedWithin(int nSeconds) { return GetAdjustedTime() - sigTime < nSeconds; }

    bool IsPingedWithin(int nSeconds, int64_t nTimeToCheckAt = -1)
    {
        if(lastPing == CGhostnodePing()) return false;

        if(nTimeToCheckAt == -1) {
            nTimeToCheckAt = GetAdjustedTime();
        }
        return nTimeToCheckAt - lastPing.sigTime < nSeconds;
    }

    bool IsEnabled() { return nActiveState == GHOSTNODE_ENABLED; }
    bool IsPreEnabled() { return nActiveState == GHOSTNODE_PRE_ENABLED; }
    bool IsPoSeBanned() { return nActiveState == GHOSTNODE_POSE_BAN; }
    // NOTE: this one relies on nPoSeBanScore, not on nActiveState as everything else here
    bool IsPoSeVerified() { return nPoSeBanScore <= -GHOSTNODE_POSE_BAN_MAX_SCORE; }
    bool IsExpired() { return nActiveState == GHOSTNODE_EXPIRED; }
    bool IsOutpointSpent() { return nActiveState == GHOSTNODE_OUTPOINT_SPENT; }
    bool IsUpdateRequired() { return nActiveState == GHOSTNODE_UPDATE_REQUIRED; }
    bool IsWatchdogExpired() { return nActiveState == GHOSTNODE_WATCHDOG_EXPIRED; }
    bool IsNewStartRequired() { return nActiveState == GHOSTNODE_NEW_START_REQUIRED; }

    static bool IsValidStateForAutoStart(int nActiveStateIn)
    {
        return  nActiveStateIn == GHOSTNODE_ENABLED ||
                nActiveStateIn == GHOSTNODE_PRE_ENABLED ||
                nActiveStateIn == GHOSTNODE_EXPIRED ||
                nActiveStateIn == GHOSTNODE_WATCHDOG_EXPIRED;
    }

    bool IsValidForPayment();

    bool IsValidNetAddr();
    static bool IsValidNetAddr(CService addrIn);

    void IncreasePoSeBanScore() { if(nPoSeBanScore < GHOSTNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore++; }
    void DecreasePoSeBanScore() { if(nPoSeBanScore > -GHOSTNODE_POSE_BAN_MAX_SCORE) nPoSeBanScore--; }

    ghostnode_info_t GetInfo();

    static std::string StateToString(int nStateIn);
    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string ToString() const;

    int GetCollateralAge();

    int GetLastPaidTime() { return nTimeLastPaid; }
    int GetLastPaidBlock() { return nBlockLastPaid; }
    void UpdateLastPaid(const CBlockIndex *pindex, int nMaxBlocksToScanBack);

    // KEEP TRACK OF EACH GOVERNANCE ITEM INCASE THIS NODE GOES OFFLINE, SO WE CAN RECALC THEIR STATUS
    void AddGovernanceVote(uint256 nGovernanceObjectHash);
    // RECALCULATE CACHED STATUS FLAGS FOR ALL AFFECTED OBJECTS
    void FlagGovernanceItemsAsDirty();

    void RemoveGovernanceObject(uint256 nGovernanceObjectHash);

    void UpdateWatchdogVoteTime();

    CGhostnode& operator=(CGhostnode from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const CGhostnode& a, const CGhostnode& b)
    {
        return a.vin == b.vin;
    }
    friend bool operator!=(const CGhostnode& a, const CGhostnode& b)
    {
        return !(a.vin == b.vin);
    }

};


//
// The Ghostnode Broadcast Class : Contains a different serialize method for sending ghostnodes through the network
//

class CGhostnodeBroadcast : public CGhostnode
{
public:

    bool fRecovery;

    CGhostnodeBroadcast() : CGhostnode(), fRecovery(false) {}
    CGhostnodeBroadcast(const CGhostnode& mn) : CGhostnode(mn), fRecovery(false) {}
    CGhostnodeBroadcast(CService addrNew, CTxIn vinNew, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyGhostnodeNew, int nProtocolVersionIn) :
        CGhostnode(addrNew, vinNew, pubKeyCollateralAddressNew, pubKeyGhostnodeNew, nProtocolVersionIn), fRecovery(false) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyGhostnode);
        READWRITE(vchSig);
        READWRITE(sigTime);
        READWRITE(nProtocolVersion);
        READWRITE(lastPing);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << pubKeyCollateralAddress;
        ss << sigTime;
        return ss.GetHash();
    }

    /// Create Ghostnode broadcast, needs to be relayed manually after that
    static bool Create(CTxIn vin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyGhostnodeNew, CPubKey pubKeyGhostnodeNew, std::string &strErrorRet, CGhostnodeBroadcast &mnbRet);
    static bool Create(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, CGhostnodeBroadcast &mnbRet, bool fOffline = false);

    bool SimpleCheck(int& nDos);
    bool Update(CGhostnode* pmn, int& nDos);
    bool CheckOutpoint(int& nDos);

    bool Sign(CKey& keyCollateralAddress);
    bool CheckSignature(int& nDos);
    void RelayGhostNode();
};

class CGhostnodeVerification
{
public:
    CTxIn vin1;
    CTxIn vin2;
    CService addr;
    int nonce;
    int nBlockHeight;
    std::vector<unsigned char> vchSig1;
    std::vector<unsigned char> vchSig2;

    CGhostnodeVerification() :
        vin1(),
        vin2(),
        addr(),
        nonce(0),
        nBlockHeight(0),
        vchSig1(),
        vchSig2()
        {}

    CGhostnodeVerification(CService addr, int nonce, int nBlockHeight) :
        vin1(),
        vin2(),
        addr(addr),
        nonce(nonce),
        nBlockHeight(nBlockHeight),
        vchSig1(),
        vchSig2()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vin1);
        READWRITE(vin2);
        READWRITE(addr);
        READWRITE(nonce);
        READWRITE(nBlockHeight);
        READWRITE(vchSig1);
        READWRITE(vchSig2);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin1;
        ss << vin2;
        ss << addr;
        ss << nonce;
        ss << nBlockHeight;
        return ss.GetHash();
    }

    void Relay() const
    {
        CInv inv(MSG_GHOSTNODE_VERIFY, GetHash());
        g_connman->RelayInv(inv);
    }
};

#endif
