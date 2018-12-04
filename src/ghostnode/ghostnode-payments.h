// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GHOSTNODE_PAYMENTS_H
#define GHOSTNODE_PAYMENTS_H

#include "util.h"
#include "core_io.h"
#include "key.h"
#include "validation.h"
#include "ghostnode.h"
#include "utilstrencodings.h"

class CGhostnodePayments;
class CGhostnodePaymentVote;
class CGhostnodeBlockPayees;

static const int MNPAYMENTS_SIGNATURES_REQUIRED         = 6;
static const int MNPAYMENTS_SIGNATURES_TOTAL            = 10;

//! minimum peer version that can receive and send ghostnode payment messages,
//  vote for ghostnode and be elected as a payment winner
// V1 - Last protocol version before update
// V2 - Newest protocol version
static const int MIN_GHOSTNODE_PAYMENT_PROTO_VERSION_1 = 70020;
static const int MIN_GHOSTNODE_PAYMENT_PROTO_VERSION_2 = 70021;

extern CCriticalSection cs_vecPayees;
extern CCriticalSection cs_mapGhostnodeBlocks;
extern CCriticalSection cs_mapGhostnodePayeeVotes;

extern CGhostnodePayments mnpayments;

/// TODO: all 4 functions do not belong here really, they should be refactored/moved somewhere (main.cpp ?)
bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string &strErrorRet);
bool IsBlockPayeeValid(const CTransaction& txNew, int nBlockHeight, CAmount blockReward);
void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutGhostnodeRet, std::vector<CTxOut>& voutSuperblockRet);
std::string GetRequiredPaymentsString(int nBlockHeight);

class CGhostnodePayee
{
private:
    CScript scriptPubKey;
    std::vector<uint256> vecVoteHashes;

public:
    CGhostnodePayee() :
        scriptPubKey(),
        vecVoteHashes()
        {}

    CGhostnodePayee(CScript payee, uint256 hashIn) :
        scriptPubKey(payee),
        vecVoteHashes()
    {
        vecVoteHashes.push_back(hashIn);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(vecVoteHashes);
    }

    CScript GetPayee() { return scriptPubKey; }

    void AddVoteHash(uint256 hashIn) { vecVoteHashes.push_back(hashIn); }
    std::vector<uint256> GetVoteHashes() { return vecVoteHashes; }
    int GetVoteCount() { return vecVoteHashes.size(); }
    std::string ToString() const;
};

// Keep track of votes for payees from ghostnodes
class CGhostnodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CGhostnodePayee> vecPayees;

    CGhostnodeBlockPayees() :
        nBlockHeight(0),
        vecPayees()
        {}
    CGhostnodeBlockPayees(int nBlockHeightIn) :
        nBlockHeight(nBlockHeightIn),
        vecPayees()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayees);
    }

    void AddPayee(const CGhostnodePaymentVote& vote);
    bool GetBestPayee(CScript& payeeRet);
    bool HasPayeeWithVotes(CScript payeeIn, int nVotesReq);

    bool IsTransactionValid(const CTransaction& txNew);

    std::string GetRequiredPaymentsString();
};

// vote for the winning payment
class CGhostnodePaymentVote
{
public:
    CTxIn vinGhostnode;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CGhostnodePaymentVote() :
        vinGhostnode(),
        nBlockHeight(0),
        payee(),
        vchSig()
        {}

    CGhostnodePaymentVote(CTxIn vinGhostnode, int nBlockHeight, CScript payee) :
        vinGhostnode(vinGhostnode),
        nBlockHeight(nBlockHeight),
        payee(payee),
        vchSig()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vinGhostnode);
        READWRITE(nBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        READWRITE(vchSig);
    }

    uint256 GetHash() const {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << *(CScriptBase*)(&payee);
        ss << nBlockHeight;
        ss << vinGhostnode.prevout;
        return ss.GetHash();
    }

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeyGhostnode, int nValidationHeight, int &nDos);

    bool IsValid(CNode* pnode, int nValidationHeight, std::string& strError);
    void Relay();

    bool IsVerified() { return !vchSig.empty(); }
    void MarkAsNotVerified() { vchSig.clear(); }

    std::string ToString() const;
};

//
// Ghostnode Payments Class
// Keeps track of who should get paid for which blocks
//

class CGhostnodePayments
{
private:
    // ghostnode count times nStorageCoeff payments blocks should be stored ...
    const float nStorageCoeff;
    // ... but at least nMinBlocksToStore (payments blocks)
    const int nMinBlocksToStore;

    // Keep track of current block index
    const CBlockIndex *pCurrentBlockIndex;

public:
    std::map<uint256, CGhostnodePaymentVote> mapGhostnodePaymentVotes;
    std::map<int, CGhostnodeBlockPayees> mapGhostnodeBlocks;
    std::map<COutPoint, int> mapGhostnodesLastVote;

    CGhostnodePayments() : nStorageCoeff(1.25), nMinBlocksToStore(5000) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mapGhostnodePaymentVotes);
        READWRITE(mapGhostnodeBlocks);
    }

    void Clear();

    bool AddPaymentVote(const CGhostnodePaymentVote& vote);
    bool HasVerifiedPaymentVote(uint256 hashIn);
    bool ProcessBlock(int nBlockHeight);

    void Sync(CNode* node);
    void RequestLowDataPaymentBlocks(CNode* pnode);
    void CheckAndRemove();

    bool GetBlockPayee(int nBlockHeight, CScript& payee);
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight);
    bool IsScheduled(CGhostnode& mn, int nNotBlockHeight);

    bool CanVote(COutPoint outGhostnode, int nBlockHeight);

    int GetMinGhostnodePaymentsProto();
    void ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, CTxOut& txoutGhostnodeRet);
    std::string ToString() const;

    int GetBlockCount() { return mapGhostnodeBlocks.size(); }
    int GetVoteCount() { return mapGhostnodePaymentVotes.size(); }

    bool IsEnoughData();
    int GetStorageLimit();

    void UpdatedBlockTip(const CBlockIndex *pindex);
};

#endif
