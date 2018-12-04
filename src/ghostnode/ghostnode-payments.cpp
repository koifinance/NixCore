// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activeghostnode.h"
#include "darksend.h"
#include "ghostnode-payments.h"
#include "ghostnode-sync.h"
#include "ghostnodeman.h"
#include "netfulfilledman.h"
#include "spork.h"
#include "util.h"
#include "netmessagemaker.h"
#include "chainparams.h"

#include <boost/lexical_cast.hpp>

/** Object for who's going to get paid on which blocks */
CGhostnodePayments mnpayments;

CCriticalSection cs_vecPayees;
CCriticalSection cs_mapGhostnodeBlocks;
CCriticalSection cs_mapGhostnodePaymentVotes;

/**
* IsBlockValueValid
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In Dash some blocks are superblocks, which output much higher amounts of coins
*   - Otherblocks are 10% lower in outgoing value, so in total, no extra coins are created
*   - When non-superblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValid(const CBlock &block, int nBlockHeight, CAmount blockReward, std::string &strErrorRet) {
    strErrorRet = "";
    bool isBlockRewardValueMet = block.vtx[0]->IsCoinStake() ? true :  (block.vtx[0]->GetValueOut() <= blockReward);
    //LogPrintf("IsBlockValueValid(): value-out=%llf, block-reward=%llf \n", block.vtx[0]->GetValueOut(), blockReward);
    //if (fDebug) //LogPrint("block.vtx[0].GetValueOut() %lld <= blockReward %lld\n", block.vtx[0]->GetValueOut(), blockReward);


    if (!ghostnodeSync.IsSynced(chainActive.Height())) {

        if (!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, only regular blocks are allowed at this height",
                                    nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        }
        // it MUST be a regular block otherwise
        return isBlockRewardValueMet;
    }

    // we are synced, let's try to check as much data as we can

    if (sporkManager.IsSporkActive(SPORK_9_SUPERBLOCKS_ENABLED)) {
    } else {
//        // should NOT allow superblocks at all, when superblocks are disabled
        //LogPrint("gobject", "IsBlockValueValid -- Superblocks are disabled, no superblocks allowed\n");
        if (!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, superblocks are disabled",
                                    nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        }
    }

    // it MUST be a regular block
    return isBlockRewardValueMet;
}

bool IsBlockPayeeValid(const CTransaction &txNew, int nBlockHeight, CAmount blockReward) {
    // we can only check ghostnode payment /
    const Consensus::Params &consensusParams = Params().GetConsensus();

    if (nBlockHeight < consensusParams.nGhostnodePaymentsStartBlock) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        //if (fDebug) //LogPrint("IsBlockPayeeValid -- ghostnode isn't start\n");
        return true;
    }
    if (!ghostnodeSync.IsSynced(chainActive.Height())) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        //if (fDebug) //LogPrint("IsBlockPayeeValid -- WARNING: Client not synced, skipping block payee checks\n");
        return true;
    }

    //check for ghostnode payee
    if (mnpayments.IsTransactionValid(txNew, nBlockHeight)) {
        //LogPrint("mnpayments", "IsBlockPayeeValid -- Valid ghostnode payment at height %d: %s", nBlockHeight, txNew.ToString());
        return true;
    } else {
        if(sporkManager.IsSporkActive(SPORK_8_GHOSTNODE_PAYMENT_ENFORCEMENT)){
            return false;
        } else {
            //LogPrint("GhostNode payment enforcement is disabled, accepting block\n");
            return true;
        }
    }
}

void FillBlockPayments(CMutableTransaction &txNew, int nBlockHeight, CAmount ghostnodePayment, CTxOut &txoutGhostnodeRet, std::vector <CTxOut> &voutSuperblockRet) {

    // FILL BLOCK PAYEE WITH GHOSTNODE PAYMENT OTHERWISE
    mnpayments.FillBlockPayee(txNew, nBlockHeight, ghostnodePayment, txoutGhostnodeRet);
    //LogPrint("mnpayments", "FillBlockPayments -- nBlockHeight %d ghostnodePayment %lld txoutGhostnodeRet %s txNew %s",
             //nBlockHeight, ghostnodePayment, txoutGhostnodeRet.ToString(), txNew.ToString());
}

std::string GetRequiredPaymentsString(int nBlockHeight) {
    // IF WE HAVE A ACTIVATED TRIGGER FOR THIS HEIGHT - IT IS A SUPERBLOCK, GET THE REQUIRED PAYEES
//    if(CSuperblockManager::IsSuperblockTriggered(nBlockHeight)) {
//        return CSuperblockManager::GetRequiredPaymentsString(nBlockHeight);
//    }

    // OTHERWISE, PAY GHOSTNODE
    return mnpayments.GetRequiredPaymentsString(nBlockHeight);
}

void CGhostnodePayments::Clear() {
    LOCK2(cs_mapGhostnodeBlocks, cs_mapGhostnodePaymentVotes);
    mapGhostnodeBlocks.clear();
    mapGhostnodePaymentVotes.clear();
}

bool CGhostnodePayments::CanVote(COutPoint outGhostnode, int nBlockHeight) {
    LOCK(cs_mapGhostnodePaymentVotes);

    if (mapGhostnodesLastVote.count(outGhostnode) && mapGhostnodesLastVote[outGhostnode] == nBlockHeight) {
        return false;
    }

    //record this ghostnode voted
    mapGhostnodesLastVote[outGhostnode] = nBlockHeight;
    return true;
}

std::string CGhostnodePayee::ToString() const {
    CTxDestination address1;
    ExtractDestination(scriptPubKey, address1);
    CBitcoinAddress address2(address1);
    std::string str;
    str += "(address: ";
    str += address2.ToString();
    str += ")\n";
    return str;
}

/**
*   FillBlockPayee
*
*   Fill Ghostnode ONLY payment block
*/

void CGhostnodePayments::FillBlockPayee(CMutableTransaction &txNew, int nBlockHeight, CAmount ghostnodePayment, CTxOut &txoutGhostnodeRet) {
    // make sure it's not filled yet
    txoutGhostnodeRet = CTxOut();

    CScript payee;
    bool foundMaxVotedPayee = true;

    if (!mnpayments.GetBlockPayee(nBlockHeight, payee)) {
        // no ghostnode detected...
        // //LogPrint("no ghostnode detected...\n");
        foundMaxVotedPayee = false;
        int nCount = 0;
        CGhostnode *winningNode = mnodeman.GetNextGhostnodeInQueueForPayment(nBlockHeight, true, nCount);
        if (!winningNode) {
            // ...and we can't calculate it on our own
            //LogPrint("CGhostnodePayments::FillBlockPayee -- Failed to detect ghostnode to pay\n");
            return;
        }
        // fill payee with locally calculated winner and hope for the best
        payee = GetScriptForDestination(winningNode->pubKeyCollateralAddress.GetID());
        //LogPrint("payee=%s\n", winningNode->ToString());
    }
    txoutGhostnodeRet = CTxOut(ghostnodePayment, payee);
    txNew.vout.push_back(txoutGhostnodeRet);

    CTxDestination address1;
    ExtractDestination(payee, address1);
    CBitcoinAddress address2(address1);
    if (foundMaxVotedPayee) {
        //LogPrint("CGhostnodePayments::FillBlockPayee::foundMaxVotedPayee -- Ghostnode payment %lld to %s\n", ghostnodePayment, address2.ToString());
    } else {
        //LogPrint("CGhostnodePayments::FillBlockPayee -- Ghostnode payment %lld to %s\n", ghostnodePayment, address2.ToString());
    }

}

int CGhostnodePayments::GetMinGhostnodePaymentsProto() {
    if(chainActive.Height() > Params().GetConsensus().nStartGhostFeeDistribution)
        return MIN_GHOSTNODE_PAYMENT_PROTO_VERSION_2;

    return sporkManager.IsSporkActive(SPORK_10_GHOSTNODE_PAY_UPDATED_NODES)
           ? MIN_GHOSTNODE_PAYMENT_PROTO_VERSION_2
           : MIN_GHOSTNODE_PAYMENT_PROTO_VERSION_1;
}

void CGhostnodePayments::ProcessMessage(CNode *pfrom, std::string &strCommand, CDataStream &vRecv) {

    //LogPrintf("CGhostnodePayments::ProcessMessage strCommand=%s\n", strCommand);
    // Ignore any payments messages until ghostnode list is synced
    if (!ghostnodeSync.IsGhostnodeListSynced()) return;

    if (fLiteMode) return; // disable all Dash specific functionality

    if (strCommand == NetMsgType::GHOSTNODEPAYMENTSYNC) { //Ghostnode Payments Request Sync

        // Ignore such requests until we are fully synced.
        // We could start processing this after ghostnode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!ghostnodeSync.IsSynced(chainActive.Height())) return;

        int nCountNeeded;
        vRecv >> nCountNeeded;

        if (netfulfilledman.HasFulfilledRequest(pfrom->addr, NetMsgType::GHOSTNODEPAYMENTSYNC)) {
            // Asking for the payments list multiple times in a short period of time is no good
            //LogPrintf("GHOSTNODEPAYMENTSYNC -- peer already asked me for the list\n");
            Misbehaving(pfrom->GetId(), 20);
            return;
        }
        netfulfilledman.AddFulfilledRequest(pfrom->addr, NetMsgType::GHOSTNODEPAYMENTSYNC);

        Sync(pfrom);
        //LogPrintf("mnpayments GHOSTNODEPAYMENTSYNC -- Sent Ghostnode payment votes to peer \n");

    } else if (strCommand == NetMsgType::GHOSTNODEPAYMENTVOTE) { // Ghostnode Payments Vote for the Winner

        CGhostnodePaymentVote vote;
        vRecv >> vote;

        if (pfrom->nVersion < GetMinGhostnodePaymentsProto()) return;

        if (!pCurrentBlockIndex) return;

        uint256 nHash = vote.GetHash();

        pfrom->setAskFor.erase(nHash);

        {
            LOCK(cs_mapGhostnodePaymentVotes);
            if (mapGhostnodePaymentVotes.count(nHash)) {
                //LogPrintf("mnpayments GHOSTNODEPAYMENTVOTE -- nHeight=%d seen\n", pCurrentBlockIndex->nHeight);
                return;
            }

            // Avoid processing same vote multiple times
            mapGhostnodePaymentVotes[nHash] = vote;
            // but first mark vote as non-verified,
            // AddPaymentVote() below should take care of it if vote is actually ok
            mapGhostnodePaymentVotes[nHash].MarkAsNotVerified();
        }

        int nFirstBlock = pCurrentBlockIndex->nHeight - GetStorageLimit();
        if (vote.nBlockHeight < nFirstBlock || vote.nBlockHeight > pCurrentBlockIndex->nHeight + 20) {
            //LogPrintf("mnpaymentsGHOSTNODEPAYMENTVOTE -- vote out of range: nFirstBlock=%d, nBlockHeight=%d, nHeight=%d\n", nFirstBlock, vote.nBlockHeight, pCurrentBlockIndex->nHeight);
            return;
        }

        std::string strError = "";
        if (!vote.IsValid(pfrom, pCurrentBlockIndex->nHeight, strError)) {
            //LogPrintf("mnpayments GHOSTNODEPAYMENTVOTE -- invalid message, error: %s\n", strError);
            return;
        }

        if (!CanVote(vote.vinGhostnode.prevout, vote.nBlockHeight)) {
            //LogPrintf("GHOSTNODEPAYMENTVOTE -- ghostnode already voted, ghostnode\n");
            return;
        }

        ghostnode_info_t mnInfo = mnodeman.GetGhostnodeInfo(vote.vinGhostnode);
        if (!mnInfo.fInfoValid) {
            // mn was not found, so we can't check vote, some info is probably missing
            //LogPrintf("GHOSTNODEPAYMENTVOTE -- ghostnode is missing \n");
            mnodeman.AskForMN(pfrom, vote.vinGhostnode);
            return;
        }

        int nDos = 0;
        if (!vote.CheckSignature(mnInfo.pubKeyGhostnode, pCurrentBlockIndex->nHeight, nDos)) {
            if (nDos) {
                //LogPrintf("GHOSTNODEPAYMENTVOTE -- ERROR: invalid signature\n");
                Misbehaving(pfrom->GetId(), nDos);
            } else {
                // only warn about anything non-critical (i.e. nDos == 0) in debug mode
                //LogPrintf("mnpayments GHOSTNODEPAYMENTVOTE -- WARNING: invalid signature\n");
            }
            // Either our info or vote info could be outdated.
            // In case our info is outdated, ask for an update,
            mnodeman.AskForMN(pfrom, vote.vinGhostnode);
            // but there is nothing we can do if vote info itself is outdated
            // (i.e. it was signed by a mn which changed its key),
            // so just quit here.
            return;
        }

        CTxDestination address1;
        ExtractDestination(vote.payee, address1);
        CBitcoinAddress address2(address1);

        //LogPrintf("mnpayments GHOSTNODEPAYMENTVOTE -- vote: address=%s, nBlockHeight=%d, nHeight=%d, prevout=%s\n", address2.ToString(), vote.nBlockHeight, pCurrentBlockIndex->nHeight, vote.vinGhostnode.prevout.ToStringShort());

        if (AddPaymentVote(vote)) {
            vote.Relay();
            ghostnodeSync.AddedPaymentVote();
        }
    }
}

bool CGhostnodePaymentVote::Sign() {
    std::string strError;
    std::string strMessage = vinGhostnode.prevout.ToStringShort() +
                             boost::lexical_cast<std::string>(nBlockHeight) +
                             ScriptToAsmStr(payee);

    if (!darkSendSigner.SignMessage(strMessage, vchSig, activeGhostnode.keyGhostnode)) {
        //LogPrint("CGhostnodePaymentVote::Sign -- SignMessage() failed\n");
        return false;
    }

    if (!darkSendSigner.VerifyMessage(activeGhostnode.pubKeyGhostnode, vchSig, strMessage, strError)) {
        //LogPrint("CGhostnodePaymentVote::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CGhostnodePayments::GetBlockPayee(int nBlockHeight, CScript &payee) {
    if (mapGhostnodeBlocks.count(nBlockHeight)) {
        return mapGhostnodeBlocks[nBlockHeight].GetBestPayee(payee);
    }

    return false;
}

// Is this ghostnode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 blocks of votes
bool CGhostnodePayments::IsScheduled(CGhostnode &mn, int nNotBlockHeight) {
    LOCK(cs_mapGhostnodeBlocks);

    if (!pCurrentBlockIndex) return false;

    CScript mnpayee;
    mnpayee = GetScriptForDestination(mn.pubKeyCollateralAddress.GetID());

    CScript payee;
    for (int64_t h = pCurrentBlockIndex->nHeight; h <= pCurrentBlockIndex->nHeight + 8; h++) {
        if (h == nNotBlockHeight) continue;
        if (mapGhostnodeBlocks.count(h) && mapGhostnodeBlocks[h].GetBestPayee(payee) && mnpayee == payee) {
            return true;
        }
    }

    return false;
}

bool CGhostnodePayments::AddPaymentVote(const CGhostnodePaymentVote &vote) {
    //LogPrintf("\nghostnode-payments CGhostnodePayments::AddPaymentVote\n");
    uint256 blockHash = uint256();
    if (!GetBlockHash(blockHash, vote.nBlockHeight - 100)){
        LogPrintf("\nghostnode-payments CGhostnodePayments::Invalid Hash\n");
        return false;
    }
    if (HasVerifiedPaymentVote(vote.GetHash())) return false;

    LOCK2(cs_mapGhostnodeBlocks, cs_mapGhostnodePaymentVotes);

    mapGhostnodePaymentVotes[vote.GetHash()] = vote;

    if (!mapGhostnodeBlocks.count(vote.nBlockHeight)) {
        CGhostnodeBlockPayees blockPayees(vote.nBlockHeight);
        mapGhostnodeBlocks[vote.nBlockHeight] = blockPayees;
    }

    mapGhostnodeBlocks[vote.nBlockHeight].AddPayee(vote);

    return true;
}

bool CGhostnodePayments::HasVerifiedPaymentVote(uint256 hashIn) {
    LOCK(cs_mapGhostnodePaymentVotes);
    std::map<uint256, CGhostnodePaymentVote>::iterator it = mapGhostnodePaymentVotes.find(hashIn);
    return it != mapGhostnodePaymentVotes.end() && it->second.IsVerified();
}

void CGhostnodeBlockPayees::AddPayee(const CGhostnodePaymentVote &vote) {
    LOCK(cs_vecPayees);

    BOOST_FOREACH(CGhostnodePayee & payee, vecPayees)
    {
        if (payee.GetPayee() == vote.payee) {
            payee.AddVoteHash(vote.GetHash());
            return;
        }
    }
    CGhostnodePayee payeeNew(vote.payee, vote.GetHash());
    vecPayees.push_back(payeeNew);
}

bool CGhostnodeBlockPayees::GetBestPayee(CScript &payeeRet) {
    LOCK(cs_vecPayees);
    //LogPrint("mnpayments", "CGhostnodeBlockPayees::GetBestPayee, vecPayees.size()=%s\n", vecPayees.size());
    if (!vecPayees.size()) {
        //LogPrint("mnpayments", "CGhostnodeBlockPayees::GetBestPayee -- ERROR: couldn't find any payee\n");
        return false;
    }

    int nVotes = -1;
    BOOST_FOREACH(CGhostnodePayee & payee, vecPayees)
    {
        if (payee.GetVoteCount() > nVotes) {
            payeeRet = payee.GetPayee();
            nVotes = payee.GetVoteCount();
        }
    }

    return (nVotes > -1);
}

bool CGhostnodeBlockPayees::HasPayeeWithVotes(CScript payeeIn, int nVotesReq) {
    LOCK(cs_vecPayees);

    BOOST_FOREACH(CGhostnodePayee & payee, vecPayees)
    {
        if (payee.GetVoteCount() >= nVotesReq && payee.GetPayee() == payeeIn) {
            return true;
        }
    }

//    //LogPrint("mnpayments", "CGhostnodeBlockPayees::HasPayeeWithVotes -- ERROR: couldn't find any payee with %d+ votes\n", nVotesReq);
    return false;
}

bool CGhostnodeBlockPayees::IsTransactionValid(const CTransaction &txNew) {
    LOCK(cs_vecPayees);

    int nMaxSignatures = 0;
    std::string strPayeesPossible = "";

    CAmount nGhostnodePayment = GetGhostnodePayment(nBlockHeight, txNew.GetValueOut());

    //require at least MNPAYMENTS_SIGNATURES_REQUIRED signatures

    BOOST_FOREACH(CGhostnodePayee & payee, vecPayees)
    {
        if (payee.GetVoteCount() >= nMaxSignatures) {
            nMaxSignatures = payee.GetVoteCount();
        }
    }

    // if we don't have at least MNPAYMENTS_SIGNATURES_REQUIRED signatures on a payee, approve whichever is the longest chain
    if (nMaxSignatures < MNPAYMENTS_SIGNATURES_REQUIRED) return true;

    bool hasValidPayee = false;

    BOOST_FOREACH(CGhostnodePayee & payee, vecPayees)
    {
        if (payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
            hasValidPayee = true;

            BOOST_FOREACH(CTxOut txout, txNew.vout) {
                if (payee.GetPayee() == txout.scriptPubKey && nGhostnodePayment == txout.nValue) {
                    //LogPrint("mnpayments", "CGhostnodeBlockPayees::IsTransactionValid -- Found required payment\n");
                    return true;
                }
            }

            CTxDestination address1;
            ExtractDestination(payee.GetPayee(), address1);
            CBitcoinAddress address2(address1);

            if (strPayeesPossible == "") {
                strPayeesPossible = address2.ToString();
            } else {
                strPayeesPossible += "," + address2.ToString();
            }
        }
    }

    if (!hasValidPayee) return true;

    //LogPrint("CGhostnodeBlockPayees::IsTransactionValid -- ERROR: Missing required payment, possible payees: '%s', amount: %f NIX\n", strPayeesPossible, (float) nGhostnodePayment / COIN);
    return false;
}

std::string CGhostnodeBlockPayees::GetRequiredPaymentsString() {
    LOCK(cs_vecPayees);

    std::string strRequiredPayments = "Unknown";

    BOOST_FOREACH(CGhostnodePayee & payee, vecPayees)
    {
        CTxDestination address1;
        ExtractDestination(payee.GetPayee(), address1);
        CBitcoinAddress address2(address1);

        if (strRequiredPayments != "Unknown") {
            strRequiredPayments += ", " + address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.GetVoteCount());
        } else {
            strRequiredPayments = address2.ToString() + ":" + boost::lexical_cast<std::string>(payee.GetVoteCount());
        }
    }

    return strRequiredPayments;
}

std::string CGhostnodePayments::GetRequiredPaymentsString(int nBlockHeight) {
    LOCK(cs_mapGhostnodeBlocks);

    if (mapGhostnodeBlocks.count(nBlockHeight)) {
        return mapGhostnodeBlocks[nBlockHeight].GetRequiredPaymentsString();
    }

    return "Unknown";
}

bool CGhostnodePayments::IsTransactionValid(const CTransaction &txNew, int nBlockHeight) {
    LOCK(cs_mapGhostnodeBlocks);

    if (mapGhostnodeBlocks.count(nBlockHeight)) {
        return mapGhostnodeBlocks[nBlockHeight].IsTransactionValid(txNew);
    }

    return true;
}

void CGhostnodePayments::CheckAndRemove() {
    if (!pCurrentBlockIndex) return;

    LOCK2(cs_mapGhostnodeBlocks, cs_mapGhostnodePaymentVotes);

    int nLimit = GetStorageLimit();

    std::map<uint256, CGhostnodePaymentVote>::iterator it = mapGhostnodePaymentVotes.begin();
    while (it != mapGhostnodePaymentVotes.end()) {
        CGhostnodePaymentVote vote = (*it).second;

        if (pCurrentBlockIndex->nHeight - vote.nBlockHeight > nLimit) {
            //LogPrint("mnpayments", "CGhostnodePayments::CheckAndRemove -- Removing old Ghostnode payment: nBlockHeight=%d\n", vote.nBlockHeight);
            mapGhostnodePaymentVotes.erase(it++);
            mapGhostnodeBlocks.erase(vote.nBlockHeight);
        } else {
            ++it;
        }
    }
    //LogPrint("CGhostnodePayments::CheckAndRemove -- %s\n", ToString());
}

bool CGhostnodePaymentVote::IsValid(CNode *pnode, int nValidationHeight, std::string &strError) {
    CGhostnode *pmn = mnodeman.Find(vinGhostnode);

    if (!pmn) {
        strError = strprintf("Unknown Ghostnode: prevout=%s", vinGhostnode.prevout.ToStringShort());
        // Only ask if we are already synced and still have no idea about that Ghostnode
        if (ghostnodeSync.IsGhostnodeListSynced()) {
            mnodeman.AskForMN(pnode, vinGhostnode);
        }

        return false;
    }

    int nMinRequiredProtocol;
    if (nBlockHeight >= nValidationHeight) {
        // new votes must comply SPORK_10_GHOSTNODE_PAY_UPDATED_NODES rules
        nMinRequiredProtocol = mnpayments.GetMinGhostnodePaymentsProto();
    } else {
        // allow non-updated ghostnodes for old blocks
        nMinRequiredProtocol = MIN_GHOSTNODE_PAYMENT_PROTO_VERSION_1;
    }

    if (pmn->nProtocolVersion < nMinRequiredProtocol) {
        strError = strprintf("Ghostnode protocol is too old: nProtocolVersion=%d, nMinRequiredProtocol=%d", pmn->nProtocolVersion, nMinRequiredProtocol);
        return false;
    }

    // Only ghostnodes should try to check ghostnode rank for old votes - they need to pick the right winner for future blocks.
    // Regular clients (miners included) need to verify ghostnode rank for future block votes only.
    if (!fGhostNode && nBlockHeight < nValidationHeight) return true;

    int nRank = mnodeman.GetGhostnodeRank(vinGhostnode, nBlockHeight - 100, nMinRequiredProtocol, false);

    if (nRank == -1) {
        //LogPrint("mnpayments", "CGhostnodePaymentVote::IsValid -- Can't calculate rank for ghostnode %s\n",
                 //vinGhostnode.prevout.ToStringShort());
        return false;
    }

    if (nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        // It's common to have ghostnodes mistakenly think they are in the top 10
        // We don't want to print all of these messages in normal mode, debug mode should print though
        strError = strprintf("Ghostnode is not in the top %d (%d)", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        // Only ban for new mnw which is out of bounds, for old mnw MN list itself might be way too much off
        if (nRank > MNPAYMENTS_SIGNATURES_TOTAL * 2 && nBlockHeight > nValidationHeight) {
            strError = strprintf("Ghostnode is not in the top %d (%d)", MNPAYMENTS_SIGNATURES_TOTAL * 2, nRank);
            //LogPrint("CGhostnodePaymentVote::IsValid -- Error: %s\n", strError);
            Misbehaving(pnode->GetId(), 20);
        }
        // Still invalid however
        return false;
    }

    return true;
}

bool CGhostnodePayments::ProcessBlock(int nBlockHeight) {

    // DETERMINE IF WE SHOULD BE VOTING FOR THE NEXT PAYEE

    if (fLiteMode || !fGhostNode) {
        return false;
    }

    // We have little chances to pick the right winner if winners list is out of sync
    // but we have no choice, so we'll try. However it doesn't make sense to even try to do so
    // if we have not enough data about ghostnodes.
    if (!ghostnodeSync.IsGhostnodeListSynced()) {
        return false;
    }

    int nRank = mnodeman.GetGhostnodeRank(activeGhostnode.vin, nBlockHeight - 100, GetMinGhostnodePaymentsProto(), false);

    if (nRank == -1) {
        LogPrintf("mnpayments CGhostnodePayments::ProcessBlock -- Unknown Ghostnode\n");
        return false;
    }

    if (nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrintf("mnpayments CGhostnodePayments::ProcessBlock -- Ghostnode not in the top %d (%d)\n", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        return false;
    }

    // LOCATE THE NEXT GHOSTNODE WHICH SHOULD BE PAID

    //LogPrintf("CGhostnodePayments::ProcessBlock -- Start: nBlockHeight=%d, ghostnode=%s\n", nBlockHeight, activeGhostnode.vin.prevout.ToStringShort());

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    int nCount = 0;
    CGhostnode *pmn = mnodeman.GetNextGhostnodeInQueueForPayment(nBlockHeight, true, nCount);

    if (pmn == NULL) {
        LogPrintf("CGhostnodePayments::ProcessBlock -- ERROR: Failed to find ghostnode to pay\n");
        return false;
    }

    //LogPrintf("CGhostnodePayments::ProcessBlock -- Ghostnode found by GetNextGhostnodeInQueueForPayment(): %s\n", pmn->vin.prevout.ToStringShort());


    CScript payee = GetScriptForDestination(pmn->pubKeyCollateralAddress.GetID());

    CGhostnodePaymentVote voteNew(activeGhostnode.vin, nBlockHeight, payee);

    CTxDestination address1;
    ExtractDestination(payee, address1);
    CBitcoinAddress address2(address1);

    // SIGN MESSAGE TO NETWORK WITH OUR GHOSTNODE KEYS

    //LogPrintf("ProcessBlock -- vote: address=%s, nBlockHeight=%d, nHeight=%d, prevout=%s\n", address2.ToString(), voteNew.nBlockHeight, pCurrentBlockIndex->nHeight, voteNew.vinGhostnode.prevout.ToStringShort());

    if (voteNew.Sign()) {
        if (AddPaymentVote(voteNew)) {
            voteNew.Relay();
            return true;
        }
    }

    return false;
}

void CGhostnodePaymentVote::Relay() {
    // do not relay until synced
    if (!ghostnodeSync.IsWinnersListSynced()) {
        //LogPrint("CGhostnodePaymentVote::Relay - ghostnodeSync.IsWinnersListSynced() not sync\n");
        return;
    }
    CInv inv(MSG_GHOSTNODE_PAYMENT_VOTE, GetHash());
    g_connman->RelayInv(inv);
}

bool CGhostnodePaymentVote::CheckSignature(const CPubKey &pubKeyGhostnode, int nValidationHeight, int &nDos) {
    // do not ban by default
    nDos = 0;

    std::string strMessage = vinGhostnode.prevout.ToStringShort() +
                             boost::lexical_cast<std::string>(nBlockHeight) +
                             ScriptToAsmStr(payee);

    std::string strError = "";
    if (!darkSendSigner.VerifyMessage(pubKeyGhostnode, vchSig, strMessage, strError)) {
        // Only ban for future block vote when we are already synced.
        // Otherwise it could be the case when MN which signed this vote is using another key now
        // and we have no idea about the old one.
        if (ghostnodeSync.IsGhostnodeListSynced() && nBlockHeight > nValidationHeight) {
            nDos = 20;
        }
        return error("CGhostnodePaymentVote::CheckSignature -- Got bad Ghostnode payment signature, ghostnode=%s, error: %s", vinGhostnode.prevout.ToStringShort().c_str(), strError);
    }

    return true;
}

std::string CGhostnodePaymentVote::ToString() const {
    std::ostringstream info;

    info << vinGhostnode.prevout.ToStringShort() <<
         ", " << nBlockHeight <<
         ", " << ScriptToAsmStr(payee) <<
         ", " << (int) vchSig.size();

    return info.str();
}

// Send only votes for future blocks, node should request every other missing payment block individually
void CGhostnodePayments::Sync(CNode *pnode) {
    LOCK(cs_mapGhostnodeBlocks);

    if (!pCurrentBlockIndex) return;

    int nInvCount = 0;

    for (int h = pCurrentBlockIndex->nHeight; h < pCurrentBlockIndex->nHeight + 20; h++) {
        if (mapGhostnodeBlocks.count(h)) {
            BOOST_FOREACH(CGhostnodePayee & payee, mapGhostnodeBlocks[h].vecPayees)
            {
                std::vector <uint256> vecVoteHashes = payee.GetVoteHashes();
                BOOST_FOREACH(uint256 & hash, vecVoteHashes)
                {
                    if (!HasVerifiedPaymentVote(hash)) continue;
                    pnode->PushInventory(CInv(MSG_GHOSTNODE_PAYMENT_VOTE, hash));
                    nInvCount++;
                }
            }
        }
    }

    //LogPrint("CGhostnodePayments::Sync -- Sent %d votes to peer %d\n", nInvCount, pnode->GetId());
    const CNetMsgMaker msgMaker(pnode->GetSendVersion());
    g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::SYNCSTATUSCOUNT, GHOSTNODE_SYNC_MNW, nInvCount));
}

// Request low data/unknown payment blocks in batches directly from some node instead of/after preliminary Sync.
void CGhostnodePayments::RequestLowDataPaymentBlocks(CNode *pnode) {
    if (!pCurrentBlockIndex) return;

    LOCK2(cs_main, cs_mapGhostnodeBlocks);

    std::vector <CInv> vToFetch;
    int nLimit = GetStorageLimit();

    const CBlockIndex *pindex = pCurrentBlockIndex;

    while (pCurrentBlockIndex->nHeight - pindex->nHeight < nLimit) {
        if (!mapGhostnodeBlocks.count(pindex->nHeight)) {
            // We have no idea about this block height, let's ask
            vToFetch.push_back(CInv(MSG_GHOSTNODE_PAYMENT_BLOCK, pindex->GetBlockHash()));
            // We should not violate GETDATA rules
            if (vToFetch.size() == MAX_INV_SZ) {
                //LogPrint("CGhostnodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d blocks\n", pnode->GetId(), MAX_INV_SZ);
                const CNetMsgMaker msgMaker(pnode->GetSendVersion());
                g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
                // Start filling new batch
                vToFetch.clear();
            }
        }
        if (!pindex->pprev) break;
        pindex = pindex->pprev;
    }

    std::map<int, CGhostnodeBlockPayees>::iterator it = mapGhostnodeBlocks.begin();

    while (it != mapGhostnodeBlocks.end()) {
        int nTotalVotes = 0;
        bool fFound = false;
        BOOST_FOREACH(CGhostnodePayee & payee, it->second.vecPayees)
        {
            if (payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
                fFound = true;
                break;
            }
            nTotalVotes += payee.GetVoteCount();
        }
        // A clear winner (MNPAYMENTS_SIGNATURES_REQUIRED+ votes) was found
        // or no clear winner was found but there are at least avg number of votes
        if (fFound || nTotalVotes >= (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED) / 2) {
            // so just move to the next block
            ++it;
            continue;
        }
        // DEBUG
//        DBG (
//            // Let's see why this failed
//            BOOST_FOREACH(CGhostnodePayee& payee, it->second.vecPayees) {
//                CTxDestination address1;
//                ExtractDestination(payee.GetPayee(), address1);
//                CBitcoinAddress address2(address1);
//                printf("payee %s votes %d\n", address2.ToString().c_str(), payee.GetVoteCount());
//            }
//            printf("block %d votes total %d\n", it->first, nTotalVotes);
//        )
        // END DEBUG
        // Low data block found, let's try to sync it
        uint256 hash;
        if (GetBlockHash(hash, it->first)) {
            vToFetch.push_back(CInv(MSG_GHOSTNODE_PAYMENT_BLOCK, hash));
        }
        // We should not violate GETDATA rules
        if (vToFetch.size() == MAX_INV_SZ) {
            //LogPrint("CGhostnodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d payment blocks\n", pnode->GetId(), MAX_INV_SZ);
            // Start filling new batch
            const CNetMsgMaker msgMaker(pnode->GetSendVersion());
            g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
            vToFetch.clear();
        }
        ++it;
    }
    // Ask for the rest of it
    if (!vToFetch.empty()) {
        //LogPrint("CGhostnodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d payment blocks\n", pnode->GetId(), vToFetch.size());
        const CNetMsgMaker msgMaker(pnode->GetSendVersion());
        g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
    }
}

std::string CGhostnodePayments::ToString() const {
    std::ostringstream info;

    info << "Votes: " << (int) mapGhostnodePaymentVotes.size() <<
         ", Blocks: " << (int) mapGhostnodeBlocks.size();

    return info.str();
}

bool CGhostnodePayments::IsEnoughData() {
    float nAverageVotes = (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED) / 2;
    int nStorageLimit = GetStorageLimit();
    return GetBlockCount() > nStorageLimit && GetVoteCount() > nStorageLimit * nAverageVotes;
}

int CGhostnodePayments::GetStorageLimit() {
    return std::max(int(mnodeman.size() * nStorageCoeff), nMinBlocksToStore);
}

void CGhostnodePayments::UpdatedBlockTip(const CBlockIndex *pindex) {
    pCurrentBlockIndex = pindex;
    //LogPrint("mnpayments", "CGhostnodePayments::UpdatedBlockTip -- pCurrentBlockIndex->nHeight=%d\n", pCurrentBlockIndex->nHeight);
    
    ProcessBlock(pindex->nHeight + 5);
}
