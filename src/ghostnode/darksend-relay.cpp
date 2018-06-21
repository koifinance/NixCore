// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "darksend.h"
#include "darksend-relay.h"
#include "netmessagemaker.h"


CDarkSendRelay::CDarkSendRelay()
{
    vinGhostnode = CTxIn();
    nBlockHeight = 0;
    nRelayType = 0;
    in = CTxIn();
    out = CTxOut();
}

CDarkSendRelay::CDarkSendRelay(CTxIn& vinGhostnodeIn, vector<unsigned char>& vchSigIn, int nBlockHeightIn, int nRelayTypeIn, CTxIn& in2, CTxOut& out2)
{
    vinGhostnode = vinGhostnodeIn;
    vchSig = vchSigIn;
    nBlockHeight = nBlockHeightIn;
    nRelayType = nRelayTypeIn;
    in = in2;
    out = out2;
}

std::string CDarkSendRelay::ToString()
{
    std::ostringstream info;

    info << "vin: " << vinGhostnode.ToString() <<
        " nBlockHeight: " << (int)nBlockHeight <<
        " nRelayType: "  << (int)nRelayType <<
        " in " << in.ToString() <<
        " out " << out.ToString();
        
    return info.str();   
}

bool CDarkSendRelay::Sign(std::string strSharedKey)
{
    std::string strError = "";
    std::string strMessage = in.ToString() + out.ToString();

    CKey key2;
    CPubKey pubkey2;

    if(!darkSendSigner.GetKeysFromSecret(strSharedKey, key2, pubkey2)) {
        //LogPrint("CDarkSendRelay::Sign -- GetKeysFromSecret() failed, invalid shared key %s\n", strSharedKey);
        return false;
    }

    if(!darkSendSigner.SignMessage(strMessage, vchSig2, key2)) {
        //LogPrint("CDarkSendRelay::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, vchSig2, strMessage, strError)) {
        //LogPrint("CDarkSendRelay::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CDarkSendRelay::VerifyMessage(std::string strSharedKey)
{
    std::string strError = "";
    std::string strMessage = in.ToString() + out.ToString();

    CKey key2;
    CPubKey pubkey2;

    if(!darkSendSigner.GetKeysFromSecret(strSharedKey, key2, pubkey2)) {
        //LogPrint("CDarkSendRelay::VerifyMessage -- GetKeysFromSecret() failed, invalid shared key %s\n", strSharedKey);
        return false;
    }

    if(!darkSendSigner.VerifyMessage(pubkey2, vchSig2, strMessage, strError)) {
        //LogPrint("CDarkSendRelay::VerifyMessage -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

void CDarkSendRelay::Relay()
{
    int nCount = std::min(mnodeman.CountEnabled(MIN_PRIVATESEND_PEER_PROTO_VERSION), 20);
    int nRank1 = (rand() % nCount)+1; 
    int nRank2 = (rand() % nCount)+1; 

    //keep picking another second number till we get one that doesn't match
    while(nRank1 == nRank2) nRank2 = (rand() % nCount)+1;

    //printf("rank 1 - rank2 %d %d \n", nRank1, nRank2);

    //relay this message through 2 separate nodes for redundancy
    RelayThroughNode(nRank1);
    RelayThroughNode(nRank2);
}

void CDarkSendRelay::RelayThroughNode(int nRank)
{
    CGhostnode* pmn = mnodeman.GetGhostnodeByRank(nRank, nBlockHeight, MIN_PRIVATESEND_PEER_PROTO_VERSION);

    if(pmn != NULL){
        //printf("RelayThroughNode %s\n", pmn->addr.ToString().c_str());
        CNode* pnode = g_connman->ConnectNode(CAddress(pmn->addr, NODE_NETWORK), NULL, false, false);
        if(pnode) {
            //printf("Connected\n");
            const CNetMsgMaker msgMaker(pnode->GetSendVersion());
            g_connman->PushMessage(pnode, msgMaker.Make("dsr", (*this)));
            return;
        }
    } else {
        //printf("RelayThroughNode NULL\n");
    }
}
