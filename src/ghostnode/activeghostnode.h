// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ACTIVEGHOSTNODE_H
#define ACTIVEGHOSTNODE_H

#include "net.h"
#include "key.h"
#include "wallet/wallet.h"

class CActiveGhostnode;

static const int ACTIVE_GHOSTNODE_INITIAL          = 0; // initial state
static const int ACTIVE_GHOSTNODE_SYNC_IN_PROCESS  = 1;
static const int ACTIVE_GHOSTNODE_INPUT_TOO_NEW    = 2;
static const int ACTIVE_GHOSTNODE_NOT_CAPABLE      = 3;
static const int ACTIVE_GHOSTNODE_STARTED          = 4;

extern CActiveGhostnode activeGhostnode;

// Responsible for activating the Ghostnode and pinging the network
class CActiveGhostnode
{
public:
    enum ghostnode_type_enum_t {
        GHOSTNODE_UNKNOWN = 0,
        GHOSTNODE_REMOTE  = 1,
        GHOSTNODE_LOCAL   = 2
    };

private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    ghostnode_type_enum_t eType;

    bool fPingerEnabled;

    /// Ping Ghostnode
    bool SendGhostnodePing();

public:
    // Keys for the active Ghostnode
    CPubKey pubKeyGhostnode;
    CKey keyGhostnode;

    // Initialized while registering Ghostnode
    CTxIn vin;
    CService service;

    int nState; // should be one of ACTIVE_GHOSTNODE_XXXX
    std::string strNotCapableReason;

    CActiveGhostnode()
        : eType(GHOSTNODE_UNKNOWN),
          fPingerEnabled(false),
          pubKeyGhostnode(),
          keyGhostnode(),
          vin(),
          service(),
          nState(ACTIVE_GHOSTNODE_INITIAL)
    {}

    /// Manage state of active Ghostnode
    void ManageState();

    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string GetTypeString() const;

private:
    void ManageStateInitial();
    void ManageStateRemote();
    void ManageStateLocal();
};

#endif
