// Copyright (c) 2014-2017 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ACTIVEZOINODE_H
#define ACTIVEZOINODE_H

#include "net.h"
#include "key.h"
#include "wallet/wallet.h"

class CActiveZoinode;

static const int ACTIVE_ZOINODE_INITIAL          = 0; // initial state
static const int ACTIVE_ZOINODE_SYNC_IN_PROCESS  = 1;
static const int ACTIVE_ZOINODE_INPUT_TOO_NEW    = 2;
static const int ACTIVE_ZOINODE_NOT_CAPABLE      = 3;
static const int ACTIVE_ZOINODE_STARTED          = 4;

extern CActiveZoinode activeZoinode;

// Responsible for activating the Zoinode and pinging the network
class CActiveZoinode
{
public:
    enum zoinode_type_enum_t {
        ZOINODE_UNKNOWN = 0,
        ZOINODE_REMOTE  = 1,
        ZOINODE_LOCAL   = 2
    };

private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    zoinode_type_enum_t eType;

    bool fPingerEnabled;

    /// Ping Zoinode
    bool SendZoinodePing();

public:
    // Keys for the active Zoinode
    CPubKey pubKeyZoinode;
    CKey keyZoinode;

    // Initialized while registering Zoinode
    CTxIn vin;
    CService service;

    int nState; // should be one of ACTIVE_ZOINODE_XXXX
    std::string strNotCapableReason;

    CActiveZoinode()
        : eType(ZOINODE_UNKNOWN),
          fPingerEnabled(false),
          pubKeyZoinode(),
          keyZoinode(),
          vin(),
          service(),
          nState(ACTIVE_ZOINODE_INITIAL)
    {}

    /// Manage state of active Zoinode
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
