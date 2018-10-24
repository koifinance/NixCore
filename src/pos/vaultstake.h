// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_VAULTSTAKE_H
#define NIX_VAULTSTAKE_H

#include "zerocoin/zerocoin.h"
#include "primitives/transaction.h"

class CZerocoinEntry;

class CVaultStake
{
    const CTxIn stakeIn;
    const CTxOut stakePrevOut;
    list <CZerocoinEntry> pubCoinList;
    bool isZerocoinMint;
    bool isZerocoinSpend;
    int maxAge;

public:
    CVaultStake();
    CVaultStake(const list <CZerocoinEntry> &listPubCoin, CValidationState state);
    setNull(){
        maxAge = 0;
        stakeIn = CTxIn();
        stakePrevOut = CTxOut();
    }
};

#endif // NIX_VAULTSTAKE_H
