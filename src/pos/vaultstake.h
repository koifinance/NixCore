// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NIX_VAULTSTAKE_H
#define NIX_VAULTSTAKE_H

#include "zerocoin/zerocoin.h"
#include "primitives/transaction.h"


class VaultStake
{
    const CTxIn stakeIn;
    const CTxOut stakePrevOut;
    bool isZerocoinMint;
    bool isZerocoinSpend;

public:
    VaultStake();
    VaultStake(const CTxIn _stakeIn, CValidationState state);
    setNull(){
        stakeIn = CTxIn();
        stakePrevOut = CTxOut();
    }
};

#endif // NIX_VAULTSTAKE_H
