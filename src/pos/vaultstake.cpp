// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vaultstake.h"
#include "validation.h"
#include "Coin.h"
#include "consensus/validation.h"

VaultStake::VaultStake()
{

}

VaultStake::VaultStake(const CTxIn _stakeIn, CValidationState state): stakeIn(_stakeIn){


    CTransactionRef txPrev;
    Coin coin;
    CBigNum pubCoin;

    if (!pcoinsTip->GetCoin(stakeIn.prevout, coin) || coin.IsSpent())
    {
        // Must find the prevout in the txdb / blocks

        CBlock blockKernel; // block containing stake kernel, GetTransaction should only fill the header.
        if (!GetTransaction(stakeIn.prevout.hash, txPrev, Params().GetConsensus(), blockKernel, true)
            || stakeIn.prevout.n >= txPrev->vout.size())
            return state.DoS(10, error("%s: prevout-not-in-chain", __func__), REJECT_INVALID, "prevout-not-in-chain");

        stakePrevOut = txPrev->vout[stakeIn.prevout.n];

        //sanity check using minted outputs
        assert(stakePrevOut.scriptPubKey.IsZerocoinMint());

        int nDepth;
        if (!CheckAge(pindexPrev, hashBlock, nDepth))
            return state.DoS(100, error("%s: Tried to stake at depth %d", __func__, nDepth + 1), REJECT_INVALID, "invalid-stake-depth");

        kernelPubKey = stakePrevOut.scriptPubKey;
        amount = stakePrevOut.nValue;
        nBlockFromTime = blockKernel.nTime;
        pubCoin = vector<unsigned char>(stakePrevOut.scriptPubKey.begin()+6, stakePrevOut.scriptPubKey.end());
    } else
    {
        //sanity check using minted outputs
        assert(coin.out.scriptPubKey.IsZerocoinMint());

        CBlockIndex *pindex = chainActive[coin.nHeight];
        CBlockIndex *pindexPrev = chainActive[coin.nHeight - 1];
        if (!pindex)
            return state.DoS(100, error("%s: invalid-prevout", __func__), REJECT_INVALID, "invalid-prevout");

        nDepth = pindexPrev->nHeight - coin.nHeight;
        int nRequiredDepth = std::min((int)(Params().GetStakeMinConfirmations()-1), (int)(pindexPrev->nHeight / 2));
        if (nRequiredDepth > nDepth)
            return state.DoS(100, error("%s: Tried to stake at depth %d", __func__, nDepth + 1), REJECT_INVALID, "invalid-stake-depth");

        kernelPubKey = coin.out.scriptPubKey;
        amount = coin.out.nValue;
        nBlockFromTime = pindex->GetBlockTime();
        pubCoin = vector<unsigned char>(coin.out.scriptPubKey.begin()+6, coin.out.scriptPubKey.end());
    }

}
