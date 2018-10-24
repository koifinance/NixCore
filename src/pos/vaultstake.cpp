// Copyright (c) 2017-2018 The NIX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "vaultstake.h"
#include "validation.h"
#include "Coin.h"
#include "consensus/validation.h"
#include "wallet/wallet.h"
#include "boost/foreach.hpp"
#include "consensus/consensus.h"

bool CompDenom(const CZerocoinEntry &a, const CZerocoinEntry &b) { return a.denomination < b.denomination; }

CVaultStake::CVaultStake()
{

}

CVaultStake::CVaultStake(list <CZerocoinEntry> &listPubCoin, CValidationState state){


    CZerocoinState *zerocoinState = CZerocoinState::GetZerocoinState();

    //sort list with highest pubcoin value
    listPubCoin.sort(CompDenom);
    pubCoinList = listPubCoin;

    CZerocoinEntry coinToUse;

    CBigNum accumulatorValue;
    uint256 accumulatorBlockHash;

    int coinId = INT_MAX;
    int coinHeight;

    //remove any coins not old enough
    BOOST_FOREACH(const CZerocoinEntry &minIdPubcoin, listPubCoin) {
        if (minIdPubcoin.denomination == denomination
                && minIdPubcoin.IsUsed == false
                && minIdPubcoin.randomness != 0
                && minIdPubcoin.serialNumber != 0) {

            int id;
            coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
            if (coinHeight > 0
                    && id < coinId
                    && coinHeight + (1) <= chainActive.Height()
                    && zerocoinState->GetAccumulatorValueForSpend(&chainActive,
                            chainActive.Height()-(1),
                            minIdPubcoin.denomination,
                            id,
                            accumulatorValue,
                            accumulatorBlockHash) > 1
                    ) {
                coinId = id;
                coinToUse = minIdPubcoin;
            }
        }
    }

    BOOST_FOREACH(const CZerocoinEntry &minIdPubcoin, listPubCoin) {
        if (minIdPubcoin.denomination == denomination
                && minIdPubcoin.IsUsed == false
                && minIdPubcoin.randomness != 0
                && minIdPubcoin.serialNumber != 0) {

            int id;
            coinHeight = zerocoinState->GetMintedCoinHeightAndId(minIdPubcoin.value, minIdPubcoin.denomination, id);
            if (coinHeight > 0
                    && id < coinId
                    && coinHeight + (1) <= chainActive.Height()
                    && zerocoinState->GetAccumulatorValueForSpend(&chainActive,
                            chainActive.Height()-(1),
                            minIdPubcoin.denomination,
                            id,
                            accumulatorValue,
                            accumulatorBlockHash) > 1
                    ) {
                coinId = id;
                coinToUse = minIdPubcoin;
            }
        }
    }

    if (coinId == INT_MAX)
        state.DoS(100, false, REJECT_INVALID ,"No eligible ghosted coins!");

    if(coinHeight < COINBASE_MATURITY_V2 + chainActive.Height())
        state.DoS(100, false, REJECT_INVALID ,"Ghosted coins not old enough to stake!");

}
