// Copyright (c) 2017 The Particl Core developers
// Copyright (c) 2018 The NIX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addressindex.h>

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <util.h>

bool ExtractIndexInfo(const CScript *pScript, int &scriptType, std::vector<uint8_t> &hashBytes)
{
    scriptType = ADDR_INDT_UNKNOWN;
    if (pScript->IsPayToPublicKeyHash())
    {
        hashBytes.assign(pScript->begin()+3, pScript->begin()+23);
        scriptType = ADDR_INDT_PUBKEY_ADDRESS;
    } else
    if (pScript->IsPayToScriptHash())
    {
        hashBytes.assign(pScript->begin()+2, pScript->begin()+22);
        scriptType = ADDR_INDT_SCRIPT_ADDRESS;
    }
    else
    if (pScript->IsPayToScriptHash_CS())
    {
        //use owners address
        hashBytes.assign(pScript->begin()+28, pScript->begin()+48);
        scriptType = ADDR_INDT_SCRIPT_ADDRESS;
    }

    return true;
};

bool ExtractIndexInfo(const CTxOut *out, int &scriptType, std::vector<uint8_t> &hashBytes, CAmount &nValue, const CScript *&pScript)
{
    const CScript *ps = &out->scriptPubKey;
    if (!(pScript = ps))
    {
        LogPrintf("ERROR: %s - expected script pointer.\n", __func__);
        return false;
    };

    nValue =  out->nValue;

    ExtractIndexInfo(pScript, scriptType, hashBytes);

    return true;
};

