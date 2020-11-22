/******************************************************************************
 * Copyright © 2014-2020 The Komodo Platform Developers.                      *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * Komodo Platform software, including this file may be copied, modified,     *
 * propagated or distributed except according to the terms contained in the   *
 * LICENSE file.                                                              *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "cc/eval.h"
#include "crosschain.h"
#include "notarisationdb.h"
#include "notaries_staked.h"

int GetSymbolAuthority(const char* symbol)
{
    if (strncmp(symbol, "TXSCL", 5) == 0)
        return CROSSCHAIN_TXSCL;
    if (is_STAKED(symbol) != 0) {
        //LogPrintf("RETURNED CROSSCHAIN STAKED AS TRUE\n");
        return CROSSCHAIN_STAKED;
    }
    //LogPrintf("RETURNED CROSSCHAIN KOMODO AS TRUE\n");
    return CROSSCHAIN_KOMODO;
}


bool CheckTxAuthority(const CTransaction &tx, CrosschainAuthority auth)
{
    EvalRef eval;

    if (tx.vin.size() < auth.requiredSigs) return false;

    uint8_t seen[64] = {0};

    BOOST_FOREACH(const CTxIn &txIn, tx.vin)
    {
        // Get notary pubkey
        CTransaction tx;
        uint256 hashBlock;
        if (!eval->GetTxUnconfirmed(txIn.prevout.hash, tx, hashBlock)) return false;
        if (tx.vout.size() < txIn.prevout.n) return false;
        CScript spk = tx.vout[txIn.prevout.n].scriptPubKey;
        if (spk.size() != 35) return false;
        const unsigned char *pk = &spk[0];
        if (pk++[0] != 33) return false;
        if (pk[33] != OP_CHECKSIG) return false;

        // Check it's a notary
        for (int i=0; i<auth.size; i++) {
            if (!seen[i]) {
                if (memcmp(pk, auth.notaries[i], 33) == 0) {
                    seen[i] = 1;
                    goto found;
                } else {
                    //LogPrintf("notary.%i is not valid!\n",i);
                }
            }
        }

        return false;
        found:;
    }

    return true;
}


/*
const CrosschainAuthority auth_STAKED = [&](){
    CrosschainAuthority auth;
    auth.requiredSigs = (num_notaries_STAKED / 5);
    auth.size = num_notaries_STAKED;
    for (int n=0; n<auth.size; n++)
        for (size_t i=0; i<33; i++)
            sscanf(notaries_STAKED[n][1]+(i*2), "%2hhx", auth.notaries[n]+i);
    return auth;
}();
*/
