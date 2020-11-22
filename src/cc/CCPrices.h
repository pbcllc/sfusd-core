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


#ifndef CC_PRICES_H
#define CC_PRICES_H

#include "CCinclude.h"
extern void GetKomodoEarlytxidScriptPub();
extern CScript POWERBLOCKCOIN_EARLYTXID_SCRIPTPUB;

extern int32_t ASSETCHAINS_BLOCKTIME;

#define PRICES_DAYWINDOW ((3600*24/ASSETCHAINS_BLOCKTIME) + 1) // defined in komodo_defs.h
#define PRICES_TXFEE 10000
#define PRICES_MAXLEVERAGE 777
#define PRICES_SMOOTHWIDTH 1
#define POWERBLOCKCOIN_MAXPRICES 2048 // must be power of 2 and less than 8192
#define POWERBLOCKCOIN_PRICEMASK (~(POWERBLOCKCOIN_MAXPRICES -  1))     // actually 1111 1000 0000 0000
#define PRICES_WEIGHT (POWERBLOCKCOIN_MAXPRICES * 1)            //          0000 1000 0000 0000
#define PRICES_MULT (POWERBLOCKCOIN_MAXPRICES * 2)              //          0001 0000 0000 0000
#define PRICES_DIV (POWERBLOCKCOIN_MAXPRICES * 3)               //          0001 1000 0000 0000
#define PRICES_INV (POWERBLOCKCOIN_MAXPRICES * 4)               //          0010 0000 0000 0000
#define PRICES_MDD (POWERBLOCKCOIN_MAXPRICES * 5)               //          0010 1000 0000 0000
#define PRICES_MMD (POWERBLOCKCOIN_MAXPRICES * 6)               //          0011 0000 0000 0000
#define PRICES_MMM (POWERBLOCKCOIN_MAXPRICES * 7)               //          0011 1000 0000 0000
#define PRICES_DDD (POWERBLOCKCOIN_MAXPRICES * 8)               //          0100 0000 0000 0000

extern struct priceinfo
{
    FILE *fp;
    char symbol[64];
} PRICES[POWERBLOCKCOIN_MAXPRICES];

//#define PRICES_NORMFACTOR   (int64_t)(SATOSHIDEN)
//#define PRICES_POINTFACTOR   (int64_t)10000

#define PRICES_REVSHAREDUST 10000
#define PRICES_SUBREVSHAREFEE(amount) ((amount) * 199 / 200)    // revshare fee percentage == 0.005
#define PRICES_MINAVAILFUNDFRACTION  0.1                             // leveraged bet limit < fund fraction

bool PricesValidate(struct CCcontract_info *cp,Eval* eval,const CTransaction &tx, uint32_t nIn);

// CCcustom
UniValue PricesBet(int64_t txfee,int64_t amount,int16_t leverage,std::vector<std::string> synthetic);
UniValue PricesAddFunding(int64_t txfee,uint256 bettxid,int64_t amount);
UniValue PricesSetcostbasis(int64_t txfee,uint256 bettxid);
UniValue PricesRekt(int64_t txfee,uint256 bettxid,int32_t rektheight);
UniValue PricesCashout(int64_t txfee,uint256 bettxid);
UniValue PricesInfo(uint256 bettxid,int32_t refheight);
UniValue PricesList(uint32_t filter, CPubKey mypk);
UniValue PricesGetOrderbook();
UniValue PricesRefillFund(int64_t amount);


#endif
