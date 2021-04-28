// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2020 The SmartUSD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <base58.h>
#include <chain.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <httpserver.h>
#include <validation.h>
#include <net.h>
#include <policy/feerate.h>
#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <rpc/mining.h>
#include <rpc/safemode.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <script/sign.h>
#include <timedata.h>
#include <util.h>
#include <utilmoneystr.h>
#include <wallet/coincontrol.h>
#include <wallet/feebumper.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
#include <notaries_staked.h>

#include <init.h>  // For StartShutdown

#include <stdint.h>

#include <univalue.h>

static const std::string WALLET_ENDPOINT_BASE = "/wallet/";
std::string CCerror;
extern std::string ASSETCHAINS_CCLIB;
extern std::map <std::int8_t, int32_t> mapHeightEvalActivate;
extern uint8_t ASSETCHAINS_CCDISABLES[256];
extern uint256 Parseuint256(const char *hexstr);

#define PLAN_NAME_MAX   8
#define VALID_PLAN_NAME(x)  (strlen(x) <= PLAN_NAME_MAX)

//local vars due to unsupported notarisation now
extern uint8_t NOTARY_PUBKEY33[33];

CWallet *GetWalletForJSONRPCRequest(const JSONRPCRequest& request)
{
    if (request.URI.substr(0, WALLET_ENDPOINT_BASE.size()) == WALLET_ENDPOINT_BASE) {
        // wallet endpoint was used
        std::string requestedWallet = urlDecode(request.URI.substr(WALLET_ENDPOINT_BASE.size()));
        for (CWalletRef pwallet : ::vpwallets) {
            if (pwallet->GetName() == requestedWallet) {
                return pwallet;
            }
        }
        throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Requested wallet does not exist or is not loaded");
    }
    return ::vpwallets.size() == 1 || (request.fHelp && ::vpwallets.size() > 0) ? ::vpwallets[0] : nullptr;
}

std::string HelpRequiringPassphrase(CWallet * const pwallet)
{
    return pwallet && pwallet->IsCrypted()
        ? "\nRequires wallet passphrase to be set with walletpassphrase call."
        : "";
}

bool EnsureWalletIsAvailable(CWallet * const pwallet, bool avoidException)
{
    if (pwallet) return true;
    if (avoidException) return false;
    if (::vpwallets.empty()) {
        // Note: It isn't currently possible to trigger this error because
        // wallet RPC methods aren't registered unless a wallet is loaded. But
        // this error is being kept as a precaution, because it's possible in
        // the future that wallet RPC methods might get or remain registered
        // when no wallets are loaded.
        throw JSONRPCError(
            RPC_METHOD_NOT_FOUND, "Method not found (wallet method is disabled because no wallet is loaded)");
    }
    throw JSONRPCError(RPC_WALLET_NOT_SPECIFIED,
        "Wallet file not specified (must request wallet RPC through /wallet/<filename> uri-path).");
}

void EnsureWalletIsUnlocked(CWallet * const pwallet)
{
    if (pwallet->IsLocked()) {
        throw JSONRPCError(RPC_WALLET_UNLOCK_NEEDED, "Error: Please enter the wallet passphrase with walletpassphrase first.");
    }
}

void WalletTxToJSON(const CWalletTx& wtx, UniValue& entry)
{
    int confirms = wtx.GetDepthInMainChain();
    entry.push_back(Pair("confirmations", confirms));
    if (wtx.IsCoinBase())
        entry.push_back(Pair("generated", true));
    if (confirms > 0)
    {
        entry.push_back(Pair("blockhash", wtx.hashBlock.GetHex()));
        entry.push_back(Pair("blockindex", wtx.nIndex));
        entry.push_back(Pair("blocktime", mapBlockIndex[wtx.hashBlock]->GetBlockTime()));
    } else {
        entry.push_back(Pair("trusted", wtx.IsTrusted()));
    }
    uint256 hash = wtx.GetHash();
    entry.push_back(Pair("txid", hash.GetHex()));
    UniValue conflicts(UniValue::VARR);
    for (const uint256& conflict : wtx.GetConflicts())
        conflicts.push_back(conflict.GetHex());
    entry.push_back(Pair("walletconflicts", conflicts));
    entry.push_back(Pair("time", wtx.GetTxTime()));
    entry.push_back(Pair("timereceived", (int64_t)wtx.nTimeReceived));

    // Add opt-in RBF status
    std::string rbfStatus = "no";
    if (confirms <= 0) {
        LOCK(mempool.cs);
        RBFTransactionState rbfState = IsRBFOptIn(*wtx.tx, mempool);
        if (rbfState == RBF_TRANSACTIONSTATE_UNKNOWN)
            rbfStatus = "unknown";
        else if (rbfState == RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125)
            rbfStatus = "yes";
    }
    entry.push_back(Pair("bip125-replaceable", rbfStatus));

    for (const std::pair<std::string, std::string>& item : wtx.mapValue)
        entry.push_back(Pair(item.first, item.second));
}

std::string AccountFromValue(const UniValue& value)
{
    std::string strAccount = value.get_str();
    if (strAccount == "*")
        throw JSONRPCError(RPC_WALLET_INVALID_ACCOUNT_NAME, "Invalid account name");
    return strAccount;
}

UniValue getnewaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "getnewaddress ( \"account\" \"address_type\" )\n"
            "\nReturns a new SmartUSD address for receiving payments.\n"
            "If 'account' is specified (DEPRECATED), it is added to the address book \n"
            "so payments received with the address will be credited to 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, optional) DEPRECATED. The account name for the address to be linked to. If not provided, the default account \"\" is used. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created if there is no account by the given name.\n"
            "2. \"address_type\"   (string, optional) The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -addresstype.\n"
            "\nResult:\n"
            "\"address\"    (string) The new smartusd address\n"
            "\nExamples:\n"
            + HelpExampleCli("getnewaddress", "")
            + HelpExampleRpc("getnewaddress", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount;
    if (!request.params[0].isNull())
        strAccount = AccountFromValue(request.params[0]);

    OutputType output_type = g_address_type;
    if (!request.params[1].isNull()) {
        output_type = ParseOutputType(request.params[1].get_str(), g_address_type);
        if (output_type == OUTPUT_TYPE_NONE) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[1].get_str()));
        }
    }

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwallet->GetKeyFromPool(newKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }
    pwallet->LearnRelatedScripts(newKey, output_type);
    CTxDestination dest = GetDestinationForKey(newKey, output_type);

    pwallet->SetAddressBook(dest, strAccount, "receive");

    return EncodeDestination(dest);
}


CTxDestination GetAccountDestination(CWallet* const pwallet, std::string strAccount, bool bForceNew=false)
{
    CTxDestination dest;
    if (!pwallet->GetAccountDestination(dest, strAccount, bForceNew)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    return dest;
}

UniValue getaccountaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaccountaddress \"account\"\n"
            "\nDEPRECATED. Returns the current SmartUSD address for receiving payments to this account.\n"
            "\nArguments:\n"
            "1. \"account\"       (string, required) The account name for the address. It can also be set to the empty string \"\" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.\n"
            "\nResult:\n"
            "\"address\"          (string) The account smartusd address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccountaddress", "")
            + HelpExampleCli("getaccountaddress", "\"\"")
            + HelpExampleCli("getaccountaddress", "\"myaccount\"")
            + HelpExampleRpc("getaccountaddress", "\"myaccount\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Parse the account first so we don't generate a key if there's an error
    std::string strAccount = AccountFromValue(request.params[0]);

    UniValue ret(UniValue::VSTR);

    ret = EncodeDestination(GetAccountDestination(pwallet, strAccount));
    return ret;
}


UniValue getrawchangeaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "getrawchangeaddress ( \"address_type\" )\n"
            "\nReturns a new SmartUSD address, for receiving change.\n"
            "This is for use with raw transactions, NOT normal use.\n"
            "\nArguments:\n"
            "1. \"address_type\"           (string, optional) The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -changetype.\n"
            "\nResult:\n"
            "\"address\"    (string) The address\n"
            "\nExamples:\n"
            + HelpExampleCli("getrawchangeaddress", "")
            + HelpExampleRpc("getrawchangeaddress", "")
       );

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->IsLocked()) {
        pwallet->TopUpKeyPool();
    }

    OutputType output_type = g_change_type != OUTPUT_TYPE_NONE ? g_change_type : g_address_type;
    if (!request.params[0].isNull()) {
        output_type = ParseOutputType(request.params[0].get_str(), output_type);
        if (output_type == OUTPUT_TYPE_NONE) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[0].get_str()));
        }
    }

    CReserveKey reservekey(pwallet);
    CPubKey vchPubKey;
    if (!reservekey.GetReservedKey(vchPubKey, true))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    reservekey.KeepKey();

    pwallet->LearnRelatedScripts(vchPubKey, output_type);
    CTxDestination dest = GetDestinationForKey(vchPubKey, output_type);

    return EncodeDestination(dest);
}


UniValue setaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "setaccount \"address\" \"account\"\n"
            "\nDEPRECATED. Sets the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The smartusd address to be associated with an account.\n"
            "2. \"account\"         (string, required) The account to assign the address to.\n"
            "\nExamples:\n"
            + HelpExampleCli("setaccount", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\" \"tabby\"")
            + HelpExampleRpc("setaccount", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\", \"tabby\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SmartUSD address");
    }

    std::string strAccount;
    if (!request.params[1].isNull())
        strAccount = AccountFromValue(request.params[1]);

    // Only add the account if the address is yours.
    if (IsMine(*pwallet, dest)) {
        // Detect when changing the account of an address that is the 'unused current key' of another account:
        if (pwallet->mapAddressBook.count(dest)) {
            std::string strOldAccount = pwallet->mapAddressBook[dest].name;
            if (dest == GetAccountDestination(pwallet, strOldAccount)) {
                GetAccountDestination(pwallet, strOldAccount, true);
            }
        }
        pwallet->SetAddressBook(dest, strAccount, "receive");
    }
    else
        throw JSONRPCError(RPC_MISC_ERROR, "setaccount can only be used with own address");

    return NullUniValue;
}


UniValue getaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaccount \"address\"\n"
            "\nDEPRECATED. Returns the account associated with the given address.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The smartusd address for account lookup.\n"
            "\nResult:\n"
            "\"accountname\"        (string) the account address\n"
            "\nExamples:\n"
            + HelpExampleCli("getaccount", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\"")
            + HelpExampleRpc("getaccount", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SmartUSD address");
    }

    std::string strAccount;
    std::map<CTxDestination, CAddressBookData>::iterator mi = pwallet->mapAddressBook.find(dest);
    if (mi != pwallet->mapAddressBook.end() && !(*mi).second.name.empty()) {
        strAccount = (*mi).second.name;
    }
    return strAccount;
}


UniValue getaddressesbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getaddressesbyaccount \"account\"\n"
            "\nDEPRECATED. Returns the list of addresses for the given account.\n"
            "\nArguments:\n"
            "1. \"account\"        (string, required) The account name.\n"
            "\nResult:\n"
            "[                     (json array of string)\n"
            "  \"address\"         (string) a smartusd address associated with the given account\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressesbyaccount", "\"tabby\"")
            + HelpExampleRpc("getaddressesbyaccount", "\"tabby\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);

    // Find all addresses that have the given account
    UniValue ret(UniValue::VARR);
    for (const std::pair<CTxDestination, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CTxDestination& dest = item.first;
        const std::string& strName = item.second.name;
        if (strName == strAccount) {
            ret.push_back(EncodeDestination(dest));
        }
    }
    return ret;
}

static void SendMoney(CWallet * const pwallet, const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew, const CCoinControl& coin_control)
{
    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    return SendMoneyToScript(pwallet, scriptPubKey, nValue, fSubtractFeeFromAmount, wtxNew, coin_control);
}

void SendMoneyToScript(CWallet* const pwallet, const CScript &scriptPubKey,
                       CAmount nValue,
                       bool fSubtractFeeFromAmount, CWalletTx& wtxNew,
                       const CCoinControl& coin_control)
{
    CAmount curBalance = pwallet->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    /* If we have an additional input that is a name, we have to take this
       name's value into account as well for the balance check.  Otherwise one
       sees spurious "Insufficient funds" errors when updating names when the
       wallet's balance it smaller than the amount locked in the name.  */
    CAmount lockedValue = 0;
    std::string strError;

    if (nValue > curBalance + lockedValue)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError, coin_control)) {
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > curBalance)
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

UniValue sendtoaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 8)
        throw std::runtime_error(
            "sendtoaddress \"address\" amount ( \"comment\" \"comment_to\" subtractfeefromamount replaceable conf_target \"estimate_mode\")\n"
            "\nSend an amount to a given address.\n"
            + HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"address\"            (string, required) The smartusd address to send to.\n"
            "2. \"amount\"             (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"            (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment_to\"         (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less smartusds than you enter in the amount field.\n"
            "6. replaceable            (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
            "7. conf_target            (numeric, optional) Confirmation target (in blocks)\n"
            "8. \"estimate_mode\"      (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\"\n"
            "\nResult:\n"
            "\"txid\"                  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\", 0.1, \"donation\", \"seans outpost\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    /* Note that the code below is duplicated in sendtoname.  Make sure
       to update it accordingly with changes made here.  */

    // Amount
    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");

    // Wallet comments
    CWalletTx wtx;
    if (!request.params[2].isNull() && !request.params[2].get_str().empty())
        wtx.mapValue["comment"] = request.params[2].get_str();
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["to"]      = request.params[3].get_str();

    bool fSubtractFeeFromAmount = false;
    if (!request.params[4].isNull()) {
        fSubtractFeeFromAmount = request.params[4].get_bool();
    }

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.signalRbf = request.params[5].get_bool();
    }

    if (!request.params[6].isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[6]);
    }

    if (!request.params[7].isNull()) {
        if (!FeeModeFromString(request.params[7].get_str(), coin_control.m_fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
    }


    EnsureWalletIsUnlocked(pwallet);

    SendMoney(pwallet, dest, nAmount, fSubtractFeeFromAmount, wtx, coin_control);

    return wtx.GetHash().GetHex();
}

UniValue listaddressgroupings(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listaddressgroupings\n"
            "\nLists groups of addresses which have had their common ownership\n"
            "made public by common use as inputs or as the resulting change\n"
            "in past transactions\n"
            "\nResult:\n"
            "[\n"
            "  [\n"
            "    [\n"
            "      \"address\",            (string) The smartusd address\n"
            "      amount,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"account\"             (string, optional) DEPRECATED. The account\n"
            "    ]\n"
            "    ,...\n"
            "  ]\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listaddressgroupings", "")
            + HelpExampleRpc("listaddressgroupings", "")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue jsonGroupings(UniValue::VARR);
    std::map<CTxDestination, CAmount> balances = pwallet->GetAddressBalances();
    for (const std::set<CTxDestination>& grouping : pwallet->GetAddressGroupings()) {
        UniValue jsonGrouping(UniValue::VARR);
        for (const CTxDestination& address : grouping)
        {
            UniValue addressInfo(UniValue::VARR);
            addressInfo.push_back(EncodeDestination(address));
            addressInfo.push_back(ValueFromAmount(balances[address]));
            {
                if (pwallet->mapAddressBook.find(address) != pwallet->mapAddressBook.end()) {
                    addressInfo.push_back(pwallet->mapAddressBook.find(address)->second.name);
                }
            }
            jsonGrouping.push_back(addressInfo);
        }
        jsonGroupings.push_back(jsonGrouping);
    }
    return jsonGroupings;
}

UniValue signmessage(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "signmessage \"address\" \"message\"\n"
            "\nSign a message with the private key of an address"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The smartusd address to use for the private key.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessage", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\", \"my message\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string strAddress = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    }

    const CKeyID *keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    }

    CKey key;
    if (!pwallet->GetKey(*keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key not available");
    }

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(vchSig.data(), vchSig.size());
}

UniValue getreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaddress \"address\" ( minconf )\n"
            "\nReturns the total amount received by the given address in transactions with at least minconf confirmations.\n"
            "\nArguments:\n"
            "1. \"address\"         (string, required) The smartusd address for transactions.\n"
            "2. minconf             (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount   (numeric) The total amount in " + CURRENCY_UNIT + " received at this address.\n"
            "\nExamples:\n"
            "\nThe amount from transactions with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\"") +
            "\nThe amount including unconfirmed transactions, zero confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaddress", "\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\", 6")
       );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    // Bitcoin address
    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SmartUSD address");
    }
    CScript scriptPubKey = GetScriptForDestination(dest);
    if (!IsMine(*pwallet, scriptPubKey)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Address not found in wallet");
    }

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull())
        nMinDepth = request.params[1].get_int();

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        for (const CTxOut& txout : wtx.tx->vout)
            if (txout.scriptPubKey == scriptPubKey)
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
    }

    return  ValueFromAmount(nAmount);
}


UniValue getreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getreceivedbyaccount \"account\" ( minconf )\n"
            "\nDEPRECATED. Returns the total amount received by addresses with <account> in transactions with at least [minconf] confirmations.\n"
            "\nArguments:\n"
            "1. \"account\"      (string, required) The selected account, may be the default account using \"\".\n"
            "2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nAmount received by the default account with at least 1 confirmation\n"
            + HelpExampleCli("getreceivedbyaccount", "\"\"") +
            "\nAmount received at the tabby account including unconfirmed amounts with zero confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 0") +
            "\nThe amount with at least 6 confirmations\n"
            + HelpExampleCli("getreceivedbyaccount", "\"tabby\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getreceivedbyaccount", "\"tabby\", 6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    // Minimum confirmations
    int nMinDepth = 1;
    if (!request.params[1].isNull())
        nMinDepth = request.params[1].get_int();

    // Get the set of pub keys assigned to account
    std::string strAccount = AccountFromValue(request.params[0]);
    std::set<CTxDestination> setAddress = pwallet->GetAccountAddresses(strAccount);

    // Tally
    CAmount nAmount = 0;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        for (const CTxOut& txout : wtx.tx->vout)
        {
            CTxDestination address;
            if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*pwallet, address) && setAddress.count(address)) {
                if (wtx.GetDepthInMainChain() >= nMinDepth)
                    nAmount += txout.nValue;
            }
        }
    }

    return ValueFromAmount(nAmount);
}


UniValue getbalance(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "getbalance ( \"account\" minconf include_watchonly )\n"
            "\nIf account is not specified, returns the server's total available balance.\n"
            "The available balance is what the wallet considers currently spendable, and is\n"
            "thus affected by options which limit spendability such as -spendzeroconfchange.\n"
            "If account is specified (DEPRECATED), returns the balance in the account.\n"
            "Note that the account \"\" is not the same as leaving the parameter out.\n"
            "The server total may be different to the balance in the default \"\" account.\n"
            "\nArguments:\n"
            "1. \"account\"         (string, optional) DEPRECATED. The account string may be given as a\n"
            "                     specific account name to find the balance associated with wallet keys in\n"
            "                     a named account, or as the empty string (\"\") to find the balance\n"
            "                     associated with wallet keys not in any named account, or as \"*\" to find\n"
            "                     the balance associated with all wallet keys regardless of account.\n"
            "                     When this option is specified, it calculates the balance in a different\n"
            "                     way than when it is not specified, and which can count spends twice when\n"
            "                     there are conflicting pending transactions (such as those created by\n"
            "                     the bumpfee command), temporarily resulting in low or even negative\n"
            "                     balances. In general, account balance calculation is not considered\n"
            "                     reliable and has resulted in confusing outcomes, so it is recommended to\n"
            "                     avoid passing this argument.\n"
            "2. minconf           (numeric, optional, default=1) Only include transactions confirmed at least this many times.\n"
            "3. include_watchonly (bool, optional, default=false) Also include balance in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.\n"
            "\nExamples:\n"
            "\nThe total amount in the wallet with 1 or more confirmations\n"
            + HelpExampleCli("getbalance", "") +
            "\nThe total amount in the wallet at least 6 blocks confirmed\n"
            + HelpExampleCli("getbalance", "\"*\" 6") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("getbalance", "\"*\", 6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    const UniValue& account_value = request.params[0];
    const UniValue& minconf = request.params[1];
    const UniValue& include_watchonly = request.params[2];

    if (account_value.isNull()) {
        if (!minconf.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "getbalance minconf option is only currently supported if an account is specified");
        }
        if (!include_watchonly.isNull()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "getbalance include_watchonly option is only currently supported if an account is specified");
        }
        return ValueFromAmount(pwallet->GetBalance());
    }

    const std::string& account_param = account_value.get_str();
    const std::string* account = account_param != "*" ? &account_param : nullptr;

    int nMinDepth = 1;
    if (!minconf.isNull())
        nMinDepth = minconf.get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(!include_watchonly.isNull())
        if(include_watchonly.get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    return ValueFromAmount(pwallet->GetLegacyBalance(filter, nMinDepth, account));
}

UniValue getunconfirmedbalance(const JSONRPCRequest &request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
                "getunconfirmedbalance\n"
                "Returns the server's total unconfirmed balance\n");

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ValueFromAmount(pwallet->GetUnconfirmedBalance());
}


UniValue movecmd(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "move \"fromaccount\" \"toaccount\" amount ( minconf \"comment\" )\n"
            "\nDEPRECATED. Move a specified amount from one account in your wallet to another.\n"
            "\nArguments:\n"
            "1. \"fromaccount\"   (string, required) The name of the account to move funds from. May be the default account using \"\".\n"
            "2. \"toaccount\"     (string, required) The name of the account to move funds to. May be the default account using \"\".\n"
            "3. amount            (numeric) Quantity of " + CURRENCY_UNIT + " to move between accounts.\n"
            "4. (dummy)           (numeric, optional) Ignored. Remains for backward compatibility.\n"
            "5. \"comment\"       (string, optional) An optional comment, stored in the wallet only.\n"
            "\nResult:\n"
            "true|false           (boolean) true if successful.\n"
            "\nExamples:\n"
            "\nMove 0.01 " + CURRENCY_UNIT + " from the default account to the account named tabby\n"
            + HelpExampleCli("move", "\"\" \"tabby\" 0.01") +
            "\nMove 0.01 " + CURRENCY_UNIT + " timotei to akiko with a comment and funds have 6 confirmations\n"
            + HelpExampleCli("move", "\"timotei\" \"akiko\" 0.01 6 \"happy birthday!\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("move", "\"timotei\", \"akiko\", 0.01, 6, \"happy birthday!\"")
        );

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strFrom = AccountFromValue(request.params[0]);
    std::string strTo = AccountFromValue(request.params[1]);
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    if (!request.params[3].isNull())
        // unused parameter, used to be nMinDepth, keep type-checking it though
        (void)request.params[3].get_int();
    std::string strComment;
    if (!request.params[4].isNull())
        strComment = request.params[4].get_str();

    if (!pwallet->AccountMove(strFrom, strTo, nAmount, strComment)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "database error");
    }

    return true;
}


UniValue sendfrom(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 3 || request.params.size() > 6)
        throw std::runtime_error(
            "sendfrom \"fromaccount\" \"toaddress\" amount ( minconf \"comment\" \"comment_to\" )\n"
            "\nDEPRECATED (use sendtoaddress). Sent an amount from an account to a bitcoin address."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"       (string, required) The name of the account to send funds from. May be the default account using \"\".\n"
            "                       Specifying an account does not influence coin selection, but it does associate the newly created\n"
            "                       transaction with the account, so the account's balance computation and transaction history can reflect\n"
            "                       the spend.\n"
            "2. \"toaddress\"         (string, required) The smartusd address to send funds to.\n"
            "3. amount                (numeric or string, required) The amount in " + CURRENCY_UNIT + " (transaction fee is added on top).\n"
            "4. minconf               (numeric, optional, default=1) Only use funds with at least this many confirmations.\n"
            "5. \"comment\"           (string, optional) A comment used to store what the transaction is for. \n"
            "                                     This is not part of the transaction, just kept in your wallet.\n"
            "6. \"comment_to\"        (string, optional) An optional comment to store the name of the person or organization \n"
            "                                     to which you're sending the transaction. This is not part of the transaction, \n"
            "                                     it is just kept in your wallet.\n"
            "\nResult:\n"
            "\"txid\"                 (string) The transaction id.\n"
            "\nExamples:\n"
            "\nSend 0.01 " + CURRENCY_UNIT + " from the default account to the address, must have at least 1 confirmation\n"
            + HelpExampleCli("sendfrom", "\"\" \"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\" 0.01") +
            "\nSend 0.01 from the tabby account to the given address, funds must have at least 6 confirmations\n"
            + HelpExampleCli("sendfrom", "\"tabby\" \"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\" 0.01 6 \"donation\" \"seans outpost\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendfrom", "\"tabby\", \"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\", 0.01, 6, \"donation\", \"seans outpost\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount = AccountFromValue(request.params[0]);
    CTxDestination dest = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SmartUSD address");
    }
    CAmount nAmount = AmountFromValue(request.params[2]);
    if (nAmount <= 0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    int nMinDepth = 1;
    if (!request.params[3].isNull())
        nMinDepth = request.params[3].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (!request.params[4].isNull() && !request.params[4].get_str().empty())
        wtx.mapValue["comment"] = request.params[4].get_str();
    if (!request.params[5].isNull() && !request.params[5].get_str().empty())
        wtx.mapValue["to"]      = request.params[5].get_str();

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, &strAccount);
    if (nAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    CCoinControl no_coin_control; // This is a deprecated API
    SendMoney(pwallet, dest, nAmount, false, wtx, no_coin_control);

    return wtx.GetHash().GetHex();
}


UniValue sendmany(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 8)
        throw std::runtime_error(
            "sendmany \"fromaccount\" {\"address\":amount,...} ( minconf \"comment\" [\"address\",...] replaceable conf_target \"estimate_mode\")\n"
            "\nSend multiple times. Amounts are double-precision floating point numbers."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"fromaccount\"         (string, required) DEPRECATED. The account to send the funds from. Should be \"\" for the default account\n"
            "2. \"amounts\"             (string, required) A json object with addresses and amounts\n"
            "    {\n"
            "      \"address\":amount   (numeric or string) The smartusd address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "      ,...\n"
            "    }\n"
            "3. minconf                 (numeric, optional, default=1) Only use the balance confirmed at least this many times.\n"
            "4. \"comment\"             (string, optional) A comment\n"
            "5. subtractfeefrom         (array, optional) A json array with addresses.\n"
            "                           The fee will be equally deducted from the amount of each selected address.\n"
            "                           Those recipients will receive less smartusds than you enter in their corresponding amount field.\n"
            "                           If no addresses are specified here, the sender pays the fee.\n"
            "    [\n"
            "      \"address\"          (string) Subtract fee from this address\n"
            "      ,...\n"
            "    ]\n"
            "6. replaceable            (boolean, optional) Allow this transaction to be replaced by a transaction with higher fees via BIP 125\n"
            "7. conf_target            (numeric, optional) Confirmation target (in blocks)\n"
            "8. \"estimate_mode\"      (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "       \"UNSET\"\n"
            "       \"ECONOMICAL\"\n"
            "       \"CONSERVATIVE\"\n"
             "\nResult:\n"
            "\"txid\"                   (string) The transaction id for the send. Only 1 transaction is created regardless of \n"
            "                                    the number of addresses.\n"
            "\nExamples:\n"
            "\nSend two amounts to two different addresses:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\\\":0.01,\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdVXX\\\":0.02}\"") +
            "\nSend two amounts to two different addresses setting the confirmation and comment:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\\\":0.01,\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdVXX\\\":0.02}\" 6 \"testing\"") +
            "\nSend two amounts to two different addresses, subtract fee from amount:\n"
            + HelpExampleCli("sendmany", "\"\" \"{\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\\\":0.01,\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdVXX\\\":0.02}\" 1 \"\" \"[\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\\\",\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdVXX\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendmany", "\"\", {\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\":0.01,\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdVXX\":0.02}, 6, \"testing\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->GetBroadcastTransactions() && !g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    }

    std::string strAccount = AccountFromValue(request.params[0]);
    UniValue sendTo = request.params[1].get_obj();
    int nMinDepth = 1;
    if (!request.params[2].isNull())
        nMinDepth = request.params[2].get_int();

    CWalletTx wtx;
    wtx.strFromAccount = strAccount;
    if (!request.params[3].isNull() && !request.params[3].get_str().empty())
        wtx.mapValue["comment"] = request.params[3].get_str();

    UniValue subtractFeeFromAmount(UniValue::VARR);
    if (!request.params[4].isNull())
        subtractFeeFromAmount = request.params[4].get_array();

    CCoinControl coin_control;
    if (!request.params[5].isNull()) {
        coin_control.signalRbf = request.params[5].get_bool();
    }

    if (!request.params[6].isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[6]);
    }

    if (!request.params[7].isNull()) {
        if (!FeeModeFromString(request.params[7].get_str(), coin_control.m_fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
    }

    std::set<CTxDestination> destinations;
    std::vector<CRecipient> vecSend;

    CAmount totalAmount = 0;
    std::vector<std::string> keys = sendTo.getKeys();
    for (const std::string& name_ : keys) {
        CTxDestination dest = DecodeDestination(name_);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid SmartUSD address: ") + name_);
        }

        if (destinations.count(dest)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
        }
        destinations.insert(dest);

        CScript scriptPubKey = GetScriptForDestination(dest);
        CAmount nAmount = AmountFromValue(sendTo[name_]);
        if (nAmount <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        totalAmount += nAmount;

        bool fSubtractFeeFromAmount = false;
        for (unsigned int idx = 0; idx < subtractFeeFromAmount.size(); idx++) {
            const UniValue& addr = subtractFeeFromAmount[idx];
            if (addr.get_str() == name_)
                fSubtractFeeFromAmount = true;
        }

        CRecipient recipient = {scriptPubKey, nAmount, fSubtractFeeFromAmount};
        vecSend.push_back(recipient);
    }

    EnsureWalletIsUnlocked(pwallet);

    // Check funds
    CAmount nBalance = pwallet->GetLegacyBalance(ISMINE_SPENDABLE, nMinDepth, &strAccount);
    if (totalAmount > nBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Account has insufficient funds");

    // Send
    CReserveKey keyChange(pwallet);
    CAmount nFeeRequired = 0;
    int nChangePosRet = -1;
    std::string strFailReason;
    bool fCreated = pwallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, nChangePosRet, strFailReason, coin_control);
    if (!fCreated)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, strFailReason);
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, keyChange, g_connman.get(), state)) {
        strFailReason = strprintf("Transaction commit failed:: %s", state.GetRejectReason());
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    return wtx.GetHash().GetHex();
}

UniValue addmultisigaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4) {
        std::string msg = "addmultisigaddress nrequired [\"key\",...] ( \"account\" \"address_type\" )\n"
            "\nAdd a nrequired-to-sign multisignature address to the wallet. Requires a new wallet backup.\n"
            "Each key is a SmartUSD address or hex-encoded public key.\n"
            "This functionality is only intended for use with non-watchonly addresses.\n"
            "See `importaddress` for watchonly p2sh address support.\n"
            "If 'account' is specified (DEPRECATED), assign address to that account.\n"

            "\nArguments:\n"
            "1. nrequired                      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"                         (string, required) A json array of smartusd addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"address\"                  (string) smartusd address or hex-encoded public key\n"
            "       ...,\n"
            "     ]\n"
            "3. \"account\"                      (string, optional) DEPRECATED. An account to assign the addresses to.\n"
            "4. \"address_type\"                 (string, optional) The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -addresstype.\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",    (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"         (string) The string value of the hex-encoded redemption script.\n"
            "}\n"
            "\nExamples:\n"
            "\nAdd a multisig address from 2 addresses\n"
            + HelpExampleCli("addmultisigaddress", "2 \"[\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\\\",\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdVXX\\\"]\"") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("addmultisigaddress", "2, \"[\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZXX\\\",\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdVXX\\\"]\"")
        ;
        throw std::runtime_error(msg);
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strAccount;
    if (!request.params[2].isNull())
        strAccount = AccountFromValue(request.params[2]);

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys_or_addrs = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys_or_addrs.size(); ++i) {
        if (IsHex(keys_or_addrs[i].get_str()) && (keys_or_addrs[i].get_str().length() == 66 || keys_or_addrs[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys_or_addrs[i].get_str()));
        } else {
            pubkeys.push_back(AddrToPubKey(pwallet, keys_or_addrs[i].get_str()));
        }
    }

    OutputType output_type = g_address_type;
    if (!request.params[3].isNull()) {
        output_type = ParseOutputType(request.params[3].get_str(), output_type);
        if (output_type == OUTPUT_TYPE_NONE) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[3].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    CScript inner = CreateMultisigRedeemscript(required, pubkeys);
    pwallet->AddCScript(inner);
    CTxDestination dest = pwallet->AddAndGetDestinationForScript(inner, output_type);
    pwallet->SetAddressBook(dest, strAccount, "send");

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));
    return result;
}

class Witnessifier : public boost::static_visitor<bool>
{
public:
    CWallet * const pwallet;
    CTxDestination result;
    bool already_witness;

    explicit Witnessifier(CWallet *_pwallet) : pwallet(_pwallet), already_witness(false) {}

    bool operator()(const CKeyID &keyID) {
        if (pwallet) {
            CScript basescript = GetScriptForDestination(keyID);
            CScript witscript = GetScriptForWitness(basescript);
            if (!IsSolvable(*pwallet, witscript)) {
                return false;
            }
            return ExtractDestination(witscript, result);
        }
        return false;
    }

    bool operator()(const CScriptID &scriptID) {
        CScript subscript;
        if (pwallet && pwallet->GetCScript(scriptID, subscript)) {
            int witnessversion;
            std::vector<unsigned char> witprog;
            if (subscript.IsWitnessProgram(witnessversion, witprog)) {
                ExtractDestination(subscript, result);
                already_witness = true;
                return true;
            }
            CScript witscript = GetScriptForWitness(subscript);
            if (!IsSolvable(*pwallet, witscript)) {
                return false;
            }
            return ExtractDestination(witscript, result);
        }
        return false;
    }

    bool operator()(const WitnessV0KeyHash& id)
    {
        already_witness = true;
        result = id;
        return true;
    }

    bool operator()(const WitnessV0ScriptHash& id)
    {
        already_witness = true;
        result = id;
        return true;
    }

    template<typename T>
    bool operator()(const T& dest) { return false; }
};

UniValue addwitnessaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
    {
        std::string msg = "addwitnessaddress \"address\" ( p2sh )\n"
            "\nDEPRECATED: set the address_type argument of getnewaddress, or option -addresstype=[bech32|p2sh-segwit] instead.\n"
            "Add a witness address for a script (with pubkey or redeemscript known). Requires a new wallet backup.\n"
            "It returns the witness script.\n"

            "\nArguments:\n"
            "1. \"address\"       (string, required) An address known to the wallet\n"
            "2. p2sh            (bool, optional, default=true) Embed inside P2SH\n"

            "\nResult:\n"
            "\"witnessaddress\",  (string) The value of the new address (P2SH or BIP173).\n"
            "}\n"
        ;
        throw std::runtime_error(msg);
    }

    if (!IsDeprecatedRPCEnabled("addwitnessaddress")) {
        throw JSONRPCError(RPC_METHOD_DEPRECATED, "addwitnessaddress is deprecated and will be fully removed in v0.17. "
            "To use addwitnessaddress in v0.16, restart bitcoind with -deprecatedrpc=addwitnessaddress.\n"
            "Projects should transition to using the address_type argument of getnewaddress, or option -addresstype=[bech32|p2sh-segwit] instead.\n");
    }

    {
        LOCK(cs_main);
        if (!IsWitnessEnabled(chainActive.Tip(), Params().GetConsensus()) && !gArgs.GetBoolArg("-walletprematurewitness", false)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Segregated witness not enabled on network");
        }
    }

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }

    bool p2sh = true;
    if (!request.params[1].isNull()) {
        p2sh = request.params[1].get_bool();
    }

    Witnessifier w(pwallet);
    bool ret = boost::apply_visitor(w, dest);
    if (!ret) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Public key or redeemscript not known to wallet, or the key is uncompressed");
    }

    CScript witprogram = GetScriptForDestination(w.result);

    if (p2sh) {
        w.result = CScriptID(witprogram);
    }

    if (w.already_witness) {
        if (!(dest == w.result)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Cannot convert between witness address types");
        }
    } else {
        pwallet->AddCScript(witprogram); // Implicit for single-key now, but necessary for multisig and for compatibility with older software
        pwallet->SetAddressBook(w.result, "", "receive");
    }

    return EncodeDestination(w.result);
}

struct tallyitem
{
    CAmount nAmount;
    int nConf;
    std::vector<uint256> txids;
    bool fIsWatchonly;
    tallyitem()
    {
        nAmount = 0;
        nConf = std::numeric_limits<int>::max();
        fIsWatchonly = false;
    }
};

UniValue ListReceived(CWallet * const pwallet, const UniValue& params, bool fByAccounts)
{
    // Minimum confirmations
    int nMinDepth = 1;
    if (!params[0].isNull())
        nMinDepth = params[0].get_int();

    // Whether to include empty accounts
    bool fIncludeEmpty = false;
    if (!params[1].isNull())
        fIncludeEmpty = params[1].get_bool();

    isminefilter filter = ISMINE_SPENDABLE;
    if(!params[2].isNull())
        if(params[2].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    // Tally
    std::map<CTxDestination, tallyitem> mapTally;
    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;

        if (wtx.IsCoinBase() || !CheckFinalTx(*wtx.tx))
            continue;

        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < nMinDepth)
            continue;

        for (const CTxOut& txout : wtx.tx->vout)
        {
            CTxDestination address;
            if (!ExtractDestination(txout.scriptPubKey, address))
                continue;

            isminefilter mine = IsMine(*pwallet, address);
            if(!(mine & filter))
                continue;

            tallyitem& item = mapTally[address];
            item.nAmount += txout.nValue;
            item.nConf = std::min(item.nConf, nDepth);
            item.txids.push_back(wtx.GetHash());
            if (mine & ISMINE_WATCH_ONLY)
                item.fIsWatchonly = true;
        }
    }

    // Reply
    UniValue ret(UniValue::VARR);
    std::map<std::string, tallyitem> mapAccountTally;
    for (const std::pair<CTxDestination, CAddressBookData>& item : pwallet->mapAddressBook) {
        const CTxDestination& dest = item.first;
        const std::string& strAccount = item.second.name;
        std::map<CTxDestination, tallyitem>::iterator it = mapTally.find(dest);
        if (it == mapTally.end() && !fIncludeEmpty)
            continue;

        CAmount nAmount = 0;
        int nConf = std::numeric_limits<int>::max();
        bool fIsWatchonly = false;
        if (it != mapTally.end())
        {
            nAmount = (*it).second.nAmount;
            nConf = (*it).second.nConf;
            fIsWatchonly = (*it).second.fIsWatchonly;
        }

        if (fByAccounts)
        {
            tallyitem& _item = mapAccountTally[strAccount];
            _item.nAmount += nAmount;
            _item.nConf = std::min(_item.nConf, nConf);
            _item.fIsWatchonly = fIsWatchonly;
        }
        else
        {
            UniValue obj(UniValue::VOBJ);
            if(fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("address",       EncodeDestination(dest)));
            obj.push_back(Pair("account",       strAccount));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            if (!fByAccounts)
                obj.push_back(Pair("label", strAccount));
            UniValue transactions(UniValue::VARR);
            if (it != mapTally.end())
            {
                for (const uint256& _item : (*it).second.txids)
                {
                    transactions.push_back(_item.GetHex());
                }
            }
            obj.push_back(Pair("txids", transactions));
            ret.push_back(obj);
        }
    }

    if (fByAccounts)
    {
        for (const auto& entry : mapAccountTally)
        {
            CAmount nAmount = entry.second.nAmount;
            int nConf = entry.second.nConf;
            UniValue obj(UniValue::VOBJ);
            if (entry.second.fIsWatchonly)
                obj.push_back(Pair("involvesWatchonly", true));
            obj.push_back(Pair("account",       entry.first));
            obj.push_back(Pair("amount",        ValueFromAmount(nAmount)));
            obj.push_back(Pair("confirmations", (nConf == std::numeric_limits<int>::max() ? 0 : nConf)));
            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue listreceivedbyaddress(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaddress ( minconf include_empty include_watchonly)\n"
            "\nList balances by receiving address.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include addresses that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,        (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"address\" : \"receivingaddress\",  (string) The receiving address\n"
            "    \"account\" : \"accountname\",       (string) DEPRECATED. The account of the receiving address. The default account is \"\".\n"
            "    \"amount\" : x.xxx,                  (numeric) The total amount in " + CURRENCY_UNIT + " received by the address\n"
            "    \"confirmations\" : n,               (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\",               (string) A comment for the address/transaction, if any\n"
            "    \"txids\": [\n"
            "       \"txid\",                         (string) The ids of transactions received with the address \n"
            "       ...\n"
            "    ]\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaddress", "")
            + HelpExampleCli("listreceivedbyaddress", "6 true")
            + HelpExampleRpc("listreceivedbyaddress", "6, true, true")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, false);
}

UniValue listreceivedbyaccount(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 3)
        throw std::runtime_error(
            "listreceivedbyaccount ( minconf include_empty include_watchonly)\n"
            "\nDEPRECATED. List balances by account.\n"
            "\nArguments:\n"
            "1. minconf           (numeric, optional, default=1) The minimum number of confirmations before payments are included.\n"
            "2. include_empty     (bool, optional, default=false) Whether to include accounts that haven't received any payments.\n"
            "3. include_watchonly (bool, optional, default=false) Whether to include watch-only addresses (see 'importaddress').\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"involvesWatchonly\" : true,   (bool) Only returned if imported addresses were involved in transaction\n"
            "    \"account\" : \"accountname\",  (string) The account name of the receiving account\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount received by addresses with this account\n"
            "    \"confirmations\" : n,          (numeric) The number of confirmations of the most recent transaction included\n"
            "    \"label\" : \"label\"           (string) A comment for the address/transaction, if any\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples:\n"
            + HelpExampleCli("listreceivedbyaccount", "")
            + HelpExampleCli("listreceivedbyaccount", "6 true")
            + HelpExampleRpc("listreceivedbyaccount", "6, true, true")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    return ListReceived(pwallet, request.params, true);
}

static void MaybePushAddress(UniValue & entry, const CTxDestination &dest)
{
    if (IsValidDestination(dest)) {
        entry.push_back(Pair("address", EncodeDestination(dest)));
    }
}

/**
 * List transactions based on the given criteria.
 *
 * @param  pwallet    The wallet.
 * @param  wtx        The wallet transaction.
 * @param  strAccount The account, if any, or "*" for all.
 * @param  nMinDepth  The minimum confirmation depth.
 * @param  fLong      Whether to include the JSON version of the transaction.
 * @param  ret        The UniValue into which the result is stored.
 * @param  filter     The "is mine" filter bool.
 */
void ListTransactions(CWallet* const pwallet, const CWalletTx& wtx, const std::string& strAccount, int nMinDepth, bool fLong, UniValue& ret, const isminefilter& filter)
{
    CAmount nFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;

    wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);

    bool fAllAccounts = (strAccount == std::string("*"));
    bool involvesWatchonly = wtx.IsFromMe(ISMINE_WATCH_ONLY);

    // Sent
    if ((!listSent.empty() || nFee != 0) && (fAllAccounts || strAccount == strSentAccount))
    {
        for (const COutputEntry& s : listSent)
        {
            UniValue entry(UniValue::VOBJ);
            if (involvesWatchonly || (::IsMine(*pwallet, s.destination) & ISMINE_WATCH_ONLY)) {
                entry.push_back(Pair("involvesWatchonly", true));
            }
            entry.push_back(Pair("account", strSentAccount));
            MaybePushAddress(entry, s.destination);
            if(!s.nameOp.empty())
                entry.push_back(Pair("name", s.nameOp));
            entry.push_back(Pair("category", "send"));
            entry.push_back(Pair("amount", ValueFromAmount(-s.amount)));
            if (pwallet->mapAddressBook.count(s.destination)) {
                entry.push_back(Pair("label", pwallet->mapAddressBook[s.destination].name));
            }
            entry.push_back(Pair("vout", s.vout));
            entry.push_back(Pair("fee", ValueFromAmount(-nFee)));
            if (fLong)
                WalletTxToJSON(wtx, entry);
            entry.push_back(Pair("abandoned", wtx.isAbandoned()));
            ret.push_back(entry);
        }
    }

    // Received
    if (listReceived.size() > 0 && wtx.GetDepthInMainChain() >= nMinDepth)
    {
        for (const COutputEntry& r : listReceived)
        {
            std::string account;
            if (pwallet->mapAddressBook.count(r.destination)) {
                account = pwallet->mapAddressBook[r.destination].name;
            }
            if (fAllAccounts || (account == strAccount))
            {
                UniValue entry(UniValue::VOBJ);
                if (involvesWatchonly || (::IsMine(*pwallet, r.destination) & ISMINE_WATCH_ONLY)) {
                    entry.push_back(Pair("involvesWatchonly", true));
                }
                entry.push_back(Pair("account", account));
                MaybePushAddress(entry, r.destination);
                if(!r.nameOp.empty())
                    entry.push_back(Pair("name", r.nameOp));
                if (wtx.IsCoinBase())
                {
                    if (wtx.GetDepthInMainChain() < 1)
                        entry.push_back(Pair("category", "orphan"));
                    else if (wtx.GetBlocksToMaturity() > 0)
                        entry.push_back(Pair("category", "immature"));
                    else
                        entry.push_back(Pair("category", "generate"));
                }
                else
                {
                    entry.push_back(Pair("category", "receive"));
                }
                entry.push_back(Pair("amount", ValueFromAmount(r.amount)));
                if (pwallet->mapAddressBook.count(r.destination)) {
                    entry.push_back(Pair("label", account));
                }
                entry.push_back(Pair("vout", r.vout));
                if (fLong)
                    WalletTxToJSON(wtx, entry);
                ret.push_back(entry);
            }
        }
    }
}

void AcentryToJSON(const CAccountingEntry& acentry, const std::string& strAccount, UniValue& ret)
{
    bool fAllAccounts = (strAccount == std::string("*"));

    if (fAllAccounts || acentry.strAccount == strAccount)
    {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("account", acentry.strAccount));
        entry.push_back(Pair("category", "move"));
        entry.push_back(Pair("time", acentry.nTime));
        entry.push_back(Pair("amount", ValueFromAmount(acentry.nCreditDebit)));
        entry.push_back(Pair("otheraccount", acentry.strOtherAccount));
        entry.push_back(Pair("comment", acentry.strComment));
        ret.push_back(entry);
    }
}

UniValue listtransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
            "listtransactions ( \"account\" count skip include_watchonly)\n"
            "\nReturns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.\n"
            "\nArguments:\n"
            "1. \"account\"    (string, optional) DEPRECATED. The account name. Should be \"*\".\n"
            "2. count          (numeric, optional, default=10) The number of transactions to return\n"
            "3. skip           (numeric, optional, default=0) The number of transactions to skip\n"
            "4. include_watchonly (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. \n"
            "                                                It will be \"\" for the default account.\n"
            "    \"address\":\"address\",    (string) The smartusd address of the transaction. Not present for \n"
            "                                                move transactions (category = move).\n"
            "    \"category\":\"send|receive|move\", (string) The transaction category. 'move' is a local (off blockchain)\n"
            "                                                transaction between accounts, and not associated with an address,\n"
            "                                                transaction id or block. 'send' and 'receive' transactions are \n"
            "                                                associated with an address, transaction id and block details\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the\n"
            "                                         'move' category for moves outbound. It is positive for the 'receive' category,\n"
            "                                         and for the 'move' category for inbound funds.\n"
            "    \"label\": \"label\",       (string) A comment for the address/transaction, if any\n"
            "    \"vout\": n,                (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                         'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and \n"
            "                                         'receive' category of transactions. Negative confirmations indicate the\n"
            "                                         transaction conflicts with the block chain\n"
            "    \"trusted\": xxx,           (bool) Whether we consider the outputs of this unconfirmed transaction safe to spend.\n"
            "    \"blockhash\": \"hashvalue\", (string) The block hash containing the transaction. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive'\n"
            "                                          category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\", (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (midnight Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (midnight Jan 1 1970 GMT). Available \n"
            "                                          for 'send' and 'receive' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"otheraccount\": \"accountname\",  (string) DEPRECATED. For the 'move' category of transactions, the account the funds came \n"
            "                                          from (for receiving funds, positive amounts), or went to (for sending funds,\n"
            "                                          negative amounts).\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                     may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx          (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
            "                                         'send' category of transactions.\n"
            "  }\n"
            "]\n"

            "\nExamples:\n"
            "\nList the most recent 10 transactions in the systems\n"
            + HelpExampleCli("listtransactions", "") +
            "\nList transactions 100 to 120\n"
            + HelpExampleCli("listtransactions", "\"*\" 20 100") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listtransactions", "\"*\", 20, 100")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::string strAccount = "*";
    if (!request.params[0].isNull())
        strAccount = request.params[0].get_str();
    int nCount = 10;
    if (!request.params[1].isNull())
        nCount = request.params[1].get_int();
    int nFrom = 0;
    if (!request.params[2].isNull())
        nFrom = request.params[2].get_int();
    isminefilter filter = ISMINE_SPENDABLE;
    if(!request.params[3].isNull())
        if(request.params[3].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    if (nCount < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative count");
    if (nFrom < 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Negative from");

    UniValue ret(UniValue::VARR);

    {
        LOCK2(cs_main, pwallet->cs_wallet);

        const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

        // iterate backwards until we have nCount items to return:
        for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
        {
            CWalletTx *const pwtx = (*it).second.first;
            if (pwtx != nullptr)
                ListTransactions(pwallet, *pwtx, strAccount, 0, true, ret, filter);
            CAccountingEntry *const pacentry = (*it).second.second;
            if (pacentry != nullptr)
                AcentryToJSON(*pacentry, strAccount, ret);

            if ((int)ret.size() >= (nCount+nFrom)) break;
        }
    }

    // ret is newest to oldest

    if (nFrom > (int)ret.size())
        nFrom = ret.size();
    if ((nFrom + nCount) > (int)ret.size())
        nCount = ret.size() - nFrom;

    std::vector<UniValue> arrTmp = ret.getValues();

    std::vector<UniValue>::iterator first = arrTmp.begin();
    std::advance(first, nFrom);
    std::vector<UniValue>::iterator last = arrTmp.begin();
    std::advance(last, nFrom+nCount);

    if (last != arrTmp.end()) arrTmp.erase(last, arrTmp.end());
    if (first != arrTmp.begin()) arrTmp.erase(arrTmp.begin(), first);

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue listaccounts(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
            "listaccounts ( minconf include_watchonly)\n"
            "\nDEPRECATED. Returns Object that has account names as keys, account balances as values.\n"
            "\nArguments:\n"
            "1. minconf             (numeric, optional, default=1) Only include transactions with at least this many confirmations\n"
            "2. include_watchonly   (bool, optional, default=false) Include balances in watch-only addresses (see 'importaddress')\n"
            "\nResult:\n"
            "{                      (json object where keys are account names, and values are numeric balances\n"
            "  \"account\": x.xxx,  (numeric) The property name is the account name, and the value is the total balance for the account.\n"
            "  ...\n"
            "}\n"
            "\nExamples:\n"
            "\nList account balances where there at least 1 confirmation\n"
            + HelpExampleCli("listaccounts", "") +
            "\nList account balances including zero confirmation transactions\n"
            + HelpExampleCli("listaccounts", "0") +
            "\nList account balances for 6 or more confirmations\n"
            + HelpExampleCli("listaccounts", "6") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("listaccounts", "6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    int nMinDepth = 1;
    if (!request.params[0].isNull())
        nMinDepth = request.params[0].get_int();
    isminefilter includeWatchonly = ISMINE_SPENDABLE;
    if(!request.params[1].isNull())
        if(request.params[1].get_bool())
            includeWatchonly = includeWatchonly | ISMINE_WATCH_ONLY;

    std::map<std::string, CAmount> mapAccountBalances;
    for (const std::pair<CTxDestination, CAddressBookData>& entry : pwallet->mapAddressBook) {
        if (IsMine(*pwallet, entry.first) & includeWatchonly) {  // This address belongs to me
            mapAccountBalances[entry.second.name] = 0;
        }
    }

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        const CWalletTx& wtx = pairWtx.second;
        CAmount nFee;
        std::string strSentAccount;
        std::list<COutputEntry> listReceived;
        std::list<COutputEntry> listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (wtx.GetBlocksToMaturity() > 0 || nDepth < 0)
            continue;
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount, includeWatchonly);
        mapAccountBalances[strSentAccount] -= nFee;
        for (const COutputEntry& s : listSent)
            mapAccountBalances[strSentAccount] -= s.amount;
        if (nDepth >= nMinDepth)
        {
            for (const COutputEntry& r : listReceived)
                if (pwallet->mapAddressBook.count(r.destination)) {
                    mapAccountBalances[pwallet->mapAddressBook[r.destination].name] += r.amount;
                }
                else
                    mapAccountBalances[""] += r.amount;
        }
    }

    const std::list<CAccountingEntry>& acentries = pwallet->laccentries;
    for (const CAccountingEntry& entry : acentries)
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;

    UniValue ret(UniValue::VOBJ);
    for (const std::pair<std::string, CAmount>& accountBalance : mapAccountBalances) {
        ret.push_back(Pair(accountBalance.first, ValueFromAmount(accountBalance.second)));
    }
    return ret;
}

UniValue listsinceblock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 4)
        throw std::runtime_error(
            "listsinceblock ( \"blockhash\" target_confirmations include_watchonly include_removed )\n"
            "\nGet all transactions in blocks since block [blockhash], or all transactions if omitted.\n"
            "If \"blockhash\" is no longer a part of the main chain, transactions from the fork point onward are included.\n"
            "Additionally, if include_removed is set, transactions affecting the wallet which were removed are returned in the \"removed\" array.\n"
            "\nArguments:\n"
            "1. \"blockhash\"            (string, optional) The block hash to list transactions since\n"
            "2. target_confirmations:    (numeric, optional, default=1) Return the nth block hash from the main chain. e.g. 1 would mean the best block hash. Note: this is not used as a filter, but only affects [lastblock] in the return value\n"
            "3. include_watchonly:       (bool, optional, default=false) Include transactions to watch-only addresses (see 'importaddress')\n"
            "4. include_removed:         (bool, optional, default=true) Show transactions that were removed due to a reorg in the \"removed\" array\n"
            "                                                           (not guaranteed to work on pruned nodes)\n"
            "\nResult:\n"
            "{\n"
            "  \"transactions\": [\n"
            "    \"account\":\"accountname\",       (string) DEPRECATED. The account name associated with the transaction. Will be \"\" for the default account.\n"
            "    \"address\":\"address\",    (string) The smartusd address of the transaction. Not present for move transactions (category = move).\n"
            "    \"category\":\"send|receive\",     (string) The transaction category. 'send' has negative amounts, 'receive' has positive amounts.\n"
            "    \"amount\": x.xxx,          (numeric) The amount in " + CURRENCY_UNIT + ". This is negative for the 'send' category, and for the 'move' category for moves \n"
            "                                          outbound. It is positive for the 'receive' category, and for the 'move' category for inbound funds.\n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"fee\": x.xxx,             (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the 'send' category of transactions.\n"
            "    \"confirmations\": n,       (numeric) The number of confirmations for the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "                                          When it's < 0, it means the transaction conflicted that many blocks ago.\n"
            "    \"blockhash\": \"hashvalue\",     (string) The block hash containing the transaction. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blockindex\": n,          (numeric) The index of the transaction in the block that includes it. Available for 'send' and 'receive' category of transactions.\n"
            "    \"blocktime\": xxx,         (numeric) The block time in seconds since epoch (1 Jan 1970 GMT).\n"
            "    \"txid\": \"transactionid\",  (string) The transaction id. Available for 'send' and 'receive' category of transactions.\n"
            "    \"time\": xxx,              (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT).\n"
            "    \"timereceived\": xxx,      (numeric) The time received in seconds since epoch (Jan 1 1970 GMT). Available for 'send' and 'receive' category of transactions.\n"
            "    \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "    \"abandoned\": xxx,         (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the 'send' category of transactions.\n"
            "    \"comment\": \"...\",       (string) If a comment is associated with the transaction.\n"
            "    \"label\" : \"label\"       (string) A comment for the address/transaction, if any\n"
            "    \"to\": \"...\",            (string) If a comment to is associated with the transaction.\n"
            "  ],\n"
            "  \"removed\": [\n"
            "    <structure is the same as \"transactions\" above, only present if include_removed=true>\n"
            "    Note: transactions that were readded in the active chain will appear as-is in this array, and may thus have a positive confirmation count.\n"
            "  ],\n"
            "  \"lastblock\": \"lastblockhash\"     (string) The hash of the block (target_confirmations-1) from the best block on the main chain. This is typically used to feed back into listsinceblock the next time you call it. So you would generally use a target_confirmations of say 6, so you will be continually re-notified of transactions until they've reached 6 confirmations plus any new ones\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("listsinceblock", "")
            + HelpExampleCli("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\" 6")
            + HelpExampleRpc("listsinceblock", "\"000000000000000bacf66f7497b7dc45ef753ee9a7d38571037cdb1a57f663ad\", 6")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    const CBlockIndex* pindex = nullptr;    // Block index of the specified block or the common ancestor, if the block provided was in a deactivated chain.
    const CBlockIndex* paltindex = nullptr; // Block index of the specified block, even if it's in a deactivated chain.
    int target_confirms = 1;
    isminefilter filter = ISMINE_SPENDABLE;

    if (!request.params[0].isNull() && !request.params[0].get_str().empty()) {
        uint256 blockId;

        blockId.SetHex(request.params[0].get_str());
        BlockMap::iterator it = mapBlockIndex.find(blockId);
        if (it == mapBlockIndex.end()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        }
        paltindex = pindex = it->second;
        if (chainActive[pindex->nHeight] != pindex) {
            // the block being asked for is a part of a deactivated chain;
            // we don't want to depend on its perceived height in the block
            // chain, we want to instead use the last common ancestor
            pindex = chainActive.FindFork(pindex);
        }
    }

    if (!request.params[1].isNull()) {
        target_confirms = request.params[1].get_int();

        if (target_confirms < 1) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter");
        }
    }

    if (!request.params[2].isNull() && request.params[2].get_bool()) {
        filter = filter | ISMINE_WATCH_ONLY;
    }

    bool include_removed = (request.params[3].isNull() || request.params[3].get_bool());

    int depth = pindex ? (1 + chainActive.Height() - pindex->nHeight) : -1;

    UniValue transactions(UniValue::VARR);

    for (const std::pair<uint256, CWalletTx>& pairWtx : pwallet->mapWallet) {
        CWalletTx tx = pairWtx.second;

        if (depth == -1 || tx.GetDepthInMainChain() < depth) {
            ListTransactions(pwallet, tx, "*", 0, true, transactions, filter);
        }
    }

    // when a reorg'd block is requested, we also list any relevant transactions
    // in the blocks of the chain that was detached
    UniValue removed(UniValue::VARR);
    while (include_removed && paltindex && paltindex != pindex) {
        CBlock block;
        if (!ReadBlockFromDisk(block, paltindex, Params().GetConsensus())) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");
        }
        for (const CTransactionRef& tx : block.vtx) {
            auto it = pwallet->mapWallet.find(tx->GetHash());
            if (it != pwallet->mapWallet.end()) {
                // We want all transactions regardless of confirmation count to appear here,
                // even negative confirmation ones, hence the big negative.
                ListTransactions(pwallet, it->second, "*", -100000000, true, removed, filter);
            }
        }
        paltindex = paltindex->pprev;
    }

    CBlockIndex *pblockLast = chainActive[chainActive.Height() + 1 - target_confirms];
    uint256 lastblock = pblockLast ? pblockLast->GetBlockHash() : uint256();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transactions", transactions));
    if (include_removed) ret.push_back(Pair("removed", removed));
    ret.push_back(Pair("lastblock", lastblock.GetHex()));

    return ret;
}

UniValue gettransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "gettransaction \"txid\" ( include_watchonly )\n"
            "\nGet detailed information about in-wallet transaction <txid>\n"
            "\nArguments:\n"
            "1. \"txid\"                  (string, required) The transaction id\n"
            "2. \"include_watchonly\"     (bool, optional, default=false) Whether to include watch-only addresses in balance calculation and details[]\n"
            "\nResult:\n"
            "{\n"
            "  \"amount\" : x.xxx,        (numeric) The transaction amount in " + CURRENCY_UNIT + "\n"
            "  \"fee\": x.xxx,            (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                              'send' category of transactions.\n"
            "  \"confirmations\" : n,     (numeric) The number of confirmations\n"
            "  \"blockhash\" : \"hash\",  (string) The block hash\n"
            "  \"blockindex\" : xx,       (numeric) The index of the transaction in the block that includes it\n"
            "  \"blocktime\" : ttt,       (numeric) The time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"txid\" : \"transactionid\",   (string) The transaction id.\n"
            "  \"time\" : ttt,            (numeric) The transaction time in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"timereceived\" : ttt,    (numeric) The time received in seconds since epoch (1 Jan 1970 GMT)\n"
            "  \"bip125-replaceable\": \"yes|no|unknown\",  (string) Whether this transaction could be replaced due to BIP125 (replace-by-fee);\n"
            "                                                   may be unknown for unconfirmed transactions not in the mempool\n"
            "  \"details\" : [\n"
            "    {\n"
            "      \"account\" : \"accountname\",      (string) DEPRECATED. The account name involved in the transaction, can be \"\" for the default account.\n"
            "      \"address\" : \"address\",          (string) The smartusd address involved in the transaction\n"
            "      \"category\" : \"send|receive\",    (string) The category, either 'send' or 'receive'\n"
            "      \"amount\" : x.xxx,                 (numeric) The amount in " + CURRENCY_UNIT + "\n"
            "      \"label\" : \"label\",              (string) A comment for the address/transaction, if any\n"
            "      \"vout\" : n,                       (numeric) the vout value\n"
            "      \"fee\": x.xxx,                     (numeric) The amount of the fee in " + CURRENCY_UNIT + ". This is negative and only available for the \n"
            "                                           'send' category of transactions.\n"
            "      \"abandoned\": xxx                  (bool) 'true' if the transaction has been abandoned (inputs are respendable). Only available for the \n"
            "                                           'send' category of transactions.\n"
            "    }\n"
            "    ,...\n"
            "  ],\n"
            "  \"hex\" : \"data\"         (string) Raw data for transaction\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleCli("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\" true")
            + HelpExampleRpc("gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    isminefilter filter = ISMINE_SPENDABLE;
    if(!request.params[1].isNull())
        if(request.params[1].get_bool())
            filter = filter | ISMINE_WATCH_ONLY;

    UniValue entry(UniValue::VOBJ);
    auto it = pwallet->mapWallet.find(hash);
    if (it == pwallet->mapWallet.end()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    const CWalletTx& wtx = it->second;

    CAmount nCredit = wtx.GetCredit(filter);
    CAmount nDebit = wtx.GetDebit(filter);
    CAmount nNet = nCredit - nDebit;
    CAmount nFee = (wtx.IsFromMe(filter) ? wtx.tx->GetValueOut(true) - nDebit : 0);

    entry.push_back(Pair("amount", ValueFromAmount(nNet - nFee)));
    if (wtx.IsFromMe(filter))
        entry.push_back(Pair("fee", ValueFromAmount(nFee)));

    WalletTxToJSON(wtx, entry);

    UniValue details(UniValue::VARR);
    ListTransactions(pwallet, wtx, "*", 0, false, details, filter);
    entry.push_back(Pair("details", details));

    std::string strHex = EncodeHexTx(*wtx.tx, RPCSerializationFlags());
    entry.push_back(Pair("hex", strHex));

    return entry;
}

UniValue abandontransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "abandontransaction \"txid\"\n"
            "\nMark in-wallet transaction <txid> as abandoned\n"
            "This will mark this transaction and all its in-wallet descendants as abandoned which will allow\n"
            "for their inputs to be respent.  It can be used to replace \"stuck\" or evicted transactions.\n"
            "It only works on transactions which are not included in a block and are not currently in the mempool.\n"
            "It has no effect on transactions which are already abandoned.\n"
            "\nArguments:\n"
            "1. \"txid\"    (string, required) The transaction id\n"
            "\nResult:\n"
            "\nExamples:\n"
            + HelpExampleCli("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
            + HelpExampleRpc("abandontransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        );
    }

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    if (!pwallet->mapWallet.count(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");
    }
    if (!pwallet->AbandonTransaction(hash)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not eligible for abandonment");
    }

    return NullUniValue;
}


UniValue backupwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "backupwallet \"destination\"\n"
            "\nSafely copies current wallet file to destination, which can be a directory or a path with filename.\n"
            "\nArguments:\n"
            "1. \"destination\"   (string) The destination directory or file\n"
            "\nExamples:\n"
            + HelpExampleCli("backupwallet", "\"backup.dat\"")
            + HelpExampleRpc("backupwallet", "\"backup.dat\"")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strDest = request.params[0].get_str();
    if (!pwallet->BackupWallet(strDest)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet backup failed!");
    }

    return NullUniValue;
}


UniValue keypoolrefill(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "keypoolrefill ( newsize )\n"
            "\nFills the keypool."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments\n"
            "1. newsize     (numeric, optional, default=100) The new keypool size\n"
            "\nExamples:\n"
            + HelpExampleCli("keypoolrefill", "")
            + HelpExampleRpc("keypoolrefill", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // 0 is interpreted by TopUpKeyPool() as the default keypool size given by -keypool
    unsigned int kpSize = 0;
    if (!request.params[0].isNull()) {
        if (request.params[0].get_int() < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected valid size.");
        kpSize = (unsigned int)request.params[0].get_int();
    }

    EnsureWalletIsUnlocked(pwallet);
    pwallet->TopUpKeyPool(kpSize);

    if (pwallet->GetKeyPoolSize() < kpSize) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error refreshing keypool.");
    }

    return NullUniValue;
}


static void LockWallet(CWallet* pWallet)
{
    LOCK(pWallet->cs_wallet);
    pWallet->nRelockTime = 0;
    pWallet->Lock();
}

UniValue walletpassphrase(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "walletpassphrase \"passphrase\" timeout\n"
            "\nStores the wallet decryption key in memory for 'timeout' seconds.\n"
            "This is needed prior to performing transactions related to private keys such as sending smartusds\n"
            "\nArguments:\n"
            "1. \"passphrase\"     (string, required) The wallet passphrase\n"
            "2. timeout            (numeric, required) The time to keep the decryption key in seconds; capped at 100000000 (~3 years).\n"
            "\nNote:\n"
            "Issuing the walletpassphrase command while the wallet is already unlocked will set a new unlock\n"
            "time that overrides the old one.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 60 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 60") +
            "\nLock the wallet again (before 60 seconds)\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletpassphrase", "\"my pass phrase\", 60")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrase was called.");
    }

    // Note that the walletpassphrase is stored in request.params[0] which is not mlock()ed
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    strWalletPass = request.params[0].get_str().c_str();

    // Get the timeout
    int64_t nSleepTime = request.params[1].get_int64();
    // Timeout cannot be negative, otherwise it will relock immediately
    if (nSleepTime < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Timeout cannot be negative.");
    }
    // Clamp timeout
    constexpr int64_t MAX_SLEEP_TIME = 100000000; // larger values trigger a macos/libevent bug?
    if (nSleepTime > MAX_SLEEP_TIME) {
        nSleepTime = MAX_SLEEP_TIME;
    }

    if (strWalletPass.length() > 0)
    {
        if (!pwallet->Unlock(strWalletPass)) {
            throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
        }
    }
    else
        throw std::runtime_error(
            "walletpassphrase <passphrase> <timeout>\n"
            "Stores the wallet decryption key in memory for <timeout> seconds.");

    pwallet->TopUpKeyPool();

    pwallet->nRelockTime = GetTime() + nSleepTime;
    RPCRunLater(strprintf("lockwallet(%s)", pwallet->GetName()), boost::bind(LockWallet, pwallet), nSleepTime);

    return NullUniValue;
}


UniValue walletpassphrasechange(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 2) {
        throw std::runtime_error(
            "walletpassphrasechange \"oldpassphrase\" \"newpassphrase\"\n"
            "\nChanges the wallet passphrase from 'oldpassphrase' to 'newpassphrase'.\n"
            "\nArguments:\n"
            "1. \"oldpassphrase\"      (string) The current passphrase\n"
            "2. \"newpassphrase\"      (string) The new passphrase\n"
            "\nExamples:\n"
            + HelpExampleCli("walletpassphrasechange", "\"old one\" \"new one\"")
            + HelpExampleRpc("walletpassphrasechange", "\"old one\", \"new one\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletpassphrasechange was called.");
    }

    // TODO: get rid of these .c_str() calls by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strOldWalletPass;
    strOldWalletPass.reserve(100);
    strOldWalletPass = request.params[0].get_str().c_str();

    SecureString strNewWalletPass;
    strNewWalletPass.reserve(100);
    strNewWalletPass = request.params[1].get_str().c_str();

    if (strOldWalletPass.length() < 1 || strNewWalletPass.length() < 1)
        throw std::runtime_error(
            "walletpassphrasechange <oldpassphrase> <newpassphrase>\n"
            "Changes the wallet passphrase from <oldpassphrase> to <newpassphrase>.");

    if (!pwallet->ChangeWalletPassphrase(strOldWalletPass, strNewWalletPass)) {
        throw JSONRPCError(RPC_WALLET_PASSPHRASE_INCORRECT, "Error: The wallet passphrase entered was incorrect.");
    }

    return NullUniValue;
}


UniValue walletlock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "walletlock\n"
            "\nRemoves the wallet encryption key from memory, locking the wallet.\n"
            "After calling this method, you will need to call walletpassphrase again\n"
            "before being able to call any methods which require the wallet to be unlocked.\n"
            "\nExamples:\n"
            "\nSet the passphrase for 2 minutes to perform a transaction\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\" 120") +
            "\nPerform a send (requires passphrase set)\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 1.0") +
            "\nClear the passphrase since we are done before 2 minutes is up\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs json rpc call\n"
            + HelpExampleRpc("walletlock", "")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (!pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an unencrypted wallet, but walletlock was called.");
    }

    pwallet->Lock();
    pwallet->nRelockTime = 0;

    return NullUniValue;
}


UniValue encryptwallet(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "encryptwallet \"passphrase\"\n"
            "\nEncrypts the wallet with 'passphrase'. This is for first time encryption.\n"
            "After this, any calls that interact with private keys such as sending or signing \n"
            "will require the passphrase to be set prior the making these calls.\n"
            "Use the walletpassphrase call for this, and then walletlock call.\n"
            "If the wallet is already encrypted, use the walletpassphrasechange call.\n"
            "Note that this will shutdown the server.\n"
            "\nArguments:\n"
            "1. \"passphrase\"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.\n"
            "\nExamples:\n"
            "\nEncrypt your wallet\n"
            + HelpExampleCli("encryptwallet", "\"my pass phrase\"") +
            "\nNow set the passphrase to use the wallet, such as for signing or sending smartusd\n"
            + HelpExampleCli("walletpassphrase", "\"my pass phrase\"") +
            "\nNow we can do something like sign\n"
            + HelpExampleCli("signmessage", "\"address\" \"test message\"") +
            "\nNow lock the wallet again by removing the passphrase\n"
            + HelpExampleCli("walletlock", "") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("encryptwallet", "\"my pass phrase\"")
        );
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (request.fHelp)
        return true;
    if (pwallet->IsCrypted()) {
        throw JSONRPCError(RPC_WALLET_WRONG_ENC_STATE, "Error: running with an encrypted wallet, but encryptwallet was called.");
    }

    // TODO: get rid of this .c_str() by implementing SecureString::operator=(std::string)
    // Alternately, find a way to make request.params[0] mlock()'d to begin with.
    SecureString strWalletPass;
    strWalletPass.reserve(100);
    strWalletPass = request.params[0].get_str().c_str();

    if (strWalletPass.length() < 1)
        throw std::runtime_error(
            "encryptwallet <passphrase>\n"
            "Encrypts the wallet with <passphrase>.");

    if (!pwallet->EncryptWallet(strWalletPass)) {
        throw JSONRPCError(RPC_WALLET_ENCRYPTION_FAILED, "Error: Failed to encrypt the wallet.");
    }

    // BDB seems to have a bad habit of writing old data into
    // slack space in .dat files; that is bad if the old data is
    // unencrypted private keys. So:
    StartShutdown();
    return "wallet encrypted; SmartUSD server stopping, restart to run with encrypted wallet. The keypool has been flushed and a new HD seed was generated (if you are using HD). You need to make a new backup.";
}

UniValue lockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "lockunspent unlock ([{\"txid\":\"txid\",\"vout\":n},...])\n"
            "\nUpdates list of temporarily unspendable outputs.\n"
            "Temporarily lock (unlock=false) or unlock (unlock=true) specified transaction outputs.\n"
            "If no transaction outputs are specified when unlocking then all current locked transaction outputs are unlocked.\n"
            "A locked transaction output will not be chosen by automatic coin selection, when spending smartusds.\n"
            "Locks are stored in memory only. Nodes start with zero locked outputs, and the locked output list\n"
            "is always cleared (by virtue of process exit) when a node stops or fails.\n"
            "Also see the listunspent call\n"
            "\nArguments:\n"
            "1. unlock            (boolean, required) Whether to unlock (true) or lock (false) the specified transactions\n"
            "2. \"transactions\"  (string, optional) A json array of objects. Each object the txid (string) vout (numeric)\n"
            "     [           (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",    (string) The transaction id\n"
            "         \"vout\": n         (numeric) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "true|false    (boolean) Whether the command was successful or not\n"

            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("lockunspent", "false, \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"")
        );

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    RPCTypeCheckArgument(request.params[0], UniValue::VBOOL);

    bool fUnlock = request.params[0].get_bool();

    if (request.params[1].isNull()) {
        if (fUnlock)
            pwallet->UnlockAllCoins();
        return true;
    }

    RPCTypeCheckArgument(request.params[1], UniValue::VARR);

    const UniValue& output_params = request.params[1];

    // Create and validate the COutPoints first.

    std::vector<COutPoint> outputs;
    outputs.reserve(output_params.size());

    for (unsigned int idx = 0; idx < output_params.size(); idx++) {
        const UniValue& o = output_params[idx].get_obj();

        RPCTypeCheckObj(o,
            {
                {"txid", UniValueType(UniValue::VSTR)},
                {"vout", UniValueType(UniValue::VNUM)},
            });

        const std::string& txid = find_value(o, "txid").get_str();
        if (!IsHex(txid)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected hex txid");
        }

        const int nOutput = find_value(o, "vout").get_int();
        if (nOutput < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");
        }

        const COutPoint outpt(uint256S(txid), nOutput);

        const auto it = pwallet->mapWallet.find(outpt.hash);
        if (it == pwallet->mapWallet.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, unknown transaction");
        }

        const CWalletTx& trans = it->second;

        if (outpt.n >= trans.tx->vout.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout index out of bounds");
        }

        if (pwallet->IsSpent(outpt.hash, outpt.n)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected unspent output");
        }

        const bool is_locked = pwallet->IsLockedCoin(outpt.hash, outpt.n);

        if (fUnlock && !is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, expected locked output");
        }

        if (!fUnlock && is_locked) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output already locked");
        }

        outputs.push_back(outpt);
    }

    // Atomically set (un)locked status for the outputs.
    for (const COutPoint& outpt : outputs) {
        if (fUnlock) pwallet->UnlockCoin(outpt);
        else pwallet->LockCoin(outpt);
    }

    return true;
}

UniValue listlockunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "listlockunspent\n"
            "\nReturns list of temporarily unspendable outputs.\n"
            "See the lockunspent call to lock and unlock transactions for spending.\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id locked\n"
            "    \"vout\" : n                      (numeric) The vout value\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            "\nList the unspent transactions\n"
            + HelpExampleCli("listunspent", "") +
            "\nLock an unspent transaction\n"
            + HelpExampleCli("lockunspent", "false \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nList the locked transactions\n"
            + HelpExampleCli("listlockunspent", "") +
            "\nUnlock the transaction again\n"
            + HelpExampleCli("lockunspent", "true \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":1}]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("listlockunspent", "")
        );

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    std::vector<COutPoint> vOutpts;
    pwallet->ListLockedCoins(vOutpts);

    UniValue ret(UniValue::VARR);

    for (COutPoint &outpt : vOutpts) {
        UniValue o(UniValue::VOBJ);

        o.push_back(Pair("txid", outpt.hash.GetHex()));
        o.push_back(Pair("vout", (int)outpt.n));
        ret.push_back(o);
    }

    return ret;
}

UniValue settxfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw std::runtime_error(
            "settxfee amount\n"
            "\nSet the transaction fee per kB. Overwrites the paytxfee parameter.\n"
            "\nArguments:\n"
            "1. amount         (numeric or string, required) The transaction fee in " + CURRENCY_UNIT + "/kB\n"
            "\nResult\n"
            "true|false        (boolean) Returns true if successful\n"
            "\nExamples:\n"
            + HelpExampleCli("settxfee", "0.00001")
            + HelpExampleRpc("settxfee", "0.00001")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    // Amount
    CAmount nAmount = AmountFromValue(request.params[0]);

    payTxFee = CFeeRate(nAmount, 1000);
    return true;
}

UniValue getwalletinfo(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getwalletinfo\n"
            "Returns an object containing various wallet state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"walletname\": xxxxx,             (string) the wallet name\n"
            "  \"walletversion\": xxxxx,          (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,              (numeric) the total confirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"unconfirmed_balance\": xxx,      (numeric) the total unconfirmed balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"immature_balance\": xxxxxx,      (numeric) the total immature balance of the wallet in " + CURRENCY_UNIT + "\n"
            "  \"txcount\": xxxxxxx,              (numeric) the total number of transactions in the wallet\n"
            "  \"keypoololdest\": xxxxxx,         (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,             (numeric) how many new keys are pre-generated (only counts external keys)\n"
            "  \"keypoolsize_hd_internal\": xxxx, (numeric) how many new keys are pre-generated for internal use (used for change outputs, only appears if the wallet is using this feature, otherwise external keys are used)\n"
            "  \"unlocked_until\": ttt,           (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,              (numeric) the transaction fee configuration, set in " + CURRENCY_UNIT + "/kB\n"
            "  \"hdmasterkeyid\": \"<hash160>\"     (string, optional) the Hash160 of the HD master pubkey (only present when HD is enabled)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getwalletinfo", "")
            + HelpExampleRpc("getwalletinfo", "")
        );

    ObserveSafeMode();

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);

    UniValue obj(UniValue::VOBJ);

    size_t kpExternalSize = pwallet->KeypoolCountExternalKeys();
    obj.push_back(Pair("walletname", pwallet->GetName()));
    obj.push_back(Pair("walletversion", pwallet->GetVersion()));
    obj.push_back(Pair("balance",       ValueFromAmount(pwallet->GetBalance())));
    obj.push_back(Pair("unconfirmed_balance", ValueFromAmount(pwallet->GetUnconfirmedBalance())));
    obj.push_back(Pair("immature_balance",    ValueFromAmount(pwallet->GetImmatureBalance())));
    obj.push_back(Pair("txcount",       (int)pwallet->mapWallet.size()));
    obj.push_back(Pair("keypoololdest", pwallet->GetOldestKeyPoolTime()));
    obj.push_back(Pair("keypoolsize", (int64_t)kpExternalSize));
    CKeyID masterKeyID = pwallet->GetHDChain().masterKeyID;
    if (!masterKeyID.IsNull() && pwallet->CanSupportFeature(FEATURE_HD_SPLIT)) {
        obj.push_back(Pair("keypoolsize_hd_internal",   (int64_t)(pwallet->GetKeyPoolSize() - kpExternalSize)));
    }
    if (pwallet->IsCrypted()) {
        obj.push_back(Pair("unlocked_until", pwallet->nRelockTime));
    }
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
    if (!masterKeyID.IsNull())
         obj.push_back(Pair("hdmasterkeyid", masterKeyID.GetHex()));
    return obj;
}

UniValue listwallets(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listwallets\n"
            "Returns a list of currently loaded wallets.\n"
            "For full information on the wallet, use \"getwalletinfo\"\n"
            "\nResult:\n"
            "[                         (json array of strings)\n"
            "  \"walletname\"            (string) the wallet name\n"
            "   ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("listwallets", "")
            + HelpExampleRpc("listwallets", "")
        );

    UniValue obj(UniValue::VARR);

    for (CWalletRef pwallet : vpwallets) {

        if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
            return NullUniValue;
        }

        LOCK(pwallet->cs_wallet);

        obj.push_back(pwallet->GetName());
    }

    return obj;
}

UniValue resendwallettransactions(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "resendwallettransactions\n"
            "Immediately re-broadcast unconfirmed wallet transactions to all peers.\n"
            "Intended only for testing; the wallet code periodically re-broadcasts\n"
            "automatically.\n"
            "Returns an RPC error if -walletbroadcast is set to false.\n"
            "Returns array of transaction ids that were re-broadcast.\n"
            );

    if (!g_connman)
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");

    LOCK2(cs_main, pwallet->cs_wallet);

    if (!pwallet->GetBroadcastTransactions()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: Wallet transaction broadcasting is disabled with -walletbroadcast");
    }

    std::vector<uint256> txids = pwallet->ResendWalletTransactionsBefore(GetTime(), g_connman.get());
    UniValue result(UniValue::VARR);
    for (const uint256& txid : txids)
    {
        result.push_back(txid.ToString());
    }
    return result;
}

UniValue listunspent(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 5)
        throw std::runtime_error(
            "listunspent ( minconf maxconf  [\"addresses\",...] [include_unsafe] [query_options])\n"
            "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filter to only include txouts paid to specified addresses.\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmations to filter\n"
            "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
            "3. \"addresses\"      (string) A json array of smartusd addresses to filter\n"
            "    [\n"
            "      \"address\"     (string) smartusd address\n"
            "      ,...\n"
            "    ]\n"
            "4. include_unsafe (bool, optional, default=true) Include outputs that are not safe to spend\n"
            "                  See description of \"safe\" attribute below.\n"
            "5. query_options    (json, optional) JSON with query options\n"
            "    {\n"
            "      \"minimumAmount\"    (numeric or string, default=0) Minimum value of each UTXO in " + CURRENCY_UNIT + "\n"
            "      \"maximumAmount\"    (numeric or string, default=unlimited) Maximum value of each UTXO in " + CURRENCY_UNIT + "\n"
            "      \"maximumCount\"     (numeric or string, default=unlimited) Maximum number of UTXOs\n"
            "      \"minimumSumAmount\" (numeric or string, default=unlimited) Minimum sum value of all UTXOs in " + CURRENCY_UNIT + "\n"
            "    }\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",          (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",    (string) the smartusd address\n"
            "    \"account\" : \"account\",    (string) DEPRECATED. The associated account, or \"\" for the default account\n"
            "    \"scriptPubKey\" : \"key\",   (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction output amount in " + CURRENCY_UNIT + "\n"
            "    \"confirmations\" : n,      (numeric) The number of confirmations\n"
            "    \"redeemScript\" : n        (string) The redeemScript if scriptPubKey is P2SH\n"
            "    \"spendable\" : xxx,        (bool) Whether we have the private keys to spend this output\n"
            "    \"solvable\" : xxx,         (bool) Whether we know how to spend this output, ignoring the lack of keys\n"
            "    \"safe\" : xxx              (bool) Whether this output is considered safe to spend. Unconfirmed transactions\n"
            "                              from outside keys and unconfirmed replacement transactions are considered unsafe\n"
            "                              and are not eligible for spending by fundrawtransaction and sendtoaddress.\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n"
            + HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdV5h\\\",\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"NDLTK7j8CzK5YAbpCdUxC3Gi1bXGDCdV5h\\\",\\\"N2xHFZ8NWNkGuuXfDxv8iMXdQGMd3tjZfx\\\"]\"")
            + HelpExampleCli("listunspent", "6 9999999 '[]' true '{ \"minimumAmount\": 0.005 }'")
            + HelpExampleRpc("listunspent", "6, 9999999, [] , true, { \"minimumAmount\": 0.005 } ")
        );

    ObserveSafeMode();

    int nMinDepth = 1;
    if (!request.params[0].isNull()) {
        RPCTypeCheckArgument(request.params[0], UniValue::VNUM);
        nMinDepth = request.params[0].get_int();
    }

    int nMaxDepth = 9999999;
    if (!request.params[1].isNull()) {
        RPCTypeCheckArgument(request.params[1], UniValue::VNUM);
        nMaxDepth = request.params[1].get_int();
    }

    std::set<CTxDestination> destinations;
    if (!request.params[2].isNull()) {
        RPCTypeCheckArgument(request.params[2], UniValue::VARR);
        UniValue inputs = request.params[2].get_array();
        for (unsigned int idx = 0; idx < inputs.size(); idx++) {
            const UniValue& input = inputs[idx];
            CTxDestination dest = DecodeDestination(input.get_str());
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid SmartUSD address: ") + input.get_str());
            }
            if (!destinations.insert(dest).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + input.get_str());
            }
        }
    }

    bool include_unsafe = true;
    if (!request.params[3].isNull()) {
        RPCTypeCheckArgument(request.params[3], UniValue::VBOOL);
        include_unsafe = request.params[3].get_bool();
    }

    CAmount nMinimumAmount = 0;
    CAmount nMaximumAmount = MAX_MONEY;
    CAmount nMinimumSumAmount = MAX_MONEY;
    uint64_t nMaximumCount = 0;

    if (!request.params[4].isNull()) {
        const UniValue& options = request.params[4].get_obj();

        if (options.exists("minimumAmount"))
            nMinimumAmount = AmountFromValue(options["minimumAmount"]);

        if (options.exists("maximumAmount"))
            nMaximumAmount = AmountFromValue(options["maximumAmount"]);

        if (options.exists("minimumSumAmount"))
            nMinimumSumAmount = AmountFromValue(options["minimumSumAmount"]);

        if (options.exists("maximumCount"))
            nMaximumCount = options["maximumCount"].get_int64();
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    UniValue results(UniValue::VARR);
    std::vector<COutput> vecOutputs;
    LOCK2(cs_main, pwallet->cs_wallet);

    pwallet->AvailableCoins(vecOutputs, !include_unsafe, nullptr, nMinimumAmount, nMaximumAmount, nMinimumSumAmount, nMaximumCount, nMinDepth, nMaxDepth);
    for (const COutput& out : vecOutputs) {
        CTxDestination address;
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (destinations.size() && (!fValidAddress || !destinations.count(address)))
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));

        if (fValidAddress) {
            entry.push_back(Pair("address", EncodeDestination(address)));

            if (pwallet->mapAddressBook.count(address)) {
                entry.push_back(Pair("account", pwallet->mapAddressBook[address].name));
            }

            if (scriptPubKey.IsPayToScriptHash()) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
                }
            }
        }

        entry.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));
        entry.push_back(Pair("amount", ValueFromAmount(out.tx->tx->vout[out.i].nValue)));
        entry.push_back(Pair("confirmations", out.nDepth));
        entry.push_back(Pair("spendable", out.fSpendable));
        entry.push_back(Pair("solvable", out.fSolvable));
        entry.push_back(Pair("safe", out.fSafe));
        results.push_back(entry);
    }

    return results;
}

UniValue fundrawtransaction(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                            "fundrawtransaction \"hexstring\" ( options iswitness )\n"
                            "\nAdd inputs to a transaction until it has enough in value to meet its out value.\n"
                            "This will not modify existing inputs, and will add at most one change output to the outputs.\n"
                            "No existing outputs will be modified unless \"subtractFeeFromOutputs\" is specified.\n"
                            "Note that inputs which were signed may need to be resigned after completion since in/outputs have been added.\n"
                            "The inputs added will not be signed, use signrawtransaction for that.\n"
                            "Note that all existing inputs must have their previous output transaction be in the wallet.\n"
                            "Note that all inputs selected must be of standard form and P2SH scripts must be\n"
                            "in the wallet using importaddress or addmultisigaddress (to calculate fees).\n"
                            "You can see whether this is the case by checking the \"solvable\" field in the listunspent output.\n"
                            "Only pay-to-pubkey, multisig, and P2SH versions thereof are currently supported for watch-only\n"
                            "\nArguments:\n"
                            "1. \"hexstring\"           (string, required) The hex string of the raw transaction\n"
                            "2. options                 (object, optional)\n"
                            "   {\n"
                            "     \"changeAddress\"          (string, optional, default pool address) The bitcoin address to receive the change\n"
                            "     \"changePosition\"         (numeric, optional, default random) The index of the change output\n"
                            "     \"change_type\"            (string, optional) The output type to use. Only valid if changeAddress is not specified. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\". Default is set by -changetype.\n"
                            "     \"includeWatching\"        (boolean, optional, default false) Also select inputs which are watch only\n"
                            "     \"lockUnspents\"           (boolean, optional, default false) Lock selected unspent outputs\n"
                            "     \"feeRate\"                (numeric, optional, default not set: makes wallet determine the fee) Set a specific fee rate in " + CURRENCY_UNIT + "/kB\n"
                            "     \"subtractFeeFromOutputs\" (array, optional) A json array of integers.\n"
                            "                              The fee will be equally deducted from the amount of each specified output.\n"
                            "                              The outputs are specified by their zero-based index, before any change output is added.\n"
                            "                              Those recipients will receive less bitcoins than you enter in their corresponding amount field.\n"
                            "                              If no outputs are specified here, the sender pays the fee.\n"
                            "                                  [vout_index,...]\n"
                            "     \"replaceable\"            (boolean, optional) Marks this transaction as BIP125 replaceable.\n"
                            "                              Allows this transaction to be replaced by a transaction with higher fees\n"
                            "     \"conf_target\"            (numeric, optional) Confirmation target (in blocks)\n"
                            "     \"estimate_mode\"          (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
                            "         \"UNSET\"\n"
                            "         \"ECONOMICAL\"\n"
                            "         \"CONSERVATIVE\"\n"
                            "   }\n"
                            "                         for backward compatibility: passing in a true instead of an object will result in {\"includeWatching\":true}\n"
                            "3. iswitness               (boolean, optional) Whether the transaction hex is a serialized witness transaction \n"
                            "                              If iswitness is not present, heuristic tests will be used in decoding\n"

                            "\nResult:\n"
                            "{\n"
                            "  \"hex\":       \"value\", (string)  The resulting raw transaction (hex-encoded string)\n"
                            "  \"fee\":       n,         (numeric) Fee in " + CURRENCY_UNIT + " the resulting transaction pays\n"
                            "  \"changepos\": n          (numeric) The position of the added change output, or -1\n"
                            "}\n"
                            "\nExamples:\n"
                            "\nCreate a transaction with no inputs\n"
                            + HelpExampleCli("createrawtransaction", "\"[]\" \"{\\\"myaddress\\\":0.01}\"") +
                            "\nAdd sufficient unsigned inputs to meet the output value\n"
                            + HelpExampleCli("fundrawtransaction", "\"rawtransactionhex\"") +
                            "\nSign the transaction\n"
                            + HelpExampleCli("signrawtransaction", "\"fundedtransactionhex\"") +
                            "\nSend the transaction\n"
                            + HelpExampleCli("sendrawtransaction", "\"signedtransactionhex\"")
                            );

    ObserveSafeMode();
    RPCTypeCheck(request.params, {UniValue::VSTR});

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    CCoinControl coinControl;
    int changePosition = -1;
    bool lockUnspents = false;
    UniValue subtractFeeFromOutputs;
    std::set<int> setSubtractFeeFromOutputs;

    if (!request.params[1].isNull()) {
      if (request.params[1].type() == UniValue::VBOOL) {
        // backward compatibility bool only fallback
        coinControl.fAllowWatchOnly = request.params[1].get_bool();
      }
      else {
        RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ, UniValue::VBOOL});

        UniValue options = request.params[1];

        RPCTypeCheckObj(options,
            {
                {"changeAddress", UniValueType(UniValue::VSTR)},
                {"changePosition", UniValueType(UniValue::VNUM)},
                {"change_type", UniValueType(UniValue::VSTR)},
                {"includeWatching", UniValueType(UniValue::VBOOL)},
                {"lockUnspents", UniValueType(UniValue::VBOOL)},
                {"reserveChangeKey", UniValueType(UniValue::VBOOL)}, // DEPRECATED (and ignored), should be removed in 0.16 or so.
                {"feeRate", UniValueType()}, // will be checked below
                {"subtractFeeFromOutputs", UniValueType(UniValue::VARR)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"conf_target", UniValueType(UniValue::VNUM)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
            },
            true, true);

        if (options.exists("changeAddress")) {
            CTxDestination dest = DecodeDestination(options["changeAddress"].get_str());

            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "changeAddress must be a valid bitcoin address");
            }

            coinControl.destChange = dest;
        }

        if (options.exists("changePosition"))
            changePosition = options["changePosition"].get_int();

        if (options.exists("change_type")) {
            if (options.exists("changeAddress")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both changeAddress and address_type options");
            }
            coinControl.change_type = ParseOutputType(options["change_type"].get_str(), coinControl.change_type);
            if (coinControl.change_type == OUTPUT_TYPE_NONE) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown change type '%s'", options["change_type"].get_str()));
            }
        }

        if (options.exists("includeWatching"))
            coinControl.fAllowWatchOnly = options["includeWatching"].get_bool();

        if (options.exists("lockUnspents"))
            lockUnspents = options["lockUnspents"].get_bool();

        if (options.exists("feeRate"))
        {
            coinControl.m_feerate = CFeeRate(AmountFromValue(options["feeRate"]));
            coinControl.fOverrideFeeRate = true;
        }

        if (options.exists("subtractFeeFromOutputs"))
            subtractFeeFromOutputs = options["subtractFeeFromOutputs"].get_array();

        if (options.exists("replaceable")) {
            coinControl.signalRbf = options["replaceable"].get_bool();
        }
        if (options.exists("conf_target")) {
            if (options.exists("feeRate")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both conf_target and feeRate");
            }
            coinControl.m_confirm_target = ParseConfirmTarget(options["conf_target"]);
        }
        if (options.exists("estimate_mode")) {
            if (options.exists("feeRate")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot specify both estimate_mode and feeRate");
            }
            if (!FeeModeFromString(options["estimate_mode"].get_str(), coinControl.m_fee_mode)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
            }
        }
      }
    }

    // parse hex string from parameter
    CMutableTransaction tx;
    bool try_witness = request.params[2].isNull() ? true : request.params[2].get_bool();
    bool try_no_witness = request.params[2].isNull() ? true : !request.params[2].get_bool();
    if (!DecodeHexTx(tx, request.params[0].get_str(), try_no_witness, try_witness)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    if (tx.vout.size() == 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "TX must have at least one output");

    if (changePosition != -1 && (changePosition < 0 || (unsigned int)changePosition > tx.vout.size()))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "changePosition out of bounds");

    for (unsigned int idx = 0; idx < subtractFeeFromOutputs.size(); idx++) {
        int pos = subtractFeeFromOutputs[idx].get_int();
        if (setSubtractFeeFromOutputs.count(pos))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, duplicated position: %d", pos));
        if (pos < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, negative position: %d", pos));
        if (pos >= int(tx.vout.size()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid parameter, position too large: %d", pos));
        setSubtractFeeFromOutputs.insert(pos);
    }

    CAmount nFeeOut;
    std::string strFailReason;

    if (!pwallet->FundTransaction(tx, nFeeOut, changePosition, strFailReason, lockUnspents, setSubtractFeeFromOutputs, coinControl)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strFailReason);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexTx(tx)));
    result.push_back(Pair("changepos", changePosition));
    result.push_back(Pair("fee", ValueFromAmount(nFeeOut)));

    return result;
}

UniValue bumpfee(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "bumpfee \"txid\" ( options ) \n"
            "\nBumps the fee of an opt-in-RBF transaction T, replacing it with a new transaction B.\n"
            "An opt-in RBF transaction with the given txid must be in the wallet.\n"
            "The command will pay the additional fee by decreasing (or perhaps removing) its change output.\n"
            "If the change output is not big enough to cover the increased fee, the command will currently fail\n"
            "instead of adding new inputs to compensate. (A future implementation could improve this.)\n"
            "The command will fail if the wallet or mempool contains a transaction that spends one of T's outputs.\n"
            "By default, the new fee will be calculated automatically using estimatesmartfee.\n"
            "The user can specify a confirmation target for estimatesmartfee.\n"
            "Alternatively, the user can specify totalFee, or use RPC settxfee to set a higher fee rate.\n"
            "At a minimum, the new fee rate must be high enough to pay an additional new relay fee (incrementalfee\n"
            "returned by getnetworkinfo) to enter the node's mempool.\n"
            "\nArguments:\n"
            "1. txid                  (string, required) The txid to be bumped\n"
            "2. options               (object, optional)\n"
            "   {\n"
            "     \"confTarget\"        (numeric, optional) Confirmation target (in blocks)\n"
            "     \"totalFee\"          (numeric, optional) Total fee (NOT feerate) to pay, in satoshis.\n"
            "                         In rare cases, the actual fee paid might be slightly higher than the specified\n"
            "                         totalFee if the tx change output has to be removed because it is too close to\n"
            "                         the dust threshold.\n"
            "     \"replaceable\"       (boolean, optional, default true) Whether the new transaction should still be\n"
            "                         marked bip-125 replaceable. If true, the sequence numbers in the transaction will\n"
            "                         be left unchanged from the original. If false, any input sequence numbers in the\n"
            "                         original transaction that were less than 0xfffffffe will be increased to 0xfffffffe\n"
            "                         so the new transaction will not be explicitly bip-125 replaceable (though it may\n"
            "                         still be replaceable in practice, for example if it has unconfirmed ancestors which\n"
            "                         are replaceable).\n"
            "     \"estimate_mode\"     (string, optional, default=UNSET) The fee estimate mode, must be one of:\n"
            "         \"UNSET\"\n"
            "         \"ECONOMICAL\"\n"
            "         \"CONSERVATIVE\"\n"
            "   }\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\":    \"value\",   (string)  The id of the new transaction\n"
            "  \"origfee\":  n,         (numeric) Fee of the replaced transaction\n"
            "  \"fee\":      n,         (numeric) Fee of the new transaction\n"
            "  \"errors\":  [ str... ] (json array of strings) Errors encountered during processing (may be empty)\n"
            "}\n"
            "\nExamples:\n"
            "\nBump the fee, get the new transaction\'s txid\n" +
            HelpExampleCli("bumpfee", "<txid>"));
    }

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VOBJ});
    uint256 hash;
    hash.SetHex(request.params[0].get_str());

    // optional parameters
    CAmount totalFee = 0;
    CCoinControl coin_control;
    coin_control.signalRbf = true;
    if (!request.params[1].isNull()) {
        UniValue options = request.params[1];
        RPCTypeCheckObj(options,
            {
                {"confTarget", UniValueType(UniValue::VNUM)},
                {"totalFee", UniValueType(UniValue::VNUM)},
                {"replaceable", UniValueType(UniValue::VBOOL)},
                {"estimate_mode", UniValueType(UniValue::VSTR)},
            },
            true, true);

        if (options.exists("confTarget") && options.exists("totalFee")) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "confTarget and totalFee options should not both be set. Please provide either a confirmation target for fee estimation or an explicit total fee for the transaction.");
        } else if (options.exists("confTarget")) { // TODO: alias this to conf_target
            coin_control.m_confirm_target = ParseConfirmTarget(options["confTarget"]);
        } else if (options.exists("totalFee")) {
            totalFee = options["totalFee"].get_int64();
            if (totalFee <= 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid totalFee %s (must be greater than 0)", FormatMoney(totalFee)));
            }
        }

        if (options.exists("replaceable")) {
            coin_control.signalRbf = options["replaceable"].get_bool();
        }
        if (options.exists("estimate_mode")) {
            if (!FeeModeFromString(options["estimate_mode"].get_str(), coin_control.m_fee_mode)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
            }
        }
    }

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);


    std::vector<std::string> errors;
    CAmount old_fee;
    CAmount new_fee;
    CMutableTransaction mtx;
    feebumper::Result res = feebumper::CreateTransaction(pwallet, hash, coin_control, totalFee, errors, old_fee, new_fee, mtx);
    if (res != feebumper::Result::OK) {
        switch(res) {
            case feebumper::Result::INVALID_ADDRESS_OR_KEY:
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errors[0]);
                break;
            case feebumper::Result::INVALID_REQUEST:
                throw JSONRPCError(RPC_INVALID_REQUEST, errors[0]);
                break;
            case feebumper::Result::INVALID_PARAMETER:
                throw JSONRPCError(RPC_INVALID_PARAMETER, errors[0]);
                break;
            case feebumper::Result::WALLET_ERROR:
                throw JSONRPCError(RPC_WALLET_ERROR, errors[0]);
                break;
            default:
                throw JSONRPCError(RPC_MISC_ERROR, errors[0]);
                break;
        }
    }

    // sign bumped transaction
    if (!feebumper::SignTransaction(pwallet, mtx)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Can't sign transaction.");
    }
    // commit the bumped transaction
    uint256 txid;
    if (feebumper::CommitTransaction(pwallet, hash, std::move(mtx), errors, txid) != feebumper::Result::OK) {
        throw JSONRPCError(RPC_WALLET_ERROR, errors[0]);
    }
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("txid", txid.GetHex()));
    result.push_back(Pair("origfee", ValueFromAmount(old_fee)));
    result.push_back(Pair("fee", ValueFromAmount(new_fee)));
    UniValue result_errors(UniValue::VARR);
    for (const std::string& error : errors) {
        result_errors.push_back(error);
    }
    result.push_back(Pair("errors", result_errors));

    return result;
}

UniValue generate(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2) {
        throw std::runtime_error(
            "generate nblocks ( maxtries )\n"
            "\nMine up to nblocks blocks immediately (before the RPC call returns) to an address in the wallet.\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks are generated immediately.\n"
            "2. maxtries     (numeric, optional) How many iterations to try (default = 1000000).\n"
            "\nResult:\n"
            "[ blockhashes ]     (array) hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n"
            + HelpExampleCli("generate", "11")
        );
    }

    int num_generate = request.params[0].get_int();
    uint64_t max_tries = 1000000;
    if (!request.params[1].isNull()) {
        max_tries = request.params[1].get_int();
    }

    std::shared_ptr<CReserveScript> coinbase_script;
    pwallet->GetScriptForMining(coinbase_script);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbase_script) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    }

    //throw an error if no script was provided
    if (coinbase_script->reserveScript.empty()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available");
    }

    return generateBlocks(coinbase_script, num_generate, max_tries, true);
}

UniValue rescanblockchain(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() > 2) {
        throw std::runtime_error(
            "rescanblockchain (\"start_height\") (\"stop_height\")\n"
            "\nRescan the local blockchain for wallet related transactions.\n"
            "\nArguments:\n"
            "1. \"start_height\"    (numeric, optional) block height where the rescan should start\n"
            "2. \"stop_height\"     (numeric, optional) the last block height that should be scanned\n"
            "\nResult:\n"
            "{\n"
            "  \"start_height\"     (numeric) The block height where the rescan has started. If omitted, rescan started from the genesis block.\n"
            "  \"stop_height\"      (numeric) The height of the last rescanned block. If omitted, rescan stopped at the chain tip.\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("rescanblockchain", "100000 120000")
            + HelpExampleRpc("rescanblockchain", "100000, 120000")
            );
    }

    WalletRescanReserver reserver(pwallet);
    if (!reserver.reserve()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is currently rescanning. Abort existing rescan or wait.");
    }

    CBlockIndex *pindexStart = nullptr;
    CBlockIndex *pindexStop = nullptr;
    CBlockIndex *pChainTip = nullptr;
    {
        LOCK(cs_main);
        pindexStart = chainActive.Genesis();
        pChainTip = chainActive.Tip();

        if (!request.params[0].isNull()) {
            pindexStart = chainActive[request.params[0].get_int()];
            if (!pindexStart) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
            }
        }

        if (!request.params[1].isNull()) {
            pindexStop = chainActive[request.params[1].get_int()];
            if (!pindexStop) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid stop_height");
            }
            else if (pindexStop->nHeight < pindexStart->nHeight) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "stop_height must be greater then start_height");
            }
        }
    }

    // We can't rescan beyond non-pruned blocks, stop and throw an error
    if (fPruneMode) {
        LOCK(cs_main);
        CBlockIndex *block = pindexStop ? pindexStop : pChainTip;
        while (block && block->nHeight >= pindexStart->nHeight) {
            if (!(block->nStatus & BLOCK_HAVE_DATA)) {
                throw JSONRPCError(RPC_MISC_ERROR, "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height.");
            }
            block = block->pprev;
        }
    }

    CBlockIndex *stopBlock = pwallet->ScanForWalletTransactions(pindexStart, pindexStop, reserver, true);
    if (!stopBlock) {
        if (pwallet->IsAbortingRescan()) {
            throw JSONRPCError(RPC_MISC_ERROR, "Rescan aborted.");
        }
        // if we got a nullptr returned, ScanForWalletTransactions did rescan up to the requested stopindex
        stopBlock = pindexStop ? pindexStop : pChainTip;
    }
    else {
        throw JSONRPCError(RPC_MISC_ERROR, "Rescan failed. Potentially corrupted data files.");
    }
    UniValue response(UniValue::VOBJ);
    response.pushKV("start_height", pindexStart->nHeight);
    response.pushKV("stop_height", stopBlock->nHeight);
    return response;
}

UniValue getauxblock(const JSONRPCRequest& request)
{
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);

    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp
          || (request.params.size() != 0 && request.params.size() != 2))
        throw std::runtime_error(
            "getauxblock (hash auxpow)\n"
            "\nCreate or submit a merge-mined block.\n"
            "\nWithout arguments, create a new block and return information\n"
            "required to merge-mine it.  With arguments, submit a solved\n"
            "auxpow for a previously returned block.\n"
            "\nArguments:\n"
            "1. hash      (string, optional) hash of the block to submit\n"
            "2. auxpow    (string, optional) serialised auxpow found\n"
            "\nResult (without arguments):\n"
            "{\n"
            "  \"hash\"               (string) hash of the created block\n"
            "  \"chainid\"            (numeric) chain ID for this block\n"
            "  \"previousblockhash\"  (string) hash of the previous block\n"
            "  \"coinbasevalue\"      (numeric) value of the block's coinbase\n"
            "  \"bits\"               (string) compressed target of the block\n"
            "  \"height\"             (numeric) height of the block\n"
            "  \"_target\"            (string) target in reversed byte order, deprecated\n"
            "}\n"
            "\nResult (with arguments):\n"
            "xxxxx        (boolean) whether the submitted block was correct\n"
            "\nExamples:\n"
            + HelpExampleCli("getauxblock", "")
            + HelpExampleCli("getauxblock", "\"hash\" \"serialised auxpow\"")
            + HelpExampleRpc("getauxblock", "")
            );


    /*
    std::shared_ptr<CReserveScript> coinbaseScript;
    pwallet->GetScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

    // throw an error if no script was provided
    if (!coinbaseScript->reserveScript.size())
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");

    // Create a new block
    if (request.params.size() == 0)
        return AuxMiningCreateBlock(coinbaseScript->reserveScript);
    */

   std::shared_ptr<CScript> coinbaseScript;
   std::shared_ptr<CReserveScript> coinbaseReserveScript;
   bool fReserveUsed = false;

   {
        LOCK(cs_main);
        CBlockIndex* const pindexPrev = chainActive.Tip();
        int64_t nHeight = pindexPrev->nHeight+1;
        const CChainParams& m_params = Params();
        const std::set<CScript>& setAllowedMiners = m_params.GetAllowedLicensedMinersScriptsAtHeight(nHeight);

        if (setAllowedMiners.size() != 0) {
            std::set<CScript>::iterator it = setAllowedMiners.begin();
            // we will take first allowed miner for merged mining, or we can somehow advance iterator
            // to take the script that we exactly need
            coinbaseScript = std::make_shared<CScript>(*it);
        }
        else
        {
            // any script for mining is allowed, back to original scheme
            pwallet->GetScriptForMining(coinbaseReserveScript);
            fReserveUsed = true;
            if (!coinbaseReserveScript) {
                throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
            }
            if (!coinbaseReserveScript->reserveScript.size()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "No coinbase script available (mining requires a wallet)");
            }
            coinbaseScript = std::make_shared<CScript>(coinbaseReserveScript->reserveScript);
        }
   }

    // Create a new block
    if (request.params.size() == 0)
        return AuxMiningCreateBlock(*coinbaseScript);

    /* Submit a block instead.  Note that this need not lock cs_main,
       since ProcessNewBlock below locks it instead.  */
    assert(request.params.size() == 2);
    bool fAccepted = AuxMiningSubmitBlock(request.params[0].get_str(), 
                                          request.params[1].get_str());
    if (fAccepted && fReserveUsed)
        coinbaseReserveScript->KeepScript();

    return fAccepted;
}

#include "../cc/CCfaucet.h"
#include "../cc/CCassets.h"
#include "../cc/CCrewards.h"
#include "../cc/CCdice.h"
#include "../cc/CCfsm.h"
#include "../cc/CCauction.h"
#include "../cc/CClotto.h"
#include "../cc/CCchannels.h"
#include "../cc/CCOracles.h"
#include "../cc/CCGateways.h"
#include "../cc/CCPrices.h"
#include "../cc/CCHeir.h"
#include "../cc/CCMarmara.h"
#include "../cc/CCPayments.h"
#include "../cc/CCPegs.h"

int32_t ensure_CCrequirements(uint8_t evalcode)
{
    CCerror = "";
    if ( ASSETCHAINS_CCDISABLES[evalcode] != 0 || (evalcode == EVAL_MARMARA && ASSETCHAINS_MARMARA == 0) )
    {
        // check if a height activation has been set. 
        LogPrintf( "evalcode.%i activates at height. %i current height.%i\n", evalcode, mapHeightEvalActivate[evalcode], currentheight());
        if ( mapHeightEvalActivate[evalcode] == 0 || currentheight() == 0 || mapHeightEvalActivate[evalcode] > currentheight() )
        {
            LogPrintf("evalcode %d disabled\n",evalcode);
            return(-1);
        }
    }
    if ( NOTARY_PUBKEY33[0] == 0 )
    {
        LogPrintf("no -pubkey set\n");
        return(-1);
    }
    else if ( gArgs.GetBoolArg("-addressindex", DEFAULT_ADDRESSINDEX) == 0 )
    {
        LogPrintf("no -addressindex\n");
        return(-1);
    }
    else if ( gArgs.GetBoolArg("-spentindex", DEFAULT_SPENTINDEX) == 0 )
    {
        LogPrintf("no -spentindex\n");
        return(-1);
    }
    else return(0);
}

UniValue CCaddress(struct CCcontract_info *cp,char *name,std::vector<unsigned char> &pubkey)
{
    UniValue result(UniValue::VOBJ); char destaddr[64],str[64]; CPubKey mypk,pk;
    pk = GetUnspendable(cp,0);
    GetCCaddress(cp,destaddr,pk);
    if ( strcmp(destaddr,cp->unspendableCCaddr) != 0 )
    {
        uint8_t priv[32];
        Myprivkey(priv); // it is assumed the CC's normal address'es -pubkey was used
        LogPrintf("fix mismatched CCaddr %s -> %s\n",cp->unspendableCCaddr,destaddr);
        strcpy(cp->unspendableCCaddr,destaddr);
        memset(priv,0,32);
    }
    result.push_back(Pair("result", "success"));
    sprintf(str,"%sCCAddress",name);
    result.push_back(Pair(str,cp->unspendableCCaddr));
    sprintf(str,"%sCCBalance",name);
    result.push_back(Pair(str,ValueFromAmount(CCaddress_balance(cp->unspendableCCaddr,1))));
    sprintf(str,"%sNormalAddress",name);
    result.push_back(Pair(str,cp->normaladdr));
    sprintf(str,"%sNormalBalance",name);
    result.push_back(Pair(str,ValueFromAmount(CCaddress_balance(cp->normaladdr,0))));
    if (strcmp(name,"Gateways")==0) result.push_back(Pair("GatewaysPubkey","03ea9c062b9652d8eff34879b504eda0717895d27597aaeb60347d65eed96ccb40"));
    if ((strcmp(name,"Channels")==0 || strcmp(name,"Heir")==0) && pubkey.size() == 33)
    {
        sprintf(str,"%sCC1of2Address",name);
        mypk = pubkey2pk(Mypubkey());
        GetCCaddress1of2(cp,destaddr,mypk,pubkey2pk(pubkey));
        result.push_back(Pair(str,destaddr));
        if (GetTokensCCaddress1of2(cp,destaddr,mypk,pubkey2pk(pubkey))>0)
        {
            sprintf(str,"%sCC1of2TokensAddress",name);
            result.push_back(Pair(str,destaddr));
        }
    }
    else if (strcmp(name,"Tokens")!=0)
    {
        if (GetTokensCCaddress(cp,destaddr,pk)>0)
        {
            sprintf(str,"%sCCTokensAddress",name);
            result.push_back(Pair(str,destaddr));
        }
    }
    if ( pubkey.size() == 33 )
    {
        if ( GetCCaddress(cp,destaddr,pubkey2pk(pubkey)) != 0 )
        {
            sprintf(str,"PubkeyCCaddress(%s)",name);
            result.push_back(Pair(str,destaddr));
            sprintf(str,"PubkeyCCbalance(%s)",name);
            result.push_back(Pair(str,ValueFromAmount(CCaddress_balance(destaddr,0))));
        }
    }
    if ( GetCCaddress(cp,destaddr,pubkey2pk(Mypubkey())) != 0 )
    {
        sprintf(str,"myCCAddress(%s)",name);
        result.push_back(Pair(str,destaddr));
        sprintf(str,"myCCbalance(%s)",name);
        result.push_back(Pair(str,ValueFromAmount(CCaddress_balance(destaddr,1))));
    }
    if ( Getscriptaddress(destaddr,(CScript() << Mypubkey() << OP_CHECKSIG)) != 0 )
    {
        result.push_back(Pair("myaddress",destaddr));
        result.push_back(Pair("mybalance",ValueFromAmount(CCaddress_balance(destaddr,0))));
    }
    return(result);
}

UniValue channelsaddress(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;

    cp = CCinit(&C,EVAL_CHANNELS);
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("channelsaddress pubkey\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Channels",pubkey));
}

UniValue cclibaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey; uint8_t evalcode = EVAL_FIRSTUSER;
    if ( request.fHelp || request.params.size() > 2 )
        throw std::runtime_error("cclibaddress [evalcode] [pubkey]\n");
    if ( request.params.size() >= 1 )
    {
        evalcode = atoi(request.params[0].get_str().c_str());
        if ( evalcode < EVAL_FIRSTUSER || evalcode > EVAL_LASTUSER )
            throw std::runtime_error("evalcode not between EVAL_FIRSTUSER and EVAL_LASTUSER\n");
        if ( request.params.size() == 2 )
            pubkey = ParseHex(request.params[1].get_str().c_str());
    }
    cp = CCinit(&C,evalcode);
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( cp == 0 )
        throw std::runtime_error("error creating *cp\n");
    return(CCaddress(cp,(char *)"CClib",pubkey));
}

UniValue cclibinfo(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; uint8_t evalcode = EVAL_FIRSTUSER;
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("cclibinfo\n");
    if ( ensure_CCrequirements(0) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    cp = CCinit(&C,evalcode);
    return(CClib_info(cp));
}

UniValue cclib(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; char *method,*jsonstr=0; uint8_t evalcode = EVAL_FIRSTUSER;
    std::string vobjJsonSerialized;

    if ( request.fHelp || request.params.size() > 3 )
        throw std::runtime_error("cclib method [evalcode] [JSON params]\n");
    if ( ASSETCHAINS_CCLIB.size() == 0 )
        throw std::runtime_error("no -ac_cclib= specified\n");
    if ( ensure_CCrequirements(0) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    method = (char *)request.params[0].get_str().c_str();
    if ( request.params.size() >= 2 )
    {
        evalcode = atoi(request.params[1].get_str().c_str());
        if ( evalcode < EVAL_FIRSTUSER || evalcode > EVAL_LASTUSER )
        {
            //LogPrintf("evalcode.%d vs (%d, %d)\n",evalcode,EVAL_FIRSTUSER,EVAL_LASTUSER);
            throw std::runtime_error("evalcode not between EVAL_FIRSTUSER and EVAL_LASTUSER\n");
        }
        if ( request.params.size() == 3 )
        {
            if (request.params[2].getType() == UniValue::VOBJ) {
                vobjJsonSerialized = request.params[2].write(0, 0);
                jsonstr = (char *)vobjJsonSerialized.c_str();
            }
            else  // VSTR assumed
                jsonstr = (char *)request.params[2].get_str().c_str();
            //fprintf(stderr,"params.(%s %s %s)\n",request.params[0].get_str().c_str(),request.params[1].get_str().c_str(),jsonstr);
        }
    }
    cp = CCinit(&C,evalcode);
    return(CClib(cp,method,jsonstr));
}

UniValue payments_release(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("paymentsrelease \"[%22createtxid%22,amount,(skipminimum)]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsRelease(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_fund(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("paymentsfund \"[%22createtxid%22,amount(,useopret)]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsFund(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_merge(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("paymentsmerge \"[%22createtxid%22]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsMerge(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_txidopret(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("paymentstxidopret \"[allocation,%22scriptPubKey%22(,%22destopret%22)]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsTxidopret(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_create(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("paymentscreate \"[lockedblocks,minamount,%22paytxid0%22,...,%22paytxidN%22]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsCreate(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_airdrop(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("paymentsairdrop \"[lockedblocks,minamount,mintoaddress,top,bottom,fixedFlag,%22excludeAddress%22,...,%22excludeAddressN%22]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsAirdrop(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_airdroptokens(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("payments_airdroptokens \"[%22tokenid%22,lockedblocks,minamount,mintoaddress,top,bottom,fixedFlag,%22excludePubKey%22,...,%22excludePubKeyN%22]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsAirdropTokens(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_info(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("paymentsinfo \"[%22createtxid%22]\"\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsInfo(cp,(char *)request.params[0].get_str().c_str()));
}

UniValue payments_list(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C;
    if ( request.fHelp || request.params.size() != 0 )
        throw std::runtime_error("paymentslist\n");
    if ( ensure_CCrequirements(EVAL_PAYMENTS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    cp = CCinit(&C,EVAL_PAYMENTS);
    return(PaymentsList(cp,(char *)""));
}

UniValue oraclesaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_ORACLES);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("oraclesaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Oracles",pubkey));
}

UniValue pegsaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_PEGS);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("pegssaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Pegs",pubkey));
}

UniValue marmaraaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_MARMARA);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("Marmaraaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Marmara",pubkey));
}

UniValue paymentsaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_PAYMENTS);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("paymentsaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Payments",pubkey));
}

UniValue gatewaysaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_GATEWAYS);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("gatewaysaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Gateways",pubkey));
}

UniValue heiraddress(const JSONRPCRequest& request)
{
	struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
	cp = CCinit(&C,EVAL_HEIR);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("heiraddress pubkey\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pubkey = ParseHex(request.params[0].get_str().c_str());
	return(CCaddress(cp,(char *)"Heir",pubkey));
}

UniValue 
lottoaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_LOTTO);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("lottoaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Lotto",pubkey));
}

UniValue FSMaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_FSM);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("FSMaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"FSM",pubkey));
}

UniValue auctionaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_AUCTION);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("auctionaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Auction",pubkey));
}

UniValue diceaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_DICE);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("diceaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Dice",pubkey));
}

UniValue faucetaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    int error;
    cp = CCinit(&C,EVAL_FAUCET);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("faucetaddress [pubkey]\n");
    error = ensure_CCrequirements(cp->evalcode);
    if ( error < 0 )
        throw std::runtime_error(strprintf("to use CC contracts, you need to launch daemon with valid -pubkey= for an address in your wallet. ERR=%d\n", error));
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Faucet",pubkey));
}

UniValue rewardsaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_REWARDS);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("rewardsaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Rewards",pubkey));
}

UniValue assetsaddress(const JSONRPCRequest& request)
{
	struct CCcontract_info *cp, C; std::vector<unsigned char> pubkey;
	cp = CCinit(&C, EVAL_ASSETS);
	if (request.fHelp || request.params.size() > 1)
		throw std::runtime_error("assetsaddress [pubkey]\n");
	if (ensure_CCrequirements(cp->evalcode) < 0)
		throw std::runtime_error(CC_REQUIREMENTS_MSG);
	if (request.params.size() == 1)
		pubkey = ParseHex(request.params[0].get_str().c_str());
	return(CCaddress(cp, (char *)"Assets", pubkey));
}

UniValue tokenaddress(const JSONRPCRequest& request)
{
    struct CCcontract_info *cp,C; std::vector<unsigned char> pubkey;
    cp = CCinit(&C,EVAL_TOKENS);
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("tokenaddress [pubkey]\n");
    if ( ensure_CCrequirements(cp->evalcode) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    if ( request.params.size() == 1 )
        pubkey = ParseHex(request.params[0].get_str().c_str());
    return(CCaddress(cp,(char *)"Tokens", pubkey));
}

UniValue marmara_poolpayout(const JSONRPCRequest& request)
{
    int32_t firstheight; double perc; char *jsonstr;
    if ( request.fHelp || request.params.size() != 3 )
    {
        // marmarapoolpayout 0.5 2 '[["024131032ed90941e714db8e6dd176fe5a86c9d873d279edecf005c06f773da686",1000],["02ebc786cb83de8dc3922ab83c21f3f8a2f3216940c3bf9da43ce39e2a3a882c92",100]]';
        //marmarapoolpayout 0 2 '[["024131032ed90941e714db8e6dd176fe5a86c9d873d279edecf005c06f773da686",1000]]'
        throw std::runtime_error("marmarapoolpayout perc firstheight \"[[\\\"pubkey\\\":shares], ...]\"\n");
    }
    if ( ensure_CCrequirements(EVAL_MARMARA) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    perc = atof(request.params[0].get_str().c_str()) / 100.;
    firstheight = atol(request.params[1].get_str().c_str());
    jsonstr = (char *)request.params[2].get_str().c_str();
    return(MarmaraPoolPayout(0,firstheight,perc,jsonstr)); // [[pk0, shares0], [pk1, shares1], ...]
}

UniValue marmara_receive(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 batontxid; std::vector<uint8_t> senderpub; int64_t amount; int32_t matures; std::string currency;
    if ( request.fHelp || (request.params.size() != 5 && request.params.size() != 4) )
    {
        // automatic flag -> lsb of matures
        // 1st marmarareceive 028076d42eb20efc10007fafb5ca66a2052523c0d2221e607adf958d1a332159f6 7.5 MARMARA 1440
        // after marmarareceive 039433dc3749aece1bd568f374a45da3b0bc6856990d7da3cd175399577940a775 7.5 MARMARA 1168 d72d87aa0d50436de695c93e2bf3d7273c63c92ef6307913aa01a6ee6a16548b
        throw std::runtime_error("marmarareceive senderpk amount currency matures batontxid\n");
    }
    if ( ensure_CCrequirements(EVAL_MARMARA) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    memset(&batontxid,0,sizeof(batontxid));
    senderpub = ParseHex(request.params[0].get_str().c_str());
    if (senderpub.size()!= 33)
    {
        ERR_RESULT("invalid sender pubkey");
        return result;
    }
    amount = atof(request.params[1].get_str().c_str()) * COIN + 0.00000000499999;
    currency = request.params[2].get_str();
    if ( request.params.size() == 5 )
    {
        matures = atol(request.params[3].get_str().c_str());
        batontxid = Parseuint256((char *)request.params[4].get_str().c_str());
    } else matures = atol(request.params[3].get_str().c_str()) + chainActive.LastTip()->GetHeight() + 1;
    return(MarmaraReceive(0,pubkey2pk(senderpub),amount,currency,matures,batontxid,true));
}

UniValue marmara_issue(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 approvaltxid; std::vector<uint8_t> receiverpub; int64_t amount; int32_t matures; std::string currency;
    if ( request.fHelp || request.params.size() != 5 )
    {
        // marmaraissue 039433dc3749aece1bd568f374a45da3b0bc6856990d7da3cd175399577940a775 7.5 MARMARA 1168 32da4cb3e886ee42de90b4a15042d71169077306badf909099c5c5c692df3f27
        // marmaraissue 039433dc3749aece1bd568f374a45da3b0bc6856990d7da3cd175399577940a775 700 MARMARA 2629 11fe8bf1de80c2ef69124d08907f259aef7f41e3a632ca2d48ad072a8c8f3078 -> 335df3a5dd6b92a3d020c9465d4d76e0d8242126106b83756dcecbad9813fdf3

        throw std::runtime_error("marmaraissue receiverpk amount currency matures approvaltxid\n");
    }
    if ( ensure_CCrequirements(EVAL_MARMARA) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    receiverpub = ParseHex(request.params[0].get_str().c_str());
    if (receiverpub.size()!= 33)
    {
        ERR_RESULT("invalid receiverpub pubkey");
        return result;
    }
    amount = atof(request.params[1].get_str().c_str()) * COIN + 0.00000000499999;
    currency = request.params[2].get_str();
    matures = atol(request.params[3].get_str().c_str());
    approvaltxid = Parseuint256((char *)request.params[4].get_str().c_str());
    return(MarmaraIssue(0,'I',pubkey2pk(receiverpub),amount,currency,matures,approvaltxid,zeroid));
}

UniValue marmara_transfer(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 approvaltxid,batontxid; std::vector<uint8_t> receiverpub; int64_t amount; int32_t matures; std::string currency; std::vector<uint256> creditloop;
    if ( request.fHelp || request.params.size() != 5 )
    {
        // marmaratransfer 028076d42eb20efc10007fafb5ca66a2052523c0d2221e607adf958d1a332159f6 7.5 MARMARA 1168 1506c774e4b2804a6e25260920840f4cfca8d1fb400e69fe6b74b8e593dbedc5
        throw std::runtime_error("marmaratransfer receiverpk amount currency matures approvaltxid\n");
    }
    if ( ensure_CCrequirements(EVAL_MARMARA) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    receiverpub = ParseHex(request.params[0].get_str().c_str());
    if (receiverpub.size()!= 33)
    {
        ERR_RESULT("invalid receiverpub pubkey");
        return result;
    }
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    amount = atof(request.params[1].get_str().c_str()) * COIN + 0.00000000499999;
    currency = request.params[2].get_str();
    matures = atol(request.params[3].get_str().c_str());
    approvaltxid = Parseuint256((char *)request.params[4].get_str().c_str());
    if ( MarmaraGetbatontxid(creditloop,batontxid,approvaltxid) < 0 )
        throw std::runtime_error("couldnt find batontxid\n");
    return(MarmaraIssue(0,'T',pubkey2pk(receiverpub),amount,currency,matures,approvaltxid,batontxid));
}

UniValue marmara_info(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); CPubKey issuerpk; std::vector<uint8_t> issuerpub; int64_t minamount,maxamount; int32_t firstheight,lastheight; std::string currency;
    if ( request.fHelp || request.params.size() < 4 || request.params.size() > 6 )
    {
        throw std::runtime_error("marmarainfo firstheight lastheight minamount maxamount [currency issuerpk]\n");
    }
    if ( ensure_CCrequirements(EVAL_MARMARA) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    firstheight = atol(request.params[0].get_str().c_str());
    lastheight = atol(request.params[1].get_str().c_str());
    minamount = atof(request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    maxamount = atof(request.params[3].get_str().c_str()) * COIN + 0.00000000499999;
    if ( request.params.size() >= 5 )
        currency = request.params[4].get_str();
    if ( request.params.size() == 6 )
    {
        issuerpub = ParseHex(request.params[5].get_str().c_str());
        if ( issuerpub.size()!= 33 )
        {
            ERR_RESULT("invalid issuer pubkey");
            return result;
        }
        issuerpk = pubkey2pk(issuerpub);
    }
    result = MarmaraInfo(issuerpk,firstheight,lastheight,minamount,maxamount,currency);
    return(result);
}

UniValue marmara_creditloop(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 txid;
    if ( request.fHelp || request.params.size() != 1 )
    {
        // marmaracreditloop 010ff7f9256cefe3b5dee3d72c0eeae9fc6f34884e6f32ffe5b60916df54a9be
        throw std::runtime_error("marmaracreditloop txid\n");
    }
    if ( ensure_CCrequirements(EVAL_MARMARA) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    result = MarmaraCreditloop(txid);
    return(result);
}

UniValue marmara_settlement(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 batontxid;
    if ( request.fHelp || request.params.size() != 1 )
    {
        // marmarasettlement 010ff7f9256cefe3b5dee3d72c0eeae9fc6f34884e6f32ffe5b60916df54a9be
        // marmarasettlement ff3e259869196f3da9b5ea3f9e088a76c4fc063cf36ab586b652e121d441a603
        throw std::runtime_error("marmarasettlement batontxid\n");
    }
    if ( ensure_CCrequirements(EVAL_MARMARA) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    batontxid = Parseuint256((char *)request.params[0].get_str().c_str());
    result = MarmaraSettlement(0,batontxid);
    return(result);
}

UniValue marmara_lock(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int64_t amount; int32_t height;
    if ( request.fHelp || request.params.size() > 2 || request.params.size() == 0 )
    {
        throw std::runtime_error("marmaralock amount unlockht\n");
    }
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    amount = atof(request.params[0].get_str().c_str()) * COIN + 0.00000000499999;
    if ( request.params.size() == 2 )
        height = atol(request.params[1].get_str().c_str());
    else height = chainActive.LastTip()->GetHeight() + 1;
    return(MarmaraLock(0,amount,height));
}

UniValue channelslist(const JSONRPCRequest& request)
{
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("channelslist\n");
    if ( ensure_CCrequirements(EVAL_CHANNELS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    return(ChannelsList(CPubKey()));
}

UniValue channelsinfo(const JSONRPCRequest& request)
{
    uint256 opentxid;
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("channelsinfo [opentxid]\n");
    if ( ensure_CCrequirements(EVAL_CHANNELS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    opentxid=zeroid;
    if (request.params.size() > 0 && !request.params[0].isNull() && !request.params[0].get_str().empty())
        opentxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(ChannelsInfo(CPubKey(),opentxid));
}

UniValue channelsopen(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int32_t numpayments; int64_t payment; std::vector<unsigned char> destpub; struct CCcontract_info *cp,C;
    uint256 tokenid=zeroid;

    cp = CCinit(&C,EVAL_CHANNELS);
    if ( request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error("channelsopen destpubkey numpayments payment [tokenid]\n");
    if ( ensure_CCrequirements(EVAL_CHANNELS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    destpub = ParseHex(request.params[0].get_str().c_str());
    numpayments = atoi(request.params[1].get_str().c_str());
    payment = atol(request.params[2].get_str().c_str());
    if (request.params.size()==4)
    {
        tokenid=Parseuint256((char *)request.params[3].get_str().c_str());
    }
    result = ChannelOpen(CPubKey(),0,pubkey2pk(destpub),numpayments,payment,tokenid);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue channelspayment(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); struct CCcontract_info *cp,C; uint256 opentxid,secret=zeroid; int32_t n; int64_t amount;
    cp = CCinit(&C,EVAL_CHANNELS);
    if ( request.fHelp || request.params.size() < 2 ||  request.params.size() >3 )
        throw std::runtime_error("channelspayment opentxid amount [secret]\n");
    if ( ensure_CCrequirements(EVAL_CHANNELS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    opentxid = Parseuint256((char *)request.params[0].get_str().c_str());
    amount = atoi((char *)request.params[1].get_str().c_str());
    if (request.params.size() > 2 && !request.params[2].isNull() && !request.params[2].get_str().empty())
    {
        secret = Parseuint256((char *)request.params[2].get_str().c_str());
    }
    result = ChannelPayment(CPubKey(),0,opentxid,amount,secret);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue channelsclose(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); struct CCcontract_info *cp,C; uint256 opentxid;
    cp = CCinit(&C,EVAL_CHANNELS);
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("channelsclose opentxid\n");
    if ( ensure_CCrequirements(EVAL_CHANNELS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    opentxid = Parseuint256((char *)request.params[0].get_str().c_str());
    result = ChannelClose(CPubKey(),0,opentxid);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue channelsrefund(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); struct CCcontract_info *cp,C; uint256 opentxid,closetxid;
    cp = CCinit(&C,EVAL_CHANNELS);
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("channelsrefund opentxid closetxid\n");
    if ( ensure_CCrequirements(EVAL_CHANNELS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    opentxid = Parseuint256((char *)request.params[0].get_str().c_str());
    closetxid = Parseuint256((char *)request.params[1].get_str().c_str());
    result = ChannelRefund(CPubKey(),0,opentxid,closetxid);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue rewardscreatefunding(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); char *name; int64_t funds,APR,minseconds,maxseconds,mindeposit; std::string hex;
    if ( request.fHelp || request.params.size() > 6 || request.params.size() < 2 )
        throw std::runtime_error("rewardscreatefunding name amount APR mindays maxdays mindeposit\n");
    if ( ensure_CCrequirements(EVAL_REWARDS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
   // default to OOT request.params
    APR = 5 * COIN;
    minseconds = maxseconds = 60 * 3600 * 24;
    mindeposit = 100 * COIN;
    name = (char *)request.params[0].get_str().c_str();
    funds = atof(request.params[1].get_str().c_str()) * COIN + 0.00000000499999;

    if (!VALID_PLAN_NAME(name)) {
        ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
        return(result);
    }

    if ( funds <= 0 ) {
        ERR_RESULT("funds must be positive");
        return result;
    }
    if ( request.params.size() > 2 )
    {
        APR = atof(request.params[2].get_str().c_str()) * COIN;
        if ( APR > REWARDSCC_MAXAPR )
        {
            ERR_RESULT("25% APR is maximum");
            return result;
        }
        if ( request.params.size() > 3 )
        {
            minseconds = atol(request.params[3].get_str().c_str()) * 3600 * 24;
            if ( minseconds < 0 ) {
                ERR_RESULT("mindays must be non-negative");
                return result;
            }
            if ( request.params.size() > 4 )
            {
                maxseconds = atol(request.params[4].get_str().c_str()) * 3600 * 24;
                if ( maxseconds <= 0 ) {
                    ERR_RESULT("maxdays must be positive");
                    return result;
                }
                if ( maxseconds < minseconds ) {
                    ERR_RESULT("maxdays must be greater than mindays");
                    return result;
                }
                if ( request.params.size() > 5 )
                    mindeposit = atof(request.params[5].get_str().c_str()) * COIN + 0.00000000499999;
                    if ( mindeposit <= 0 ) {
                        ERR_RESULT("mindeposit must be positive");
                        return result;
                    }
            }
        }
    }
    hex = RewardsCreateFunding(0,name,funds,APR,minseconds,maxseconds,mindeposit);
    if ( hex.size() > 0 )
    {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    } else ERR_RESULT("couldnt create rewards funding transaction");
    return(result);
}

UniValue rewardslock(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); char *name; uint256 fundingtxid; int64_t amount; std::string hex;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("rewardslock name fundingtxid amount\n");
    if ( ensure_CCrequirements(EVAL_REWARDS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    fundingtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    amount = atof(request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    hex = RewardsLock(0,name,fundingtxid,amount);

    if (!VALID_PLAN_NAME(name)) {
            ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
            return(result);
    }
    if ( CCerror != "" ){
        ERR_RESULT(CCerror);
    } else if ( amount > 0 ) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT( "couldnt create rewards lock transaction");
    } else ERR_RESULT("amount must be positive");
    return(result);
}

UniValue rewardsaddfunding(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); char *name; uint256 fundingtxid; int64_t amount; std::string hex;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("rewardsaddfunding name fundingtxid amount\n");
    if ( ensure_CCrequirements(EVAL_REWARDS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    fundingtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    amount = atof(request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    hex = RewardsAddfunding(0,name,fundingtxid,amount);

    if (!VALID_PLAN_NAME(name)) {
            ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
            return(result);
    }
    if (CCerror != "") {
        ERR_RESULT(CCerror);
    } else if (amount > 0) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else {
            result.push_back(Pair("result", "error"));
            result.push_back(Pair("error", "couldnt create rewards addfunding transaction"));
        }
    } else {
            ERR_RESULT("funding amount must be positive");
    }
    return(result);
}

UniValue rewardsunlock(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string hex; char *name; uint256 fundingtxid,txid;
    if ( request.fHelp || request.params.size() > 3 || request.params.size() < 2 )
        throw std::runtime_error("rewardsunlock name fundingtxid [txid]\n");
    if ( ensure_CCrequirements(EVAL_REWARDS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    fundingtxid = Parseuint256((char *)request.params[1].get_str().c_str());

    if (!VALID_PLAN_NAME(name)) {
            ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
            return(result);
    }
    if ( request.params.size() > 2 )
        txid = Parseuint256((char *)request.params[2].get_str().c_str());
    else memset(&txid,0,sizeof(txid));
    hex = RewardsUnlock(0,name,fundingtxid,txid);
    if (CCerror != "") {
        ERR_RESULT(CCerror);
    } else if ( hex.size() > 0 ) {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    } else ERR_RESULT("couldnt create rewards unlock transaction");
    return(result);
}

UniValue rewardslist(const JSONRPCRequest& request)
{
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("rewardslist\n");
    if ( ensure_CCrequirements(EVAL_REWARDS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    return(RewardsList());
}

UniValue rewardsinfo(const JSONRPCRequest& request)
{
    uint256 fundingtxid;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("rewardsinfo fundingtxid\n");
    if ( ensure_CCrequirements(EVAL_REWARDS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    fundingtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(RewardsInfo(fundingtxid));
}

UniValue gatewayslist(const JSONRPCRequest& request)
{
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("gatewayslist\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    return(GatewaysList());
}

UniValue gatewaysexternaladdress(const JSONRPCRequest& request)
{
    uint256 bindtxid; CPubKey pubkey;

    if ( request.fHelp || request.params.size() != 2)
        throw std::runtime_error("gatewaysexternaladdress bindtxid pubkey\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    pubkey = ParseHex(request.params[1].get_str().c_str());
    return(GatewaysExternalAddress(bindtxid,pubkey));
}

UniValue gatewaysdumpprivkey(const JSONRPCRequest& request)
{
    uint256 bindtxid;

    if ( request.fHelp || request.params.size() != 2)
        throw std::runtime_error("gatewaysdumpprivkey bindtxid address\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    std::string strAddress = request.params[1].get_str();
    CTxDestination dest = DecodeDestination(strAddress);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid transparent address");
    }
    const CKeyID *keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    }
    CKey vchSecret;
    if (!pwalletMain->GetKey(*keyID, vchSecret)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    }
    return(GatewaysDumpPrivKey(bindtxid,vchSecret));
}

UniValue gatewaysinfo(const JSONRPCRequest& request)
{
    uint256 txid;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("gatewaysinfo bindtxid\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(GatewaysInfo(txid));
}

UniValue gatewaysbind(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 tokenid,oracletxid; int32_t i; int64_t totalsupply; std::vector<CPubKey> pubkeys;
    uint8_t M,N,p1,p2,p3,p4=0; std::string coin; std::vector<unsigned char> pubkey;

    if ( request.fHelp || request.params.size() < 10 )
        throw std::runtime_error("gatewaysbind tokenid oracletxid coin tokensupply M N pubkey(s) pubtype p2shtype wiftype [taddr]\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    oracletxid = Parseuint256((char *)request.params[1].get_str().c_str());
    coin = request.params[2].get_str();
    totalsupply = atol((char *)request.params[3].get_str().c_str());
    M = atoi((char *)request.params[4].get_str().c_str());
    N = atoi((char *)request.params[5].get_str().c_str());
    if ( M > N || N == 0 || N > 15 || totalsupply < COIN/100 || tokenid == zeroid )
    {
        throw std::runtime_error("illegal M or N > 15 or tokensupply or invalid tokenid\n");
    }
    if ( request.params.size() < 6+N+3 )
    {
        throw std::runtime_error("not enough parameters for N pubkeys\n");
    }
    for (i=0; i<N; i++)
    {       
        pubkey = ParseHex(request.params[6+i].get_str().c_str());
        if (pubkey.size()!= 33)
        {
            throw std::runtime_error("invalid destination pubkey");
        }
        pubkeys.push_back(pubkey2pk(pubkey));
    }
    p1 = atoi((char *)request.params[6+N].get_str().c_str());
    p2 = atoi((char *)request.params[6+N+1].get_str().c_str());
    p3 = atoi((char *)request.params[6+N+2].get_str().c_str());
    if (request.params.size() == 9+N+1) p4 = atoi((char *)request.params[9+N].get_str().c_str());
    result = GatewaysBind(CPubKey(),0,coin,tokenid,totalsupply,oracletxid,M,N,pubkeys,p1,p2,p3,p4);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue gatewaysdeposit(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int32_t i,claimvout,height; int64_t amount; std::string coin,deposithex; uint256 bindtxid,cointxid; std::vector<uint8_t>proof,destpub,pubkey;
    if ( request.fHelp || request.params.size() != 9 )
        throw std::runtime_error("gatewaysdeposit bindtxid height coin cointxid claimvout deposithex proof destpub amount\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    height = atoi((char *)request.params[1].get_str().c_str());
    coin = request.params[2].get_str();
    cointxid = Parseuint256((char *)request.params[3].get_str().c_str());
    claimvout = atoi((char *)request.params[4].get_str().c_str());
    deposithex = request.params[5].get_str();
    proof = ParseHex(request.params[6].get_str());
    destpub = ParseHex(request.params[7].get_str());
    amount = atof((char *)request.params[8].get_str().c_str()) * COIN + 0.00000000499999;
    if ( amount <= 0 || claimvout < 0 )
    {
        throw std::runtime_error("invalid param: amount, numpks or claimvout\n");
    }
    if (destpub.size()!= 33)
    {
        throw std::runtime_error("invalid destination pubkey");
    }
    result = GatewaysDeposit(CPubKey(),0,bindtxid,height,coin,cointxid,claimvout,deposithex,proof,pubkey2pk(destpub),amount);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue gatewaysclaim(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string coin; uint256 bindtxid,deposittxid; std::vector<uint8_t>destpub; int64_t amount;
    if ( request.fHelp || request.params.size() != 5 )
        throw std::runtime_error("gatewaysclaim bindtxid coin deposittxid destpub amount\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    deposittxid = Parseuint256((char *)request.params[2].get_str().c_str());
    destpub = ParseHex(request.params[3].get_str());
    amount = atof((char *)request.params[4].get_str().c_str()) * COIN + 0.00000000499999;
    if (destpub.size()!= 33)
    {
        throw std::runtime_error("invalid destination pubkey");
    }
    result = GatewaysClaim(CPubKey(),0,bindtxid,coin,deposittxid,pubkey2pk(destpub),amount);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue gatewayswithdraw(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 bindtxid; int64_t amount; std::string coin; std::vector<uint8_t> withdrawpub;
    if ( request.fHelp || request.params.size() != 4 )
        throw std::runtime_error("gatewayswithdraw bindtxid coin withdrawpub amount\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    withdrawpub = ParseHex(request.params[2].get_str());
    amount = atof((char *)request.params[3].get_str().c_str()) * COIN + 0.00000000499999;
    if (withdrawpub.size()!= 33)
    {
        throw std::runtime_error("invalid destination pubkey");
    }
    result = GatewaysWithdraw(CPubKey(),0,bindtxid,coin,pubkey2pk(withdrawpub),amount);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue gatewayspartialsign(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string coin,parthex; uint256 txid;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("gatewayspartialsign txidaddr refcoin hex\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    parthex = request.params[2].get_str();
    result = GatewaysPartialSign(CPubKey(),0,txid,coin,parthex);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue gatewayscompletesigning(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 withdrawtxid; std::string txhex,coin;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("gatewayscompletesigning withdrawtxid coin hex\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    withdrawtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    txhex = request.params[2].get_str();
    result = GatewaysCompleteSigning(CPubKey(),0,withdrawtxid,coin,txhex);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue gatewaysmarkdone(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 completetxid; std::string coin;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("gatewaysmarkdone completesigningtx coin\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    completetxid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    result = GatewaysMarkDone(CPubKey(),0,completetxid,coin);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue gatewayspendingdeposits(const JSONRPCRequest& request)
{
    uint256 bindtxid; std::string coin;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("gatewayspendingdeposits bindtxid coin\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    return(GatewaysPendingDeposits(CPubKey(),bindtxid,coin));
}

UniValue gatewayspendingwithdraws(const JSONRPCRequest& request)
{
    uint256 bindtxid; std::string coin;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("gatewayspendingwithdraws bindtxid coin\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    return(GatewaysPendingWithdraws(CPubKey(),bindtxid,coin));
}

UniValue gatewaysprocessed(const JSONRPCRequest& request)
{
    uint256 bindtxid; std::string coin;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("gatewaysprocessed bindtxid coin\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    bindtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    coin = request.params[1].get_str();
    return(GatewaysProcessedWithdraws(CPubKey(),bindtxid,coin));
}

UniValue oracleslist(const JSONRPCRequest& request)
{
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("oracleslist\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    return(OraclesList());
}

UniValue oraclesinfo(const JSONRPCRequest& request)
{
    uint256 txid;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("oraclesinfo oracletxid\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(OracleInfo(txid));
}

UniValue oraclesfund(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 txid;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("oraclesfund oracletxid\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    result = OracleFund(CPubKey(),0,txid);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue oraclesregister(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 txid; int64_t datafee;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("oraclesregister oracletxid datafee\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    if ( (datafee= atol((char *)request.params[1].get_str().c_str())) == 0 )
        datafee = atof((char *)request.params[1].get_str().c_str()) * COIN + 0.00000000499999;
    result = OracleRegister(CPubKey(),0,txid,datafee);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue oraclessubscribe(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 txid; int64_t amount; std::vector<unsigned char> pubkey;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("oraclessubscribe oracletxid publisher amount\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    pubkey = ParseHex(request.params[1].get_str().c_str());
    amount = atof((char *)request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    result = OracleSubscribe(CPubKey(),0,txid,pubkey2pk(pubkey),amount);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue oraclessample(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 oracletxid,txid; int32_t num; char *batonaddr;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("oraclessample oracletxid txid\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    oracletxid = Parseuint256((char *)request.params[0].get_str().c_str());
    txid = Parseuint256((char *)request.params[1].get_str().c_str());
    return(OracleDataSample(oracletxid,txid));
}

UniValue oraclessamples(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 txid; int32_t num; char *batonaddr;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("oraclessamples oracletxid batonaddress num\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    batonaddr = (char *)request.params[1].get_str().c_str();
    num = atoi((char *)request.params[2].get_str().c_str());
    return(OracleDataSamples(txid,batonaddr,num));
}

UniValue oraclesdata(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 txid; std::vector<unsigned char> data;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("oraclesdata oracletxid hexstr\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    txid = Parseuint256((char *)request.params[0].get_str().c_str());
    data = ParseHex(request.params[1].get_str().c_str());
    result = OracleData(CPubKey(),0,txid,data);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue oraclescreate(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string name,description,format;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("oraclescreate name description format\n");
    if ( ensure_CCrequirements(EVAL_ORACLES) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    name = request.params[0].get_str();
    description = request.params[1].get_str();
    format = request.params[2].get_str();
    result = OracleCreate(CPubKey(),0,name,description,format);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue FSMcreate(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string name,states,hex;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("FSMcreate name states\n");
    if ( ensure_CCrequirements(EVAL_FSM) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = request.params[0].get_str();
    states = request.params[1].get_str();
    hex = FSMCreate(0,name,states);
    if ( hex.size() > 0 )
    {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    } else result.push_back(Pair("error", "couldnt create FSM transaction"));
    return(result);
}

UniValue FSMlist(const JSONRPCRequest& request)
{
    uint256 tokenid;
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("FSMlist\n");
    if ( ensure_CCrequirements(EVAL_FSM) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    return(FSMList());
}

UniValue FSMinfo(const JSONRPCRequest& request)
{
    uint256 FSMtxid;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("FSMinfo fundingtxid\n");
    if ( ensure_CCrequirements(EVAL_FSM) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    FSMtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(FSMInfo(FSMtxid));
}

UniValue faucetinfo(const JSONRPCRequest& request)
{
    uint256 fundingtxid;
    if ( request.fHelp || request.params.size() != 0 )
        throw std::runtime_error("faucetinfo\n");
    if ( ensure_CCrequirements(EVAL_FAUCET) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    return(FaucetInfo());
}

UniValue faucetfund(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int64_t funds; std::string hex;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("faucetfund amount\n");
    funds = atof(request.params[0].get_str().c_str()) * COIN + 0.00000000499999;
    if ( ensure_CCrequirements(EVAL_FAUCET) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);

    //const CKeyStore& keystore = *pwalletMain;
    //LOCK2(cs_main, pwalletMain->cs_wallet);

    bool lockWallet = false;
//    if (!mypk.IsValid())   // if mypk is not set then it is a local call, use local wallet in AddNormalInputs
    lockWallet = true;

    if (funds > 0) 
    {
        if (lockWallet)
        {
            ENTER_CRITICAL_SECTION(cs_main);
            ENTER_CRITICAL_SECTION(pwalletMain->cs_wallet);
        }
        result = FaucetFund(CPubKey(), 0,(uint64_t) funds);
        if (lockWallet)
        {
            LEAVE_CRITICAL_SECTION(pwalletMain->cs_wallet);
            LEAVE_CRITICAL_SECTION(cs_main);
        }

        if ( result[JSON_HEXTX].getValStr().size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            //result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt create faucet funding transaction");
    } else ERR_RESULT( "funding amount must be positive");
    return(result);
}

UniValue faucetget(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string hex;
    if ( request.fHelp || request.params.size() !=0 )
        throw std::runtime_error("faucetget\n");
    if ( ensure_CCrequirements(EVAL_FAUCET) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);

    bool lockWallet = false;
//    if (!mypk.IsValid())   // if mypk is not set then it is a local call, use wallet in AddNormalInputs (see check for this there)
    lockWallet = true;

    //const CKeyStore& keystore = *pwalletMain;
    //LOCK2(cs_main, pwalletMain->cs_wallet);

    if (lockWallet)
    {
        // use this instead LOCK2 because we need conditional wallet lock
        ENTER_CRITICAL_SECTION(cs_main);
        ENTER_CRITICAL_SECTION(pwalletMain->cs_wallet);
    }
    result = FaucetGet(CPubKey(), 0);
    if (lockWallet)
    {
        LEAVE_CRITICAL_SECTION(pwalletMain->cs_wallet);
        LEAVE_CRITICAL_SECTION(cs_main);
    }

    if (result[JSON_HEXTX].getValStr().size() > 0 ) {
        result.push_back(Pair("result", "success"));
        //result.push_back(Pair("hex", hex));
    } else ERR_RESULT("couldnt create faucet get transaction");
    return(result);
}

UniValue dicefund(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int64_t funds,minbet,maxbet,maxodds,timeoutblocks; std::string hex; char *name;
    if ( request.fHelp || request.params.size() != 6 )
        throw std::runtime_error("dicefund name funds minbet maxbet maxodds timeoutblocks\n");
    if ( ensure_CCrequirements(EVAL_DICE) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    funds = atof(request.params[1].get_str().c_str()) * COIN + 0.00000000499999;
    minbet = atof(request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    maxbet = atof(request.params[3].get_str().c_str()) * COIN + 0.00000000499999;
    maxodds = atol(request.params[4].get_str().c_str());
    timeoutblocks = atol(request.params[5].get_str().c_str());

    if (!VALID_PLAN_NAME(name)) {
        ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
        return(result);
    }

    hex = DiceCreateFunding(0,name,funds,minbet,maxbet,maxodds,timeoutblocks);
    if (CCerror != "") {
        ERR_RESULT(CCerror);
    } else if ( hex.size() > 0 ) {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    } else  {
        ERR_RESULT( "couldnt create dice funding transaction");
    }
    return(result);
}

UniValue diceaddfunds(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); char *name; uint256 fundingtxid; int64_t amount; std::string hex;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("diceaddfunds name fundingtxid amount\n");
    if ( ensure_CCrequirements(EVAL_DICE) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    fundingtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    amount = atof(request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    if (!VALID_PLAN_NAME(name)) {
        ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
        return(result);
    }
    if ( amount > 0 ) {
        hex = DiceAddfunding(0,name,fundingtxid,amount);
        if (CCerror != "") {
            ERR_RESULT(CCerror);
        } else if ( hex.size() > 0 ) {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt create dice addfunding transaction");
    } else ERR_RESULT("amount must be positive");
    return(result);
}

UniValue dicebet(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string hex,error; uint256 fundingtxid; int64_t amount,odds; char *name;
    if ( request.fHelp || request.params.size() != 4 )
        throw std::runtime_error("dicebet name fundingtxid amount odds\n");
    if ( ensure_CCrequirements(EVAL_DICE) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    fundingtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    amount = atof(request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    odds = atol(request.params[3].get_str().c_str());

    if (!VALID_PLAN_NAME(name)) {
        ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
        return(result);
    }
    if (amount > 0 && odds > 0) {
        hex = DiceBet(0,name,fundingtxid,amount,odds);
        RETURN_IF_ERROR(CCerror);
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        }
    } else {
        ERR_RESULT("amount and odds must be positive");
    }
    return(result);
}

UniValue dicefinish(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint8_t funcid; char *name; uint256 entropyused,fundingtxid,bettxid; std::string hex; int32_t r,entropyvout;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("dicefinish name fundingtxid bettxid\n");
    if ( ensure_CCrequirements(EVAL_DICE) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    if (!VALID_PLAN_NAME(name)) {
        ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
        return(result);
    }
    fundingtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    bettxid = Parseuint256((char *)request.params[2].get_str().c_str());
    hex = DiceBetFinish(funcid,entropyused,entropyvout,&r,0,name,fundingtxid,bettxid,1,zeroid,-1);
    if ( CCerror != "" )
    {
        ERR_RESULT(CCerror);
    } else if ( hex.size() > 0 )
    {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
        if ( funcid != 0 )
        {
            char funcidstr[2];
            funcidstr[0] = funcid;
            funcidstr[1] = 0;
            result.push_back(Pair("funcid", funcidstr));
        }
    } else ERR_RESULT( "couldnt create dicefinish transaction");
    return(result);
}

UniValue dicestatus(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); char *name; uint256 fundingtxid,bettxid; std::string status,error; double winnings;
    if ( request.fHelp || (request.params.size() != 2 && request.params.size() != 3) )
        throw std::runtime_error("dicestatus name fundingtxid bettxid\n");
    if ( ensure_CCrequirements(EVAL_DICE) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = (char *)request.params[0].get_str().c_str();
    if (!VALID_PLAN_NAME(name)) {
        ERR_RESULT(strprintf("Plan name can be at most %d ASCII characters",PLAN_NAME_MAX));
        return(result);
    }
    fundingtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    memset(&bettxid,0,sizeof(bettxid));
    if ( request.params.size() == 3 )
        bettxid = Parseuint256((char *)request.params[2].get_str().c_str());
    winnings = DiceStatus(0,name,fundingtxid,bettxid);
    RETURN_IF_ERROR(CCerror);

    result.push_back(Pair("result", "success"));
    if ( winnings >= 0. )
    {
        if ( winnings > 0. )
        {
            if ( request.params.size() == 3 )
            {
                int64_t val;
                val = winnings * COIN + 0.00000000499999;
                result.push_back(Pair("status", "win"));
                result.push_back(Pair("won", ValueFromAmount(val)));
            }
            else
            {
                result.push_back(Pair("status", "finalized"));
                result.push_back(Pair("n", (int64_t)winnings));
            }
        }
        else
        {
            if ( request.params.size() == 3 )
                result.push_back(Pair("status", "loss"));
            else result.push_back(Pair("status", "no pending bets"));
        }
    } else result.push_back(Pair("status", "bet still pending"));
    return(result);
}

UniValue dicelist(const JSONRPCRequest& request)
{
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("dicelist\n");
    if ( ensure_CCrequirements(EVAL_DICE) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    return(DiceList());
}

UniValue diceinfo(const JSONRPCRequest& request)
{
    uint256 fundingtxid;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("diceinfo fundingtxid\n");
    if ( ensure_CCrequirements(EVAL_DICE) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    fundingtxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(DiceInfo(fundingtxid));
}

UniValue tokenlist(const JSONRPCRequest& request)
{
    uint256 tokenid;
    if ( request.fHelp || request.params.size() > 0 )
        throw std::runtime_error("tokenlist\n");
    if ( ensure_CCrequirements(EVAL_TOKENS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    return(TokenList());
}

UniValue tokeninfo(const JSONRPCRequest& request)
{
    uint256 tokenid;
    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("tokeninfo tokenid\n");
    if ( ensure_CCrequirements(EVAL_TOKENS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(TokenInfo(tokenid));
}

UniValue tokenorders(const JSONRPCRequest& request)
{
    uint256 tokenid;
    if ( request.fHelp || request.params.size() > 1 )
        throw std::runtime_error("tokenorders [tokenid]\n"
                            "returns token orders for the tokenid or all available token orders if tokenid is not set\n"
                            "(this rpc supports only fungible tokens)\n" "\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
	if (request.params.size() == 1) {
		tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
		if (tokenid == zeroid) 
			throw std::runtime_error("incorrect tokenid\n");
        return AssetOrders(tokenid, CPubKey(), 0);
	}
    else {
        // throw std::runtime_error("no tokenid\n");
        return AssetOrders(zeroid, CPubKey(), 0);
    }
}


UniValue mytokenorders(const JSONRPCRequest& request)
{
    uint256 tokenid;
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error("mytokenorders [evalcode]\n"
                            "returns all the token orders for mypubkey\n"
                            "if evalcode is set then returns mypubkey token orders for non-fungible tokens with this evalcode\n" "\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    uint8_t additionalEvalCode = 0;
    if (request.params.size() == 1)
        additionalEvalCode = strtol(request.params[0].get_str().c_str(), NULL, 0);  // supports also 0xEE-like values

    return AssetOrders(zeroid, Mypubkey(), additionalEvalCode);
}

UniValue tokenbalance(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 tokenid; uint64_t balance; std::vector<unsigned char> pubkey; struct CCcontract_info *cp,C;
	CCerror.clear();

    if ( request.fHelp || request.params.size() > 2 )
        throw std::runtime_error("tokenbalance tokenid [pubkey]\n");
    if ( ensure_CCrequirements(EVAL_TOKENS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    
	LOCK(cs_main);

    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    if ( request.params.size() == 2 )
        pubkey = ParseHex(request.params[1].get_str().c_str());
    else 
		pubkey = Mypubkey();

    balance = GetTokenBalance(pubkey2pk(pubkey),tokenid);

	if (CCerror.empty()) {
		char destaddr[64];

		result.push_back(Pair("result", "success"));
        cp = CCinit(&C,EVAL_TOKENS);
		if (GetCCaddress(cp, destaddr, pubkey2pk(pubkey)) != 0)
			result.push_back(Pair("CCaddress", destaddr));

		result.push_back(Pair("tokenid", request.params[0].get_str()));
		result.push_back(Pair("balance", (int64_t)balance));
	}
	else {
		ERR_RESULT(CCerror);
	}

    return(result);
}

UniValue tokencreate(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ);
    std::string name, description, hextx; 
    std::vector<uint8_t> nonfungibleData;
    int64_t supply; // changed from uin64_t to int64_t for this 'if ( supply <= 0 )' to work as expected

    CCerror.clear();

    if ( request.fHelp || request.params.size() > 4 || request.params.size() < 2 )
        throw std::runtime_error("tokencreate name supply [description][data]\n");
    if ( ensure_CCrequirements(EVAL_TOKENS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    name = request.params[0].get_str();
    if (name.size() == 0 || name.size() > 32)   {
        ERR_RESULT("Token name must not be empty and up to 32 characters");
        return(result);
    }

    supply = atof(request.params[1].get_str().c_str()) * COIN + 0.00000000499999;   // what for is this '+0.00000000499999'? it will be lost while converting double to int64_t (dimxy)
    if (supply <= 0)    {
        ERR_RESULT("Token supply must be positive");
        return(result);
    }
    
    if (request.params.size() >= 3)     {
        description = request.params[2].get_str();
        if (description.size() > 4096)   {
            ERR_RESULT("Token description must be <= 4096 characters");
            return(result);
        }
    }
    
    if (request.params.size() == 4)    {
        nonfungibleData = ParseHex(request.params[3].get_str());
        if (nonfungibleData.size() > IGUANA_MAXSCRIPTSIZE) // opret limit
        {
            ERR_RESULT("Non-fungible data size must be <= " + std::to_string(IGUANA_MAXSCRIPTSIZE));
            return(result);
        }
        if( nonfungibleData.empty() ) {
            ERR_RESULT("Non-fungible data incorrect");
            return(result);
        }
    }

    hextx = CreateToken(0, supply, name, description, nonfungibleData);
    if( hextx.size() > 0 )     {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hextx));
    } 
    else 
        ERR_RESULT(CCerror);
    return(result);
}

UniValue tokentransfer(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); 
    std::string hex; 
    int64_t amount; 
    uint256 tokenid;
    
    CCerror.clear();

    if ( request.fHelp || request.params.size() != 3)
        throw std::runtime_error("tokentransfer tokenid destpubkey amount\n");
    if ( ensure_CCrequirements(EVAL_TOKENS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    std::vector<unsigned char> pubkey(ParseHex(request.params[1].get_str().c_str()));
    //amount = atol(request.params[2].get_str().c_str());
	amount = atoll(request.params[2].get_str().c_str()); // dimxy changed to prevent loss of significance
    if( tokenid == zeroid )    {
        ERR_RESULT("invalid tokenid");
        return(result);
    }
    if( amount <= 0 )    {
        ERR_RESULT("amount must be positive");
        return(result);
    }

    hex = TokenTransfer(0, tokenid, pubkey, amount);

    if( !CCerror.empty() )   {
        ERR_RESULT(CCerror);
    }
    else {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    }
    return(result);
}

UniValue tokenconvert(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string hex; int32_t evalcode; int64_t amount; uint256 tokenid;
    if ( request.fHelp || request.params.size() != 4 )
        throw std::runtime_error("tokenconvert evalcode tokenid pubkey amount\n");
    if ( ensure_CCrequirements(EVAL_ASSETS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    evalcode = atoi(request.params[0].get_str().c_str());
    tokenid = Parseuint256((char *)request.params[1].get_str().c_str());
    std::vector<unsigned char> pubkey(ParseHex(request.params[2].get_str().c_str()));
    //amount = atol(request.params[3].get_str().c_str());
	amount = atoll(request.params[3].get_str().c_str()); // dimxy changed to prevent loss of significance
    if ( tokenid == zeroid )
    {
        ERR_RESULT("invalid tokenid");
        return(result);
    }
    if ( amount <= 0 )
    {
        ERR_RESULT("amount must be positive");
        return(result);
    }

	ERR_RESULT("deprecated");
	return(result);

/*    hex = AssetConvert(0,tokenid,pubkey,amount,evalcode);
    if (amount > 0) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt convert tokens");
    } else {
        ERR_RESULT("amount must be positive");
    }
    return(result); */
}

UniValue tokenbid(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int64_t bidamount,numtokens; std::string hex; double price; uint256 tokenid;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("tokenbid numtokens tokenid price\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    //numtokens = atoi(request.params[0].get_str().c_str());
	numtokens = atoll(request.params[0].get_str().c_str());  // dimxy changed to prevent loss of significance
    tokenid = Parseuint256((char *)request.params[1].get_str().c_str());
    price = atof(request.params[2].get_str().c_str());
    bidamount = (price * numtokens) * COIN + 0.0000000049999;
    if ( price <= 0 )
    {
        ERR_RESULT("price must be positive");
        return(result);
    }
    if ( tokenid == zeroid )
    {
        ERR_RESULT("invalid tokenid");
        return(result);
    }
    if ( bidamount <= 0 )
    {
        ERR_RESULT("bid amount must be positive");
        return(result);
    }
    hex = CreateBuyOffer(0,bidamount,tokenid,numtokens);
    if (price > 0 && numtokens > 0) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt create bid");
    } else {
        ERR_RESULT("price and numtokens must be positive");
    }
    return(result);
}

UniValue tokencancelbid(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string hex; int32_t i; uint256 tokenid,bidtxid;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("tokencancelbid tokenid bidtxid\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    bidtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    if ( tokenid == zeroid || bidtxid == zeroid )
    {
        result.push_back(Pair("error", "invalid parameter"));
        return(result);
    }
    hex = CancelBuyOffer(0,tokenid,bidtxid);
    if ( hex.size() > 0 )
    {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    } else ERR_RESULT("couldnt cancel bid");
    return(result);
}

UniValue tokenfillbid(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int64_t fillamount; std::string hex; uint256 tokenid,bidtxid;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("tokenfillbid tokenid bidtxid fillamount\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    bidtxid = Parseuint256((char *)request.params[1].get_str().c_str());
    // fillamount = atol(request.params[2].get_str().c_str());
	fillamount = atoll(request.params[2].get_str().c_str());		// dimxy changed to prevent loss of significance
    if ( fillamount <= 0 )
    {
        ERR_RESULT("fillamount must be positive");
        return(result);
    }
    if ( tokenid == zeroid || bidtxid == zeroid )
    {
        ERR_RESULT("must provide tokenid and bidtxid");
        return(result);
    }
    hex = FillBuyOffer(0,tokenid,bidtxid,fillamount);
    if ( hex.size() > 0 )
    {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    } else ERR_RESULT("couldnt fill bid");
    return(result);
}

UniValue tokenask(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int64_t askamount,numtokens; std::string hex; double price; uint256 tokenid;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("tokenask numtokens tokenid price\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    //numtokens = atoi(request.params[0].get_str().c_str());
	numtokens = atoll(request.params[0].get_str().c_str());			// dimxy changed to prevent loss of significance
    tokenid = Parseuint256((char *)request.params[1].get_str().c_str());
    price = atof(request.params[2].get_str().c_str());
    askamount = (price * numtokens) * COIN + 0.0000000049999;
	//std::cerr << std::boolalpha << "tokenask(): (tokenid == zeroid) is "  << (tokenid == zeroid) << " (numtokens <= 0) is " << (numtokens <= 0) << " (price <= 0) is " << (price <= 0) << " (askamount <= 0) is " << (askamount <= 0) << std::endl;
    if ( tokenid == zeroid || numtokens <= 0 || price <= 0 || askamount <= 0 )
    {
        ERR_RESULT("invalid parameter");
        return(result);
    }
    hex = CreateSell(0,numtokens,tokenid,askamount);
    if (price > 0 && numtokens > 0) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt create ask");
    } else {
        ERR_RESULT("price and numtokens must be positive");
    }
    return(result);
}

UniValue tokenswapask(const JSONRPCRequest& request)
{
    static uint256 zeroid;
    UniValue result(UniValue::VOBJ); int64_t askamount,numtokens; std::string hex; double price; uint256 tokenid,otherid;
    if ( request.fHelp || request.params.size() != 4 )
        throw std::runtime_error("tokenswapask numtokens tokenid otherid price\n");
    if ( ensure_CCrequirements(EVAL_ASSETS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    //numtokens = atoi(request.params[0].get_str().c_str());
	numtokens = atoll(request.params[0].get_str().c_str());			// dimxy changed to prevent loss of significance
    tokenid = Parseuint256((char *)request.params[1].get_str().c_str());
    otherid = Parseuint256((char *)request.params[2].get_str().c_str());
    price = atof(request.params[3].get_str().c_str());
    askamount = (price * numtokens);
    hex = CreateSwap(0,numtokens,tokenid,otherid,askamount);
    if (price > 0 && numtokens > 0) {
        if ( hex.size() > 0 )
        {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt create swap");
    } else {
        ERR_RESULT("price and numtokens must be positive");
    }
    return(result);
}

UniValue tokencancelask(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); std::string hex; int32_t i; uint256 tokenid,asktxid;
    if ( request.fHelp || request.params.size() != 2 )
        throw std::runtime_error("tokencancelask tokenid asktxid\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    asktxid = Parseuint256((char *)request.params[1].get_str().c_str());
    if ( tokenid == zeroid || asktxid == zeroid )
    {
        result.push_back(Pair("error", "invalid parameter"));
        return(result);
    }
    hex = CancelSell(0,tokenid,asktxid);
    if ( hex.size() > 0 )
    {
        result.push_back(Pair("result", "success"));
        result.push_back(Pair("hex", hex));
    } else ERR_RESULT("couldnt cancel ask");
    return(result);
}

UniValue tokenfillask(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int64_t fillunits; std::string hex; uint256 tokenid,asktxid;
    if ( request.fHelp || request.params.size() != 3 )
        throw std::runtime_error("tokenfillask tokenid asktxid fillunits\n");
    if (ensure_CCrequirements(EVAL_ASSETS) < 0 || ensure_CCrequirements(EVAL_TOKENS) < 0)
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    asktxid = Parseuint256((char *)request.params[1].get_str().c_str());
    //fillunits = atol(request.params[2].get_str().c_str());
	fillunits = atoll(request.params[2].get_str().c_str());	 // dimxy changed to prevent loss of significance
    if ( fillunits <= 0 )
    {
        ERR_RESULT("fillunits must be positive");
        return(result);
    }
    if ( tokenid == zeroid || asktxid == zeroid )
    {
        result.push_back(Pair("error", "invalid parameter"));
        return(result);
    }
    hex = FillSell(0,tokenid,zeroid,asktxid,fillunits);
    if (fillunits > 0) {
        if (CCerror != "") {
            ERR_RESULT(CCerror);
        } else if ( hex.size() > 0) {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else {
            ERR_RESULT("couldnt fill ask");
        }
    } else {
        ERR_RESULT("fillunits must be positive");
    }
    return(result);
}

UniValue tokenfillswap(const JSONRPCRequest& request)
{
    static uint256 zeroid;
    UniValue result(UniValue::VOBJ); int64_t fillunits; std::string hex; uint256 tokenid,otherid,asktxid;
    if ( request.fHelp || request.params.size() != 4 )
        throw std::runtime_error("tokenfillswap tokenid otherid asktxid fillunits\n");
    if ( ensure_CCrequirements(EVAL_ASSETS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    LOCK2(cs_main, pwalletMain->cs_wallet);
    tokenid = Parseuint256((char *)request.params[0].get_str().c_str());
    otherid = Parseuint256((char *)request.params[1].get_str().c_str());
    asktxid = Parseuint256((char *)request.params[2].get_str().c_str());
    //fillunits = atol(request.params[3].get_str().c_str());
	fillunits = atoll(request.params[3].get_str().c_str());  // dimxy changed to prevent loss of significance
    hex = FillSell(0,tokenid,otherid,asktxid,fillunits);
    if (fillunits > 0) {
        if ( hex.size() > 0 ) {
            result.push_back(Pair("result", "success"));
            result.push_back(Pair("hex", hex));
        } else ERR_RESULT("couldnt fill bid");
    } else {
        ERR_RESULT("fillunits must be positive");
    }
    return(result);
}

// heir contract functions for coins and tokens
UniValue heirfund(const JSONRPCRequest& request)
{
	UniValue result(UniValue::VOBJ);
	uint256 tokenid = zeroid;
	int64_t amount;
	int64_t inactivitytime;
	std::string hex;
	std::vector<unsigned char> pubkey;
	std::string name, memo;

        CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
	if (!EnsureWalletIsAvailable(pwallet,request.fHelp))
	    return NullUniValue;

	if (request.fHelp || request.params.size() != 5 && request.params.size() != 6)
		throw std::runtime_error("heirfund funds heirname heirpubkey inactivitytime memo [tokenid]\n");
	if (ensure_CCrequirements(EVAL_HEIR) < 0)
		throw std::runtime_error(CC_REQUIREMENTS_MSG);

	const CKeyStore& keystore = *pwalletMain;
	LOCK2(cs_main, pwalletMain->cs_wallet);

	if (request.params.size() == 6)	// tokens in satoshis:
		amount = atoll(request.params[0].get_str().c_str());
    	else { // coins:
        	amount = 0;   
        	if (!ParseFixedPoint(request.params[0].get_str(), 8, &amount))  // using ParseFixedPoint instead atof to avoid small round errors
            		amount = -1; // set error
    	}
	if (amount <= 0) {
		result.push_back(Pair("result", "error"));
		result.push_back(Pair("error", "incorrect amount"));
		return result;
	}

	name = request.params[1].get_str();

	pubkey = ParseHex(request.params[2].get_str().c_str());
	if (!pubkey2pk(pubkey).IsValid()) {
		result.push_back(Pair("result", "error"));
		result.push_back(Pair("error", "incorrect pubkey"));
		return result;
	}

	inactivitytime = atoll(request.params[3].get_str().c_str());
	if (inactivitytime <= 0) {
		result.push_back(Pair("result", "error"));
		result.push_back(Pair("error", "incorrect inactivity time"));
		return result;
	}

	memo = request.params[4].get_str();

	if (request.params.size() == 6) {
		tokenid = Parseuint256((char*)request.params[5].get_str().c_str());
		if (tokenid == zeroid) {
			result.push_back(Pair("result", "error"));
			result.push_back(Pair("error", "incorrect tokenid"));
			return result;
		}
	}

	if( tokenid == zeroid )
		result = HeirFundCoinCaller(0, amount, name, pubkey2pk(pubkey), inactivitytime, memo);
	else
		result = HeirFundTokenCaller(0, amount, name, pubkey2pk(pubkey), inactivitytime, memo, tokenid);

	return result;
}

UniValue heiradd(const JSONRPCRequest& request)
{
	UniValue result; 
	uint256 fundingtxid;
	int64_t amount;
	int64_t inactivitytime;
	std::string hex;
	std::vector<unsigned char> pubkey;
	std::string name;

        CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
	if (!EnsureWalletIsAvailable(pwallet,request.fHelp))
	    return NullUniValue;

	if (request.fHelp || request.params.size() != 2)
		throw std::runtime_error("heiradd funds fundingtxid\n");
	if (ensure_CCrequirements(EVAL_HEIR) < 0)
		throw std::runtime_error(CC_REQUIREMENTS_MSG);

	const CKeyStore& keystore = *pwalletMain;
	LOCK2(cs_main, pwalletMain->cs_wallet);

	std::string strAmount = request.params[0].get_str();
	fundingtxid = Parseuint256((char*)request.params[1].get_str().c_str());

	result = HeirAddCaller(fundingtxid, 0, strAmount);
	return result;
}

UniValue heirclaim(const JSONRPCRequest& request)
{
	UniValue result; uint256 fundingtxid;

        CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
	if (!EnsureWalletIsAvailable(pwallet,request.fHelp))
	    return NullUniValue;
	if (request.fHelp || request.params.size() != 2)
		throw std::runtime_error("heirclaim funds fundingtxid\n");
	if (ensure_CCrequirements(EVAL_HEIR) < 0)
		throw std::runtime_error(CC_REQUIREMENTS_MSG);

	const CKeyStore& keystore = *pwalletMain;
	LOCK2(cs_main, pwalletMain->cs_wallet);

    	std::string strAmount = request.params[0].get_str();
	fundingtxid = Parseuint256((char*)request.params[1].get_str().c_str());
	result = HeirClaimCaller(fundingtxid, 0, strAmount);
	return result;
}

UniValue heirinfo(const JSONRPCRequest& request)
{
	uint256 fundingtxid;
	if (request.fHelp || request.params.size() != 1) 
		throw std::runtime_error("heirinfo fundingtxid\n");
    if ( ensure_CCrequirements(EVAL_HEIR) < 0 )
	    throw std::runtime_error(CC_REQUIREMENTS_MSG);
	fundingtxid = Parseuint256((char*)request.params[0].get_str().c_str());
	return (HeirInfo(fundingtxid));
}

UniValue heirlist(const JSONRPCRequest& request)
{
	if (request.fHelp || request.params.size() != 0) 
		throw std::runtime_error("heirlist\n");
    if ( ensure_CCrequirements(EVAL_HEIR) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
	return (HeirList());
}

UniValue pegscreate(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); int32_t i; std::vector<uint256> txids;
    uint8_t N; uint256 txid; int64_t amount;

    if ( request.fHelp || request.params.size()<3)
        throw std::runtime_error("pegscreate amount N bindtxid1 [bindtxid2 ...]\n");
    if ( ensure_CCrequirements(EVAL_PEGS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    amount = atof((char *)request.params[0].get_str().c_str()) * COIN + 0.00000000499999;
    N = atoi((char *)request.params[1].get_str().c_str());
    if ( request.params.size() < N+1 )
    {
        throw std::runtime_error("not enough parameters for N pegscreate\n");
    }
    for (i=0; i<N; i++)
    {       
        txid = Parseuint256(request.params[i+2].get_str().c_str());
        txids.push_back(txid);
    }
    result = PegsCreate(CPubKey(),0,amount,txids);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue pegsfund(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 pegstxid,tokenid; int64_t amount;


    if ( request.fHelp || request.params.size()!=3)
        throw std::runtime_error("pegsfund pegstxid tokenid amount\n");
    if ( ensure_CCrequirements(EVAL_PEGS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    const CKeyStore& keystore = *pwalletMain;
    pegstxid = Parseuint256(request.params[0].get_str().c_str());
    tokenid = Parseuint256(request.params[1].get_str().c_str());
    amount = atof((char *)request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    result = PegsFund(CPubKey(),0,pegstxid,tokenid,amount);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue pegsget(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 pegstxid,tokenid; int64_t amount;

    if ( request.fHelp || request.params.size()!=3)
        throw std::runtime_error("pegsget pegstxid tokenid amount\n");
    if ( ensure_CCrequirements(EVAL_PEGS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256(request.params[0].get_str().c_str());
    tokenid = Parseuint256(request.params[1].get_str().c_str());
    amount = atof((char *)request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    result = PegsGet(CPubKey(),0,pegstxid,tokenid,amount);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue pegsredeem(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 pegstxid,tokenid; int64_t amount;

    if ( request.fHelp || request.params.size()!=2)
        throw std::runtime_error("pegsredeem pegstxid tokenid\n");
    if ( ensure_CCrequirements(EVAL_PEGS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256(request.params[0].get_str().c_str());
    tokenid = Parseuint256(request.params[1].get_str().c_str());
    result = PegsRedeem(CPubKey(),0,pegstxid,tokenid);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue pegsliquidate(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 pegstxid,tokenid,accounttxid;

    if ( request.fHelp || request.params.size()!=3)
        throw std::runtime_error("pegsliquidate pegstxid tokenid accounttxid\n");
    if ( ensure_CCrequirements(EVAL_PEGS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256(request.params[0].get_str().c_str());
    tokenid = Parseuint256(request.params[1].get_str().c_str());
    accounttxid = Parseuint256(request.params[2].get_str().c_str());
    result = PegsLiquidate(CPubKey(),0,pegstxid,tokenid,accounttxid);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue pegsexchange(const JSONRPCRequest& request)
{
    UniValue result(UniValue::VOBJ); uint256 pegstxid,tokenid,accounttxid; int64_t amount;

    if ( request.fHelp || request.params.size()!=3)
        throw std::runtime_error("pegsexchange pegstxid tokenid amount\n");
    if ( ensure_CCrequirements(EVAL_PEGS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256(request.params[0].get_str().c_str());
    tokenid = Parseuint256(request.params[1].get_str().c_str());
    amount = atof((char *)request.params[2].get_str().c_str()) * COIN + 0.00000000499999;
    result = PegsExchange(CPubKey(),0,pegstxid,tokenid,amount);
    if ( result[JSON_HEXTX].getValStr().size() > 0  )
    {
        result.push_back(Pair("result", "success"));
    }
    return(result);
}

UniValue pegsaccounthistory(const JSONRPCRequest& request)
{
    uint256 pegstxid;

    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("pegsaccounthistory pegstxid\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(PegsAccountHistory(CPubKey(),pegstxid));
}

UniValue pegsaccountinfo(const JSONRPCRequest& request)
{
    uint256 pegstxid;

    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("pegsaccountinfo pegstxid\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(PegsAccountInfo(CPubKey(),pegstxid));
}

UniValue pegsworstaccounts(const JSONRPCRequest& request)
{
    uint256 pegstxid;

    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("pegsworstaccounts pegstxid\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(PegsWorstAccounts(pegstxid));
}

UniValue pegsinfo(const JSONRPCRequest& request)
{
    uint256 pegstxid;

    if ( request.fHelp || request.params.size() != 1 )
        throw std::runtime_error("pegsinfo pegstxid\n");
    if ( ensure_CCrequirements(EVAL_GATEWAYS) < 0 )
        throw std::runtime_error(CC_REQUIREMENTS_MSG);
    pegstxid = Parseuint256((char *)request.params[0].get_str().c_str());
    return(PegsInfo(pegstxid));
}

extern UniValue abortrescan(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue dumpprivkey(const JSONRPCRequest& request); // in rpcdump.cpp
extern UniValue importprivkey(const JSONRPCRequest& request);
extern UniValue importaddress(const JSONRPCRequest& request);
extern UniValue importpubkey(const JSONRPCRequest& request);
extern UniValue dumpwallet(const JSONRPCRequest& request);
extern UniValue importwallet(const JSONRPCRequest& request);
extern UniValue importprunedfunds(const JSONRPCRequest& request);
extern UniValue removeprunedfunds(const JSONRPCRequest& request);
extern UniValue importmulti(const JSONRPCRequest& request);
extern UniValue rescanblockchain(const JSONRPCRequest& request);

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           argNames
    //  --------------------- ------------------------    -----------------------  ----------
    { "rawtransactions",    "fundrawtransaction",       &fundrawtransaction,       {"hexstring","options","iswitness"} },
    { "hidden",             "resendwallettransactions", &resendwallettransactions, {} },
    { "wallet",             "abandontransaction",       &abandontransaction,       {"txid"} },
    { "wallet",             "abortrescan",              &abortrescan,              {} },
    { "wallet",             "addmultisigaddress",       &addmultisigaddress,       {"nrequired","keys","account","address_type"} },
    { "hidden",             "addwitnessaddress",        &addwitnessaddress,        {"address","p2sh"} },
    { "wallet",             "backupwallet",             &backupwallet,             {"destination"} },
    { "wallet",             "bumpfee",                  &bumpfee,                  {"txid", "options"} },
    { "wallet",             "dumpprivkey",              &dumpprivkey,              {"address"}  },
    { "wallet",             "dumpwallet",               &dumpwallet,               {"filename"} },
    { "wallet",             "encryptwallet",            &encryptwallet,            {"passphrase"} },
    { "wallet",             "getaccountaddress",        &getaccountaddress,        {"account"} },
    { "wallet",             "getaccount",               &getaccount,               {"address"} },
    { "wallet",             "getaddressesbyaccount",    &getaddressesbyaccount,    {"account"} },
    { "wallet",             "getbalance",               &getbalance,               {"account","minconf","include_watchonly"} },
    { "wallet",             "getnewaddress",            &getnewaddress,            {"account","address_type"} },
    { "wallet",             "getrawchangeaddress",      &getrawchangeaddress,      {"address_type"} },
    { "wallet",             "getreceivedbyaccount",     &getreceivedbyaccount,     {"account","minconf"} },
    { "wallet",             "getreceivedbyaddress",     &getreceivedbyaddress,     {"address","minconf"} },
    { "wallet",             "gettransaction",           &gettransaction,           {"txid","include_watchonly"} },
    { "wallet",             "getunconfirmedbalance",    &getunconfirmedbalance,    {} },
    { "wallet",             "getwalletinfo",            &getwalletinfo,            {} },
    { "wallet",             "importmulti",              &importmulti,              {"requests","options"} },
    { "wallet",             "importprivkey",            &importprivkey,            {"privkey","label","rescan"} },
    { "wallet",             "importwallet",             &importwallet,             {"filename"} },
    { "wallet",             "importaddress",            &importaddress,            {"address","label","rescan","p2sh"} },
    { "wallet",             "importprunedfunds",        &importprunedfunds,        {"rawtransaction","txoutproof"} },
    { "wallet",             "importpubkey",             &importpubkey,             {"pubkey","label","rescan"} },
    { "wallet",             "keypoolrefill",            &keypoolrefill,            {"newsize"} },
    { "wallet",             "listaccounts",             &listaccounts,             {"minconf","include_watchonly"} },
    { "wallet",             "listaddressgroupings",     &listaddressgroupings,     {} },
    { "wallet",             "listlockunspent",          &listlockunspent,          {} },
    { "wallet",             "listreceivedbyaccount",    &listreceivedbyaccount,    {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listreceivedbyaddress",    &listreceivedbyaddress,    {"minconf","include_empty","include_watchonly"} },
    { "wallet",             "listsinceblock",           &listsinceblock,           {"blockhash","target_confirmations","include_watchonly","include_removed"} },
    { "wallet",             "listtransactions",         &listtransactions,         {"account","count","skip","include_watchonly"} },
    { "wallet",             "listunspent",              &listunspent,              {"minconf","maxconf","addresses","include_unsafe","query_options"} },
    { "wallet",             "listwallets",              &listwallets,              {} },
    { "wallet",             "lockunspent",              &lockunspent,              {"unlock","transactions"} },
    { "wallet",             "move",                     &movecmd,                  {"fromaccount","toaccount","amount","minconf","comment"} },
    { "wallet",             "sendfrom",                 &sendfrom,                 {"fromaccount","toaddress","amount","minconf","comment","comment_to"} },
    { "wallet",             "sendmany",                 &sendmany,                 {"fromaccount","amounts","minconf","comment","subtractfeefrom","replaceable","conf_target","estimate_mode"} },
    { "wallet",             "sendtoaddress",            &sendtoaddress,            {"address","amount","comment","comment_to","subtractfeefromamount","replaceable","conf_target","estimate_mode"} },
    { "wallet",             "setaccount",               &setaccount,               {"address","account"} },
    { "wallet",             "settxfee",                 &settxfee,                 {"amount"} },
    { "wallet",             "signmessage",              &signmessage,              {"address","message"} },
    { "wallet",             "walletlock",               &walletlock,               {} },
    { "wallet",             "walletpassphrasechange",   &walletpassphrasechange,   {"oldpassphrase","newpassphrase"} },
    { "wallet",             "walletpassphrase",         &walletpassphrase,         {"passphrase","timeout"} },
    { "wallet",             "removeprunedfunds",        &removeprunedfunds,        {"txid"} },
    { "wallet",             "rescanblockchain",         &rescanblockchain,         {"start_height", "stop_height"} },

    // auction
    { "auction",       "auctionaddress",    &auctionaddress,  {"pubkey"} },

    // lotto
    { "lotto",       "lottoaddress",    &lottoaddress,  {"pubkey"} },

    // fsm
    { "FSM",       "FSMaddress",   &FSMaddress, {"pubkey"} },
    { "FSM", "FSMcreate",    &FSMcreate,  {} },
    { "FSM",   "FSMlist",      &FSMlist,    {} },
    { "FSM",   "FSMinfo",      &FSMinfo,    {} },

    // rewards
    { "rewards",       "rewardslist",       &rewardslist,     {} },
    { "rewards",       "rewardsinfo",       &rewardsinfo,     {} },
    { "rewards",       "rewardscreatefunding",       &rewardscreatefunding,     {} },
    { "rewards",       "rewardsaddfunding",       &rewardsaddfunding,     {} },
    { "rewards",       "rewardslock",       &rewardslock,     {} },
    { "rewards",       "rewardsunlock",     &rewardsunlock,   {} },
    { "rewards",       "rewardsaddress",    &rewardsaddress,  {"pubkey"} },

    // faucet
    { "faucet",       "faucetinfo",      &faucetinfo,         {} },
    { "faucet",       "faucetfund",      &faucetfund,         {} },
    { "faucet",       "faucetget",       &faucetget,          {} },
    { "faucet",       "faucetaddress",   &faucetaddress,      {"pubkey"} },

		// Heir
	{ "heir",       "heiraddress",   &heiraddress,      {"pubkey"} },
	{ "heir",       "heirfund",   &heirfund,      {} },
	{ "heir",       "heiradd",    &heiradd,        {} },
	{ "heir",       "heirclaim",  &heirclaim,     {} },
/*	{ "heir",       "heirfundtokens",   &heirfundtokens,      {} },
	{ "heir",       "heiraddtokens",    &heiraddtokens,        {} },
	{ "heir",       "heirclaimtokens",  &heirclaimtokens,     {} },*/
	{ "heir",       "heirinfo",   &heirinfo,      {} },
	{ "heir",       "heirlist",   &heirlist,      {} },

    // Channels
    { "channels",       "channelsaddress",   &channelsaddress,   {"pubkey"} },
    { "channels",       "channelslist",      &channelslist,      {} },
    { "channels",       "channelsinfo",      &channelsinfo,      {} },
    { "channels",       "channelsopen",      &channelsopen,      {} },
    { "channels",       "channelspayment",   &channelspayment,   {} },
    { "channels",       "channelsclose",     &channelsclose,      {} },
    { "channels",       "channelsrefund",    &channelsrefund,    {} },

    // Oracles
    { "oracles",       "oraclesaddress",   &oraclesaddress,     {"pubkey"} },
    { "oracles",       "oracleslist",      &oracleslist,        {} },
    { "oracles",       "oraclesinfo",      &oraclesinfo,        {} },
    { "oracles",       "oraclescreate",    &oraclescreate,      {} },
    { "oracles",       "oraclesfund",  &oraclesfund,    {} },
    { "oracles",       "oraclesregister",  &oraclesregister,    {} },
    { "oracles",       "oraclessubscribe", &oraclessubscribe,   {} },
    { "oracles",       "oraclesdata",      &oraclesdata,        {} },
    { "oracles",       "oraclessample",   &oraclessample,     {} },
    { "oracles",       "oraclessamples",   &oraclessamples,     {} },

    // Pegs
    { "pegs",       "pegsaddress",   &pegsaddress,      {"pubkey"} },

    // Marmara
    { "marmara",       "marmaraaddress",   &marmaraaddress,      {"pubkey"} },
    { "marmara",       "marmarapoolpayout",   &marmara_poolpayout,      {} },
    { "marmara",       "marmarareceive",   &marmara_receive,      {} },
    { "marmara",       "marmaraissue",   &marmara_issue,      {} },
    { "marmara",       "marmaratransfer",   &marmara_transfer,      {} },
    { "marmara",       "marmarainfo",   &marmara_info,      {} },
    { "marmara",       "marmaracreditloop",   &marmara_creditloop,      {} },
    { "marmara",       "marmarasettlement",   &marmara_settlement,      {} },
    { "marmara",       "marmaralock",   &marmara_lock,      {} },

    { "CClib",       "cclibaddress",   &cclibaddress,      {} },
    { "CClib",       "cclibinfo",   &cclibinfo,      {} },
    { "CClib",       "cclib",   &cclib,      {} },

    // Payments
    { "payments",       "paymentsaddress",   &paymentsaddress,       {"pubkey"} },
    { "payments",       "paymentstxidopret", &payments_txidopret,    {"allocation","scriptPubKey","destopret"} },
    { "payments",       "paymentscreate",    &payments_create,       {"lockedblocks","minamount","paytxid"} },
    { "payments",       "paymentsairdrop",   &payments_airdrop,      {} },
    { "payments",       "paymentsairdroptokens",   &payments_airdroptokens,      {} },
    { "payments",       "paymentslist",      &payments_list,         {} },
    { "payments",       "paymentsinfo",      &payments_info,         {} },
    { "payments",       "paymentsfund",      &payments_fund,         {"createtxid","amount","useopret"} },
    { "payments",       "paymentsmerge",     &payments_merge,        {"createtxid"} },
    { "payments",       "paymentsrelease",   &payments_release,      {"createtxid","amount","skipminimum"} },

    // Gateways
    { "gateways",       "gatewaysaddress",   &gatewaysaddress,      {"pubkey"} },
    { "gateways",       "gatewayslist",      &gatewayslist,         {} },
    { "gateways",       "gatewaysexternaladdress",      &gatewaysexternaladdress,         {} },
    { "gateways",       "gatewaysdumpprivkey",      &gatewaysdumpprivkey,         {} },
    { "gateways",       "gatewaysinfo",      &gatewaysinfo,         {} },
    { "gateways",       "gatewaysbind",      &gatewaysbind,         {} },
    { "gateways",       "gatewaysdeposit",   &gatewaysdeposit,      {} },
    { "gateways",       "gatewaysclaim",     &gatewaysclaim,        {} },
    { "gateways",       "gatewayswithdraw",  &gatewayswithdraw,     {} },
    { "gateways",       "gatewayspartialsign",  &gatewayspartialsign,     {} },
    { "gateways",       "gatewayscompletesigning",  &gatewayscompletesigning,     {} },
    { "gateways",       "gatewaysmarkdone",  &gatewaysmarkdone,     {} },
    { "gateways",       "gatewayspendingdeposits",   &gatewayspendingdeposits,      {} },
    { "gateways",       "gatewayspendingwithdraws",   &gatewayspendingwithdraws,      {} },
    { "gateways",       "gatewaysprocessed",   &gatewaysprocessed,  {} },

    // dice
    { "dice",       "dicelist",      &dicelist,         {} },
    { "dice",       "diceinfo",      &diceinfo,         {} },
    { "dice",       "dicefund",      &dicefund,         {} },
    { "dice",       "diceaddfunds",  &diceaddfunds,     {} },
    { "dice",       "dicebet",       &dicebet,          {} },
    { "dice",       "dicefinish",    &dicefinish,       {} },
    { "dice",       "dicestatus",    &dicestatus,       {} },
    { "dice",       "diceaddress",   &diceaddress,      {"pubkey"} },

    // tokens & assets
	{ "tokens",       "assetsaddress",     &assetsaddress,      {"pubkey"} },
    { "tokens",       "tokeninfo",        &tokeninfo,         {} },
    { "tokens",       "tokenlist",        &tokenlist,         {} },
    { "tokens",       "tokenorders",      &tokenorders,       {} },
    { "tokens",       "mytokenorders",    &mytokenorders,     {} },
    { "tokens",       "tokenaddress",     &tokenaddress,      {"pubkey"} },
    { "tokens",       "tokenbalance",     &tokenbalance,      {} },
    { "tokens",       "tokencreate",      &tokencreate,       {} },
    { "tokens",       "tokentransfer",    &tokentransfer,     {} },
    { "tokens",       "tokenbid",         &tokenbid,          {} },
    { "tokens",       "tokencancelbid",   &tokencancelbid,    {} },
    { "tokens",       "tokenfillbid",     &tokenfillbid,      {} },
    { "tokens",       "tokenask",         &tokenask,          {} },
    //{ "tokens",       "tokenswapask",     &tokenswapask,      {} },
    { "tokens",       "tokencancelask",   &tokencancelask,    {} },
    { "tokens",       "tokenfillask",     &tokenfillask,      {} },
    //{ "tokens",       "tokenfillswap",    &tokenfillswap,     {} },
    { "tokens",       "tokenconvert", &tokenconvert, {} },

    // pegs
    { "pegs",       "pegscreate",     &pegscreate,      {} },
    { "pegs",       "pegsfund",         &pegsfund,      {} },
    { "pegs",       "pegsget",         &pegsget,        {} },
    { "pegs",       "pegsredeem",         &pegsredeem,        {} },
    { "pegs",       "pegsliquidate",         &pegsliquidate,        {} },
    { "pegs",       "pegsexchange",         &pegsexchange,        {} },
    { "pegs",       "pegsaccounthistory", &pegsaccounthistory,      {} },
    { "pegs",       "pegsaccountinfo", &pegsaccountinfo,      {} },
    { "pegs",       "pegsworstaccounts",         &pegsworstaccounts,      {} },
    { "pegs",       "pegsinfo",         &pegsinfo,      {} },

    { "generating",         "generate",                 &generate,                 {"nblocks","maxtries"} },
    { "mining",             "getauxblock",              &getauxblock,              {"hash", "auxpow"} },
};

void RegisterWalletRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
