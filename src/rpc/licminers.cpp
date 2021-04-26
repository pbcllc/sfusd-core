// Copyright (c) 2021 The SmartUSD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>

#include <rpc/licminers.h>
#include <univalue.h>
#include <rpc/server.h>
#include <utilstrencodings.h>
#include <chainparams.h>
#include <base58.h>


UniValue letsdebug(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "letsdebug\n"
            "\nExamples:\n"
            + HelpExampleCli("letsdebug", "")
            + HelpExampleRpc("letsdebug", "")
        );

    return NullUniValue;
}

UniValue convertaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "convertaddress \"address\"\n"
            "\nExamples:\n"
            + HelpExampleCli("convertaddresss", "")
            + HelpExampleRpc("convertaddresss", "")
        );

    UniValue ret(UniValue::VOBJ);

    const CChainParams& m_params = Params();
    std::string strAddress = request.params[0].get_str();
    std::vector<unsigned char> vch;
    std::vector<unsigned char> kmd_pubkey_address = std::vector<unsigned char>(1,60);
    std::vector<unsigned char> kmd_script_address = std::vector<unsigned char>(1,85);

    if (DecodeBase58Check(strAddress, vch) && vch.size() >= 1 + CHash160::OUTPUT_SIZE) {

        std::vector<unsigned char> id(vch.end() - CHash160::OUTPUT_SIZE, vch.end());
        vch.resize(vch.size() - CHash160::OUTPUT_SIZE); // vch now should contain prefix bytes only
        /* ... */
        if (vch == kmd_pubkey_address)
        {
            ret.push_back(Pair("type", "pubkey"));
            vch = m_params.Base58Prefix(CChainParams::PUBKEY_ADDRESS);
            vch.insert(vch.end(), id.begin(), id.end());
        }
        else if (vch == kmd_script_address)
        {
            ret.push_back(Pair("type", "script"));
            vch = m_params.Base58Prefix(CChainParams::SCRIPT_ADDRESS);
            vch.insert(vch.end(), id.begin(), id.end());
        }
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address type, possible not KMD address");

        ret.push_back(Pair("address_from", strAddress));
        ret.push_back(Pair("address_id", HexStr(id)));
        ret.push_back(Pair("address_to", EncodeBase58Check(vch)));

    } else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address");

    return ret;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "hidden",         "letsdebug",                  &letsdebug,              {} },
    { "hidden",         "convertaddress",             &convertaddress,         {"address"} },
};

void RegisterLicMinersRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
