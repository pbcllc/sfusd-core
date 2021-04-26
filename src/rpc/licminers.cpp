// Copyright (c) 2021 The SmartUSD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/licminers.h>
#include <univalue.h>
#include <rpc/server.h>
#include <utilstrencodings.h>

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

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "hidden",         "letsdebug",      &letsdebug,      {} },
};

void RegisterLicMinersRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
