// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2020 The SmartUSD Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>
#include <memory>

#include <chainparamsseeds.h>
#include <pubkey.h>

// #include <arith_uint256.h>
// #include <uint256.h>

bool CChainParams::IsHistoricBug(const uint256& txid, unsigned nHeight, BugType& type) const
{
    const std::pair<unsigned, uint256> key(nHeight, txid);
    std::map<std::pair<unsigned, uint256>, BugType>::const_iterator mi;

    mi = mapHistoricBugs.find (key);
    if (mi != mapHistoricBugs.end ())
    {
        type = mi->second;
        return true;
    }

    return false;
}

static CBlock CreateGenesisBlock(const CScript& genesisInputScript, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = genesisInputScript;
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "March 7th 2021 - SFUSD powered by cutting edge Crypto Conditions technology";
    const CScript genesisInputScript = CScript() << 0x1d00ffff << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    const CScript genesisOutputScript = CScript() << ParseHex("041c72af63c74cec7a65a4c52cbb35d7ef0b302c7f5eecd9ba2be2148fe64b588e3b3d5add7f0ea14af2c2d8df66b593a17665989baa343485359eac454ecf777b") << OP_CHECKSIG;
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Build genesis block for testnet.  In SmartUSD, it has a changed timestamp
 * and output script (it uses Bitcoin's).
 */
static CBlock CreateTestnetGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "March 7th 2021 - SFUSD powered by cutting edge Crypto Conditions technology";
    const CScript genesisInputScript = CScript() << 0x1d00ffff << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    const CScript genesisOutputScript = CScript() << ParseHex("041c72af63c74cec7a65a4c52cbb35d7ef0b302c7f5eecd9ba2be2148fe64b588e3b3d5add7f0ea14af2c2d8df66b593a17665989baa343485359eac454ecf777b") << OP_CHECKSIG;
    return CreateGenesisBlock(genesisInputScript, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

const std::set<CScript> CChainParams::GetAllowedLicensedMinersScriptsAtHeight(int64_t height) const
{
    std::set<CScript> res;

    if (height > nUseLicensedMinersAfterHeight)
    {
        // searching for licensed miners only after certain height
        std::for_each(vLicensedMinersPubkeys.begin(), vLicensedMinersPubkeys.end(), [height, &res](const std::pair<std::string, uint64_t> &lm)
        {
            CScript script;
            if ( height <= lm.second ) {
                // std::cerr << lm.first << std::endl;
                script = CScript() << ParseHex(lm.first) << OP_CHECKSIG; // P2PK
                res.insert(script);
                // std::cerr << script.ToString() << std::endl;
                script = CScript() << OP_DUP << OP_HASH160 << ToByteVector(CPubKey(ParseHex(lm.first)).GetID()) << OP_EQUALVERIFY << OP_CHECKSIG; // P2PKH
                // std::cerr << script.ToString() << std::endl;
                res.insert(script);
            }
        });
    }

    /*** Logic is following: if we return empty set -> any scripts / miners in coinbase are allowed, regardless of
     * it's mistake or not, bcz chain should go. If set contains at least one element - this means that for this
     * block height we have licensed miners set and we will accept blocks only from these allowed miners. */

    return res;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        /* Note that these are not the actual activation heights, but blocks
           after them.  They are too deep in the chain to be ever reorged,
           and thus this is also fine.  */
        // FIXME: Activate BIP16 with a softfork.
        consensus.nCCActivationHeight = 128;
        consensus.BIP16Height = 10000000;
        consensus.BIP34Height = 128;
        consensus.BIP34Hash = uint256S("0x000000001419c08805f6e6feb69c33fadc375b17ae19a411e2ecfd8bcccc332a");
        consensus.BIP65Height = 128;
        consensus.BIP66Height = 128;
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 20 * 60; // 20 minutes (60 blocks)
        consensus.nPowTargetSpacing  = 20;      // 20 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // Not yet enabled

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // Not yet enabled

        // The best chain should have at least this much work.
        // The value is the chain work of the SmartUSD mainnet chain at height
        // 0, with best block hash:
        // 00000000a9eab671c3f2753a9d21e449b3c12a1fd62b3a9c388e580617e5a363
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000010000100");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000001419c08805f6e6feb69c33fadc375b17ae19a411e2ecfd8bcccc332a");

        consensus.nAuxpowChainId = 0x0333;
        consensus.nAuxpowStartHeight = 128;
        consensus.fStrictChainId = true;
        consensus.nLegacyBlocksBefore = 128;

        consensus.rules.reset(new Consensus::MainNetConsensus());

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xca;
        pchMessageStart[1] = 0x33;
        pchMessageStart[2] = 0x30;
        pchMessageStart[3] = 0x37; //updated for SmartFi (SFUSD) relaunch
        nDefaultPort = 47777;
        nPruneAfterHeight = 100000;

        /*
        {
            // Search for Genesis Block candidate
            uint32_t nPowLimitCompact = UintToArith256(consensus.powLimit).GetCompact();
            arith_uint256 hashTarget = arith_uint256().SetCompact(nPowLimitCompact);
            uint32_t nNonce = 0xacd7571c; uint32_t nTime = 1615075200; // Sun Mar 07 2021 00:00:00 GMT+0000

            std::cerr << "Searching for Genesis block candidate ..." << std::endl;
            std::cerr << "Target: 0x" << hashTarget.ToString() << std::endl;
            while (true) {
                genesis = CreateGenesisBlock(nTime, nNonce, nPowLimitCompact, 1, 50 * COIN);

                if ( UintToArith256(genesis.GetHash()) <= hashTarget )
                    break;
                if ((genesis.nNonce & 0xFFFFF) == 0 ) {
                    std::cerr << "nNonce 0x" << strprintf("%08x (%u)", nNonce, nNonce) << ": hash = 0x" << genesis.GetHash().ToString() << std::endl;
                }
                ++nNonce;
                if (nNonce == 0) nTime++;
            }

            std::cerr << "genesis.nTime = " << genesis.nTime << std::endl;
            std::cerr << "genesis.nNonce = 0x" << strprintf("%08x (%u)", nNonce, nNonce) << std::endl;
            std::cerr << "genesis.nVersion = " << genesis.nVersion << std::endl;
            std::cerr << "genesis.hashMerkleRoot = 0x" << genesis.hashMerkleRoot.ToString() << std::endl;
            std::cerr << "genesis.GetHash = 0x" << genesis.GetHash().ToString() << std::endl;
        }
        */

        genesis = CreateGenesisBlock(1615075200, 0xacd7571c, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000000c36f0406d516605e0a2d2702085d565ec0c1283883002127dfcd52b7"));
        assert(genesis.hashMerkleRoot == uint256S("0x7aec6215dcca9a09df51d0bab4cf9f43f52f0fbe680f26aeaa3dd45b188ef745"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.emplace_back("seed.pbc.kmd.sh"); // static dns seeder

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); // updated for SmartFi (SFUSD) relaunch
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        /* FIXME: Update these below.  */
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "pc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {      1, uint256S("000000006918d44ef41f28dd9bde0b677731f610b6fee85ad92557a65e56ad06")},
                {    128, uint256S("000000001419c08805f6e6feb69c33fadc375b17ae19a411e2ecfd8bcccc332a")},
                {    129, uint256S("000000006a874f00f9e16280762554aeaa0455875b548af22ab15043b36172ce")},
                {    333, uint256S("000000005ec9cddd641e9bd16151da1ea902a7e8f4b730f6bd71e4c3e2a5fbc8")},
                {    334, uint256S("0000000039dd88401c1e2c5ab2c78eeddf3df3cc7a7ccb9e0ce086fdcfd37368")},
                {    999, uint256S("0029d80593721799da417dfe45e43568a6536274aa1cadf15f7ffa47d4bc6f33")},
                {   1024, uint256S("5b52b2d33fa1e8894c2eb9985fe65f12a6a2c27a8475709f01c5cf94aca4a038")},
                {   2048, uint256S("14c53bc830bc8abcacfad30c15c9f45d25f3b261743d853e983a560f072881aa")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000000000000166d612d5595e2b1cd88d71d695fc580af64d8da8658c23 (height 446482).
            0, // * UNIX timestamp of last known number of transactions
            0, // * total number of transactions between genesis and that timestamp
               //   (the tx=... number in the SetBestChain debug.log lines)
            0  // * estimated number of transactions per second after checkpoint
        };

        nUseLicensedMinersAfterHeight = 333;
        vLicensedMinersPubkeys.clear();
        vLicensedMinersPubkeys.emplace_back("020f6d2d0eb16d95f590bc1ea4e49097fa24c55b5d02839e64e602b46727fdf04e", 9999999); // SQpK545xFPmEyiEt9yjVCgqqZjrjVDoVfd
        vLicensedMinersPubkeys.emplace_back("038c6fc023b625524bc475c0e7efe99d5e621e190c69e9b6cafeff94857bfdcdbe", 9999999); // SZSQXDpZFtZYijoASjfPzNUuVdf1VyLXH9
        vLicensedMinersPubkeys.emplace_back("02729b51f9675a9ecb46f3e092e4c68ff569346bdcee759e313954f60e605ada28", 9999999); // ShXGwyEa6S7Gy5ZzwXsTHEynG2eJ1icgWj
        vLicensedMinersPubkeys.emplace_back("02473419cecdaf734435dec284a7d854bc0bcae0bcd3f2d2a900a9308c84179102",     333); // ShXLBrk5ZcgM5XCBTSrdGAR1a9FTmU5K2R
        // std::cerr << "vLicensedMinersPubkeys.size() = " << vLicensedMinersPubkeys.size() << std::endl;

        assert(mapHistoricBugs.empty());
        assert(!vLicensedMinersPubkeys.empty());
    }

    int DefaultCheckNameDB () const
    {
        return -1;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        /* As before, these are not the actual activation heights but some
           blocks after them.  */
        consensus.nCCActivationHeight = 128;
        // FIXME: Activate BIP16 with a softfork.
        consensus.BIP16Height = 10000000;
        consensus.BIP34Height = 128;
        consensus.BIP34Hash = uint256S("0xe0a05455d89a54bb7c1b5bb785d6b1b7c5bda42ed4ce8dc19d68652ba8835954");
        consensus.BIP65Height = 128;
        consensus.BIP66Height = 128;
        consensus.powLimit = uint256S("0000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 30 * 60; // 30 minutes (60 blocks)
        consensus.nPowTargetSpacing = 30; // 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = false;
        //consensus.nMinDifficultySince = 1600175285;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // Not yet enabled

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // Not yet enabled

        // The best chain should have at least this much work.
        // The value is the chain work of the SmartUSD testnet chain at height
        // 158,460, with best block hash:
        // cebebb916288ed48cd8a359576d900c550203883bf69fc8d5ed92c5d778a1e32
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000010000100");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xe0a05455d89a54bb7c1b5bb785d6b1b7c5bda42ed4ce8dc19d68652ba8835954"); //130000

        consensus.nAuxpowStartHeight = 128;
        consensus.nAuxpowChainId = 0x0777;
        consensus.fStrictChainId = false;
        consensus.nLegacyBlocksBefore = -1;

        consensus.rules.reset(new Consensus::TestNetConsensus());

        pchMessageStart[0] = 0xca;
        pchMessageStart[1] = 0x77;
        pchMessageStart[2] = 0x70;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 47333;
        nPruneAfterHeight = 1000;

        /*
        {
            // Search for Genesis Block candidate
            uint32_t nPowLimitCompact = UintToArith256(consensus.powLimit).GetCompact();
            arith_uint256 hashTarget = arith_uint256().SetCompact(nPowLimitCompact);
            uint32_t nNonce = 0x0; uint32_t nTime = 1615075200; // Sun Mar 07 2021 00:00:00 GMT+0000

            std::cerr << "Searching for Testnet Genesis block candidate ..." << std::endl;
            std::cerr << "Target: 0x" << hashTarget.ToString() << std::endl;
            while (true) {
                genesis = CreateTestnetGenesisBlock(nTime, nNonce, nPowLimitCompact, 1, 50 * COIN);

                if ( UintToArith256(genesis.GetHash()) <= hashTarget )
                    break;
                if ((genesis.nNonce & 0xFFFFF) == 0 ) {
                    std::cerr << "nNonce 0x" << strprintf("%08x (%u)", nNonce, nNonce) << ": hash = 0x" << genesis.GetHash().ToString() << std::endl;
                }
                ++nNonce;
                if (nNonce == 0) nTime++;
            }

            std::cerr << "genesis.nTime = " << genesis.nTime << std::endl;
            std::cerr << "genesis.nNonce = 0x" << strprintf("%08x (%u)", nNonce, nNonce) << std::endl;
            std::cerr << "genesis.nVersion = " << genesis.nVersion << std::endl;
            std::cerr << "genesis.hashMerkleRoot = 0x" << genesis.hashMerkleRoot.ToString() << std::endl;
            std::cerr << "genesis.GetHash = 0x" << genesis.GetHash().ToString() << std::endl;
        }
        */

        genesis = CreateTestnetGenesisBlock(1615075200, 0x061b0d40, 0x1d0fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000008847aeebcad7381740577f9076dce511e0c1b4978658802ba2b3b8781"));
        assert(genesis.hashMerkleRoot == uint256S("0x7aec6215dcca9a09df51d0bab4cf9f43f52f0fbe680f26aeaa3dd45b188ef745"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("seed.test.smartusd.org");

        // https://en.bitcoin.it/wiki/List_of_address_prefixes
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); // updated for SmartFi (SFUSD) relaunch
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        /* FIXME: Update these below.  */
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "ts";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                /*{0, uint256S("00000004ccfcb7808a7c2216a0292061ede3e6281c27ff3b90814c85038b07f0")},*/
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0.0
        };

        nUseLicensedMinersAfterHeight = 9999999;
        vLicensedMinersPubkeys.clear();
        vLicensedMinersPubkeys.emplace_back("020f6d2d0eb16d95f590bc1ea4e49097fa24c55b5d02839e64e602b46727fdf04e", 9999999); // SQpK545xFPmEyiEt9yjVCgqqZjrjVDoVfd
        vLicensedMinersPubkeys.emplace_back("038c6fc023b625524bc475c0e7efe99d5e621e190c69e9b6cafeff94857bfdcdbe", 9999999); // SZSQXDpZFtZYijoASjfPzNUuVdf1VyLXH9
        vLicensedMinersPubkeys.emplace_back("02729b51f9675a9ecb46f3e092e4c68ff569346bdcee759e313954f60e605ada28", 9999999); // ShXGwyEa6S7Gy5ZzwXsTHEynG2eJ1icgWj
        // std::cerr << "vLicensedMinersPubkeys.size() = " << vLicensedMinersPubkeys.size() << std::endl;

        assert(mapHistoricBugs.empty());
        assert(!vLicensedMinersPubkeys.empty());
    }

    int DefaultCheckNameDB () const
    {
        return -1;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nCCActivationHeight = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 30 * 60; // 30 minutes (60 blocks)
        consensus.nPowTargetSpacing = 30; // 30 seconds
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.nMinDifficultySince = 0;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.nAuxpowStartHeight = 0;
        consensus.nAuxpowChainId = 0x0001;
        consensus.fStrictChainId = true;
        consensus.nLegacyBlocksBefore = 0;

        consensus.rules.reset(new Consensus::RegTestConsensus());

        pchMessageStart[0] = 0xdc;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x10;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 47111;
        nPruneAfterHeight = 1000;

        genesis = CreateTestnetGenesisBlock(1615075200, 0x00000000, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x2038fa5a407cadf93f683635c446a4942de2cbc37097df1b1bf56e08458bf4e4"));
        assert(genesis.hashMerkleRoot == uint256S("0x7aec6215dcca9a09df51d0bab4cf9f43f52f0fbe680f26aeaa3dd45b188ef745"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("1093283d7efb768e41bd2468de6a528096eca726c1d602ec8a85a69821593b29")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); // updated for SmartFi (SFUSD) relaunch
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "scrt";

        assert(mapHistoricBugs.empty());
    }

    int DefaultCheckNameDB () const
    {
        return 0;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
