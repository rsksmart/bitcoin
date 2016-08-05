// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "test/test_bitcoin.h"

#include "chainparams.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "keystore.h"
#include "main.h"
#include "miner.h"
#include "policy/policy.h"
#include "script/drivechain.h"
#include "script/interpreter.h"

#include <memory>
#include <boost/test/unit_test.hpp>

namespace
{
const unsigned char vchKey0[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

/* Test fixture */
class DriveChainSetup : public TestingSetup
{
public:
    DriveChainSetup();
};

DriveChainSetup::DriveChainSetup() : TestingSetup()
{
}

/* To nicely convert from char* to vector<unsigned char> without '\0' at the end */
template <typename U, unsigned int N>
std::vector<unsigned char> ChainIdFromString(U(&in)[N])
{
    return std::vector<unsigned char>(in, in + N - 1); // Skip final '\0'
}

/* Create a transaction with a script vote */
CTransaction CreateTxVote(std::vector<unsigned char> script)
{
    CMutableTransaction tx;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = CScript(script.begin(), script.end());
    return tx;
}

/* Returns a vector with a serialized FullAckList */
std::vector<unsigned char> GetScript(FullAckList fullAckList, bool label)
{
    CDataStream dataStream(SER_DISK, 0);
    if (label)
        dataStream.write(reinterpret_cast<const char*>(&ACK_LABEL[0]), ACK_LABEL_LENGTH);
    dataStream << fullAckList;
    return std::vector<unsigned char>(dataStream.begin(), dataStream.end());
}

/* Blockchain mock for VerifyScript and EvalScript */
class DriveChainTestCheckerBlockReader : public MutableTransactionSignatureChecker, public BaseBlockReader
{
    int blockNumber;
    std::vector<unsigned char> hashSpend;
    std::map<int, CTransaction> txs;

public:
    virtual bool CountAcks(const std::vector<unsigned char>& chainId, int periodAck, int periodLiveness, int& positiveAcks, int& negativeAcks) const
    {
        return ::CountAcks(hashSpend, chainId, periodAck, periodLiveness, positiveAcks, negativeAcks, *this);
    }

    virtual int GetBlockNumber() const
    {
        return blockNumber;
    }

    virtual CTransaction GetBlockCoinbase(int blockNumber) const
    {
        auto result = txs.find(blockNumber);
        if (result != txs.end()) {
            return (*result).second;
        }
        return CTransaction();
    }

    DriveChainTestCheckerBlockReader(int blockNumber, std::vector<unsigned char>&& hashSpend, std::map<int, CTransaction>&& txs, const CMutableTransaction* txToIn, unsigned int nInIn, const CAmount& amount)
        : MutableTransactionSignatureChecker(txToIn, nInIn, amount), blockNumber(blockNumber), hashSpend(std::move(hashSpend)), txs(std::move(txs))
    {
    }
};

/* Like CHashWriter but only applies SHA256 once. */
class SHA256Writer
{
private:
    CSHA256 ctx;

public:
    int nType;
    int nVersion;

    SHA256Writer(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}

    SHA256Writer& write(const char* pch, size_t size)
    {
        ctx.Write((const unsigned char*)pch, size);
        return (*this);
    }

    uint256 GetHash()
    {
        uint256 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }

    template <typename T>
    SHA256Writer& operator<<(const T& obj)
    {
        ::Serialize(*this, obj, nType, nVersion);
        return (*this);
    }
};
}

BOOST_FIXTURE_TEST_SUITE(drivechain_tests, DriveChainSetup)

BOOST_AUTO_TEST_CASE(drivechain_ParseProposal)
{
    std::vector<unsigned char> payload = GetScript(
        FullAckList() << ChainAckList(ChainIdFromString("DRVCOIN")) << Ack(ChainIdFromString(""), ParseHex("2020202020202020202020202020202020202020202020202020202020202020")), false);

    uint32_t sizePayload = static_cast<uint32_t>(payload[0]);
    BOOST_CHECK(sizePayload < 253);
    BOOST_CHECK(payload.size() == 1 + sizePayload);

    CDataStream ss(payload, SER_DISK, 0);
    FullAckList fullAckList;
    ss >> fullAckList;

    BOOST_CHECK(1 == fullAckList.vChainAcks.size());
    BOOST_CHECK(fullAckList.vChainAcks[0].chainId == ChainIdFromString("DRVCOIN"));
    BOOST_CHECK(fullAckList.vChainAcks[0].ackList.vAck.size() == 1);
    BOOST_CHECK(fullAckList.vChainAcks[0].ackList.vAck[0].prefix.size() == 0);
    BOOST_CHECK(fullAckList.vChainAcks[0].ackList.vAck[0].preimage.size() == 32);
    BOOST_CHECK(fullAckList.vChainAcks[0].ackList.vAck[0].preimage == ParseHex("2020202020202020202020202020202020202020202020202020202020202020"));
}

BOOST_AUTO_TEST_CASE(drivechain_ParseVotes)
{
    std::vector<unsigned char> payload = GetScript(
        FullAckList() << ChainAckList(ChainIdFromString("DRVCOIN")) << Ack(ParseHex("ba")) << Ack(ParseHex("84e0")) << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("FF")), false);

    size_t sizePayload = static_cast<size_t>(payload[0]);
    BOOST_CHECK(sizePayload < 253);
    BOOST_CHECK(payload.size() == 1 + sizePayload);

    CDataStream ss(payload, SER_DISK, 0);
    FullAckList fullAckListOut;
    ss >> fullAckListOut;

    BOOST_CHECK(fullAckListOut.vChainAcks.size() == 2);
    BOOST_CHECK(fullAckListOut.vChainAcks[0].chainId == ChainIdFromString("DRVCOIN"));
    BOOST_CHECK(fullAckListOut.vChainAcks[0].ackList.vAck.size() == 2);
    BOOST_CHECK(fullAckListOut.vChainAcks[0].ackList.vAck[0].prefix.size() == 1);
    BOOST_CHECK(fullAckListOut.vChainAcks[0].ackList.vAck[0].prefix == ParseHex("ba"));
    BOOST_CHECK(fullAckListOut.vChainAcks[0].ackList.vAck[0].preimage.size() == 0);
    BOOST_CHECK(fullAckListOut.vChainAcks[0].ackList.vAck[1].prefix.size() == 2);
    BOOST_CHECK(fullAckListOut.vChainAcks[0].ackList.vAck[1].prefix == ParseHex("84e0"));
    BOOST_CHECK(fullAckListOut.vChainAcks[0].ackList.vAck[1].preimage.size() == 0);
    BOOST_CHECK(fullAckListOut.vChainAcks[1].chainId == ChainIdFromString("XCOIN"));
    BOOST_CHECK(fullAckListOut.vChainAcks[1].ackList.vAck.size() == 1);
    BOOST_CHECK(fullAckListOut.vChainAcks[1].ackList.vAck[0].prefix.size() == 1);
    BOOST_CHECK(fullAckListOut.vChainAcks[1].ackList.vAck[0].prefix == ParseHex("FF"));
    BOOST_CHECK(fullAckListOut.vChainAcks[1].ackList.vAck[0].preimage.size() == 0);
}

BOOST_AUTO_TEST_CASE(drivechain_EvalScript)
{
    std::vector<unsigned char> tx_hash_preimage = ParseHex("1010101010101010101010101010101010101010101010101010101010101010");
    std::vector<unsigned char> tx_hash(32);
    CSHA256().Write(begin_ptr(tx_hash_preimage), tx_hash_preimage.size()).Finalize(begin_ptr(tx_hash));

    std::map<int, CTransaction> txs;
    txs[101] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), tx_hash_preimage), true));
    txs[102] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true));
    for (int i = 103; i <= 200; ++i)
        txs[i] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true));
    txs[201] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true));
    for (int i = 202; i <= 225; ++i)
        txs[i] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true));
    CMutableTransaction tx;
    DriveChainTestCheckerBlockReader checker(370, std::move(tx_hash), std::move(txs), &tx, 0, 0);
    CScript scriptPubKey;
    scriptPubKey << ChainIdFromString("XCOIN");
    scriptPubKey << CScriptNum(144);
    scriptPubKey << CScriptNum(144);
    scriptPubKey << OP_COUNT_ACKS;
    std::vector<std::vector<unsigned char> > stack;
    ScriptError err;
    BOOST_CHECK(EvalScript(stack, scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, checker, SIGVERSION_WITNESS_V0, &err));
    BOOST_CHECK(stack.size() == 2);
    CScriptNum positiveAcks(stack[0], true);
    CScriptNum negativeAcks(stack[1], true);
    BOOST_CHECK(positiveAcks.getint() == 100);
    BOOST_CHECK(negativeAcks.getint() == 25);
}

BOOST_AUTO_TEST_CASE(drivechain_VerifyScript)
{
    // From script_tests.cpp "Basic P2WSH"
    {
        CKey key0;
        key0.Set(vchKey0, vchKey0 + 32, true);

        CScript scriptPubKey;
        CScript witscript = CScript() << ToByteVector(key0.GetPubKey()) << OP_CHECKSIG;
        CScriptWitness scriptWitness;

        {
            witscript << OP_VERIFY;
            // From here OP_COUNT_ACKS script
            witscript << ChainIdFromString("XCOIN");
            witscript << CScriptNum(144);
            witscript << CScriptNum(144);
            witscript << OP_COUNT_ACKS;
            witscript << OP_2DUP;
            witscript << OP_GREATERTHAN;
            witscript << OP_VERIFY;
            witscript << OP_SUB;
            witscript << CScriptNum(72);
            witscript << OP_GREATERTHAN;
        }

        int witnessversion = 0;
        {
            uint256 hash;
            CSHA256().Write(&witscript[0], witscript.size()).Finalize(hash.begin());
            scriptPubKey = CScript() << witnessversion << ToByteVector(hash);
        }

        CAmount nValue = 123;
        CMutableTransaction creditTx;
        {
            creditTx.nVersion = 1;
            creditTx.nLockTime = 0;
            creditTx.vin.resize(1);
            creditTx.vout.resize(1);
            creditTx.vin[0].prevout.SetNull();
            creditTx.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
            creditTx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
            creditTx.vout[0].scriptPubKey = scriptPubKey;
            creditTx.vout[0].nValue = nValue;
        }

        CMutableTransaction spendTx;
        {
            spendTx.nVersion = 1;
            spendTx.nLockTime = 0;
            spendTx.vin.resize(1);
            spendTx.vout.resize(1);
            spendTx.wit.vtxinwit.resize(1);
            spendTx.wit.vtxinwit[0].scriptWitness = CScriptWitness();
            spendTx.vin[0].prevout.hash = creditTx.GetHash();
            spendTx.vin[0].prevout.n = 0;
            spendTx.vin[0].scriptSig = CScript();
            spendTx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
            spendTx.vout[0].scriptPubKey = CScript();
            spendTx.vout[0].nValue = creditTx.vout[0].nValue;
        }

        {
            uint256 hash = SignatureHash(witscript, spendTx, 0, SIGHASH_ALL, nValue, SIGVERSION_WITNESS_V0);
            std::vector<unsigned char> vchSig;
            uint32_t iter = 0;
            do {
                key0.Sign(hash, vchSig, iter++);
            } while (32 != vchSig[3] || 32 != vchSig[5 + vchSig[3]]);
            vchSig.push_back(static_cast<unsigned char>(SIGHASH_ALL));
            scriptWitness.stack.push_back(vchSig);
        }
        scriptWitness.stack.push_back(std::vector<unsigned char>(witscript.begin(), witscript.end()));

        spendTx.wit.vtxinwit[0].scriptWitness = scriptWitness;

        std::unique_ptr<DriveChainTestCheckerBlockReader> checker;
        {
            SHA256Writer ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
            ss << spendTx;
            uint256 tx_hash_preimage = ss.GetHash();
            uint256 tx_hash;
            CSHA256().Write(tx_hash_preimage.begin(), tx_hash_preimage.size()).Finalize(tx_hash.begin());

            BOOST_CHECK(spendTx.GetHash() == tx_hash);

            std::map<int, CTransaction> txs;
            txs[101] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), std::vector<unsigned char>(tx_hash_preimage.begin(), tx_hash_preimage.end())), true));
            for (int i = 102; i <= 200; ++i)
                txs[i] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(std::vector<unsigned char>(tx_hash.begin(), tx_hash.begin() + 1)), true));
            for (int i = 201; i <= 225; ++i)
                txs[i] = CreateTxVote(GetScript(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true));
            checker = std::unique_ptr<DriveChainTestCheckerBlockReader>(new DriveChainTestCheckerBlockReader(370, std::vector<unsigned char>(tx_hash.begin(), tx_hash.end()), std::move(txs), &spendTx, 0, creditTx.vout[0].nValue));
        }

        int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
        ScriptError err;
        BOOST_CHECK(VerifyScript(spendTx.vin[0].scriptSig, creditTx.vout[0].scriptPubKey, &scriptWitness, flags, *checker.get(), &err) == true);
    }
}

//BOOST_AUTO_TEST_CASE(drivechain_Complete)
//{
//    const CChainParams& chainparams = Params();
//
//    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
//    CScript xcoinScript;
//    xcoinScript << ChainIdFromString("XCOIN");
//    xcoinScript << CScriptNum(144);
//    xcoinScript << CScriptNum(144);
//    xcoinScript << OP_COUNT_ACKS;
//    xcoinScript << OP_2DUP;
//    xcoinScript << OP_GREATERTHAN;
//    xcoinScript << OP_VERIFY;
//    xcoinScript << OP_SUB;
//    xcoinScript << CScriptNum(72);
//    xcoinScript << OP_GREATERTHAN;
//    CMutableTransaction txProposal;
//    txProposal.nVersion = 1;
//    txProposal.nLockTime = 0;
//    txProposal.vin.resize(1);
//    txProposal.vout.resize(1);
//    //txProposal.wit.vtxinwit.resize(1);
//    txProposal.vin[0].prevout.hash = coinbaseTxns[0].GetHash();
//    txProposal.vin[0].prevout.n = 0;
//    txProposal.vin[0].scriptSig = xcoinScript;
//    //txProposal.vin[0].wit = scriptDriveChain;
//    txProposal.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
//    //txProposal.wit.vtxinwit[0].scriptWitness = scriptDriveChain;
//    txProposal.vout[0].scriptPubKey = CScript() << ToByteVector(destKey.GetPubKey()) << OP_CHECKSIG;
//    txProposal.vout[0].nValue = coinbaseTxns[0].vout[0].nValue;
//
//    std::vector<unsigned char> vchSig;
//    uint256 hash = SignatureHash(scriptPubKey, txProposal, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
//    BOOST_CHECK(coinbaseKey.Sign(hash, vchSig));
//    vchSig.push_back((unsigned char)SIGHASH_ALL);
//    txProposal.vin[0].scriptSig << vchSig;
//
//    SHA256Writer ss(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
//    ss << txProposal;
//    uint256 tx_hash_preimage = ss.GetHash();
//
//    uint256 tx_hash;
//    CSHA256().Write(tx_hash_preimage.begin(), tx_hash_preimage.size()).Finalize(tx_hash.begin());
//
//    uint256 tx_hash_spend = txProposal.GetHash();
//
//    BOOST_CHECK(tx_hash == tx_hash_spend);
//
//    std::vector<unsigned char> scriptProposal = GetScript(
//        FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ChainIdFromString(""), std::vector<unsigned char>(tx_hash_preimage.begin(), tx_hash_preimage.end())), true);
//    std::vector<unsigned char> scriptPositiveVote = GetScript(
//        FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(std::vector<unsigned char>{*tx_hash.begin()}), true);
//    std::vector<unsigned char> scriptNegativeVote = GetScript(
//        FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true);
//
//    CBlockTemplate* pblocktemplate;
//    BOOST_CHECK(chainActive.Height() == 100);
//    for (unsigned int i = 101; i < 370; ++i) {
//        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
//        CBlock* pblock = &pblocktemplate->block;
//
//        std::vector<unsigned char> scriptExtra;
//        if (i == 101) {
//            scriptExtra = scriptProposal;
//        } else if (i > 101 && i <= 200) {
//            scriptExtra = scriptPositiveVote;
//        } else if (i >= 201 && i <= 225) {
//            scriptExtra = scriptNegativeVote;
//        }
//
//        if (!scriptExtra.empty()) {
//            CMutableTransaction txCoinbase(pblock->vtx[0]);
//            txCoinbase.vout.resize(2);
//            txCoinbase.vout[1].nValue = CAmount(0);
//            txCoinbase.vout[1].scriptPubKey = CScript() << scriptExtra;
//            pblock->vtx[0] = txCoinbase;
//        }
//
//        unsigned int extraNonce = 0;
//        IncrementExtraNonce(pblock, chainActive.Tip(), extraNonce);
//
//        while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, chainparams.GetConsensus()))
//            ++pblock->nNonce;
//
//        CValidationState state;
//        BOOST_CHECK(ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL));
//        BOOST_CHECK(state.IsValid());
//        delete pblocktemplate;
//    }
//
//    BOOST_CHECK(chainActive.Height() == 369);
//
//    {
//        pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
//        CBlock* pblock = &pblocktemplate->block;
//
//        pblock->vtx.resize(1);
//        pblock->vtx.push_back(txProposal);
//
//        unsigned int extraNonce = 0;
//        IncrementExtraNonce(pblock, chainActive.Tip(), extraNonce);
//
//        while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, chainparams.GetConsensus()))
//            ++pblock->nNonce;
//
//        CValidationState state;
//        BOOST_CHECK(ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL));
//        BOOST_CHECK(state.IsValid());
//
//        delete pblocktemplate;
//    }
//}

BOOST_AUTO_TEST_SUITE_END()
