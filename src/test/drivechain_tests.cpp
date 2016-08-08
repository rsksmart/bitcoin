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
    tx.vout[0].scriptPubKey = CScript() << OP_RETURN << script;
    return tx;
}

/* Create transaction list with a script vote */
std::map<int, CTransaction> CreateTxVote(int from, int to, std::vector<unsigned char> script)
{
    std::map<int, CTransaction> result;
    for (int i=from; i<=to; ++i)
        result[i] = CreateTxVote(script);
    return result;
}

/* Returns a vector with the object t serialized */
template <typename T>
std::vector<unsigned char> SerializeDrivechain(T t, bool label = false)
{
    CDataStream dataStream(SER_DISK, 0);
    if (label)
        dataStream.write(reinterpret_cast<const char*>(&ACK_LABEL[0]), ACK_LABEL_LENGTH);
    dataStream << t;
    return std::vector<unsigned char>(dataStream.begin(), dataStream.end());
}

template <typename T>
T ParseDrivechain(const std::vector<unsigned char>& payload, uint* rest = nullptr)
{
    T t;
    CDataStream ss(payload, SER_DISK, 0);
    ss >> t;
    if (rest)
        *rest = ss.size();
    return t;
}

/* Blockchain mock for VerifyScript and EvalScript */
class DriveChainTestCheckerBlockReader : public TransactionSignatureChecker, public BaseBlockReader
{
    int blockNumber;
    std::vector<unsigned char> hashSpend;
    std::map<int, CTransaction> txs;
    const CTransaction txTo;

public:
    bool CheckSig(const std::vector<unsigned char>& vchSigIn, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const
    {
        return true;
    }

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

    DriveChainTestCheckerBlockReader(int blockNumber, const std::vector<unsigned char>& hashSpend, const std::map<int, CTransaction>& txs, const CAmount& amount)
        : TransactionSignatureChecker(&txTo, 0, amount), blockNumber(blockNumber), hashSpend(hashSpend), txs(txs)
    {
    }
};

/* Like CHashWriter but only applies SHA256 once */
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

// Helper to concatenate two maps
template <typename M1, typename M2>
void InsertMap(M1& m1, const M2& m2)
{
    m1.insert(m2.cbegin(), m2.cend());
}

// Evaluate a call to EvalScript
void RunEvalScriptTest(std::vector<unsigned char> hash, std::map<int, CTransaction> txs, CScript scriptPubKey, int blockNumber, ScriptError result, int positive = -1, int negative = -1)
{
    DriveChainTestCheckerBlockReader checker(blockNumber, hash, txs, 1);
    std::vector<std::vector<unsigned char> > stack;
    ScriptError err;
    BOOST_CHECK(EvalScript(stack, scriptPubKey, STANDARD_SCRIPT_VERIFY_FLAGS, checker, SIGVERSION_WITNESS_V0, &err) == (result == SCRIPT_ERR_OK));
    BOOST_CHECK(err == result);
    if (result == SCRIPT_ERR_OK) {
        BOOST_CHECK(stack.size() == 2);
        CScriptNum positiveAcks(stack[0], true);
        CScriptNum negativeAcks(stack[1], true);
        BOOST_CHECK(positiveAcks.getint() == positive);
        BOOST_CHECK(negativeAcks.getint() == negative);
    }
}
}

BOOST_FIXTURE_TEST_SUITE(drivechain_tests, DriveChainSetup)

BOOST_AUTO_TEST_CASE(ParsingTest)
{
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("0100")));
        BOOST_CHECK(ack.prefix.size() == 0);
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("010000"))); // 1 extra byte after payload
        BOOST_CHECK(ack.prefix.size() == 0);
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("0201BA")));
        BOOST_CHECK(ack.prefix.size() == 1);
        BOOST_CHECK(ack.prefix == ParseHex("BA"));
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("0201DEFB")));
        BOOST_CHECK(ack.prefix.size() == 1);
        BOOST_CHECK(ack.prefix == ParseHex("DE"));
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("04014E018F")));
        BOOST_CHECK(ack.prefix.size() == 1);
        BOOST_CHECK(ack.prefix == ParseHex("4E"));
        BOOST_CHECK(ack.preimage.size() == 1);
        BOOST_CHECK(ack.preimage == ParseHex("8F"));
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("03000136")));
        BOOST_CHECK(ack.prefix.size() == 0);
        BOOST_CHECK(ack.preimage.size() == 1);
        BOOST_CHECK(ack.preimage == ParseHex("36"));
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("2120000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")));
        BOOST_CHECK(ack.prefix.size() == 32);
        BOOST_CHECK(ack.prefix == ParseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
        BOOST_CHECK(ack.preimage.size() == 0);
    }
    {
        Ack ack;
        BOOST_CHECK_NO_THROW(ack = ParseDrivechain<Ack>(ParseHex("4220000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                                                                 "20000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")));
        BOOST_CHECK(ack.prefix.size() == 32);
        BOOST_CHECK(ack.prefix == ParseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
        BOOST_CHECK(ack.preimage.size() == 32);
        BOOST_CHECK(ack.preimage == ParseHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"));
    }
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("00")), std::runtime_error);                                                                     // Bad payload size
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("01")), std::runtime_error);                                                                     // Missing payload
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("0101")), std::runtime_error);                                                                   // Broken payload
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("010100")), std::runtime_error);                                                                 // Incorrect payload size
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("01010000")), std::runtime_error);                                                               // Incorrect payload: size mismatch
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("03010000")), std::runtime_error);                                                               // Incorrect payload: empty preimage
    BOOST_CHECK_THROW(ParseDrivechain<Ack>(ParseHex("2221000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")), std::runtime_error); // hash and preimage are 32 bytes or less

    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("00")));
        BOOST_CHECK(ackList.vAck.size() == 0);
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("020100")));
        BOOST_CHECK(ackList.vAck.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 0);
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("030201C7")));
        BOOST_CHECK(ackList.vAck.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix == ParseHex("C7"));
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("030201C0020100")));
        BOOST_CHECK(ackList.vAck.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 1);
        BOOST_CHECK(ackList.vAck[0].prefix == ParseHex("C0"));
    }
    {
        AckList ackList;
        BOOST_CHECK_NO_THROW(ackList = ParseDrivechain<AckList>(ParseHex("0401000100")));
        BOOST_CHECK(ackList.vAck.size() == 2);
        BOOST_CHECK(ackList.vAck[0].prefix.size() == 0);
        BOOST_CHECK(ackList.vAck[0].preimage.size() == 0);
        BOOST_CHECK(ackList.vAck[1].prefix.size() == 0);
        BOOST_CHECK(ackList.vAck[1].preimage.size() == 0);
    }
    BOOST_CHECK_THROW(ParseDrivechain<AckList>(ParseHex("0100")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<AckList>(ParseHex("0501000100")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<AckList>(ParseHex("05010001000100")), std::runtime_error);

    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("0301FF00")));
        BOOST_CHECK(chainAckList.chainId.size() == 1);
        BOOST_CHECK(chainAckList.chainId == ParseHex("FF"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 0);
    }
    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("0501CA020100")));
        BOOST_CHECK(chainAckList.chainId.size() == 1);
        BOOST_CHECK(chainAckList.chainId == ParseHex("CA"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 1);
        BOOST_CHECK(chainAckList.ackList.vAck[0].prefix.size() == 0);
        BOOST_CHECK(chainAckList.ackList.vAck[0].preimage.size() == 0);
    }
    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("1614000102030405060708090A0B0C0D0E0F1011121300")));
        BOOST_CHECK(chainAckList.chainId.size() == 20);
        BOOST_CHECK(chainAckList.chainId == ParseHex("000102030405060708090A0B0C0D0E0F10111213"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 0);
    }
    {
        ChainAckList chainAckList;
        BOOST_CHECK_NO_THROW(chainAckList = ParseDrivechain<ChainAckList>(ParseHex("FDFF000158FC"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "0100010001000100010001000100010001000100010001000100010001000100"
                                                                                   "01000100010001000100010001000100010001000100010001000100")));
        BOOST_CHECK(chainAckList.chainId.size() == 1);
        BOOST_CHECK(chainAckList.chainId == ParseHex("58"));
        BOOST_CHECK(chainAckList.ackList.vAck.size() == 126);
        for (int i = 0; i < 126; ++i) {
            BOOST_CHECK(chainAckList.ackList.vAck[i].prefix.size() == 0);
            BOOST_CHECK(chainAckList.ackList.vAck[i].preimage.size() == 0);
        }
    }
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("171500000000000000000000000000000000000000000000")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("0502FF")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("FD000301FF00")), std::runtime_error);
    BOOST_CHECK_THROW(ParseDrivechain<ChainAckList>(ParseHex("0502FF")), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(SerializingTest)
{
    {
        BOOST_CHECK(SerializeDrivechain(Ack()) == ParseHex("0100"));
        BOOST_CHECK(SerializeDrivechain(Ack(ParseHex("BA"))) == ParseHex("0201BA"));
        BOOST_CHECK(SerializeDrivechain(Ack(ParseHex(""), ParseHex("BA"))) == ParseHex("030001BA"));
        BOOST_CHECK(SerializeDrivechain(Ack(ParseHex("BA"), ParseHex("BA"))) == ParseHex("0401BA01BA"));
    }
    {
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack()) == ParseHex("050158020100"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack(ParseHex("ABCD"), ParseHex(""))) == ParseHex("070158040302ABCD"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack(ParseHex(""), ParseHex("ABCD"))) == ParseHex("08015805040002ABCD"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("Y")) << Ack() << Ack()) == ParseHex("0701590401000100"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("Y")) << Ack(ParseHex("10")) << Ack(ParseHex(""), ParseHex("10"))) ==
                    ParseHex("0A01590702011003000110"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("X")) << Ack(ParseHex("10")) << Ack(ParseHex("20"))) ==
                    ParseHex("09015806020110020120"));
        BOOST_CHECK(SerializeDrivechain(ChainAckList(ChainIdFromString("Y")) << Ack(ParseHex("BA")) << Ack(ParseHex("BA"))) ==
                    ParseHex("090159060201BA0201BA"));
    }
    {
        BOOST_CHECK(SerializeDrivechain(
                        FullAckList() << ChainAckList(ChainIdFromString("X")) << Ack(ParseHex("DE")) << Ack(ParseHex("BA"))
                                      << ChainAckList(ChainIdFromString("Y")) << Ack(ParseHex("0102")) << Ack(ParseHex(""))) ==
                    ParseHex("14090158060201DE0201BA09015906030201020100"));
    }
    {
        std::vector<unsigned char> payload = SerializeDrivechain(
            FullAckList() << ChainAckList(ChainIdFromString("DRVCOIN")) << Ack(ParseHex(""), ParseHex("00102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F0")));
        BOOST_CHECK(payload == ParseHex("2D2C07445256434F494E2322002000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F0"));
    }
}

BOOST_AUTO_TEST_CASE(EvalScriptTest)
{
    const auto preimage = ParseHex("1010101010101010101010101010101010101010101010101010101010101010");
    const auto hash = ParseHex("baa501b37267c06d8d20f316622f90a3e343e9e730771f2ce2e314b794e31853");
    const CScript scriptPubKey = CScript() << ChainIdFromString("XCOIN") << CScriptNum(144) << CScriptNum(144) << OP_COUNT_ACKS;

    {
        // Invalid block number
        RunEvalScriptTest(hash, std::map<int, CTransaction>(), scriptPubKey, 200, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }
    {
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 125, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));
        RunEvalScriptTest(hash, txs, scriptPubKey, 370, SCRIPT_ERR_OK, 25, 25);
    }
    {
        // Incorrect hash
        auto hash = ParseHex("baD501b37267c06d8d20f316622f90a3e343e9e730771f2ce2e314b794e31853");

        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 125, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunEvalScriptTest(hash, std::map<int, CTransaction>(), scriptPubKey, 370, SCRIPT_ERR_COUNT_ACKS_INVALID_PARAM);
    }
    {
        std::map<int, CTransaction> txs;
        InsertMap(txs, CreateTxVote(101, 101, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), preimage), true)));
        InsertMap(txs, CreateTxVote(102, 200, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex("ba")), true)));
        InsertMap(txs, CreateTxVote(201, 225, SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true)));

        RunEvalScriptTest(hash, txs, scriptPubKey, 370, SCRIPT_ERR_OK, 100, 25);
    }
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
            txs[101] = CreateTxVote(SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(ParseHex(""), std::vector<unsigned char>(tx_hash_preimage.begin(), tx_hash_preimage.end())), true));
            for (int i = 102; i <= 200; ++i)
                txs[i] = CreateTxVote(SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(std::vector<unsigned char>(tx_hash.begin(), tx_hash.begin() + 1)), true));
            for (int i = 201; i <= 225; ++i)
                txs[i] = CreateTxVote(SerializeDrivechain(FullAckList() << ChainAckList(ChainIdFromString("XCOIN")) << Ack(), true));
            checker = std::unique_ptr<DriveChainTestCheckerBlockReader>(new DriveChainTestCheckerBlockReader(370, std::vector<unsigned char>(tx_hash.begin(), tx_hash.end()), std::move(txs), creditTx.vout[0].nValue));
        }

        int flags = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH;
        ScriptError err;
        BOOST_CHECK(::VerifyScript(spendTx.vin[0].scriptSig, creditTx.vout[0].scriptPubKey, &scriptWitness, flags, *checker.get(), &err) == true);
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
