#include <stdio.h>
#include <cstdint>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <fuzzing/datasource/id.hpp>
#include <fuzzing/datasource/datasource.hpp>

extern "C" {
    #include <oqs/oqs.h>
}

namespace fs = std::filesystem;

using fuzzing::datasource::ID;

static const uint64_t SIG_TYPE    = ID("Cryptofuzz/PQSign/ML-DSA-65");
static const char*    SIG_NAME    = "mldsa65";
static const char*    SIG_ALG     = OQS_SIG_alg_ml_dsa_65;

static const uint64_t OP_KEYGEN   = ID("Cryptofuzz/Operation/PQSign_GenerateKeyPair");
static const uint64_t OP_SIGN     = ID("Cryptofuzz/Operation/PQSign_Sign");
static const uint64_t OP_VERIFY   = ID("Cryptofuzz/Operation/PQSign_Verify");

static std::random_device rd;
static std::mt19937 gen(rd());

static std::vector<uint8_t> randomBytes(size_t len) {
    std::uniform_int_distribution<> dist(0, 255);
    std::vector<uint8_t> out(len);
    for (auto& b : out) {
        b = static_cast<uint8_t>(dist(gen));
    }
    return out;
}

static void writeCorpusFile(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        std::cerr << "[-] Failed to write: " << filename << "\n";
        return;
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    std::cout << "[+] " << filename << " (" << data.size() << " bytes)\n";
}

static void putModifier(fuzzing::datasource::Datasource& ds) {
    const std::vector<uint8_t> modifier;
    ds.PutData(modifier);
}

static std::vector<uint8_t> makeKeygen() {
    fuzzing::datasource::Datasource ds(nullptr, 0);
    {
        fuzzing::datasource::Datasource payload(nullptr, 0);
        payload.Put<uint64_t>(SIG_TYPE);
        payload.Put<bool>(false);  // no seed
        ds.Put<uint64_t>(OP_KEYGEN);
        ds.PutData(payload.GetOut());
    }
    putModifier(ds);
    return ds.GetOut();
}

static std::vector<uint8_t> makeSign(const std::vector<uint8_t>& sk,
                                     const std::vector<uint8_t>& msg) {
    fuzzing::datasource::Datasource ds(nullptr, 0);
    {
        fuzzing::datasource::Datasource payload(nullptr, 0);
        payload.Put<uint64_t>(SIG_TYPE);
        payload.PutData(sk);
        payload.PutData(msg);
        payload.Put<bool>(false);  // no context
        ds.Put<uint64_t>(OP_SIGN);
        ds.PutData(payload.GetOut());
    }
    putModifier(ds);
    return ds.GetOut();
}

static std::vector<uint8_t> makeVerify(const std::vector<uint8_t>& pk,
                                       const std::vector<uint8_t>& msg,
                                       const std::vector<uint8_t>& signature) {
    fuzzing::datasource::Datasource ds(nullptr, 0);
    {
        fuzzing::datasource::Datasource payload(nullptr, 0);
        payload.Put<uint64_t>(SIG_TYPE);
        payload.PutData(pk);
        payload.PutData(msg);
        payload.PutData(signature);
        payload.Put<bool>(false);  // no context
        ds.Put<uint64_t>(OP_VERIFY);
        ds.PutData(payload.GetOut());
    }
    putModifier(ds);
    return ds.GetOut();
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <output_dir>\n";
        return 1;
    }

    const std::string outputDir = argv[1];

    try {
        fs::create_directories(outputDir);
    } catch (...) {
        std::cerr << "[-] Failed to create directory: " << outputDir << "\n";
        return 1;
    }

    OQS_SIG* sig = OQS_SIG_new(SIG_ALG);
    if (sig == nullptr) {
        std::cerr << "[-] OQS_SIG_new failed for " << SIG_ALG << "\n";
        return 1;
    }

    std::cout << "[*] Generating valid ML-DSA-65 seeds in: " << outputDir << "\n";

    static const size_t MESSAGE_SIZES[] = { 0, 1, 32, 256, 1024 };
    static const int KEYPAIRS = 3;

    size_t keygenCount = 0, signCount = 0, verifyCount = 0;
    size_t counter = 0;

    for (int kp = 0; kp < KEYPAIRS; kp++) {
        std::vector<uint8_t> pk(sig->length_public_key);
        std::vector<uint8_t> sk(sig->length_secret_key);

        // Generate real keypair
        if (OQS_SIG_keypair(sig, pk.data(), sk.data()) != OQS_SUCCESS) {
            std::cerr << "[-] OQS_SIG_keypair failed (keypair " << kp << ")\n";
            continue;
        }

        // Keygen seed (once per keypair)
        {
            const std::string f = outputDir + "/pqsign_valid_keygen_" + SIG_NAME + "_" + std::to_string(kp);
            writeCorpusFile(f, makeKeygen());
            keygenCount++;
        }

        for (size_t msgLen : MESSAGE_SIZES) {
            const std::vector<uint8_t> msg = randomBytes(msgLen);
            std::vector<uint8_t> signature(sig->length_signature);
            size_t sig_len = 0;

            // Sign with real sk — result is a valid signature
            if (OQS_SIG_sign(sig, signature.data(), &sig_len,
                             msg.data(), msg.size(), sk.data()) != OQS_SUCCESS) {
                std::cerr << "[-] OQS_SIG_sign failed (kp=" << kp << " msgLen=" << msgLen << ")\n";
                continue;
            }
            signature.resize(sig_len);

            // Sign seed: real sk + message
            {
                const std::string f = outputDir + "/pqsign_valid_sign_" + SIG_NAME + "_" + std::to_string(counter);
                writeCorpusFile(f, makeSign(sk, msg));
                signCount++;
            }

            // Verify seed: real pk + message + real signature — verification should return true
            {
                const std::string f = outputDir + "/pqsign_valid_verify_" + SIG_NAME + "_" + std::to_string(counter);
                writeCorpusFile(f, makeVerify(pk, msg, signature));
                verifyCount++;
            }

            counter++;
        }
    }

    OQS_SIG_free(sig);

    std::cout << "\n[+] Done.\n";
    std::cout << "    Valid keygen seeds : " << keygenCount << "\n";
    std::cout << "    Valid sign seeds   : " << signCount << "\n";
    std::cout << "    Valid verify seeds : " << verifyCount << "\n";
    std::cout << "    Total              : " << (keygenCount + signCount + verifyCount) << "\n";

    return 0;
}
