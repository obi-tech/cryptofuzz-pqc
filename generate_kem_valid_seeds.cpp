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

static const uint64_t KEM_TYPE    = ID("Cryptofuzz/KEM/ML-KEM-768");
static const char*    KEM_NAME    = "mlkem768";
static const char*    KEM_ALG     = OQS_KEM_alg_ml_kem_768;

static const uint64_t OP_KEYGEN   = ID("Cryptofuzz/Operation/KEM_GenerateKeyPair");
static const uint64_t OP_ENCAPS   = ID("Cryptofuzz/Operation/KEM_Encapsulate");
static const uint64_t OP_DECAPS   = ID("Cryptofuzz/Operation/KEM_Decapsulate");

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
        payload.Put<uint64_t>(KEM_TYPE);
        payload.Put<bool>(false);  // no seed
        ds.Put<uint64_t>(OP_KEYGEN);
        ds.PutData(payload.GetOut());
    }
    putModifier(ds);
    return ds.GetOut();
}

static std::vector<uint8_t> makeEncaps(const std::vector<uint8_t>& pk) {
    fuzzing::datasource::Datasource ds(nullptr, 0);
    {
        fuzzing::datasource::Datasource payload(nullptr, 0);
        payload.Put<uint64_t>(KEM_TYPE);
        payload.PutData(pk);
        payload.Put<bool>(false);  // no seed
        ds.Put<uint64_t>(OP_ENCAPS);
        ds.PutData(payload.GetOut());
    }
    putModifier(ds);
    return ds.GetOut();
}

static std::vector<uint8_t> makeDecaps(const std::vector<uint8_t>& sk,
                                       const std::vector<uint8_t>& ct) {
    fuzzing::datasource::Datasource ds(nullptr, 0);
    {
        fuzzing::datasource::Datasource payload(nullptr, 0);
        payload.Put<uint64_t>(KEM_TYPE);
        payload.PutData(sk);
        payload.PutData(ct);
        ds.Put<uint64_t>(OP_DECAPS);
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

    OQS_KEM* kem = OQS_KEM_new(KEM_ALG);
    if (kem == nullptr) {
        std::cerr << "[-] OQS_KEM_new failed for " << KEM_ALG << "\n";
        return 1;
    }

    std::cout << "[*] Generating valid ML-KEM-768 seeds in: " << outputDir << "\n";

    size_t keygenCount = 0, encapsCount = 0, decapsCount = 0;

    static const int ITERATIONS = 5;

    for (int i = 0; i < ITERATIONS; i++) {
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);
        std::vector<uint8_t> ct(kem->length_ciphertext);
        std::vector<uint8_t> ss_enc(kem->length_shared_secret);
        std::vector<uint8_t> ss_dec(kem->length_shared_secret);

        // Generate real keypair
        if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS) {
            std::cerr << "[-] OQS_KEM_keypair failed (iter " << i << ")\n";
            continue;
        }

        // Keygen seed: operation with no key inputs (keygen takes no input)
        {
            const std::string f = outputDir + "/kem_valid_keygen_" + KEM_NAME + "_" + std::to_string(i);
            writeCorpusFile(f, makeKeygen());
            keygenCount++;
        }

        // Encaps seed: uses real public key — encapsulation should succeed
        if (OQS_KEM_encaps(kem, ct.data(), ss_enc.data(), pk.data()) != OQS_SUCCESS) {
            std::cerr << "[-] OQS_KEM_encaps failed (iter " << i << ")\n";
            continue;
        }
        {
            const std::string f = outputDir + "/kem_valid_encaps_" + KEM_NAME + "_" + std::to_string(i);
            writeCorpusFile(f, makeEncaps(pk));
            encapsCount++;
        }

        // Decaps seed: uses real sk + real ct — decapsulation should succeed
        if (OQS_KEM_decaps(kem, ss_dec.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
            std::cerr << "[-] OQS_KEM_decaps failed (iter " << i << ")\n";
            continue;
        }
        {
            const std::string f = outputDir + "/kem_valid_decaps_" + KEM_NAME + "_" + std::to_string(i);
            writeCorpusFile(f, makeDecaps(sk, ct));
            decapsCount++;
        }
    }

    OQS_KEM_free(kem);

    std::cout << "\n[+] Done.\n";
    std::cout << "    Valid keygen seeds : " << keygenCount << "\n";
    std::cout << "    Valid encaps seeds : " << encapsCount << "\n";
    std::cout << "    Valid decaps seeds : " << decapsCount << "\n";
    std::cout << "    Total              : " << (keygenCount + encapsCount + decapsCount) << "\n";

    return 0;
}
