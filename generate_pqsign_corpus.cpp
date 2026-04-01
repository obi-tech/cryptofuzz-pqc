#include <stdio.h>
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <fuzzing/datasource/id.hpp>
#include <fuzzing/datasource/datasource.hpp>

namespace fs = std::filesystem;

using fuzzing::datasource::ID;

struct PQSignParams {
    uint64_t sigType;
    const char* name;
    size_t pkSize;
    size_t skSize;
    size_t sigSize;
};

static const std::vector<PQSignParams> pqsignParams = {
    { ID("Cryptofuzz/PQSign/ML-DSA-44"), "mldsa44", 1312, 2560, 2420 },
    { ID("Cryptofuzz/PQSign/ML-DSA-65"), "mldsa65", 1952, 4032, 3309 },
    { ID("Cryptofuzz/PQSign/ML-DSA-87"), "mldsa87", 2592, 4896, 4627 },
};

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

static std::vector<uint8_t> zeroBytes(size_t len) {
    return std::vector<uint8_t>(len, 0x00);
}

static std::vector<uint8_t> ffBytes(size_t len) {
    return std::vector<uint8_t>(len, 0xFF);
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

static std::vector<size_t> candidateSizes(size_t exact) {
    return {
        0,
        1,
        16,
        32,
        64,
        exact > 0 ? exact - 1 : 0,
        exact,
        exact + 1
    };
}

static std::vector<size_t> messageSizes() {
    return { 0, 1, 16, 32, 64, 256, 1024 };
}

static std::vector<std::vector<uint8_t>> makeFieldVariants(size_t exactSize) {
    std::vector<std::vector<uint8_t>> out;
    for (size_t sz : candidateSizes(exactSize)) {
        out.push_back(randomBytes(sz));
        out.push_back(zeroBytes(sz));
        out.push_back(ffBytes(sz));
    }
    return out;
}

static void putModifier(fuzzing::datasource::Datasource& ds) {
    const std::vector<uint8_t> modifier;
    ds.PutData(modifier);
}

static void generatePQSignKeygenSeeds(const std::string& outputDir, size_t& counter) {
    const uint64_t operation = ID("Cryptofuzz/Operation/PQSign_GenerateKeyPair");

    for (const auto& p : pqsignParams) {
        for (bool withSeed : {false, true}) {
            fuzzing::datasource::Datasource ds(nullptr, 0);

            {
                fuzzing::datasource::Datasource payload(nullptr, 0);
                payload.Put<uint64_t>(p.sigType);
                payload.Put<bool>(withSeed);
                if (withSeed) {
                    payload.PutData(randomBytes(32));
                }
                ds.Put<uint64_t>(operation);
                ds.PutData(payload.GetOut());
            }
            putModifier(ds);

            const std::string filename =
                outputDir + "/pqsign_keygen_" + std::string(p.name) + "_" + std::to_string(counter++);
            writeCorpusFile(filename, ds.GetOut());
        }
    }
}

static void generatePQSignSignSeeds(const std::string& outputDir, size_t& counter) {
    const uint64_t operation = ID("Cryptofuzz/Operation/PQSign_Sign");

    for (const auto& p : pqsignParams) {
        const auto skVariants = makeFieldVariants(p.skSize);

        for (const auto& sk : skVariants) {
            for (size_t msgLen : messageSizes()) {
                fuzzing::datasource::Datasource ds(nullptr, 0);

                {
                    fuzzing::datasource::Datasource payload(nullptr, 0);
                    payload.Put<uint64_t>(p.sigType);
                    payload.PutData(sk);
                    payload.PutData(randomBytes(msgLen));
                    payload.Put<bool>(false);  // no context
                    ds.Put<uint64_t>(operation);
                    ds.PutData(payload.GetOut());
                }
                putModifier(ds);

                const std::string filename =
                    outputDir + "/pqsign_sign_" + std::string(p.name) + "_" + std::to_string(counter++);
                writeCorpusFile(filename, ds.GetOut());
            }
        }
    }
}

static void generatePQSignVerifySeeds(const std::string& outputDir, size_t& counter) {
    const uint64_t operation = ID("Cryptofuzz/Operation/PQSign_Verify");

    for (const auto& p : pqsignParams) {
        const auto pkVariants = makeFieldVariants(p.pkSize);
        const auto sigVariants = makeFieldVariants(p.sigSize);

        for (const auto& pk : pkVariants) {
            for (const auto& sig : sigVariants) {
                for (size_t msgLen : {0u, 32u, 256u}) {
                    fuzzing::datasource::Datasource ds(nullptr, 0);

                    {
                        fuzzing::datasource::Datasource payload(nullptr, 0);
                        payload.Put<uint64_t>(p.sigType);
                        payload.PutData(pk);
                        payload.PutData(randomBytes(msgLen));
                        payload.PutData(sig);
                        payload.Put<bool>(false);  // no context
                        ds.Put<uint64_t>(operation);
                        ds.PutData(payload.GetOut());
                    }
                    putModifier(ds);

                    const std::string filename =
                        outputDir + "/pqsign_verify_" + std::string(p.name) + "_" + std::to_string(counter++);
                    writeCorpusFile(filename, ds.GetOut());
                }
            }
        }
    }
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

    std::cout << "[*] Generating PQSign corpus in: " << outputDir << "\n";

    size_t keygenCounter = 0;
    size_t signCounter = 0;
    size_t verifyCounter = 0;

    generatePQSignKeygenSeeds(outputDir, keygenCounter);
    generatePQSignSignSeeds(outputDir, signCounter);
    generatePQSignVerifySeeds(outputDir, verifyCounter);

    std::cout << "\n[+] Done.\n";
    std::cout << "    PQSign keygen seeds : " << keygenCounter << "\n";
    std::cout << "    PQSign sign seeds   : " << signCounter << "\n";
    std::cout << "    PQSign verify seeds : " << verifyCounter << "\n";
    std::cout << "    Total               : " << (keygenCounter + signCounter + verifyCounter) << "\n";

    return 0;
}
