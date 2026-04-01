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

struct MLKEMParams {
    uint64_t kemType;
    const char* name;
    size_t pkSize;
    size_t skSize;
    size_t ctSize;
};

static const std::vector<MLKEMParams> mlkemParams = {
    { ID("Cryptofuzz/KEM/ML-KEM-512"),  "mlkem512",  800, 1632,  768 },
    { ID("Cryptofuzz/KEM/ML-KEM-768"),  "mlkem768", 1184, 2400, 1088 },
    { ID("Cryptofuzz/KEM/ML-KEM-1024"), "mlkem1024", 1568, 3168, 1568 },
};

static std::random_device rd;
static std::mt19937 gen(rd());

static bool randomBool() {
    std::uniform_int_distribution<> dist(0, 1);
    return dist(gen) == 1;
}

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
    std::vector<size_t> sizes = {
        0,
        1,
        16,
        32,
        exact > 0 ? exact - 1 : 0,
        exact,
        exact + 1
    };
    return sizes;
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

static void generateKEMKeygenSeeds(const std::string& outputDir, size_t& counter) {
    const uint64_t operation = ID("Cryptofuzz/Operation/KEM_GenerateKeyPair");

    for (const auto& p : mlkemParams) {
        for (bool withSeed : {false, true}) {
            fuzzing::datasource::Datasource ds(nullptr, 0);

            {
                fuzzing::datasource::Datasource payload(nullptr, 0);
                payload.Put<uint64_t>(p.kemType);
                payload.Put<bool>(withSeed);
                if (withSeed) {
                    payload.PutData(randomBytes(64));  /* FIPS 203 §7.1: d‖z = 64 bytes */
                }
                ds.Put<uint64_t>(operation);
                ds.PutData(payload.GetOut());
            }
            putModifier(ds);

            const std::string filename =
                outputDir + "/kem_keygen_" + std::string(p.name) + "_" + std::to_string(counter++);
            writeCorpusFile(filename, ds.GetOut());
        }
    }
}

static void generateKEMEncapsSeeds(const std::string& outputDir, size_t& counter) {
    const uint64_t operation = ID("Cryptofuzz/Operation/KEM_Encapsulate");

    for (const auto& p : mlkemParams) {
        const auto pkVariants = makeFieldVariants(p.pkSize);

        for (size_t i = 0; i < pkVariants.size(); i++) {
            for (bool withSeed : {false, true}) {
                fuzzing::datasource::Datasource ds(nullptr, 0);

                {
                    fuzzing::datasource::Datasource payload(nullptr, 0);
                    payload.Put<uint64_t>(p.kemType);
                    payload.PutData(pkVariants[i]);
                    payload.Put<bool>(withSeed);
                    if (withSeed) {
                        payload.PutData(randomBytes(32));
                    }
                    ds.Put<uint64_t>(operation);
                    ds.PutData(payload.GetOut());
                }
                putModifier(ds);

                const std::string filename =
                    outputDir + "/kem_encaps_" + std::string(p.name) + "_" + std::to_string(counter++);
                writeCorpusFile(filename, ds.GetOut());
            }
        }
    }
}

static void generateKEMDecapsSeeds(const std::string& outputDir, size_t& counter) {
    const uint64_t operation = ID("Cryptofuzz/Operation/KEM_Decapsulate");

    for (const auto& p : mlkemParams) {
        const auto skVariants = makeFieldVariants(p.skSize);
        const auto ctVariants = makeFieldVariants(p.ctSize);

        for (const auto& sk : skVariants) {
            for (const auto& ct : ctVariants) {
                fuzzing::datasource::Datasource ds(nullptr, 0);

                {
                    fuzzing::datasource::Datasource payload(nullptr, 0);
                    payload.Put<uint64_t>(p.kemType);
                    payload.PutData(sk);
                    payload.PutData(ct);
                    ds.Put<uint64_t>(operation);
                    ds.PutData(payload.GetOut());
                }
                putModifier(ds);

                const std::string filename =
                    outputDir + "/kem_decaps_" + std::string(p.name) + "_" + std::to_string(counter++);
                writeCorpusFile(filename, ds.GetOut());
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

    std::cout << "[*] Generating improved ML-KEM corpus in: " << outputDir << "\n";

    size_t keygenCounter = 0;
    size_t encapsCounter = 0;
    size_t decapsCounter = 0;

    generateKEMKeygenSeeds(outputDir, keygenCounter);
    generateKEMEncapsSeeds(outputDir, encapsCounter);
    generateKEMDecapsSeeds(outputDir, decapsCounter);

    std::cout << "\n[+] Done.\n";
    std::cout << "    KEM keygen seeds : " << keygenCounter << "\n";
    std::cout << "    KEM encaps seeds : " << encapsCounter << "\n";
    std::cout << "    KEM decaps seeds : " << decapsCounter << "\n";
    std::cout << "    Total            : " << (keygenCounter + encapsCounter + decapsCounter) << "\n";

    return 0;
}
