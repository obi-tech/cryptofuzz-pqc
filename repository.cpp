#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include <map>
#include <cstdint>
#include <string>
#include "repository_map.h"

namespace cryptofuzz {
namespace repository {

bool IsCBC(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CBC;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsCCM(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CCM;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsCFB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CFB;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsCTR(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).CTR;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsECB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).ECB;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsGCM(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).GCM;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsOCB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).OCB;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsOFB(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).OFB;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsXTS(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).XTS;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsAEAD(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).AEAD;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsWRAP(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).WRAP;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

bool IsAES(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).AES;
    } catch ( std::out_of_range& ) {
        return false;
    }
}

std::string DigestToString(const uint64_t id) {
    try {
        return DigestLUTMap.at(id).name;
    } catch ( std::out_of_range& ) {
        return "(unknown)";
    }
}

std::optional<uint64_t> DigestFromString(const std::string& s) {
    for (const auto& curve : DigestLUTMap) {
        if ( s == curve.second.name ) {
            return curve.first;
        }
    }

    return std::nullopt;
}

std::string CipherToString(const uint64_t id) {
    try {
        return CipherLUTMap.at(id).name;
    } catch ( std::out_of_range& ) {
        return "(unknown)";
    }
}

std::string ECC_CurveToString(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).name;
    } catch ( std::out_of_range& ) {
        return "(unknown)";
    }
}

std::optional<uint64_t> ECC_CurveFromString(const std::string& s) {
    for (const auto& curve : ECC_CurveLUTMap) {
        if ( s == curve.second.name ) {
            return curve.first;
        }
    }

    return std::nullopt;
}

std::optional<size_t> ECC_CurveToBits(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).bits;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToPrime(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).prime;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToA(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).a;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToB(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).b;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToX(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).x;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToY(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).y;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToOrderMin1(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).order_min_1;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::optional<std::string> ECC_CurveToOrder(const uint64_t id) {
    try {
        return ECC_CurveLUTMap.at(id).order;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::string CalcOpToString(const uint64_t id) {
    try {
        return CalcOpLUTMap.at(id).name;
    } catch ( std::out_of_range& ) {
        return "(unknown)";
    }
}
size_t CalcOpToNumParams(const uint64_t id) {
    try {
        return CalcOpLUTMap.at(id).num_params;
    } catch ( std::out_of_range& ) {
        return 0;
    }
}

std::optional<size_t> DigestSize(const uint64_t id) {
    try {
        return DigestLUTMap.at(id).size;
    } catch ( std::out_of_range& ) {
        return std::nullopt;
    }
}

std::string KEMToString(const uint64_t id) {
    switch(id) {
        case 0x8e3e1d5c6a2b4f90ULL: // 
            return "ML-KEM-512";
        case 0x7d2c3b4a5e6f8091ULL: 
            return "ML-KEM-768";
        case 0x6c1b2a394d5e7f82ULL: 
            return "ML-KEM-1024";
        default:
            return "(unknown KEM)";
    }
}

std::optional<uint64_t> KEMFromString(const std::string& s) {
    static const std::map<std::string, uint64_t> LUT = {
        {"ML-KEM-512", 0x8e3e1d5c6a2b4f90ULL},
        {"ML-KEM-768", 0x7d2c3b4a5e6f8091ULL},
        {"ML-KEM-1024", 0x6c1b2a394d5e7f82ULL},
    };
    
    if ( LUT.find(s) == LUT.end() ) {
        return std::nullopt;
    }
    
    return LUT.at(s);
}

std::string PQSignToString(const uint64_t id) {
    switch(id) {
        case fuzzing::datasource::ID("Cryptofuzz/PQSign/ML-DSA-44"):
            return "ML-DSA-44";
        case fuzzing::datasource::ID("Cryptofuzz/PQSign/ML-DSA-65"):
            return "ML-DSA-65";
        case fuzzing::datasource::ID("Cryptofuzz/PQSign/ML-DSA-87"):
            return "ML-DSA-87";
        default:
            return "(unknown PQSign)";
    }
}

std::optional<uint64_t> PQSignFromString(const std::string& s) {
    static const std::map<std::string, uint64_t> LUT = {
        {"ML-DSA-44", fuzzing::datasource::ID("Cryptofuzz/PQSign/ML-DSA-44")},
        {"ML-DSA-65", fuzzing::datasource::ID("Cryptofuzz/PQSign/ML-DSA-65")},
        {"ML-DSA-87", fuzzing::datasource::ID("Cryptofuzz/PQSign/ML-DSA-87")},
    };

    if ( LUT.find(s) == LUT.end() ) {
        return std::nullopt;
    }

    return LUT.at(s);
}

} /* namespace repository */
} /* namespace cryptofuzz */
