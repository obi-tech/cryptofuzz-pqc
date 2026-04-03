#include "module.h"
#include "deterministic_rng.h" 
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/datasource.hpp>
#include <cstring>
#include <cstdlib>
#include <memory>

extern "C" {
    #include <oqs/oqs.h>
}

namespace cryptofuzz {
namespace module {

liboqs::liboqs(void) :
    Module("liboqs") {
}

namespace {
    // Helper function to map Cryptofuzz KEM types to liboqs algorithm names
    const char* kemTypeToOQSAlg(uint64_t kemType) {
        // ML-KEM (Kyber) variants
        if (kemType == CF_KEM("ML-KEM-512")) {
            return OQS_KEM_alg_ml_kem_512;
        } else if (kemType == CF_KEM("ML-KEM-768")) {
            return OQS_KEM_alg_ml_kem_768;
        } else if (kemType == CF_KEM("ML-KEM-1024")) {
            return OQS_KEM_alg_ml_kem_1024;
        }
        
        return nullptr;
    }

    // Wrapper to use either style
    OQS_KEM* getKEM(uint64_t kemType) {
        const char* alg_name = kemTypeToOQSAlg(kemType);
        if (alg_name == nullptr) {
            return nullptr;
        }
        return OQS_KEM_new(alg_name);
    }

    // Helper function to map Cryptofuzz PQSign types to liboqs algorithm names
    const char* pqsignTypeToOQSAlg(uint64_t pqsignType) {
        if (pqsignType == CF_PQSIGN("ML-DSA-44")) {
            return OQS_SIG_alg_ml_dsa_44;
        } else if (pqsignType == CF_PQSIGN("ML-DSA-65")) {
            return OQS_SIG_alg_ml_dsa_65;
        } else if (pqsignType == CF_PQSIGN("ML-DSA-87")) {
            return OQS_SIG_alg_ml_dsa_87;
        }
        return nullptr;
    }

    OQS_SIG* getPQSIG(uint64_t pqsignType) {
        const char* alg_name = pqsignTypeToOQSAlg(pqsignType);
        if (alg_name == nullptr) {
            return nullptr;
        }
        return OQS_SIG_new(alg_name);
    }
}

// KEM Operations with Deterministic RNG Support
std::optional<component::KEM_KeyPair> liboqs::OpKEM_GenerateKeyPair(operation::KEM_GenerateKeyPair& op) {
    std::optional<component::KEM_KeyPair> ret = std::nullopt;
    
    OQS_KEM* kem = nullptr;
    uint8_t* public_key = nullptr;
    uint8_t* secret_key = nullptr;
    
    // Get the KEM algorithm
    CF_CHECK_NE(kem = getKEM(op.kemType.Get()), nullptr);
    
    // Allocate key buffers
    public_key = util::malloc(kem->length_public_key);
    secret_key = util::malloc(kem->length_secret_key);
    
    // FIPS 203 §7.1: KeyGen takes exactly 64 bytes (d‖z)
    if ( op.seed != std::nullopt && op.seed->GetSize() > 0 ) {
        CF_CHECK_EQ(op.seed->GetSize(), kem->length_keypair_seed);
        CF_CHECK_EQ(OQS_KEM_keypair_derand(kem, public_key, secret_key,
                                           op.seed->GetPtr(nullptr)), OQS_SUCCESS);
    } else {
        CF_CHECK_EQ(OQS_KEM_keypair(kem, public_key, secret_key), OQS_SUCCESS);
    }
    
    // Create return value
    ret = component::KEM_KeyPair(
        component::KEM_PublicKey(public_key, kem->length_public_key),
        component::KEM_PrivateKey(secret_key, kem->length_secret_key)
    );

end:
    util::free(public_key);
    util::free(secret_key);
    OQS_KEM_free(kem);
    
    return ret;
}

std::optional<component::KEM_Encapsulated> liboqs::OpKEM_Encapsulate(operation::KEM_Encapsulate& op) {
    std::optional<component::KEM_Encapsulated> ret = std::nullopt;
    
    OQS_KEM* kem = nullptr;
    uint8_t* ciphertext = nullptr;
    uint8_t* shared_secret = nullptr;
    
    // Get the KEM algorithm
    CF_CHECK_NE(kem = getKEM(op.kemType.Get()), nullptr);
    
    // Validate public key size
    CF_CHECK_EQ(op.pub.GetSize(), kem->length_public_key);
    
    // Allocate outputs
    ciphertext = util::malloc(kem->length_ciphertext);
    shared_secret = util::malloc(kem->length_shared_secret);
    
    // FIPS 203 §7.2: Encaps takes exactly 32 bytes (m)
    if ( op.seed != std::nullopt && op.seed->GetSize() > 0 ) {
        CF_CHECK_EQ(op.seed->GetSize(), kem->length_encaps_seed);
        CF_CHECK_EQ(OQS_KEM_encaps_derand(kem, ciphertext, shared_secret,
                                          op.pub.GetPtr(), op.seed->GetPtr(nullptr)), OQS_SUCCESS);
    } else {
        CF_CHECK_EQ(OQS_KEM_encaps(kem, ciphertext, shared_secret, op.pub.GetPtr()), OQS_SUCCESS);
    }
    
    // Create return value
    ret = component::KEM_Encapsulated(
        component::KEM_Ciphertext(ciphertext, kem->length_ciphertext),
        component::KEM_SharedSecret(shared_secret, kem->length_shared_secret)
    );

end:
    util::free(ciphertext);
    util::free(shared_secret);
    OQS_KEM_free(kem);
    
    return ret;
}

std::optional<component::KEM_SharedSecret> liboqs::OpKEM_Decapsulate(operation::KEM_Decapsulate& op) {
    std::optional<component::KEM_SharedSecret> ret = std::nullopt;
    
    OQS_KEM* kem = nullptr;
    uint8_t* shared_secret = nullptr;
    
    // Get the KEM algorithm
    CF_CHECK_NE(kem = getKEM(op.kemType.Get()), nullptr);
    
    // Verify sizes
    CF_CHECK_EQ(op.priv.GetSize(), kem->length_secret_key);
    CF_CHECK_EQ(op.ciphertext.GetSize(), kem->length_ciphertext);
    
    // Allocate output
    shared_secret = util::malloc(kem->length_shared_secret);
    
    // Decapsulate (no RNG needed - deterministic operation)
    CF_CHECK_EQ(OQS_KEM_decaps(kem, shared_secret, 
                               op.ciphertext.GetPtr(), op.priv.GetPtr()), 
                OQS_SUCCESS);
    
    // Create return value
    ret = component::KEM_SharedSecret(shared_secret, kem->length_shared_secret);

end:
    util::free(shared_secret);
    OQS_KEM_free(kem);
    
    return ret;
}

// PQSign Operations with Deterministic RNG Support
std::optional<component::PQSign_KeyPair> liboqs::OpPQSign_GenerateKeyPair(operation::PQSign_GenerateKeyPair& op) {
    std::optional<component::PQSign_KeyPair> ret = std::nullopt;

    OQS_SIG* sig = nullptr;
    uint8_t* public_key = nullptr;
    uint8_t* secret_key = nullptr;
    bool rng_replaced = false;

    // Get the SIG algorithm
    CF_CHECK_NE(sig = getPQSIG(op.pqsignType.Get()), nullptr);

    // Allocate key buffers
    public_key = util::malloc(sig->length_public_key);
    secret_key = util::malloc(sig->length_secret_key);

    // FIPS 204 §6.1: KeyGen draws exactly 32 bytes (ξ) — pass seed verbatim via fixed-buffer RNG
    if ( op.seed != std::nullopt && op.seed->GetSize() > 0 ) {
        CF_CHECK_EQ(op.seed->GetSize(), 32);
        liboqs_detail::seed_fixed_rng(op.seed->GetPtr(nullptr), 32);
        OQS_randombytes_custom_algorithm(&liboqs_detail::fixed_randombytes);
        rng_replaced = true;
    }

    CF_CHECK_EQ(OQS_SIG_keypair(sig, public_key, secret_key), OQS_SUCCESS);

    ret = component::PQSign_KeyPair(
        component::PQSign_PublicKey(public_key, sig->length_public_key),
        component::PQSign_PrivateKey(secret_key, sig->length_secret_key)
    );

end:
    if ( rng_replaced ) {
        OQS_randombytes_custom_algorithm(nullptr);
    }
    util::free(public_key);
    util::free(secret_key);
    OQS_SIG_free(sig);

    return ret;
}

std::optional<component::PQSign_Signature> liboqs::OpPQSign_Sign(operation::PQSign_Sign& op) {
    std::optional<component::PQSign_Signature> ret = std::nullopt;

    OQS_SIG* sig = nullptr;
    uint8_t* signature = nullptr;
    size_t sig_len = 0;

    // Get the SIG algorithm
    CF_CHECK_NE(sig = getPQSIG(op.pqsignType.Get()), nullptr);

    // Validate private key size
    CF_CHECK_EQ(op.priv.GetSize(), sig->length_secret_key);

    // Allocate signature buffer
    signature = util::malloc(sig->length_signature);

    // DETERMINISTIC MODE: always seed from priv bytes for reproducible signing
    liboqs_detail::seed_deterministic_rng(op.priv.GetPtr(nullptr), op.priv.GetSize());
    OQS_randombytes_custom_algorithm(&liboqs_detail::deterministic_randombytes);

    // Sign the message (use context variant if context is provided)
    if ( op.context != std::nullopt ) {
        CF_CHECK_EQ(sig->sign_with_ctx_str(
            signature, &sig_len,
            op.message.GetPtr(nullptr), op.message.GetSize(),
            op.context->GetPtr(nullptr), op.context->GetSize(),
            op.priv.GetPtr(nullptr)
        ), OQS_SUCCESS);
    } else {
        CF_CHECK_EQ(sig->sign(
            signature, &sig_len,
            op.message.GetPtr(nullptr), op.message.GetSize(),
            op.priv.GetPtr(nullptr)
        ), OQS_SUCCESS);
    }

    // Restore original RNG
    OQS_randombytes_custom_algorithm(nullptr);
    liboqs_detail::cleanup_deterministic_rng();

    // Create return value
    ret = component::PQSign_Signature(signature, sig_len);

end:
    util::free(signature);
    OQS_SIG_free(sig);

    return ret;
}

std::optional<bool> liboqs::OpPQSign_Verify(operation::PQSign_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    OQS_SIG* sig = nullptr;

    // Get the SIG algorithm
    CF_CHECK_NE(sig = getPQSIG(op.pqsignType.Get()), nullptr);

    // Validate public key size
    CF_CHECK_EQ(op.pub.GetSize(), sig->length_public_key);

    {
        // Verify the signature (use context variant if context is provided)
        OQS_STATUS result;
        if ( op.context != std::nullopt ) {
            result = sig->verify_with_ctx_str(
                op.message.GetPtr(nullptr), op.message.GetSize(),
                op.signature.GetPtr(nullptr), op.signature.GetSize(),
                op.context->GetPtr(nullptr), op.context->GetSize(),
                op.pub.GetPtr(nullptr)
            );
        } else {
            result = sig->verify(
                op.message.GetPtr(nullptr), op.message.GetSize(),
                op.signature.GetPtr(nullptr), op.signature.GetSize(),
                op.pub.GetPtr(nullptr)
            );
        }

        ret = (result == OQS_SUCCESS);
    }

end:
    OQS_SIG_free(sig);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */