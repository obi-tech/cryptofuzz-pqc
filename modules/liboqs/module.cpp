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
    
    // Check if deterministic seed is provided
    if ( op.seed != std::nullopt && op.seed->GetSize() > 0 ) {
        // DETERMINISTIC MODE for differential testing
        liboqs_detail::seed_deterministic_rng(op.seed->GetPtr(nullptr), op.seed->GetSize());
        OQS_randombytes_custom_algorithm(&liboqs_detail::deterministic_randombytes);
    }
    
    // Generate keypair
    CF_CHECK_EQ(OQS_KEM_keypair(kem, public_key, secret_key), OQS_SUCCESS);
    
    // Restore original RNG if we used deterministic
    if ( op.seed != std::nullopt && op.seed->GetSize() > 0 ) {
        OQS_randombytes_custom_algorithm(nullptr);
        liboqs_detail::cleanup_deterministic_rng();
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
    
    // Check if deterministic seed is provided
    if ( op.seed != std::nullopt && op.seed->GetSize() > 0 ) {
        // DETERMINISTIC MODE for differential testing
        liboqs_detail::seed_deterministic_rng(op.seed->GetPtr(nullptr), op.seed->GetSize());
        OQS_randombytes_custom_algorithm(&liboqs_detail::deterministic_randombytes);
    }
    
    // Encapsulate
    CF_CHECK_EQ(OQS_KEM_encaps(kem, ciphertext, shared_secret, op.pub.GetPtr()), OQS_SUCCESS);
    
    // Restore original RNG if we used deterministic
    if ( op.seed != std::nullopt && op.seed->GetSize() > 0 ) {
        OQS_randombytes_custom_algorithm(nullptr);
        liboqs_detail::cleanup_deterministic_rng();
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

} /* namespace module */
} /* namespace cryptofuzz */