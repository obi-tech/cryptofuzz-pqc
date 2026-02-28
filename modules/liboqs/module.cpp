#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
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
}

std::optional<component::KEM_KeyPair> liboqs::OpKEM_GenerateKeyPair(operation::KEM_GenerateKeyPair& op) {
    std::optional<component::KEM_KeyPair> ret = std::nullopt;
    
    const char* alg_name = kemTypeToOQSAlg(op.kemType.Get());
    if (alg_name == nullptr) {
        return ret;
    }
    
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (kem == nullptr) {
        return ret;
    }
    
    std::unique_ptr<uint8_t[]> public_key(new uint8_t[kem->length_public_key]);
    std::unique_ptr<uint8_t[]> secret_key(new uint8_t[kem->length_secret_key]);
    
    if (OQS_KEM_keypair(kem, public_key.get(), secret_key.get()) == OQS_SUCCESS) {
        component::KEM_PublicKey pub(public_key.get(), kem->length_public_key);
        component::KEM_PrivateKey priv(secret_key.get(), kem->length_secret_key);
        ret = component::KEM_KeyPair(pub, priv);
    }
    
    OQS_KEM_free(kem);
    return ret;
}

std::optional<component::KEM_Encapsulated> liboqs::OpKEM_Encapsulate(operation::KEM_Encapsulate& op) {
    std::optional<component::KEM_Encapsulated> ret = std::nullopt;
    
    const char* alg_name = kemTypeToOQSAlg(op.kemType.Get());
    if (alg_name == nullptr) {
        return ret;
    }
    
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (kem == nullptr) {
        return ret;
    }
    
    // Verify public key size matches
    if (op.pub.GetSize() != kem->length_public_key) {
        OQS_KEM_free(kem);
        return ret;
    }
    
    std::unique_ptr<uint8_t[]> ciphertext(new uint8_t[kem->length_ciphertext]);
    std::unique_ptr<uint8_t[]> shared_secret(new uint8_t[kem->length_shared_secret]);
    
    if (OQS_KEM_encaps(kem, ciphertext.get(), shared_secret.get(), 
                       op.pub.GetPtr()) == OQS_SUCCESS) {
        component::KEM_Ciphertext ct(ciphertext.get(), kem->length_ciphertext);
        component::KEM_SharedSecret ss(shared_secret.get(), kem->length_shared_secret);
        ret = component::KEM_Encapsulated(ct, ss);
    }
    
    OQS_KEM_free(kem);
    return ret;
}

std::optional<component::KEM_SharedSecret> liboqs::OpKEM_Decapsulate(operation::KEM_Decapsulate& op) {
    std::optional<component::KEM_SharedSecret> ret = std::nullopt;
    
    const char* alg_name = kemTypeToOQSAlg(op.kemType.Get());
    if (alg_name == nullptr) {
        return ret;
    }
    
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (kem == nullptr) {
        return ret;
    }
    
    // Verify sizes
    if (op.priv.GetSize() != kem->length_secret_key ||
        op.ciphertext.GetSize() != kem->length_ciphertext) {
        OQS_KEM_free(kem);
        return ret;
    }
    
    std::unique_ptr<uint8_t[]> shared_secret(new uint8_t[kem->length_shared_secret]);
    
    if (OQS_KEM_decaps(kem, shared_secret.get(), 
                       op.ciphertext.GetPtr(), op.priv.GetPtr()) == OQS_SUCCESS) {
        ret = component::KEM_SharedSecret(shared_secret.get(), kem->length_shared_secret);
    }
    
    OQS_KEM_free(kem);
    return ret;
}

std::optional<component::Digest> liboqs::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    
    if (op.digestType.Get() != CF_DIGEST("SHA256")) {
        return ret;
    }
    
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == nullptr) {
        return ret;
    }
    
    uint8_t *public_key = (uint8_t *)malloc(kem->length_public_key);
    uint8_t *secret_key = (uint8_t *)malloc(kem->length_secret_key);
    uint8_t *ciphertext = (uint8_t *)malloc(kem->length_ciphertext);
    uint8_t *shared_secret_e = (uint8_t *)malloc(kem->length_shared_secret);
    uint8_t *shared_secret_d = (uint8_t *)malloc(kem->length_shared_secret);
    
    if (public_key && secret_key && ciphertext && 
        shared_secret_e && shared_secret_d) {
        
        if (OQS_KEM_keypair(kem, public_key, secret_key) == OQS_SUCCESS) {
            if (OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key) == OQS_SUCCESS) {
                if (OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key) == OQS_SUCCESS) {
                    if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) == 0) {
                        ret = component::Digest(shared_secret_e, kem->length_shared_secret);
                    }
                }
            }
        }
    }
    
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_e);
    free(shared_secret_d);
    OQS_KEM_free(kem);
    
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */