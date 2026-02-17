#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <cstring>
#include <cstdlib>

extern "C" {
    #include <oqs/oqs.h>
}

namespace cryptofuzz {
namespace module {

liboqs::liboqs(void) :
    Module("liboqs") {
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
