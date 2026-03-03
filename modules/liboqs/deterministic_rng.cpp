#include "deterministic_rng.h"
#include <string.h>
#include <openssl/evp.h>

namespace cryptofuzz {
namespace module {
namespace liboqs_detail {

// Global state for deterministic RNG
static bool deterministic_mode = false;
static EVP_CIPHER_CTX* aes_ctx = nullptr;
static uint8_t counter[16] = {0};

void seed_deterministic_rng(const uint8_t* seed, size_t seed_len) {
    if (aes_ctx == nullptr) {
        aes_ctx = EVP_CIPHER_CTX_new();
    }
    
    // Use AES-256-CTR for deterministic random generation
    uint8_t key[32] = {0};
    uint8_t iv[16] = {0};
    
    // Hash seed to create key
    if (seed_len > 0) {
        unsigned int md_len = 0;
        EVP_Digest(seed, seed_len, key, &md_len, EVP_sha256(), nullptr);
    }
    
    EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_ctr(), nullptr, key, iv);
    memset(counter, 0, sizeof(counter));
    deterministic_mode = true;
}

void deterministic_randombytes(uint8_t* output, size_t len) {
    if (!deterministic_mode || aes_ctx == nullptr) {
        // Fallback to system RNG
        OQS_randombytes(output, len);
        return;
    }
    
    int outlen = 0;
    uint8_t* zeros = (uint8_t*)malloc(len);
    memset(zeros, 0, len);
    
    EVP_EncryptUpdate(aes_ctx, output, &outlen, zeros, (int)len);
    free(zeros);
}

void cleanup_deterministic_rng(void) {
    if (aes_ctx != nullptr) {
        EVP_CIPHER_CTX_free(aes_ctx);
        aes_ctx = nullptr;
    }
    deterministic_mode = false;
    memset(counter, 0, sizeof(counter));
}

} // namespace liboqs_detail
} // namespace module
} // namespace cryptofuzz
