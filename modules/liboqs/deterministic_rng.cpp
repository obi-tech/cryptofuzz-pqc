#include "deterministic_rng.h"
extern "C" {
#include <oqs/rand_nist.h>
}
#include <string.h>

namespace cryptofuzz {
namespace module {
namespace liboqs_detail {

void seed_deterministic_rng(const uint8_t* seed, size_t seed_len) {
    uint8_t entropy[48] = {0};
    size_t copy_len = seed_len < 48 ? seed_len : 48;
    memcpy(entropy, seed, copy_len);
    OQS_randombytes_nist_kat_init_256bit(entropy, nullptr);
}

void deterministic_randombytes(uint8_t* output, size_t len) {
    OQS_randombytes_nist_kat(output, len);
}

void cleanup_deterministic_rng(void) {
    /* State re-initialized on next seed_deterministic_rng call */
}

/* Fixed-buffer RNG for FIPS 204 §6.1: passes seed bytes verbatim to KeyGen as ξ */
static uint8_t fixed_buf[64];
static size_t  fixed_buf_len;
static size_t  fixed_buf_pos;

void seed_fixed_rng(const uint8_t* seed, size_t seed_len) {
    size_t copy_len = seed_len < sizeof(fixed_buf) ? seed_len : sizeof(fixed_buf);
    memcpy(fixed_buf, seed, copy_len);
    fixed_buf_len = copy_len;
    fixed_buf_pos = 0;
}

void fixed_randombytes(uint8_t* output, size_t len) {
    for (size_t i = 0; i < len; i++)
        output[i] = (fixed_buf_pos < fixed_buf_len) ? fixed_buf[fixed_buf_pos++] : 0;
}

} // namespace liboqs_detail
} // namespace module
} // namespace cryptofuzz
