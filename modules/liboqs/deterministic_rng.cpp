#include "deterministic_rng.h"
#include <oqs/rand_nist.h>
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

} // namespace liboqs_detail
} // namespace module
} // namespace cryptofuzz
