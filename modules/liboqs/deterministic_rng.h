#pragma once

#include <oqs/oqs.h>
#include <stdint.h>
#include <stddef.h>

namespace cryptofuzz {
namespace module {
namespace liboqs_detail {

// Initialize deterministic RNG with a seed (NIST AES-CTR DRBG — used by PQSign Sign)
void seed_deterministic_rng(const uint8_t* seed, size_t seed_len);

// Deterministic random bytes generator (NIST AES-CTR DRBG output)
void deterministic_randombytes(uint8_t* output, size_t len);

// Cleanup deterministic RNG state
void cleanup_deterministic_rng(void);

// Fixed-buffer RNG: returns seed bytes verbatim then zeroes (FIPS 204 §6.1 KeyGen)
void seed_fixed_rng(const uint8_t* seed, size_t seed_len);
void fixed_randombytes(uint8_t* output, size_t len);

} // namespace liboqs_detail
} // namespace module
} // namespace cryptofuzz
