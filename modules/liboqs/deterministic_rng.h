#pragma once

#include <oqs/oqs.h>
#include <stdint.h>
#include <stddef.h>

namespace cryptofuzz {
namespace module {
namespace liboqs_detail {

// Initialize deterministic RNG with a seed
void seed_deterministic_rng(const uint8_t* seed, size_t seed_len);

// Deterministic random bytes generator
void deterministic_randombytes(uint8_t* output, size_t len);

// Cleanup deterministic RNG state
void cleanup_deterministic_rng(void);

} // namespace liboqs_detail
} // namespace module
} // namespace cryptofuzz
