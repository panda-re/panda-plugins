#include <iostream>
#include <iomanip>
#include <cassert>
#include <array>

#include "pr61hash.h"

#define PREFIX "[pr61_hash]"

// ### Polynomial Rolling 61-bit Hash -- unofficially calling pr61

constexpr std::array<uint64_t, PAGE_SIZE> poly_hash_powers()
// Pre-compute powers
{
    std::array<uint64_t, PAGE_SIZE> _powers = {1,};
    for (size_t i = 1; i < PAGE_SIZE; i++) {
        _powers[i] = (_powers[i-1] * P) % MOD;
    }
    return _powers; 
}

static std::array<uint64_t, PAGE_SIZE> powers = poly_hash_powers();

inline uint64_t mulmod(uint64_t a, uint64_t b)
// Multiplication under Modulus 
{
    return (uint64_t)(((__uint128_t)a*b) % MOD);
}

uint64_t full_poly_hash(uint8_t* page) 
// Full page hash compute
{
    uint64_t hash = 0;
    for (size_t i = 0; i < PAGE_SIZE; i++) {
        //std::cout << powers[i] << std::endl;
        hash = (hash + mulmod(page[i], powers[i])) % MOD;
    }
    return hash;
}

uint64_t delta_poly_hash(uint64_t hash, size_t idx, uint8_t oldv, uint8_t newv)
// Compute a single value change in page to apply to old hash
{
    if (idx >= PAGE_SIZE) {
        std::cerr << PREFIX "ERROR index issue" << std::endl;
        return hash;
    }

    uint64_t newd = mulmod(newv, powers[idx]);
    uint64_t oldd = mulmod(oldv, powers[idx]);
    return (hash + newd - oldd + MOD) % MOD;
}

uint64_t apply_delta(uint64_t hash, uint8_t *old_buffer, uint8_t *new_buffer, size_t size, size_t offset)
// Compute all changes and apply to current hash. NOTE: Buffers expected to be PAGE_SIZE
{
    uint64_t curr_h = hash;
    for (size_t i = 0; i < size; i++) {
       curr_h = delta_poly_hash(curr_h, offset+i, old_buffer[i], new_buffer[i]);
    }
    return curr_h;
}

