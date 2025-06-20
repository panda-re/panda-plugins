#include <iostream>
#include <iomanip>
#include <cassert>
#include <array>

#include "pr61hash.h"

// ### Polynomial Rolling 61-bit Hash -- unofficially calling pr61

constexpr std::array<uint64_t, PAGE_SIZE> poly_hash_powers()
{
    std::array<uint64_t, PAGE_SIZE> _powers = {1,};
    for (size_t i = 1; i < PAGE_SIZE; i++) {
        _powers[i] = (_powers[i-1] * P) % MOD;
    }
    return _powers; 
}

static std::array<uint64_t, PAGE_SIZE> powers = poly_hash_powers();

inline uint64_t mulmod(uint64_t a, uint64_t b)
{
    return (uint64_t)(((__uint128_t)a*b) % MOD);
}

uint64_t full_poly_hash(uint8_t* page) 
{
    uint64_t h = 0;
    for (size_t i = 0; i < PAGE_SIZE; i++) {
        //std::cout << powers[i] << std::endl;
        h = (h + mulmod(page[i], powers[i])) % MOD;
    }
    return h;
}

uint64_t delta_poly_hash(uint64_t h, size_t i, uint8_t oldv, uint8_t newv)
{
    if (i >= PAGE_SIZE) {
        std::cerr << "ERROR index issue" << std::endl;
        return h;
    }

    uint64_t new_ = mulmod(newv, powers[i]);
    uint64_t old_ = mulmod(oldv, powers[i]);
    return (h + MOD + new_ - old_) % MOD;
}

uint64_t apply_delta(uint64_t h, uint8_t *old_buffer, uint8_t *new_buffer, size_t size, size_t offset)
{
    uint64_t curr_h = h;
    for (size_t i = 0; i < size; i++) {
       curr_h = delta_poly_hash(curr_h, offset+i, old_buffer[i], new_buffer[i]);
    }
    return curr_h;
}




