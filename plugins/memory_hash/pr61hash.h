#ifndef POLY_HASH_H
#define POLY_HASH_H

constexpr size_t   PAGE_SIZE = 4096; // x86_64 - 4KiB is default
constexpr uint64_t MOD = (1ULL << 61) - 1;
constexpr uint64_t P   = 257;

void init_poly_hash_powers();
uint64_t full_poly_hash(uint8_t *page);
uint64_t delta_poly_hash(uint64_t h, size_t i, uint8_t oldv, uint8_t newv);
uint64_t apply_delta(uint64_t h, uint8_t *old_buffer, uint8_t *new_buffer, size_t size, size_t offset);

#endif
