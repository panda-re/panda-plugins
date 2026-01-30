#include <iostream>
#include <iomanip>
#include <cassert>
#include <cstring>

#include "pr61hash.h"

const uint64_t PAGE_HASH = 0x1b1d8d0b72aebff6;


void test_fw_bw_sweep()
{
    uint8_t page1[PAGE_SIZE] = {};
    uint8_t page2[PAGE_SIZE] = {};

    uint64_t page1_hash = full_poly_hash(page1);
    uint64_t page2_hash = full_poly_hash(page2);
    
    std::cout << std::hex;
    for (size_t i = 0; i < PAGE_SIZE; i++) {
       page1[i] = i % 256;
       page1_hash = delta_poly_hash(page1_hash, i, 0, i%256);
       //std::cout << "page1 - " << i << " - 0x"<< std::setw(16) << std::setfill('0') << page1_hash << std::endl;
    }
    std::cout << "full  - ___ - 0x" << std::setw(16) << std::setfill('0') << full_poly_hash(page1) << std::endl;
    assert(page1_hash == PAGE_HASH);

    for (int i = PAGE_SIZE-1; i >= 0; i--) {
       page2[i] = i % 256;
       page2_hash = delta_poly_hash(page2_hash, i, 0, i%256);
       //std::cout << "page2 - " << i << " - 0x"<< std::setw(16) << std::setfill('0') << page2_hash << std::endl;
    }
    std::cout << "full  - ___ - 0x" << std::setw(16) << std::setfill('0') << full_poly_hash(page1) << std::endl;
    assert(full_poly_hash(page2) == full_poly_hash(page1));
    assert(page2_hash == PAGE_HASH);
    std::cout << std::dec;
    std::cout << "test_fw_bw_sweep Success!" << std::endl;
}


void test_apply_delta() {
    uint8_t page[PAGE_SIZE] = {};
    uint64_t hash = 0; // Starting hash for empty page
    uint64_t hash_new;

    const size_t sized = 8;
    uint8_t delta[sized] = {'A', 'B', 'C', 'D', 0x32, 0xFF, 0x20, 0x90};
    uint8_t buffer1[PAGE_SIZE] = {};
    uint8_t buffer2[PAGE_SIZE] = {};
   
    //Test 1
    uint16_t offset = 1024;
    memcpy(&buffer1[offset], delta, sized);
    hash_new = apply_delta(hash, page, buffer1, sized, offset);
    memcpy(&page[offset], delta, sized);
    hash = full_poly_hash(page);
    std::cout << "delta: " << std::hex << std::setw(16) << std::setfill('0') << hash_new<< std::endl;
    std::cout << "full:  " << std::hex << std::setw(16) << std::setfill('0') << hash << std::endl;
    assert(hash == hash_new); 
   
    //Test 2
    offset = 2048;
    memcpy(&buffer2[offset], delta, sized);
    hash_new = apply_delta(hash, page, buffer2, sized, offset);
    memcpy(&page[offset], delta, sized);
    hash = full_poly_hash(page);
    std::cout << "delta: " << std::hex << std::setw(16) << std::setfill('0') << hash_new<< std::endl;
    std::cout << "full:  " << std::hex << std::setw(16) << std::setfill('0') << hash << std::endl;
    assert(hash == hash_new); 

    std::cout << "test_apply_delta Success!" << std::endl;
}

// Test Suite
void test_pr61()
{
    test_apply_delta();
    test_fw_bw_sweep();
}
