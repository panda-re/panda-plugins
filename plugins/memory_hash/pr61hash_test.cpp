#include <iostream>
#include <iomanip>

#include "pr61hash.cpp"

const uint64_t PAGE_HASH = 0x1b1d8d0b72aebff6;

void test1() 
{
    uint8_t page1[PAGE_SIZE] = {};
    uint8_t page2[PAGE_SIZE] = {};

    uint64_t page1_hash = full_poly_hash(page1);
    uint64_t page2_hash = full_poly_hash(page2);
    
    std::cout << std::hex;
    for (size_t i = 0; i < PAGE_SIZE; i++) {
       page1[i] = i % 256;
       page1_hash = delta_poly_hash(page1_hash, i, 0, i%256);
       std::cout << "page1 - " << i << " - 0x"<< std::setw(16) << std::setfill('0') << page1_hash << std::endl;
    }
    std::cout << "full  - xxx - 0x" << std::setw(16) << std::setfill('0') << full_poly_hash(page1) << std::endl;
    assert(page1_hash == PAGE_HASH);

    for (int i = PAGE_SIZE-1; i >= 0; i--) {
       page2[i] = i % 256;
       page2_hash = delta_poly_hash(page2_hash, i, 0, i%256);
       std::cout << "page2 - " << i << " - 0x"<< std::setw(16) << std::setfill('0') << page2_hash << std::endl;
    }
    std::cout << "full  - xxx - 0x" << std::setw(16) << std::setfill('0') << full_poly_hash(page1) << std::endl;
    assert(full_poly_hash(page2) == full_poly_hash(page1));
    assert(page2_hash == PAGE_HASH);
    std::cout << std::dec;
}

void test2()
{
    uint8_t page1[PAGE_SIZE] = {};
    uint64_t page1_hash = full_poly_hash(page1);
    uint64_t page1_full = full_poly_hash(page1);
    
    std::cout << std::hex;
    for (size_t i = 0; i < PAGE_SIZE; i++) {
        page1[i] = i % 256;
        page1_hash = delta_poly_hash(page1_hash, i, 0, i%256);
        page1_full = full_poly_hash(page1);
        if (i < 10 || i > 4086) {
            std::cout << "page1 - " << i 
            << " - 0x" << std::setw(16) << std::setfill('0') << page1_hash 
            << " - 0x" << std::setw(16) << std::setfill('0') << page1_full
            << std::endl;
        }
    }
   
    std::cout << "full  - xxx - 0x" 
