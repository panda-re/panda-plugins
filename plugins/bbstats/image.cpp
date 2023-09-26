#include "image.h"
#include "block.h"

#include <osi/windows/pe.h>
#include <osi/windows/wintrospection.h>

bool Image::operator==(const Image& other) const
{
    return (base_address == other.base_address) && (size == other.size);
}

void Image::populate_guid(struct WindowsProcessOSI* posi)
{
    auto in_memory_pe = init_mem_pe(posi, base_address, false);
    if (in_memory_pe) {
        guid = mem_pe_get_guid(in_memory_pe);
    }
    free_mem_pe(in_memory_pe);
}

const char* Image::get_guid(struct WindowsProcessOSI* posi)
{
    if (guid.empty() && posi != nullptr) {
        // try again to populate, since the memory may not have been
        // readable originally
        this->populate_guid(posi);
    }

    return guid.c_str();
}

bool Image::address_in(uint64_t address)
{
    return (address >= base_address) && (address < (base_address + size));
}

std::shared_ptr<Block> Image::add_block(uint64_t tid, uint64_t pc, uint64_t rva,
                                        uint64_t icount, uint64_t size,
                                        struct WindowsProcessOSI* posi)
{
    auto key = pc + size;

    // Find a record that matches this basic block
    auto candidate = blocks.find(key);
    if (candidate != blocks.end()) {
        auto block = (*candidate).second;
        block->executed(tid);
        return block;
    }

    // Otherwise, create one
    std::shared_ptr<Block> b = std::make_shared<Block>(pc, rva, icount, size, posi);
    b->executed(tid);
    blocks.insert(std::make_pair(key, b));
    return b;
}
