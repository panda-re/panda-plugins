#include "image.h"
#include "block.h"
#include "ipanda/panda_x86.h"

#include <offset/i_t.h>
#include <osi/windows/manager.h>
#include <osi/windows/wintrospection.h>

std::ostream& operator<<(std::ostream& os, const Image& i)
{
    return os << "Image("
              << "base_address=" << std::hex << i.base_address << ", "
              << "size=" << std::hex << i.size << ", "
              << "name=" << i.name << ")";
}

bool Image::operator==(const Image& other) const
{
    return (base_address == other.base_address) && (size == other.size);
}

std::shared_ptr<Block> Image::add_block(uint64_t pc, uint64_t rva, uint64_t icount,
                                        uint64_t size, CPUState* env = nullptr)
{
    // Find a record that matches this basic block
    auto key = block_key(pc, size);
    auto candidate = blocks.find(key);
    if (candidate != blocks.end()) {
        auto block_ptr = (*candidate).second.get();
        if (block_ptr) {
            block_ptr->disassemble(env);
        }
        return (*candidate).second;
    }

    // Otherwise, create one
    std::shared_ptr<Block> b = std::make_shared<Block>(pc, rva, icount, size);
    auto r = blocks.insert(std::make_pair(b->key(), b));
    if (r.second) {
        // std::cerr << "DEBUG: new basic block " << *b << " in " << *this << std::endl;
        if (env != nullptr)
            b->disassemble(env);
    }

    return b;
}

uint64_t Image::get_rva(uint64_t address) { return address - base_address; }

bool Image::address_in(uint64_t address)
{
    return (address > base_address) && (address < base_address + size);
}

std::pair<uint64_t, uint64_t> parse_guid(struct WindowsKernelOSI* kosi, osi::i_t& eproc,
                                         uint64_t base_address)
{
    std::pair<uint64_t, uint64_t> guid;

    auto manager = WindowsProcessManager();
    try {
        manager.initialize(kosi, eproc.get_address());

        auto nt_header = manager.get_type(base_address, "_IMAGE_DOS_HEADER");
        uint64_t pe_header = base_address + nt_header["e_lfanew"].get32();
        osi::i_t pe;
#if defined(TARGET_I386) && defined(TARGET_X86_64)
        pe = manager.get_type(pe_header, "_IMAGE_NT_HEADERS64");
#elif defined(TARGET_I386)
        pe = manager.get_type(pe_header, "_IMAGE_NT_HEADERS");
#else
#error "Unsupported arch"
#endif
        auto fh = pe["FileHeader"];
        uint32_t timedatestamp = fh["TimeDateStamp"].get32();
        auto image_size = pe["OptionalHeader"]["SizeOfImage"].get32();
        guid.first = timedatestamp;
        guid.second = image_size;

    } catch (...) {
        fprintf(stdout, "Failed to parse image header at %lx\n", base_address);
    }

    return guid;
}
