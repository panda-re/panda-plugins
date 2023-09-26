#ifndef __IMAGE__

#include "block.h"
#include <osi/windows/wintrospection.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

class Image
{
private:
    uint64_t base_address;
    uint64_t size;
    std::string guid;
    std::string full_path;

    void populate_guid(struct WindowsProcessOSI* posi);

public:
    std::map<uint64_t, std::shared_ptr<Block>> blocks;

    Image(struct WindowsModuleEntry* entry, struct WindowsProcessOSI* posi)
    {
        base_address = module_entry_get_base_address(entry);
        size = module_entry_get_modulesize(entry);
        full_path = std::string(module_entry_get_dllpath(entry));

        this->populate_guid(posi);
    };

    bool operator==(const Image& other) const;
    bool operator!=(const Image& other) const { return !(*this == other); };

    uint64_t get_base_address() { return base_address; };

    uint64_t get_size() { return size; };

    const char* get_guid(struct WindowsProcessOSI* posi = nullptr);

    const std::string& get_full_path() const { return full_path; };

    uint64_t get_rva(uint64_t address) { return address - base_address; };

    bool address_in(uint64_t address);

    std::shared_ptr<Block> add_block(uint64_t tid, uint64_t pc, uint64_t rva,
                                     uint64_t icount, uint64_t size,
                                     struct WindowsProcessOSI* posi);
};

#define __IMAGE__
#endif
