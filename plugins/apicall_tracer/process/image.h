#ifndef __IMAGE__

#include "block.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// osi imports
#include "offset/i_t.h"
#include "osi/windows/iterator.h"
#include "osi/windows/ustring.h"
#include "osi/windows/wintrospection.h"

class Image
{
private:
    uint64_t base_address;
    uint64_t size;
    std::string name;
    std::string m_full_path;
    bool m_header_checked;

public:
    std::map<uint64_t, std::shared_ptr<Block>> blocks;

    Image()
        : base_address(0), size(0), name("unknown"), m_full_path(""),
          m_header_checked(false){};
    Image(uint64_t base_address, uint64_t size, const std::string& name)
        : base_address(base_address), size(size), name(name), m_full_path(""),
          m_header_checked(false){};

    bool operator==(const Image& other) const;
    bool operator!=(const Image& other) const { return !(*this == other); };
    friend std::ostream& operator<<(std::ostream& os, const Image& i);

    inline uint64_t key() const { return base_address + size; }

    uint64_t get_base_address() { return base_address; };

    bool is_header_checked() { return m_header_checked; }

    void set_header_checked(bool status) { m_header_checked = status; }

    uint64_t get_size() { return size; };

    std::string& get_name() { return name; };

    void set_full_path(const std::string& full_path) { m_full_path = full_path; }

    const std::string& get_full_path() const { return m_full_path; }

    bool address_in(uint64_t address);
    uint64_t get_rva(uint64_t address);
    std::shared_ptr<Block> add_block(uint64_t pc, uint64_t rva, uint64_t icount,
                                     uint64_t size, CPUState* env);
};

std::pair<uint64_t, uint64_t> parse_guid(struct WindowsKernelOSI* kosi, osi::i_t& eproc,
                                         uint64_t base_address);

#define __IMAGE__
#endif
