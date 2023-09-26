#pragma once

#include <map>
#include <memory>
#include <panda/plugin.h>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ipanda_types
{

struct Module {
    Module()
        : name(""), path(""), base_address(0), image_size(0), timedatestamp(0),
          entry_point(0)
    {
    }

    std::string name;
    std::string path;
    uint64_t base_address;
    uint64_t image_size;
    uint64_t timedatestamp;
    uint64_t entry_point;
};

struct Process {
    Process()
        : memory_address(0), name(""), cmdline(""), asid(0), pid(0), ppid(0), base_vba(0),
          create_time(0), start_rrindex(0), end_rrindex(0), process32(false)
    {
    }

    uint64_t memory_address;
    std::string name;
    std::string cmdline;
    uint64_t asid;
    uint64_t pid;
    uint64_t ppid;
    uint64_t base_vba;
    uint64_t create_time;
    uint64_t start_rrindex;
    uint64_t end_rrindex;
    bool process32; // True if WindowsProcess is WOW64 or LinuxProcess is MultArch
    std::map<std::string, Module> modules;
};

} // namespace ipanda_types

typedef std::tuple<uint64_t, uint64_t, std::string> process_key_t;
typedef std::map<std::string, ipanda_types::Module> module_map_t;
typedef std::unordered_map<std::string, std::string> guid_map_t;
