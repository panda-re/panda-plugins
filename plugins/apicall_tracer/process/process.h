#ifndef __PROCESS__

#include "image.h"

#include <osi/windows/wintrospection.h>

#include <glib.h>
#include <iostream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "range.h"

typedef std::set<std::pair<uint64_t, uint64_t>> guid_set;

class Process
{
private:
    uint64_t asid;
    uint32_t pid;
    uint32_t ppid;
    std::string name;
    std::string cmdline;
    AddressRangeList m_blacklist;
    uint64_t m_ldr_table_addr;
    uint64_t m_eprocess_addr;

    std::shared_ptr<guid_set> m_target_guids;

    std::shared_ptr<Image> add_image(std::shared_ptr<VirtualMemory> vmem,
                                     struct StructureTypeLibrary* tlib,
                                     uint64_t base_address, uint64_t size,
                                     const std::string& name, uint64_t ldr_addr);

public:
    // std::vector<std::shared_ptr<Image>> images;
    // std::unordered_map<std::string, std::shared_ptr<Image>> images;
    std::map<uint64_t, std::shared_ptr<Image>> images;

    Process()
        : asid(0), pid(0), ppid(0), name("unknown"), cmdline("unknown"),
          m_ldr_table_addr(0), m_eprocess_addr(0)
    {
        m_target_guids = std::shared_ptr<guid_set>(nullptr);
    };
    Process(osi::i_t& eproc, std::shared_ptr<guid_set> target_uids);

    bool operator==(const Process& other) const;
    bool operator!=(const Process& other) const { return !(*this == other); };
    friend std::ostream& operator<<(std::ostream& os, const Process& p);

    std::string key()
    {
        // stringstreams are too slow
        char* key = NULL;
        size_t size = 0;
        FILE* a = open_memstream(&key, &size);
        fprintf(a, "%016lx:%d:%s", asid, pid, name.c_str());
        fclose(a);

        std::string r(key);

        free(key);

        return r;
    };

    // Cache for expensive lookups
    osi::i_t get_eprocess(struct WindowsKernelOSI* kosi, CPUState* env);
    uint64_t get_ldr_table_addr(struct WindowsKernelOSI* kosi, CPUState* env);

    uint32_t get_asid() { return asid; };

    uint32_t get_pid() { return pid; };

    uint32_t get_ppid() { return ppid; };

    const std::string& get_name() { return name; }

    const std::string& get_cmdline() { return cmdline; }

    std::shared_ptr<Image> find_image(uint64_t ptr);

    void update_blacklist(struct WindowsKernelOSI* kosi, osi::i_t& eproc);
    bool address_in_blacklist(uint64_t address);

    std::shared_ptr<Image> get_image(uint64_t address, struct WindowsKernelOSI* kosi,
                                     CPUState* env);
    void walk_images(struct WindowsKernelOSI* kosi, CPUState* env);
    void walk_images(struct WindowsKernelOSI* kosi, osi::i_t& eproc);
    bool is_wow64(osi::i_t& eproc);
};

#define __PROCESS__
#endif
