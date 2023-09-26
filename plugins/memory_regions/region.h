#ifndef __REGION__
#define __REGION__

#include "metadata.h"
#include <offset/i_t.h>
#include <osi/windows/wintrospection.h>
#include <set>

class Region
{
private:
    // vad that describes this region
    osi::i_t vad;

    // identify this region
    uint64_t pid;
    std::set<uint64_t> threads;
    uint64_t asid;
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t start_rec;
    uint64_t end_rec;

    // key that identifies the region as unique: if we are using this, we have
    // all ready verified that the two regions have the same pid, asid, start addr, and
    // end addr
    std::tuple<bool /*long vad?*/, bool /*private memory?*/,
               uint64_t /*initial protections*/>
        rkey;

    // metadata to run heuristics on
    bool valid_metadata;
    metadata mdata;

    // name of the runnning process and flag if the region executes
    std::string process;
    bool executes;

    // make the region id - called by constructor
    void populate(struct WindowsProcessOSI* posi, struct WindowsKernelOSI* kosi);

    // populate() will call these functions to populate region info
    void add_location_info(struct WindowsProcessOSI* posi, struct WindowsKernelOSI* kosi);
    void add_meta_info();
    void add_subsection_info(osi::i_t node);

public:
    Region(osi::i_t curr_vad, struct WindowsProcessOSI* posi,
           struct WindowsKernelOSI* kosi);

    // called every time a memory region is encountered after
    // the first time
    void update_end_rec();

    // called if we find that memory region executes
    void does_execute(struct WindowsKernelOSI* kosi);

    // getters
    uint64_t get_pid() { return pid; };
    std::set<uint64_t> get_threads() { return threads; };
    uint64_t get_asid() { return asid; };
    std::string get_process() { return process; };
    uint64_t get_start_addr() { return start_addr; };
    uint64_t get_end_addr() { return end_addr; };
    uint64_t get_start_rec() { return start_rec; };
    uint64_t get_end_rec() { return end_rec; };
    bool get_valid_flag() { return valid_metadata; };
    metadata get_metadata() { return mdata; };
    bool get_exe_flag() { return executes; };
    // std::string  get_proc_name()  { return pname;          };

    std::tuple<bool, bool, target_ulong> get_rkey();
};

#endif
