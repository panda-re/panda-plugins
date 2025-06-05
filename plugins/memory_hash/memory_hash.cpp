/*
 * Memory Hash -- Page hashing PANDA plugin
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS
#include <iostream>
#include <set>
#include <string>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include "ipanda/ipanda.h"
#include "ipanda/manager.h"
#include "ipanda/types.h"

#include "apicall_tracer/trace_filter.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    void phys_mem_after_write(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
    void phys_mem_after_read(CPUState *env, target_ulong pc, target_ulong addr, target_ulong size, void *buf);
    
    bool init_plugin(void*);
    void uninit_plugin(void*);
}

// Todo list
// [X] TODO: Basic plugin setup (build and print messages)
// [X] TODO: Count number of Writes / Reads per insn & bb -- decide what is too much / too slow
// [X] TODO: Get memory pages from physical (maybe virtual is fine)
// [X] TODO: Filter on a PID list
// [ ] TODO: Optimize filtering
// [ ] TODO: Decide how/what to store 
// [ ] TODO: 
// [ ] TODO: 

// ### Globals
bool s_memhash_initialized = false;


// ### Memory Hash Plugin Variables ###
static uint64_t phys_read_count = 0;
static uint64_t phys_write_count = 0;
static std::set<target_ptr_t> phys_pages_read;
static std::set<target_ptr_t> phys_pages_written;

static std::shared_ptr<IntroPANDAManager> os_manager;
static auto tracefilter = std::shared_ptr<TraceFilter>();
static bool allowed = false;

bool mh_check_allowlist(CPUState *env) {
    // This check is very slow and expensive
    ipanda_types::Process current_process;
    os_manager->get_current_process(env, current_process);
    return tracefilter->quickCheck(current_process.pid, current_process.asid);
}

void mh_phys_mem_read(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t *buf)
{
    if (!allowed || panda_in_kernel(env)) return;
    if (!mh_check_allowlist(env)) return;
    phys_read_count++;
    phys_pages_read.insert(addr & ~(0xFFF));
}

void mh_phys_mem_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t *buf)
{
    if (!allowed || panda_in_kernel(env)) return;
    if (!mh_check_allowlist(env)) return;
    phys_write_count++;
    phys_pages_written.insert(addr & ~(0xFFF));
}

void init_memhash(CPUState* env)
{
    std::cout << "initializing memhash" << std::endl;
    // ipanda must load on/after first instruction
    if (!init_ipanda(env, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return;
    }
    std::cout << "initialized memhash" << std::endl;
    //allowed = mh_check_allowlist(env);
    s_memhash_initialized = true;
}

bool mh_process_change(CPUState* env, target_ulong oldval, target_ulong newval)
{
    allowed = mh_check_allowlist(env);
    return false;
}

bool init_plugin(void* self)
{
    panda_cb pcb;

    // Tracer Filter args handling
    // --panda-arg trace_filter:file=filter.json
    panda_arg_list* filter_args = panda_get_args("filter");
    const char* filter_file = strdup(panda_parse_string(filter_args, "file", ""));
    if (filter_file[0] == '\0') {
        std::cerr << "ERROR: filter not provided" << std::endl;
        return false;
    }
    tracefilter.reset(new TraceFilter(filter_file));
    panda_free_args(filter_args);
   
    // enable memory callbacks, turned off by defualt
    panda_enable_memcb();

    // Post vm load initialization
    pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(init_memhash));
    panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    // Load Callbacks
    //pcb.phys_mem_after_read = mh_phys_mem_after_read;
    //panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, pcb);
    
    pcb.phys_mem_before_write = mh_phys_mem_write;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE,  pcb);

    // Track process changes to optimize checks for target threads
    pcb.asid_changed = mh_process_change;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED,  pcb);
    
    std::cout << "loaded MEM_HASH" << std::endl;
    
    return true;
}

void uninit_plugin(void* self)
{
    std::cout << "unloaded MEM_HASH" << std::endl;
    std::cout << "PHYS READS: " << phys_read_count << std::endl;
    std::cout << "PHYS PAGES RD: " << phys_pages_read.size() << std::endl;
    std::cout << "PHYS WRITES: " << phys_write_count << std::endl;
    std::cout << "PHYS PAGES WR: " << phys_pages_written.size() << std::endl;
}
