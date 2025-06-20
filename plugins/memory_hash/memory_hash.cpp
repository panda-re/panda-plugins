/*
 * Memory Hash -- Page hashing PANDA plugin
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS
#include <iostream>
#include <iomanip>
#include <string>
#include <map>
#include <array>
#include <vector>
#include <vector>
#include <cassert>

#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/filewritestream.h>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include "ipanda/ipanda.h"
#include "ipanda/manager.h"
#include "ipanda/types.h"

#include "apicall_tracer/trace_filter.h"

#include "pr61hash.h"

#define PREFIX "[memory_hash] "

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
// [X] TODO: Optimize filtering
// [X] TODO: Polynomial Rolling Hash
// [ ] TODO: Decide how/what to store 
// [ ] TODO: 
// [ ] TODO: 

// ### Globals
bool s_memhash_initialized = false;


// ### Memory Hash Plugin Variables
static FILE *output_fp;
static uint64_t phys_write_count = 0;
static std::map<uint64_t, std::vector<uint64_t>> phys_pages_written;
static std::map<uint64_t, uint64_t> hash_freq;

static std::shared_ptr<IntroPANDAManager> os_manager;
static auto tracefilter = std::shared_ptr<TraceFilter>();
static bool allowed = false;


void write_json() {
    rapidjson::Document document;
    document.SetObject();
    rapidjson::Document::AllocatorType& allocator = document.GetAllocator();

    // Handle Pages
    rapidjson::Value pages_writtenj(rapidjson::kObjectType);
    for (const auto& kv : phys_pages_written) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setw(10) << std::setfill('0') << kv.first;
        std::string page_id = ss.str(); 
        
        rapidjson::Value deltasj(rapidjson::kArrayType);
        for (const auto& delta : kv.second) {
            std::stringstream ss;
            ss << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << delta;
            std::string hash = ss.str();

            rapidjson::Value value(hash.c_str(), allocator);
            deltasj.PushBack(value, allocator);
        }
        
        rapidjson::Value key(page_id.c_str(), allocator);
        rapidjson::Value value(deltasj, allocator);
        pages_writtenj.AddMember(key, value, allocator);
    }
    document.AddMember("pages", pages_writtenj, allocator);
    
    // Output Json
    char writeBuffer[65536]; // Buffer for writing
    rapidjson::FileWriteStream os(output_fp, writeBuffer, sizeof(writeBuffer));
    rapidjson::Writer<rapidjson::FileWriteStream> writer(os); 
    document.Accept(writer);
}

bool mh_check_allowlist(CPUState *env) {
    // This check is very slow and expensive
    ipanda_types::Process current_process;
    os_manager->get_current_process(env, current_process);
    return tracefilter->quickCheck(current_process.pid, current_process.asid);
}

void mh_phys_mem_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t *buf)
{
    if (!allowed || panda_in_kernel(env)) return;
    if (!mh_check_allowlist(env)) return;

    target_ptr_t page_id = (addr & ~(0xFFF)) >> 12;
    target_ptr_t page_offset = (addr & (0xFFF));
    uint8_t buffer[PAGE_SIZE];

    phys_write_count++;
    
    assert(page_offset + size <= PAGE_SIZE); // read/writes should per page

    // Check if first time seeing page
    if (phys_pages_written.find(page_id) == phys_pages_written.end()) {
        
        // Get page to hash
        if (panda_physical_memory_rw(page_id, buffer, PAGE_SIZE, false) != MEMTX_OK) {
            std::cout << "ERROR: failed to read page: " << page_id << std::endl;
            return;
        }
        
        // Calculate the full hash and update structures
        uint64_t hash = full_poly_hash(buffer);
        phys_pages_written[page_id] = { hash };
        hash_freq[hash]++;
    }
   
    // Get memory about to be changed
    if (panda_physical_memory_rw(page_id, buffer, size, false) != MEMTX_OK) {
        std::cout << "ERROR: failed to read page: " << page_id << std::endl;
        return;
    }

    // Calculate delta and update structures
    uint64_t hash = phys_pages_written[page_id].back();
    uint64_t delta = apply_delta(hash, buffer, buf, page_offset, size);
    phys_pages_written[page_id].push_back(delta);
    hash_freq[hash]++;
}

bool mh_process_change(CPUState* env, target_ulong oldval, target_ulong newval)
{
    allowed = mh_check_allowlist(env);
    return false;
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

bool init_plugin(void* self)
{
    panda_cb pcb;
    panda_arg_list* memhash_args = panda_get_args("memory_hash");

    // --panda-arg memory_hash:filter=filter.json
    const char* filter_file = strdup(panda_parse_string(memhash_args, "filter", ""));
    if (filter_file[0] == '\0') {
        std::cerr << "ERROR: filter not provided" << std::endl;
        return false;
    }
    tracefilter.reset(new TraceFilter(filter_file));
 
    // --panda-arg memory_hash:output=output.json
    const char* output_file = strdup(panda_parse_string(memhash_args, "output", ""));
    if (output_file[0] == '\0') {
        std::cerr << "ERROR: output not provided" << std::endl;
        return false;
    }
    output_fp = fopen(output_file, "w");
    panda_free_args(memhash_args);

    // enable memory callbacks, turned off by defualt
    panda_enable_memcb();

    // Post vm load initialization
    pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(init_memhash));
    panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

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
    std::cout << PREFIX "unloading..." << std::endl;
    std::cout << PREFIX "individual page writes: " << phys_write_count << std::endl;
    std::cout << PREFIX "unique pages pritten to: " << phys_pages_written.size() << std::endl;
    std::cout << PREFIX "unique hashes: " << hash_freq.size() << std::endl;
    
    std::cout << PREFIX "writing json output..." << std::endl;
    write_json();
    fclose(output_fp);
    std::cout << PREFIX "done." << std::endl;
}
