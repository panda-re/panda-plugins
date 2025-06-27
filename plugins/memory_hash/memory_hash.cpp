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
#include <tuple>
#include <array>
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
// [X] TODO: Decide how/what to store 
// [ ] TODO: get ASID, PID for each page

// for readability 
using physical_t = uint64_t;
using virtual_t = uint64_t;
using asid_t = uint64_t;
using pr61hash_t = uint64_t;
using page_key_t = std::tuple<asid_t, virtual_t>;
#define ASID 0
#define PAGE 1


// ### Globals
bool s_memhash_initialized = false;


// ### Memory Hash Plugin Variables
static FILE *output_fp;
static uint64_t phys_write_count = 0;
static std::map<page_key_t, std::vector<pr61hash_t>> pages_written;
static std::map<pr61hash_t, uint64_t> hash_freq;

// filter variables
static std::shared_ptr<IntroPANDAManager> os_manager;
static auto tracefilter = std::shared_ptr<TraceFilter>();
static bool allowed = false;

// before_write triggers after_write to reduce filter checks
static bool before_virt_phys = false;
static page_key_t current_page_key;


void write_json() {
    rapidjson::Document document;
    document.SetObject();
    rapidjson::Document::AllocatorType& allocator = document.GetAllocator();
    std::stringstream ss;

    // Handle Pages
    rapidjson::Value pages_writtenj(rapidjson::kArrayType);
    for (const auto& kv : pages_written) {
        // asid
        ss << std::dec << std::get<ASID>(kv.first);
        std::string asid = ss.str(); 
        ss.str("");
        ss.clear();

        // page_id
        ss << std::hex << std::uppercase << std::setw(10) << std::setfill('0') << std::get<PAGE>(kv.first);
        std::string page_id = ss.str(); 
        ss.str("");
        ss.clear();

        // hashes
        rapidjson::Value deltasj(rapidjson::kArrayType);
        for (const auto& delta : kv.second) {
            ss << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << delta;
            std::string hash = ss.str();
            ss.str("");
            ss.clear();

            rapidjson::Value value(hash.c_str(), allocator);
            deltasj.PushBack(value, allocator);
        }
        
        // element
        rapidjson::Value ele(rapidjson::kObjectType);
        rapidjson::Value asidj(asid.c_str(), allocator);
        rapidjson::Value page_idj(page_id.c_str(), allocator);
        ele.AddMember("asid", asidj, allocator);
        ele.AddMember("page_id", page_idj, allocator);
        ele.AddMember("hashes", deltasj, allocator);
        
        pages_writtenj.PushBack(ele, allocator);
    }
    document.AddMember("pages", pages_writtenj, allocator);

    // Output Json
    char writeBuffer[65536]; // Buffer for writing, recommend size by docs
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

void mh_virt_mem_before_write(CPUState *env, target_ptr_t pc, target_ptr_t vaddr, size_t size, uint8_t *buf) 
{
    if (!allowed || panda_in_kernel(env)) return;
    if (!mh_check_allowlist(env)) return;

    asid_t asid = panda_current_asid(env);

    //physical_t paddr = panda_virt_to_phys(env, vaddr); // could fail
    physical_t vpage_id = (vaddr & ~(0xFFF)) >> 12;
  
    current_page_key = std::make_tuple(asid, vpage_id);
    before_virt_phys = true;
}

void mh_phys_mem_before_write(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t *buf)
{
    if (!before_virt_phys) return;
    before_virt_phys = false;
    
    asid_t asid = panda_current_asid(env);
    physical_t page_id = (addr & ~(0xFFF)) >> 12;
    physical_t page_offset = (addr & (0xFFF));
    uint8_t buffer[PAGE_SIZE];

    phys_write_count++;
    
    // check that asid didnt just randomly change
    assert(std::get<ASID>(current_page_key) == asid); 
    
    assert(page_offset + size <= PAGE_SIZE); // read/writes should per page

    // Check if first time seeing page
    if (pages_written.find(current_page_key) == pages_written.end()) {
        // Get page to hash
        if (panda_physical_memory_rw(page_id, buffer, PAGE_SIZE, false) != MEMTX_OK) {
            std::cout << "ERROR: failed to read page: " << page_id << std::endl;
            return;
        }
        
        // Calculate the full hash and update structures
        uint64_t hash = full_poly_hash(buffer);
        pages_written[current_page_key] = { hash };
        hash_freq[hash]++;
    }
   
    // Get memory about to be changed
    if (panda_physical_memory_rw(page_id, buffer, size, false) != MEMTX_OK) {
        std::cout << "ERROR: failed to read page: " << page_id << std::endl;
        return;
    }

    // Calculate delta and update structures
    uint64_t hash = pages_written[current_page_key].back();
    uint64_t delta = apply_delta(hash, buffer, buf, page_offset, size);
    pages_written[current_page_key].push_back(delta);
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

    pcb.virt_mem_before_write = mh_virt_mem_before_write;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE,  pcb);
    
    pcb.phys_mem_before_write = mh_phys_mem_before_write;
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
    std::cout << PREFIX "unique pages pritten to: " << pages_written.size() << std::endl;
    std::cout << PREFIX "unique hashes: " << hash_freq.size() << std::endl;

    for (const auto& kv : hash_freq) {
        if (kv.second > 2) {
            std::cout << kv.first << " - " << kv.second << std::endl;
        }
    }
    
    std::cout << PREFIX "writing json output..." << std::endl;
    write_json();
    fclose(output_fp);
    std::cout << PREFIX "done." << std::endl;
}
