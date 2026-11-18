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
//#include "pr61hash_test.h"

#define PREFIX "[memory_hash] "

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
}


// Types for 
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
static std::map<page_key_t, pr61hash_t> hash_uncommitited;
static std::map<pr61hash_t, uint64_t> hash_freq; // frequency of each hash that appears

// filter variables
static std::shared_ptr<IntroPANDAManager> os_manager;
static auto tracefilter = std::shared_ptr<TraceFilter>();
static bool allowed = false;


void write_json() 
{
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
    
    physical_t vpage_id = (vaddr & ~(0xFFF));
    physical_t vpage_offset = (vaddr & (0xFFF));
    uint8_t buffer[PAGE_SIZE];
    pr61hash_t hash_new = (pr61hash_t)-1;
    page_key_t current_page_key;
    
    // "before" hook is called up to 3 times before successful page read, 
    // first fault for TLB, second fault for process PT. 
    if (panda_virtual_memory_read(env, vpage_id, buffer, PAGE_SIZE) == -1) return;
    // successful page read by this point. 

    asid_t asid = panda_current_asid(env);
    current_page_key = std::make_tuple(asid, vpage_id);

    // if first encounter with page
    if (pages_written.find(current_page_key) == pages_written.end()) {
        // Calculate the full hash and update structures
        hash_new = full_poly_hash(buffer);
        pages_written[current_page_key] = { hash_new };
    } else {
        // Theres a chance something changes in the page between committed hashes.
        // Check by calculating the full hash and comparing to last hash for the page.
        pr61hash_t hash_curr = full_poly_hash(buffer);
        pr61hash_t hash_prev = pages_written[current_page_key].back();
        //std::cout << PREFIX "before PAGE unchanged check: " << (hash_curr != hash_prev)
        //    << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
        //    << " HASH_NEW: " << hash_curr
        //    << " HASH_OLD: " << hash_prev
        //    << std::dec << std::setw(0) << std::endl;
        if (hash_curr != hash_prev) {
            //std::cerr << PREFIX "WARNING: page update went undetected, syncing..." << std::endl;
            pages_written[current_page_key].push_back(hash_curr);
            hash_freq[hash_curr]++;
        }
    }
    
    // adjust page size if needed
    if (size+vpage_offset > PAGE_SIZE) { 
        size = PAGE_SIZE - vpage_offset;
    }
   
    pr61hash_t hash_old = pages_written[current_page_key].back();
    hash_new = apply_delta(hash_old, &buffer[vpage_offset], buf, size, vpage_offset);
    hash_uncommitited[current_page_key] = hash_new;
    hash_freq[hash_new]++;

    //std::cout << PREFIX "DEBUG: before"
    //    << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
    //    << " ASID: 0x" << asid 
    //    << " PAGE: 0x" << vpage_id
    //    << " OFFSET: 0x" << vpage_offset
    //    << " SIZE: 0x" << size
    //    << " MULTIPAGE: " << (vpage_offset + size > PAGE_SIZE)
    //    << " HASH: " << hash_new
    //    << std::dec << std::setw(0) << std::endl;
}

void mh_virt_mem_after_write(CPUState *env, target_ptr_t pc, target_ptr_t vaddr, size_t size, uint8_t *buf)
{
    if (!allowed || panda_in_kernel(env)) return;

    asid_t asid = panda_current_asid(env);
    physical_t vpage_id = (vaddr & ~(0xFFF));
    //physical_t vpage_offset = (vaddr & (0xFFF));
    uint8_t buffer[PAGE_SIZE];
    
    if (panda_virtual_memory_read(env, vpage_id, buffer, PAGE_SIZE) == -1) return;
     
    page_key_t current_page_key = std::make_tuple(asid, vpage_id);
    pr61hash_t hash_new = hash_uncommitited[current_page_key];
    
    pr61hash_t hash_prev = pages_written[current_page_key].back();
    if (hash_prev == hash_new) return;

    //pr61hash_t hash_a = full_poly_hash(buffer);
    //std::cout << PREFIX "after PAGE unchanged check: " << (hash_a != hash_new) 
    //    << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
    //    << " HASH_NEW: " << hash_a
    //    << " HASH_OLD: " << hash_new
    //    << std::dec << std::setw(0) << std::endl;
    //assert(hash_a == hash_new);

    //commit hash
    pages_written[current_page_key].push_back(hash_new);
    phys_write_count++;
 
    //std::cout << PREFIX << "DEBUG: after"
    //    << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
    //    << " ASID: 0x" << asid 
    //    << " PAGE: 0x" << vpage_id
    //    << " OFFSET: 0x" << vpage_offset
    //    << " SIZE: 0x" << size
    //    << " MULTIPAGE: " << (vpage_offset + size > PAGE_SIZE)
    //    << " COMMITTED: " << hash_new
    //    << std::dec << std::setw(0) << std::endl;
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

    // Test Hash lib
    //test_pr61();

    // enable memory callbacks, turned off by defualt
    panda_enable_memcb();

    // Post vm load initialization
    pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(init_memhash));
    panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    pcb.virt_mem_before_write = mh_virt_mem_before_write;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE,  pcb);
    
    pcb.virt_mem_after_write = mh_virt_mem_after_write;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE,  pcb);
    
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

    std::cout << std::hex;
    for (const auto& kv : hash_freq) {
        if (kv.second > 100) {
            std::cout << kv.first << " - " << kv.second << std::endl;
        }
    }
    std::cout << std::dec;
    
    std::cout << PREFIX "writing json output..." << std::endl;
    write_json();
    fclose(output_fp);
    std::cout << PREFIX "done." << std::endl;
}
