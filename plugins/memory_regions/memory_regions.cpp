// panda
#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include "ipanda/ipanda.h"
#include "ipanda/manager.h"

// libosi
#include "offset/i_t.h"
#include "osi/windows/manager.h"
#include "osi/windows/wintrospection.h"

// data
#include <avro.h>   // serialization
#include <iterator> // iter
#include <map>      // map
#include <tuple>    // tuple
#include <utility>  // pair
#include <vector>   // vector

// general
#include <iostream>
#include <memory>

// memory region
#include "region.h"

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
}

#define SYSTEM_ASID_i386 0x185000
#define SYSTEM_ASID_x86_64 0x187000

typedef std::pair<target_ulong, target_ulong> keytype;

// hierarchy that gives (pid, asid) -> (start address, end address) -> small vector of
// Regions
std::map<keytype, std::map<keytype, std::vector<std::shared_ptr<Region>>>> region_map;

// keep track of current state
bool g_needs_update;
target_ulong current_pid;
target_ulong current_asid;
std::unique_ptr<WindowsProcessManager> g_posi;

// cache of last region: useful for functions with many basic blocks
// would cache region at first basic block and never look it up again
std::shared_ptr<Region> last_region_match;

std::shared_ptr<Windows7IntrospectionManager> g_os_manager;
struct WindowsKernelOSI* g_kernel_osi = nullptr;

/*--------------------------------------------------------------------------------------------------|
|                                     AVRO SERIALIZATION |
|--------------------------------------------------------------------------------------------------*/
avro_schema_t g_region_schema = nullptr;
avro_file_writer_t g_db = nullptr;
bool init_avro(const char* db)
{
    int status = 0;

    g_region_schema = avro_schema_record("region", NULL);
    // schema for a memory region

    // basic info
    avro_schema_record_field_append(g_region_schema, "pid", avro_schema_long());
    avro_schema_record_field_append(g_region_schema, "threads",
                                    avro_schema_array(avro_schema_long()));
    avro_schema_record_field_append(g_region_schema, "asid", avro_schema_long());
    avro_schema_record_field_append(g_region_schema, "process", avro_schema_string());
    avro_schema_record_field_append(g_region_schema, "memory_region_start",
                                    avro_schema_long());
    avro_schema_record_field_append(g_region_schema, "memory_region_end",
                                    avro_schema_long());
    avro_schema_record_field_append(g_region_schema, "rrindex_start", avro_schema_long());
    avro_schema_record_field_append(g_region_schema, "rrindex_end", avro_schema_long());

    // flags
    avro_schema_record_field_append(g_region_schema, "valid_metadata",
                                    avro_schema_boolean());
    avro_schema_record_field_append(g_region_schema, "executes", avro_schema_boolean());

    // meta info
    avro_schema_record_field_append(g_region_schema, "private_memory",
                                    avro_schema_boolean());
    avro_schema_record_field_append(g_region_schema, "mem_commit", avro_schema_boolean());
    avro_schema_record_field_append(g_region_schema, "initial_protections",
                                    avro_schema_long());
    avro_schema_record_field_append(g_region_schema, "backing_file",
                                    avro_schema_string());

    remove(db);

    size_t sixteen_mib = 16 * 1024 * 1024;
    status = avro_file_writer_create_with_codec(db, g_region_schema, &g_db, "deflate",
                                                sixteen_mib);
    if (status) {
        fprintf(stderr, "[E] Failed to open %s with error: %s", db, avro_strerror());
        return true;
    }
    return false;
}

void teardown_avro()
{
    avro_file_writer_flush(g_db);
    avro_file_writer_close(g_db);
    avro_schema_decref(g_region_schema);
}

void add_entry(Region* reg)
{
    avro_datum_t region_dt = avro_record(g_region_schema);

    // basic info
    avro_datum_t pid_dt = avro_int64((int64_t)reg->get_pid());
    avro_datum_t asid_dt = avro_int64((int64_t)reg->get_asid());
    avro_datum_t process_dt = avro_string(reg->get_process().c_str());
    avro_datum_t start_addr_dt = avro_int64((int64_t)reg->get_start_addr());
    avro_datum_t end_addr_dt = avro_int64((int64_t)reg->get_end_addr());
    avro_datum_t start_rec_dt = avro_int64((int64_t)reg->get_start_rec());
    avro_datum_t end_rec_dt = avro_int64((int64_t)reg->get_end_rec());

    // flags
    avro_datum_t valid_dt = avro_boolean(reg->get_valid_flag());
    avro_datum_t exe_dt = avro_boolean(reg->get_exe_flag());

    // metadata
    metadata md = reg->get_metadata();
    avro_datum_t private_dt = avro_boolean(md.private_mem);
    avro_datum_t commit_dt = avro_boolean(md.mem_commit);
    avro_datum_t protection_dt = avro_int64((int64_t)md.initial_protections);
    avro_datum_t backing_dt = avro_string(md.backing_file.c_str());

    avro_datum_t thread_dt = avro_array(avro_schema_long());
    for (auto tid : reg->get_threads()) {
        avro_datum_t tid_dt = avro_int64(tid);
        avro_array_append_datum(thread_dt, tid_dt);
    }

    if (avro_record_set(region_dt, "pid", pid_dt) ||
        avro_record_set(region_dt, "asid", asid_dt) ||
        avro_record_set(region_dt, "process", process_dt) ||
        avro_record_set(region_dt, "threads", thread_dt) ||
        avro_record_set(region_dt, "memory_region_start", start_addr_dt) ||
        avro_record_set(region_dt, "memory_region_end", end_addr_dt) ||
        avro_record_set(region_dt, "rrindex_start", start_rec_dt) ||
        avro_record_set(region_dt, "rrindex_end", end_rec_dt) ||
        avro_record_set(region_dt, "valid_metadata", valid_dt) ||
        avro_record_set(region_dt, "executes", exe_dt) ||
        avro_record_set(region_dt, "private_memory", private_dt) ||
        avro_record_set(region_dt, "mem_commit", commit_dt) ||
        avro_record_set(region_dt, "initial_protections", protection_dt) ||
        avro_record_set(region_dt, "backing_file", backing_dt)) {
        fprintf(stderr, "[%s] Avro failed to build memory region\n", __FILE__);
    }

    if (avro_file_writer_append(g_db, region_dt)) {
        fprintf(stderr, "[E] Avro failed to write %s\n", avro_strerror());
    }

    avro_datum_decref(pid_dt);
    avro_datum_decref(thread_dt);
    avro_datum_decref(asid_dt);
    avro_datum_decref(process_dt);
    avro_datum_decref(start_addr_dt);
    avro_datum_decref(end_addr_dt);
    avro_datum_decref(start_rec_dt);
    avro_datum_decref(end_rec_dt);
    avro_datum_decref(valid_dt);
    avro_datum_decref(exe_dt);
    avro_datum_decref(private_dt);
    avro_datum_decref(commit_dt);
    avro_datum_decref(protection_dt);
    avro_datum_decref(backing_dt);
}

void dump_regions()
{
    // pretty ugly iterators for looping through each layer of the map
    std::map<keytype, std::map<keytype, std::vector<std::shared_ptr<Region>>>>::iterator
        i_top;
    std::map<keytype, std::vector<std::shared_ptr<Region>>>::iterator i_sec;
    std::vector<std::shared_ptr<Region>>::iterator i_bot;

    for (i_top = region_map.begin(); i_top != region_map.end(); i_top++) {
        for (i_sec = i_top->second.begin(); i_sec != i_top->second.end(); i_sec++) {
            for (i_bot = i_sec->second.begin(); i_bot != i_sec->second.end(); i_bot++) {
                add_entry((*i_bot).get());
            }
        }
    }
}

/*--------------------------------------------------------------------------------------------------|
|                          MEMORY REGION COLLECTION: Windows Only! |
|--------------------------------------------------------------------------------------------------*/
/*
    jumps to the vector of regions with this pid, asid, start, and end and checks if this
    region corresponds to an existing region or if this is a reused region. Does so by
    comparing against a key that is __likely__ unique for a region.
*/
void unique_add_region(keytype top, keytype second, std::shared_ptr<Region> curr)
{
    std::vector<std::shared_ptr<Region>>::iterator ri;

    for (ri = region_map[top][second].begin(); ri != region_map[top][second].end();
         ri++) {
        if ((*ri)->get_rkey() == curr->get_rkey()) {
            (*ri)->update_end_rec();
            return;
        }
    }
    region_map[top][second].push_back(curr);
}

/*
    a recursive walk of the VAD Tree, recording regions along the way
*/
void walk_regions(osi::i_t vad)
{
    if (vad.get_address() == 0) {
        return;
    }

    // add the current region to the map
    auto current_region =
        std::make_shared<Region>(vad, g_posi->get_process_object(), g_kernel_osi);
    keytype pa = std::make_pair(current_region->get_pid(), current_region->get_asid());
    keytype se =
        std::make_pair(current_region->get_start_addr(), current_region->get_end_addr());

    if (region_map.find(pa) != region_map.end() &&
        region_map[pa].find(se) != region_map[pa].end()) {
        unique_add_region(pa, se, current_region);
    } else {
        region_map[pa][se].push_back(current_region);
    }

    // just keep swimming
    walk_regions(vad("LeftChild"));
    walk_regions(vad("RightChild"));
}

/*
    occurs notably when the ASID changes (which requires the page directory to be changed)
*/
bool after_pgd_write(CPUState* env, target_ulong old_pgd, target_ulong new_pgd)
{
    g_needs_update = true;
    return 0;
}

/*--------------------------------------------------------------------------------------------------|
|                           IS THIS MEMORY REGION EXECUTING? |
|--------------------------------------------------------------------------------------------------*/
bool is_addr_in_region(keytype range, target_ulong target)
{
    if (target < range.first || target > range.second)
        return false;
    else
        return true;
}

/*
    At this point, we have found that a memory region in this pid, asid, start, and end is
    currently executing. The region most recently added to the vector should be the region
    most recently allocated -- should be the one executing right now
*/
std::shared_ptr<Region> get_most_recent(std::vector<std::shared_ptr<Region>> candidates)
{
    std::vector<std::shared_ptr<Region>>::iterator ri;
    std::shared_ptr<Region> most_recent;

    for (ri = candidates.begin(); ri != candidates.end(); ri++) {
        if (most_recent == nullptr ||
            (*ri)->get_start_rec() > most_recent->get_start_rec()) {
            most_recent = (*ri);
        }
    }

    return most_recent;
}

/*
    attempts to take PC and narrow down results to a vector this region should be in
*/
std::shared_ptr<Region> fit_into_region(target_ulong pc)
{
    keytype key_top = std::make_pair(current_pid, current_asid);

    // we don't have the region
    if (region_map.find(key_top) == region_map.end()) {
        return nullptr;
    }

    // return the most recently encountered entry of this region
    std::map<keytype, std::vector<std::shared_ptr<Region>>>::iterator ri;
    for (ri = (region_map[key_top]).begin(); ri != (region_map[key_top]).end(); ri++) {
        if (is_addr_in_region(ri->first, pc)) {
            return get_most_recent(ri->second);
        }
    }

    // we don't have this region
    return nullptr;
}

bool update_vads(CPUState* env)
{
    bool success = false;

    // if this is beign called, we have changed processes
    // and need a new process memory reader
    g_posi.reset(new WindowsProcessManager());

    try {
        if (g_posi->initialize(g_kernel_osi,
                               kosi_get_current_process_address(g_kernel_osi))) {

            osi::i_t eproc = g_posi->get_process();
            current_pid = eproc["UniqueProcessId"].getu();
            current_asid = eproc.get_virtual_memory()->get_asid();

            osi::i_t vad_root = eproc["VadRoot"]["BalancedRoot"];
            walk_regions(vad_root);
            success = true;
        }
    } catch (const std::exception& e) {
    }

    return success;
}

/*
    At each basic block, check what the program counter is. Mark the memory region that
   the program counter falls in, since this would mean the memory region has execution
   within it
*/
void before_block_exec(CPUState* env, TranslationBlock* tb)
{
    // there are no VAD entries for kernel memory
    if (panda_in_kernel(env) ||
        (g_kernel_osi->system_vmem->get_pointer_width() == 8 &&
         panda_current_asid(env) == SYSTEM_ASID_x86_64) ||
        (g_kernel_osi->system_vmem->get_pointer_width() == 4 &&
         panda_current_asid(env) == SYSTEM_ASID_i386)) {
        return;
    }

    // get PC -- updated at each BB (not within BB unless panda_enable_precise_pc())
    auto pc = tb->pc;

    // check if we are still in the last region to save us a lookup
    // or update if the asid has recently changed
    if (!g_needs_update) {
        if (last_region_match != nullptr && last_region_match->get_start_addr() <= pc &&
            last_region_match->get_end_addr() >= pc) {
            return;
        }
    } else {
        update_vads(env);
        g_needs_update = false;
    }

    auto reg = fit_into_region(pc);
    if (reg != nullptr) {
        // mark as having executed and update cache
        reg->does_execute(g_kernel_osi);
        last_region_match = reg;
    } else {
        // region isn't in the VAD tree at all and isn't kernel memory?
        // fprintf(
        //    stdout,
        //    "[DEBUG] Cannot find region with | pc: 0x%16lx | pid: %lu | asid: "
        //    "0x%16lx |\n",
        //    (unsigned long)pc, (unsigned long)current_pid,
        //    (unsigned long)current_asid);
    }

    return;
}

/*--------------------------------------------------------------------------------------------------|
|                                 PLUGIN INITIALIZATION |
|--------------------------------------------------------------------------------------------------*/
bool init_plugin(void* self)
{
#if defined(TARGET_I386)
    // make sure we are on Windows
    auto panda_os_type = panda_os_familyno;
    if (panda_os_type != OS_WINDOWS) {
        fprintf(stderr, "[%s] Currently, only Windows is supported.\n", __FILE__);
        return false;
    }

    // register callbacks
    panda_cb pcb;
    pcb.asid_changed = after_pgd_write;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    // Get desired results path
    panda_arg_list* args = panda_get_args("memory_regions");
    const char* output_path =
        strdup(panda_parse_string(args, "output", "memory_regions.panda"));
    panda_free_args(args);

    // initialize avro with the output path
    if (init_avro(output_path)) {
        fprintf(stderr, "[%s] Failed to initialize avro.\n", __FILE__);
        return false;
    }

    // initialize globals
    g_needs_update = true;
    current_pid = 0;
    current_asid = 0;
    g_posi = std::make_unique<WindowsProcessManager>();

    std::shared_ptr<IntroPANDAManager> os_manager;

    if (!init_ipanda(self, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return false;
    }

    // temporary -- forcing to be windows specific so i don't have to edit any more code
    // in this plugin
    g_os_manager = std::dynamic_pointer_cast<Windows7IntrospectionManager>(os_manager);
    g_kernel_osi = g_os_manager->get_kosi();

#else
    fprintf(stderr, "[%s] Plugin not supported on this platform.\n", __FILE__);
    return false;

#endif
    fprintf(stdout, "memory_regions initialized\n");
    return true;
}

void uninit_plugin(void* self)
{
    dump_regions();
    teardown_avro();
}
