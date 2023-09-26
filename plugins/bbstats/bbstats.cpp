#include "block.h"
#include "filter.h"
#include "image.h"
#include "process.h"

#include "ipanda/ipanda.h"
#include "ipanda/manager.h"

#include "exec/cpu-defs.h"

#include <avro.h>

#include <algorithm>
#include <iostream>
#include <memory>
#include <regex>
#include <unordered_map>
#include <vector>

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
void before_block_exec(CPUState*, TranslationBlock*);
bool process_change(CPUState*, target_ulong, target_ulong);
}

std::shared_ptr<Windows7IntrospectionManager> g_os_manager;
struct WindowsKernelOSI* g_kernel_osi = nullptr;

std::shared_ptr<InstrumentationFilter> g_filter;
bool g_target_thread = true;

std::unordered_map<std::string, std::shared_ptr<Process>> process_map;

avro_schema_t g_schema = nullptr;
avro_schema_t g_subschema = nullptr;
avro_file_writer_t g_db = nullptr;

void teardown_avro()
{
    avro_file_writer_flush(g_db);
    avro_file_writer_close(g_db);
    avro_schema_decref(g_schema);
    avro_schema_decref(g_subschema);
}

bool init_avro(const char* dbname)
{
    int status = 0;
    g_subschema = avro_schema_record("instruction", NULL);
    avro_schema_record_field_append(g_subschema, "offset", avro_schema_long());
    avro_schema_record_field_append(g_subschema, "hexdump", avro_schema_string());
    avro_schema_record_field_append(g_subschema, "mnemonic", avro_schema_string());
    avro_schema_record_field_append(g_subschema, "arguments", avro_schema_string());

    g_schema = avro_schema_record("bbstat", NULL);
    avro_schema_record_field_append(g_schema, "pid", avro_schema_long());
    avro_schema_record_field_append(g_schema, "asid", avro_schema_long());
    avro_schema_record_field_append(g_schema, "threads",
                                    avro_schema_array(avro_schema_long()));
    avro_schema_record_field_append(g_schema, "image_guid", avro_schema_string());
    avro_schema_record_field_append(g_schema, "image_path", avro_schema_string());
    avro_schema_record_field_append(g_schema, "image_base", avro_schema_long());
    avro_schema_record_field_append(g_schema, "pc", avro_schema_long());
    avro_schema_record_field_append(g_schema, "rva", avro_schema_long());
    avro_schema_record_field_append(g_schema, "icount", avro_schema_long());
    avro_schema_record_field_append(g_schema, "size", avro_schema_long());
    avro_schema_record_field_append(g_schema, "hits", avro_schema_long());
    avro_schema_record_field_append(g_schema, "instructions",
                                    avro_schema_array(g_subschema));
    remove(dbname);

    size_t sixteen_mib = 16 * 1024 * 1024;
    status = avro_file_writer_create_with_codec(dbname, g_schema, &g_db, "deflate",
                                                sixteen_mib);
    if (status) {
        fprintf(stderr, "[%s] Failed to open %s for writing\n", __FILE__, dbname);
        fprintf(stderr, "[E] %s\n", avro_strerror());
        return true;
    }
    fprintf(stdout, "Writing analysis results to %s\n", dbname);
    return false;
}

void write_entry(std::shared_ptr<Process> p, std::shared_ptr<Image> i,
                 std::shared_ptr<Block> b)
{
    avro_datum_t bbstat_dt = avro_record(g_schema);

    avro_datum_t pid_dt = avro_int64(p->get_pid());
    avro_datum_t asid_dt = avro_int64(p->get_asid());
    avro_datum_t thread_dt = avro_array(avro_schema_long());
    for (auto tid : b->get_threads()) {
        avro_datum_t tid_dt = avro_int64(tid);
        avro_array_append_datum(thread_dt, tid_dt);
    }

    avro_datum_t image_guid_dt = avro_string(i->get_guid());
    avro_datum_t image_path_dt = avro_string(i->get_full_path().c_str());
    avro_datum_t image_base_dt = avro_int64((int64_t)i->get_base_address());

    avro_datum_t pc_dt = avro_int64((int64_t)b->get_pc());
    avro_datum_t rva_dt = avro_int64((int64_t)b->get_rva());
    avro_datum_t icount_dt = avro_int64((int64_t)b->get_icount());
    avro_datum_t size_dt = avro_int64((int64_t)b->get_size());
    avro_datum_t hits_dt = avro_int64((int64_t)b->get_hits());

    avro_schema_t array_schema = avro_schema_get_subschema(g_schema, "instructions");
    avro_datum_t array_dt = avro_array(array_schema);
    for (auto& inst : b->get_instructions()) {
        avro_datum_t inst_dt = avro_record(g_subschema);
        avro_record_set(inst_dt, "offset", avro_int64(std::get<0>(inst)));
        avro_record_set(inst_dt, "hexdump", avro_string(std::get<1>(inst).c_str()));
        avro_record_set(inst_dt, "mnemonic", avro_string(std::get<2>(inst).c_str()));
        avro_record_set(inst_dt, "arguments", avro_string(std::get<3>(inst).c_str()));
        avro_array_append_datum(array_dt, inst_dt);
    }

    if (avro_record_set(bbstat_dt, "pid", pid_dt) ||
        avro_record_set(bbstat_dt, "asid", asid_dt) ||
        avro_record_set(bbstat_dt, "threads", thread_dt) ||
        avro_record_set(bbstat_dt, "image_guid", image_guid_dt) ||
        avro_record_set(bbstat_dt, "image_path", image_path_dt) ||
        avro_record_set(bbstat_dt, "image_base", image_base_dt) ||
        avro_record_set(bbstat_dt, "pc", pc_dt) ||
        avro_record_set(bbstat_dt, "rva", rva_dt) ||
        avro_record_set(bbstat_dt, "icount", icount_dt) ||
        avro_record_set(bbstat_dt, "size", size_dt) ||
        avro_record_set(bbstat_dt, "hits", hits_dt) ||
        avro_record_set(bbstat_dt, "instructions", array_dt)) {

        fprintf(stderr, "[%s] Failed to create bbstat datum\n", __FILE__);
        exit(-1);
    }

    if (avro_file_writer_append(g_db, bbstat_dt)) {
        fprintf(stderr, "[%s] Failed to write bbstat: %s\n", __FILE__, avro_strerror());
        exit(-1);
    }

    avro_datum_decref(pid_dt);
    avro_datum_decref(asid_dt);
    avro_datum_decref(image_guid_dt);
    avro_datum_decref(image_path_dt);
    avro_datum_decref(image_base_dt);
    avro_datum_decref(pc_dt);
    avro_datum_decref(rva_dt);
    avro_datum_decref(icount_dt);
    avro_datum_decref(size_dt);
    avro_datum_decref(hits_dt);
    avro_datum_decref(array_dt);
}

void flush_stats()
{
    for (auto& pmap : process_map) {
        auto process = pmap.second;
        for (auto& imap : process->images) {
            auto image = imap.second;
            for (auto& bmap : image->blocks) {
                auto block = bmap.second;
                write_entry(process, image, block);
            }
        }
    }
}

bool process_change(CPUState* env, target_ulong oldval, target_ulong newval)
{
    g_target_thread = true;
    return 0;
}

void before_block_exec(CPUState* env, TranslationBlock* tb)
{
    if (!g_target_thread || panda_in_kernel(env)) {
        return;
    }

    struct WindowsProcess* proc = kosi_get_current_process(g_kernel_osi);

    // this is a quicker check
    if (!(g_filter->thread_check(process_get_pid(proc), process_get_asid(proc)))) {
        g_target_thread = false;
        free_process(proc);
        return;
    }

    // than this
    auto thread_id = kosi_get_current_tid(g_kernel_osi);
    if (!(g_filter->thread_check(process_get_pid(proc), process_get_asid(proc),
                                 thread_id))) {
        g_target_thread = false;
        free_process(proc);
        return;
    }

    auto p = std::make_shared<Process>(proc);
    auto r = process_map.insert(std::make_pair(p->key(), p));
    std::unordered_map<std::string, std::shared_ptr<Process>>::iterator it = r.first;

    uint64_t bb_address = tb->pc;
    std::shared_ptr<Image> current_image;
    if (r.second) {
        current_image = p->get_image(g_kernel_osi, proc, bb_address);
    } else {
        current_image = ((*it).second)->get_image(g_kernel_osi, proc, bb_address);
    }
    free_process(proc);

    if (current_image == nullptr) {
        return;
    }

    auto manager = WindowsProcessManager();
    manager.initialize(g_kernel_osi, p->get_eprocess());
    auto posi = manager.get_process_object();
    // check if this guid is interesting
    if (!(g_filter->module_check(current_image->get_guid(posi)))) {
        return;
    }

    // add a disassembled block
    std::shared_ptr<Block> block = current_image->add_block(
        thread_id, bb_address, current_image->get_rva(bb_address), tb->icount, tb->size,
        posi);
    block->hit();

    return;
}

bool init_plugin(void* self)
{
    // input
    panda_arg_list* param_args = panda_get_args("params");
    const char* filter_file = strdup(panda_parse_string(param_args, "filter", ""));
    if (filter_file[0] == '\0') {
        fprintf(stderr, "[%s] A filter must be provided\n", __FILE__);
        return false;
    }
    g_filter.reset(new InstrumentationFilter(filter_file));
    panda_free_args(param_args);

    // output
    panda_arg_list* bbstats_args = panda_get_args("bbstats");
    const char* output_path =
        strdup(panda_parse_string(bbstats_args, "output", "bbstats.panda"));
    if (init_avro(output_path)) {
        return false;
    }
    panda_free_args(bbstats_args);

    std::shared_ptr<IntroPANDAManager> os_manager;

    if (!init_ipanda(self, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return false;
    }

    // temporary -- forcing to be windows specific so i don't have to edit any more code
    // in this plugin
    g_os_manager = std::dynamic_pointer_cast<Windows7IntrospectionManager>(os_manager);
    g_kernel_osi = g_os_manager->get_kosi();

    // register callback
    panda_cb pcb;
    pcb.asid_changed = process_change;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    fprintf(stderr, "Finished initializing BBStats.\n");
    return true;
}

void uninit_plugin(void* self)
{
    flush_stats();
    teardown_avro();
}
