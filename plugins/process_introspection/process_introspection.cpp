#include <avro.h>
#include <glib.h>
#include <map>
#include <memory>
#include <string>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include "process_tracker.h"

#include <ipanda/ipanda.h>
#include <ipanda/manager.h>
#include <ipanda/types.h>

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
void before_block_exec(CPUState* env, TranslationBlock* tb);
}

std::unique_ptr<ProcessTracker> g_tracker;
avro_schema_t g_process_schema = nullptr;
avro_schema_t g_module_schema = nullptr;
avro_file_writer_t g_db = nullptr;
bool initialized = false;

bool init_avro(const char* dbname)
{
    int status = 0;

    g_module_schema = avro_schema_record("module", NULL);
    avro_schema_record_field_append(g_module_schema, "name", avro_schema_string());
    avro_schema_record_field_append(g_module_schema, "path", avro_schema_string());
    avro_schema_record_field_append(g_module_schema, "base_address", avro_schema_long());
    avro_schema_record_field_append(g_module_schema, "image_size", avro_schema_long());
    avro_schema_record_field_append(g_module_schema, "timedatestamp", avro_schema_long());
    avro_schema_record_field_append(g_module_schema, "entry_point", avro_schema_long());
    avro_schema_record_field_append(g_module_schema, "guid", avro_schema_string());

    // Initialize the schema for a memstring
    g_process_schema = avro_schema_record("process", NULL);
    avro_schema_record_field_append(g_process_schema, "type", avro_schema_string());
    avro_schema_record_field_append(g_process_schema, "pid", avro_schema_long());
    avro_schema_record_field_append(g_process_schema, "ppid", avro_schema_long());
    avro_schema_record_field_append(g_process_schema, "asid", avro_schema_long());
    avro_schema_record_field_append(g_process_schema, "name", avro_schema_string());
    avro_schema_record_field_append(g_process_schema, "cmdline", avro_schema_string());
    avro_schema_record_field_append(g_process_schema, "create_time", avro_schema_long());
    avro_schema_record_field_append(g_process_schema, "base_vba", avro_schema_long());
    avro_schema_record_field_append(g_process_schema, "start_rrindex",
                                    avro_schema_long());
    avro_schema_record_field_append(g_process_schema, "end_rrindex", avro_schema_long());
    avro_schema_record_field_append(g_process_schema, "modules",
                                    avro_schema_array(g_module_schema));

    remove(dbname);

    // the default maximum size of a record to be written is 16K. We've seen this be
    // exceeded, when a process has *a lot* of modules, so we are just being safe here and
    // upping that to 16M.
    status =
        avro_file_writer_create_with_codec(dbname, g_process_schema, &g_db, "deflate", 0);

    if (status) {
        fprintf(stderr, "[%s] Avro failed to open %s for writing\n", __FILE__, dbname);
        fprintf(stderr, "[E] error message: %s\n", avro_strerror());
        return true;
    }
    fprintf(stdout, "Writing analysis results to %s\n", dbname);
    return false;
}

void write_avro_record(const ipanda_types::Process& proc)
{
    avro_datum_t process_dt = avro_record(g_process_schema);
    avro_datum_t type_dt = avro_string(panda_os_name);
    avro_datum_t name_dt = avro_string(proc.name.c_str());
    avro_datum_t cmdline_dt = avro_string(proc.cmdline.c_str());
    avro_datum_t asid_dt = avro_int64((int64_t)proc.asid);
    avro_datum_t pid_dt = avro_int64((int64_t)proc.pid);
    avro_datum_t ppid_dt = avro_int64((int64_t)proc.ppid);
    avro_datum_t create_time_dt = avro_int64((int64_t)proc.create_time);
    avro_datum_t base_vba_dt = avro_int64((int64_t)proc.base_vba);
    avro_datum_t start_rrindex_dt = avro_int64((int64_t)proc.start_rrindex);
    avro_datum_t end_rrindex_dt = avro_int64((int64_t)proc.end_rrindex);

    avro_schema_t array_schema = avro_schema_get_subschema(g_process_schema, "modules");
    avro_datum_t array_dt = avro_array(array_schema);
    for (auto& pair : proc.modules) {
        auto& mod = pair.second;
        avro_datum_t mod_dt = avro_record(g_module_schema);
        avro_record_set(mod_dt, "name", avro_string(mod.name.c_str()));
        avro_record_set(mod_dt, "path", avro_string(mod.path.c_str()));
        avro_record_set(mod_dt, "base_address", avro_int64((int64_t)mod.base_address));
        avro_record_set(mod_dt, "image_size", avro_int64((int64_t)mod.image_size));
        avro_record_set(mod_dt, "timedatestamp", avro_int64((int64_t)mod.timedatestamp));
        avro_record_set(mod_dt, "entry_point", avro_int64((int64_t)mod.entry_point));

        auto guid = g_tracker->lookup_guid(mod.path);
        avro_record_set(mod_dt, "guid", avro_string(guid.c_str()));
        avro_array_append_datum(array_dt, mod_dt);
    }

    if (avro_record_set(process_dt, "type", type_dt) ||
        avro_record_set(process_dt, "pid", pid_dt) ||
        avro_record_set(process_dt, "ppid", ppid_dt) ||
        avro_record_set(process_dt, "asid", asid_dt) ||
        avro_record_set(process_dt, "name", name_dt) ||
        avro_record_set(process_dt, "cmdline", cmdline_dt) ||
        avro_record_set(process_dt, "base_vba", base_vba_dt) ||
        avro_record_set(process_dt, "create_time", create_time_dt) ||
        avro_record_set(process_dt, "modules", array_dt) ||
        avro_record_set(process_dt, "start_rrindex", start_rrindex_dt) ||
        avro_record_set(process_dt, "end_rrindex", end_rrindex_dt)) {
        fprintf(stderr, "[E] Avro failed to build process: %s\n", avro_strerror());
    }

    if (avro_file_writer_append(g_db, process_dt)) {
        fprintf(stderr, "[E] Avro failed to write process: %s\n", avro_strerror());
    }
    avro_datum_decref(type_dt);
    avro_datum_decref(name_dt);
    avro_datum_decref(cmdline_dt);
    avro_datum_decref(asid_dt);
    avro_datum_decref(pid_dt);
    avro_datum_decref(ppid_dt);
    avro_datum_decref(create_time_dt);
    avro_datum_decref(base_vba_dt);
    avro_datum_decref(array_dt);
    avro_datum_decref(start_rrindex_dt);
    avro_datum_decref(end_rrindex_dt);
    avro_datum_decref(process_dt);
}

void teardown_avro()
{
    avro_file_writer_flush(g_db);
    avro_file_writer_close(g_db);
    avro_schema_decref(g_process_schema);
    avro_schema_decref(g_module_schema);
}

void before_block_exec(CPUState* env, TranslationBlock* tb)
{
    if (!initialized) {
        return;
    }
    if (panda_in_kernel(env)) {
        return;
    }
    if (g_tracker) {
        g_tracker->before_basic_block_exec(env);
    }
    return;
}

bool context_switch_callback(CPUState* env, target_ulong old_asid, target_ulong new_asid)
{
    if (!initialized) {
        std::shared_ptr<IntroPANDAManager> os_manager;
        if (init_ipanda(env, os_manager)) {
            g_tracker = std::unique_ptr<ProcessTracker>(new ProcessTracker(os_manager));
            fprintf(stdout, "success initializing ipanda!\n");
            initialized = true;
        } else {
            return 0;
        }
    }
    if (g_tracker) {
        g_tracker->asid_updated();
    }
    return false;
}

bool init_plugin(void* self)
{
#if defined(TARGET_I386)
    fprintf(stdout, "Initializing plugin process_introspection\n");

    const char* output_path = nullptr;
    panda_arg_list* args = panda_get_args("process_introspection");
    output_path = panda_parse_string(args, "output", "process_introspection.panda");
    if (init_avro(output_path)) {
        return false;
    }

    // RW: after_PGD_write may be more efficient, but slightly more complicated
    panda_cb pcb;
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.asid_changed = context_switch_callback;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    // Initialize introspection library
    std::shared_ptr<IntroPANDAManager> os_manager;
    initialized = init_ipanda(self, os_manager);

    if (!initialized) {
        fprintf(stderr, "[%s] Could not initialize the introspection library.\n",
                __FILE__);
    } else {
        g_tracker = std::unique_ptr<ProcessTracker>(new ProcessTracker(os_manager));
    }

    panda_free_args(args);
    return true;

#else
    fprintf(stderr, "The process_introspection PANDA plugin does not support "
                    "this platform.\n");
    return false;
#endif
    return true;
}

void uninit_plugin(void* self)
{
    // Dump out to pandalog
    fprintf(stdout,
            "Unloading process_introspection plugin, dumping data to output file\n");
    if (g_tracker) {
        const auto& process_map = g_tracker->results();
        for (auto& proc : process_map) {
            write_avro_record(proc.second);
        }
    }
    teardown_avro();
}
