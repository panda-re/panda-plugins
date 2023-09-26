
#define __STDC_FORMAT_MACROS

extern "C" {
#include <Python.h>
#include <dlfcn.h>
#include <errno.h>
}
#include <avro.h>
#include <libgen.h>
#include <memory>
#include <unistd.h>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include "ipanda/panda_x86.h"

#include "ipanda/ipanda.h"
#include "ipanda/manager.h"

#include "osi/windows/wintrospection.h"

#include "filter.h"
#include "memory-server.h"

// Globals to be set by configs, eventually
char g_program_name[] = "volatility_plugin";
char g_module_name[] = "gluemod";
char g_func_name[] = "run";

char g_script_path[4096] = {0};

// Globals to be calculated by the plugin, eventually
char g_profile[512] = {0};

// Constants
#define SOCKET_PATH_FMT "/tmp/panda%d.sock"
char g_location[512] = "file://\0";
char g_filter_path[512] = {0};
const char g_script_name[] = "/volglue.py";

// Globals
std::shared_ptr<IntroPANDAManager> os_manager;
std::shared_ptr<Windows7IntrospectionManager> g_os_manager;
struct WindowsProcess* g_current_process = nullptr;

std::shared_ptr<InstrumentationFilter> g_filter;
bool g_check_for_process = true;
bool g_targeted = true;

static PyObject* g_pfunc = NULL;

#define CHECK_OR_DIE(_obj, _emsg, _elabel)                                               \
    do {                                                                                 \
        if (!_obj) {                                                                     \
            if (PyErr_Occurred()) {                                                      \
                PyErr_Print();                                                           \
            }                                                                            \
            fprintf(stderr, _emsg);                                                      \
            goto _elabel;                                                                \
        }                                                                                \
    } while (0)

// Forward declarations
extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
}

int run_volatility_analysis(CPUState* env);
bool log_analysis_results(CPUState* env, const char* data);

/**
 * Run the volatility analysis, passing the desired profile and args
 * as python strings. Stores the results in the panda log or writes them
 * to stderr
 */
int run_volatility_analysis(CPUState* env)
{
    // Convert global strings to python strings
    PyObject* pprofile_str = PyString_FromString(g_profile);
    PyObject* plocation_str = PyString_FromString(g_location);
    PyObject* pfilter_str = PyString_FromString(g_filter_path);

    PyObject* pargs = PyTuple_New(3);

    // Mildly concerned about death-by-oom
    if (!pprofile_str || !plocation_str || !pfilter_str || !pargs) {
        fprintf(stderr, "[%s] Failed to allocate args\n", __FILE__);
        Py_XDECREF(pprofile_str);
        Py_XDECREF(plocation_str);
        Py_XDECREF(pfilter_str);
        Py_XDECREF(pargs);
    }

    // Add these strings to an argument object
    PyTuple_SetItem(pargs, 0, pprofile_str);
    PyTuple_SetItem(pargs, 1, plocation_str);
    PyTuple_SetItem(pargs, 2, pfilter_str);

    // Call run(profile, location)
    PyObject* pvalue = PyObject_CallObject(g_pfunc, pargs);
    if (pvalue) {
        // The function returned a value successfully
        if (PyString_Check(pvalue)) {
            const char* json_str = PyString_AsString(pvalue);
            if (log_analysis_results(env, json_str)) {
                fprintf(stderr, "[%s] Failed to record result!\n", __FILE__);
            }
        } else {
            fprintf(stderr, "[%s] Return value was not a string!\n", __FILE__);
        }
    } else {
        // The function failed to return correctly
        if (PyErr_Occurred()) {
            PyErr_Print();
        }
        fprintf(stderr, "[%s] Didn't receive response from analysis!\n", __FILE__);
    }

    Py_XDECREF(pargs); // pargs handles components refs
    Py_XDECREF(pvalue);
    return 0;
}

avro_schema_t g_schema = nullptr;
avro_file_writer_t g_db = nullptr;

bool init_avro(const char* dbname)
{
    int status = 0;

    // Initialize the schema for a memstring
    g_schema = avro_schema_record("volatility", NULL);
    avro_schema_record_field_append(g_schema, "rrindex", avro_schema_long());
    avro_schema_record_field_append(g_schema, "results", avro_schema_string());

    remove(dbname);

    status = avro_file_writer_create_with_codec(dbname, g_schema, &g_db, "deflate",
                                                512 * 1024 * 1024);
    if (status) {
        fprintf(stderr, "[%s] Avro failed to open %s for writing\n", __FILE__, dbname);
        fprintf(stderr, "[E] error message: %s\n", avro_strerror());
        return true;
    }
    fprintf(stdout, "Writing analysis results to %s\n", dbname);
    return false;
}

void teardown_avro()
{
    avro_file_writer_close(g_db);
    avro_schema_decref(g_schema);
}

bool log_analysis_results(CPUState* env, const char* data)
{
    avro_datum_t volatility_dt = avro_record(g_schema);
    avro_datum_t rrindex_dt = avro_int64((int64_t)rr_get_guest_instr_count());
    avro_datum_t result_dt = avro_string(data);

    if (avro_record_set(volatility_dt, "rrindex", rrindex_dt)) {
        fprintf(stderr, "Avro failed to add rrindex to record\n");
        return true;
    }
    if (avro_record_set(volatility_dt, "results", result_dt)) {
        fprintf(stderr, "[E] Avro failed to build volatility result: %s\n",
                avro_strerror());
        return true;
    }

    if (avro_file_writer_append(g_db, volatility_dt)) {
        fprintf(stderr, "[E] Avro failed to write volatility: %s\n", avro_strerror());
        return true;
    }
    avro_datum_decref(result_dt);
    avro_datum_decref(rrindex_dt);
    avro_datum_decref(volatility_dt);
    return false;
}

void before_block_exec(CPUState* env, TranslationBlock* tb)
{
    auto kosi = g_os_manager->get_kosi();

    if (g_check_for_process) {
        free_process(g_current_process);

        g_current_process = kosi_get_current_process(kosi);
        g_targeted = g_filter->thread_check(process_get_pid(g_current_process),
                                            process_get_asid(g_current_process));

        g_check_for_process = false;
    }

    if (!g_targeted) {
        return;
    }

    auto pid = process_get_pid(g_current_process);
    auto asid = process_get_asid(g_current_process);
    auto tid = kosi_get_current_tid(kosi);

    if (!g_filter->thread_check(pid, asid, tid)) {
        return;
    }

    run_volatility_analysis(env);

    // remove the thread now that we've handled it and make
    // the next bb refresh state info
    g_filter->remove_thread(pid, asid, tid);
    g_check_for_process = true;

    return;
}

bool check_for_process(CPUState* env, target_ulong oldval, target_ulong newval)
{
    g_check_for_process = true;
    return 0;
}

/**
 * Set the path to the default python script, which should be
 * in the same directory as the shared object
 */
void set_default_python_script()
{
    Dl_info dl_info;
    dladdr((void*)set_default_python_script, &dl_info);

    if (dl_info.dli_sname == NULL) {
        fprintf(stderr, "[%s] Failed to locate volatility plugin shared object!\n",
                __FILE__);
        return;
    }

    const char* lib_path = dl_info.dli_fname;
    char* tmp_lib = strdup(lib_path);
    char* dir_path = dirname(tmp_lib);

    strncpy(g_script_path, dir_path, sizeof(g_script_path) - 1);
    strncat(g_script_path, g_script_name, sizeof(g_script_path) - 1);
    free(tmp_lib);
}

char* read_script(const char* fpath)
{
    fprintf(stdout, "Reading python script from %s\n", fpath);
    FILE* fp = fopen(fpath, "r");
    if (fp == NULL) {
        fprintf(stderr, "[E] Failed to open %s: %s\n", fpath, strerror(errno));
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    int len = ftell(fp);

    char* script = (char*)malloc(len + 1);
    if (!script) {
        fprintf(stderr, "[%s] Failed to allocate storage for python script of size %d\n",
                __FILE__, len + 1);
        return NULL;
    }

    fseek(fp, 0, SEEK_SET);
    int bytes_read = fread(script, 1, len, fp);
    if (bytes_read != len) {
        fprintf(stderr, "[%s] Failed to read entire python script (%d / %d)!\n", __FILE__,
                bytes_read, len);
        free(script);
        return NULL;
    }

    script[len] = '\0';
    return script;
}

bool init_plugin(void* self)
{
    PyObject* pmodule = NULL;
    PyObject* pcode = NULL;
    const char* output_path = nullptr;
    const char* filter_path = nullptr;

    panda_arg_list* vol_args = panda_get_args("volatility");
    output_path = panda_parse_string(vol_args, "output", "volatility.panda");

    panda_arg_list* filter_args = panda_get_args("filter");
    filter_path = panda_parse_string(filter_args, "file", "");
    strncpy(g_filter_path, filter_path, sizeof(g_filter_path) - 1);
    g_filter.reset(new InstrumentationFilter(g_filter_path));
    panda_free_args(filter_args);

    if (init_avro(output_path)) {
        return false;
    }
    set_default_python_script();

    // Read arguments
    const char* profile_arg = panda_os_name;
    const char* profile = nullptr; // volatility profile
    if (!profile_arg) {
        fprintf(stderr, "[%s] The -os <profile> flag is required\n", __FILE__);
        return false;
    } else if (strcasecmp(profile_arg, "windows-64-vistasp0") == 0) {
        profile = "VistaSP0x64";
    } else if (strcasecmp(profile_arg, "windows-32-vistasp0") == 0) {
        profile = "VistaSP0x86";
    } else if (strcasecmp(profile_arg, "windows-64-vistasp1") == 0) {
        profile = "VistaSP1x64";
    } else if (strcasecmp(profile_arg, "windows-32-vistasp1") == 0) {
        profile = "VistaSP1x86";
    } else if (strcasecmp(profile_arg, "windows-64-vistasp2") == 0) {
        profile = "VistaSP2x64";
    } else if (strcasecmp(profile_arg, "windows-32-vistasp2") == 0) {
        profile = "VistaSP2x86";
    } else if (strcasecmp(profile_arg, "windows-64-10x64sp0") == 0) {
        profile = "Win10x64";
    } else if (strcasecmp(profile_arg, "windows-32-10x86sp0") == 0) {
        profile = "Win10x86";
    } else if (strcasecmp(profile_arg, "windows-32-2003sp0") == 0) {
        profile = "Win2003SP0x86";
    } else if (strcasecmp(profile_arg, "windows-64-2003sp1") == 0) {
        profile = "Win2003SP1x64";
    } else if (strcasecmp(profile_arg, "windows-32-2003sp1") == 0) {
        profile = "Win2003SP1x86";
    } else if (strcasecmp(profile_arg, "windows-64-2003sp2") == 0) {
        profile = "Win2003SP2x64";
    } else if (strcasecmp(profile_arg, "windows-32-2003sp2") == 0) {
        profile = "Win2003SP2x86";
    } else if (strcasecmp(profile_arg, "windows-64-2008r2sp0") == 0) {
        profile = "Win2008R2SP0x64";
    } else if (strcasecmp(profile_arg, "windows-64-2008r2sp1") == 0) {
        profile = "Win2008R2SP1x64";
    } else if (strcasecmp(profile_arg, "windows-64-2008sp1") == 0) {
        profile = "Win2008SP1x64";
    } else if (strcasecmp(profile_arg, "windows-32-2008sp1") == 0) {
        profile = "Win2008SP1x86";
    } else if (strcasecmp(profile_arg, "windows-64-2008sp2") == 0) {
        profile = "Win2008SP2x64";
    } else if (strcasecmp(profile_arg, "windows-32-2008sp2") == 0) {
        profile = "Win2008SP2x86";
    } else if (strcasecmp(profile_arg, "windows-64-2012r2sp0") == 0) {
        profile = "Win2012R2x64";
    } else if (strcasecmp(profile_arg, "windows-64-2012sp0") == 0) {
        profile = "Win2012x64";
    } else if (strcasecmp(profile_arg, "windows-64-7sp0") == 0) {
        profile = "Win7SP0x64";
    } else if (strcasecmp(profile_arg, "windows-32-7sp0") == 0) {
        profile = "Win7SP0x86";
    } else if (strcasecmp(profile_arg, "windows-64-7sp1") == 0) {
        profile = "Win7SP1x64";
    } else if (strcasecmp(profile_arg, "windows-32-7sp1") == 0) {
        profile = "Win7SP1x86";
    } else if (strcasecmp(profile_arg, "windows-64-81sp0") == 0) {
        profile = "Win81U1x64";
    } else if (strcasecmp(profile_arg, "windows-32-81sp0") == 0) {
        profile = "Win81U1x86";
    } else if (strcasecmp(profile_arg, "windows-64-8sp0") == 0) {
        profile = "Win8SP0x64";
    } else if (strcasecmp(profile_arg, "windows-32-8sp0") == 0) {
        profile = "Win8SP0x86";
    } else if (strcasecmp(profile_arg, "windows-64-8sp1") == 0) {
        profile = "Win8SP1x64";
    } else if (strcasecmp(profile_arg, "windows-32-8sp1") == 0) {
        profile = "Win8SP1x86";
    } else if (strcasecmp(profile_arg, "windows-64-xpsp1") == 0) {
        profile = "WinXPSP1x64";
    } else if (strcasecmp(profile_arg, "windows-64-xpsp2") == 0) {
        profile = "WinXPSP2x64";
    } else if (strcasecmp(profile_arg, "windows-32-xpsp2") == 0) {
        profile = "WinXPSP2x86";
    } else if (strcasecmp(profile_arg, "windows-32-xpsp3") == 0) {
        profile = "WinXPSP3x86";
    }
    if (!profile) {
        fprintf(stderr, "[%s] Unrecognized profile\n", __FILE__);
        return false;
    }

    char* socket_path = (char*)calloc(512, 1);
    if (!socket_path) {
        fprintf(stderr, "[%s] Failed to allocate memory for socket path\n", __FILE__);
        return false;
    }
    sprintf(socket_path, SOCKET_PATH_FMT, getpid());
    strncat(g_location, socket_path, sizeof(g_location) - 1);

    const char* python_script = panda_parse_string(vol_args, "script", g_script_path);

    strncpy(g_profile, profile, sizeof(g_profile) - 1);
    panda_free_args(vol_args);

    panda_cb pcb;
    pcb.asid_changed = check_for_process;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    // This hack can be avoided by working with PANDA
    // to expose the python shared library
    dlopen("libpython2.7.so", RTLD_LAZY | RTLD_GLOBAL);

    char* script_contents = read_script(python_script);
    if (!script_contents) {
        fprintf(stderr, "[%s] Failed to open python script!\n", __FILE__);
        return false;
    }

    Py_SetProgramName(g_program_name);
    Py_Initialize();

    // Load the program as a code object
    pcode = Py_CompileString((char*)script_contents, "volglue.py", Py_file_input);
    CHECK_OR_DIE(pcode, "Failed to compile python program!\n", cleanup);

    // Load the code object into a module
    pmodule = PyImport_ExecCodeModule(g_module_name, pcode);
    CHECK_OR_DIE(pmodule, "Failed to load as module!\n", cleanup);

    // Extract the entry point of our new module
    g_pfunc = PyObject_GetAttrString(pmodule, g_func_name);
    CHECK_OR_DIE(g_pfunc, "Failed to find function!\n", cleanup);

    if (!PyCallable_Check(g_pfunc)) {
        fprintf(stderr, "[%s] Object %s is not a callable!\n", __FILE__, g_func_name);
        goto cleanup;
    }

    fprintf(stdout, "Successfully initialized python routines.\n");

    if (!start_memory_server(socket_path)) {
        fprintf(stderr, "[%s] Failed to start memory server!\n", __FILE__);
        goto cleanup;
    }

    if (script_contents) {
        free(script_contents);
    }
    Py_XDECREF(pcode);
    pcode = NULL;
    Py_XDECREF(pmodule);
    pmodule = NULL;

    if (!init_ipanda(self, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        goto cleanup;
    }

    // temporary -- forcing to be windows specific so i don't have to edit any more code
    // in this plugin
    g_os_manager = std::dynamic_pointer_cast<Windows7IntrospectionManager>(os_manager);

    return true;

cleanup:
    // If we can't load everything, explode
    if (script_contents) {
        free(script_contents);
    }
    Py_XDECREF(pcode);
    pcode = NULL;
    Py_XDECREF(pmodule);
    pmodule = NULL;
    Py_XDECREF(g_pfunc);
    g_pfunc = NULL;
    return false;
}

void uninit_plugin(void* self)
{
    stop_memory_server();
    Py_XDECREF(g_pfunc);
    g_pfunc = NULL;
    Py_Finalize();
    teardown_avro();
}
