
#define __STDC_FORMAT_MACROS

extern "C" {
#include <Python.h>
#include <dlfcn.h>
#include <errno.h>
}
#include <avro.h>
#include <cstdlib>
#include <exception>
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

// Globals to be set by configs, eventually
char g_program_name[] = "volatility_plugin";
char g_module_name[] = "gluemod";
char g_func_name[] = "run";

char g_script_path[4096] = {0};

char g_profile[512] = {0};

// Constants
#define TARGET_PAGE_SIZE 1024
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
PyConfig config;

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


void panda_memsavep(char* filename) {
    FILE* f = fopen(filename, "wb");
    if (!f) return;

    uint8_t mem_buf[TARGET_PAGE_SIZE];
    uint8_t zero_buf[TARGET_PAGE_SIZE];
    memset(zero_buf, 0, TARGET_PAGE_SIZE);
    int res;
    ram_addr_t addr;
    for (addr = 0; addr < ram_size; addr += TARGET_PAGE_SIZE) {
        res = panda_physical_memory_rw(addr, mem_buf, TARGET_PAGE_SIZE, 0);
        if (res == -1) { // I/O. Just fill page with zeroes.
            fwrite(zero_buf, TARGET_PAGE_SIZE, 1, f);
        }
        else {
            fwrite(mem_buf, TARGET_PAGE_SIZE, 1, f);
        }
    }
    fclose(f);
}

static PyObject* pandamem_read_physical(PyObject* self, PyObject* args) {
    unsigned long long addr;
    unsigned long long size;
    
    if (!PyArg_ParseTuple(args, "KK", &addr, &size)) {
       return NULL;
    }

    // Limit single read size to prevent excessive allocation
    if (size > ram_size) {
        PyErr_SetString(PyExc_ValueError, "Read size too large (max 2GB)");
        return NULL;
    }

    uint8_t* buffer = (uint8_t*)malloc(size);
    if (!buffer) {
        return PyErr_NoMemory();
    }

    int res = panda_physical_memory_rw(addr, buffer, size, 0);

    if (res == MEMTX_OK) {
        PyObject* bytes = PyBytes_FromStringAndSize((char*) buffer, size);
        free(buffer);
        return bytes;
    } else {
        memset(buffer, 0, size);
        PyObject* bytes = PyBytes_FromStringAndSize((char*)buffer, size);
        free(buffer);
        return bytes;
    }
}

static PyObject* pandamem_get_ram_size(PyObject* self, PyObject* args) {
    return PyLong_FromUnsignedLongLong(ram_size);
}

static PyMethodDef PandaMemoryMethods[] = {
    {"read_physical", pandamem_read_physical, METH_VARARGS,
     "Read physical memory: read_physical(addr, size) -> bytes"},
    {"get_ram_size", pandamem_get_ram_size, METH_NOARGS,
     "Get total RAM size: get_ram_size() -> int"},
    {NULL, NULL, NULL, NULL}
};

static struct PyModuleDef pandamemmodule = {
    PyModuleDef_HEAD_INIT,
    "pandamem",
    "PANDA direct memory access module",
    -1,
    PandaMemoryMethods
};

PyMODINIT_FUNC PyInit_pandamem(void) {
    return PyModule_Create(&pandamemmodule);
}

/**
 * Run the volatility analysis, passing the filter as a
 * python string. Stores the results in the panda log or writes them
 * to stderr
 */
int run_volatility_analysis(CPUState* env)
{
    // Dump RAM at this moment
    panda_memsavep("mem.ram");

    // Convert global strings to python strings
    PyObject* pfilter_str = PyUnicode_FromString(g_filter_path);
    PyObject* pargs = PyTuple_New(1);

    // Mildly concerned about death-by-oom
    if (!pfilter_str || !pargs) {
        Py_XDECREF(pfilter_str);
        Py_XDECREF(pargs);
        throw std::runtime_error("failed to allocate arguments for python call");
    }

    // Add these strings to an argument object
    PyTuple_SetItem(pargs, 0, pfilter_str);

    // Call run(filter)
    PyObject* pvalue = PyObject_CallObject(g_pfunc, pargs);
    if (pvalue) {
        // The function returned a value successfully
        if (PyUnicode_Check(pvalue)) {
            const char* json_str = PyUnicode_AsUTF8(pvalue);
            fprintf(stdout, "%s\n", json_str);
            if (log_analysis_results(env, json_str)) {
                fprintf(stderr, "[%s] Failed to record result!\n", __FILE__);
            }
        } else {
            fprintf(stderr, "[%s] Return value was not a string!\n", __FILE__);
        }
    } else {
        // The function failed to return correctly

        PyObject *exc_type, *exc_value, *exc_tb;
        PyErr_Fetch(&exc_type, &exc_value, &exc_tb);
        PyErr_NormalizeException(&exc_type, &exc_value, &exc_tb);

        std::string message = "python call failed";
        if (exc_value) {
            PyObject* str_obj = PyObject_Str(exc_value);
            if (str_obj) {
                const char* utf8 = PyUnicode_AsUTF8(str_obj);
                if (utf8) message = utf8;
                Py_DECREF(str_obj);
            }
        }

        Py_XDECREF(exc_type);
        Py_XDECREF(exc_value);
        Py_XDECREF(exc_tb);

        throw std::runtime_error(message);
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
    
    try {
        run_volatility_analysis(env);
    } catch (const std::exception& e) {
        fprintf(stderr, "[Volatility] fatal error, ending analysis: %s\n", e.what());
        uninit_plugin(nullptr);
        std::exit(EXIT_FAILURE);
    }
    
    unlink("mem.ram");

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
    fprintf(stdout, "[Filter file]: %s\n", g_filter_path);
    try {
        g_filter.reset(new InstrumentationFilter(g_filter_path));
    } catch (const std::exception& e) {
        fprintf(stderr, "[%s] Failed to initialize instrumentation filter: %s\n",
                __FILE__, e.what());
        panda_free_args(filter_args);
        return false;
    }
    panda_free_args(filter_args);

    if (init_avro(output_path)) {
        return false;
    }
    set_default_python_script();

    // Read arguments
    if (!panda_os_name) {
        fprintf(stderr, "[%s] The -os <profile> flag is required\n", __FILE__);
        return false;
    }

    // make sure we are on Windows
    if (panda_os_familyno != OS_WINDOWS) {
        fprintf(stderr, "[%s] Currently, only Windows is supported.\n", __FILE__);
        return false;
    }

    const char* python_script = panda_parse_string(vol_args, "script", g_script_path);

    panda_free_args(vol_args);

    panda_cb pcb;
    pcb.asid_changed = check_for_process;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    // This hack can be avoided by working with PANDA
    // to expose the python shared library
    dlopen("libpython3.8.so", RTLD_LAZY | RTLD_GLOBAL);

    char* script_contents = read_script(python_script);
    if (!script_contents) {
        fprintf(stderr, "[%s] Failed to open python script!\n", __FILE__);
        return false;
    }

    const char* venv_path_cstr = std::getenv("VIRTUAL_ENV");
    std::string venv_path(venv_path_cstr);
    std::string exec_path = venv_path + "/bin/python";
    std::wstring w_exec(exec_path.begin(), exec_path.end());

    PyImport_AppendInittab("pandamem", PyInit_pandamem);
    Py_SetProgramName((wchar_t*) g_program_name);
    PyConfig_InitPythonConfig(&config);
    PyConfig_SetString(&config, &config.executable, w_exec.c_str());
    Py_InitializeFromConfig(&config);

    // Load the program as a code object
    pcode = Py_CompileString(script_contents, "volglue.py", Py_file_input);
    CHECK_OR_DIE(pcode, "Failed to compile python program!\n", cleanup);

    // Load the code object into a module
    pmodule = PyImport_ExecCodeModule("gluemod", pcode);
    CHECK_OR_DIE(pmodule, "Failed to load as module!\n", cleanup);

    // Extract the entry point of our new module
    g_pfunc = PyObject_GetAttrString(pmodule, g_func_name);
    CHECK_OR_DIE(g_pfunc, "Failed to find function!\n", cleanup);

    if (!PyCallable_Check(g_pfunc)) {
        fprintf(stderr, "[%s] Object %s is not a callable!\n", __FILE__, g_func_name);
        goto cleanup;
    }

    fprintf(stdout, "Successfully initialized python routines.\n");

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
    PyConfig_Clear(&config);
    unlink("mem.ram");
    return false;
}

void uninit_plugin(void* self)
{
    Py_XDECREF(g_pfunc);
    g_pfunc = NULL;
    PyConfig_Clear(&config);
    Py_Finalize();
    teardown_avro();
    unlink("mem.ram");
}
