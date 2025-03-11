#define __STDC_FORMAT_MACROS

#include "logging_events.h"
#include <osi/osi_types.h>
#include "osi/windows/manager.h"
#include "osi/windows/pe.h"
#include "osi/windows/wintrospection.h"

struct WindowsKernelOSI* g_kernel_osi = nullptr;
bool g_initialized = false;
char* g_log_path;


extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
}

static bool is_log_insn(CPUState* env, target_ptr_t pc) {
    if (!g_initialized) {
        return false;
    }
    unsigned char buf[2] = {};
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
}

void register_panda_callbacks(void* self) {
    panda_cb pcb;

}


bool init_plugin(void* self)
{
    register_panda_callbacks(self);

    const char* profile = panda_os_name;
    if (!profile) {
        fprintf(stderr,
                "[%s] Could not find os name. Please re-run with -os <profile> flag\n",
                __FILE__);
        return false;
    }

    panda_require("osi");
    assert(init_os_api());

    panda_arg_list* args = panda_get_args("logging_events");
    const char* log_path = strdup(panda_parse_string(args, "output", "logging.jsonl"));
    fprintf(stdout, "Writing analysis results to %s\n", log_path);
    g_log_path = (char*)log_path;
    panda_free_args(args);

    return true;
}

void uninit_plugin(void* self) {} 