#define __STDC_FORMAT_MACROS

#include "logging_events.h"
#include <osi/osi_types.h>
#include "osi/windows/manager.h"
#include "osi/windows/pe.h"
#include "osi/windows/wintrospection.h"
#include "panda/plugins/callstack_instr/callstack_instr_ext.h"

struct WindowsKernelOSI* g_kernel_osi = nullptr;
bool g_initialized = false;
char* g_log_path;

// introspection into current process
extern CurrentProcessOSI* g_current_osi;
std::shared_ptr<Process> g_current_process;
uint64_t g_previous_asid;


extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
}

bool initialize_globals(CPUState* env) {
    const char* profile = panda_os_name;
    const char* database_path = (const char*)g_database_path;

    std::shared_ptr<IntroPANDAManager> os_manager;
    if (!init_ipanda(env, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return false;
    }
}

static bool is_log_insn(CPUState* env, target_ptr_t pc) {
    target_ulong callers[16];
    int n;
    n = get_callers(callers, 16, env);

    for (int i = 0; i < n; i++) {
        cal
    }
}

void register_panda_callbacks(void* self) {
    panda_cb pcb;

}

bool windows_interesting_call_check(CPUState* env, target_ulong func, uint64_t tid) {
    auto pid = g_current_process->get_pid();
    auto asid = g_current_process->get_asid();
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

    panda_require("callstack_instr");
    assert(init_callstack_instr_api());

    panda_arg_list* args = panda_get_args("logging_events");
    const char* log_path = strdup(panda_parse_string(args, "output", "logging.jsonl"));
    fprintf(stdout, "Writing analysis results to %s\n", log_path);
    g_log_path = (char*)log_path;
    panda_free_args(args);

    return true;
}

void uninit_plugin(void* self) {} 