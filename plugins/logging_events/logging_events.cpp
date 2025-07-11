#define __STDC_FORMAT_MACROS

#include "osi/windows/manager.h"
#include "osi/windows/pe.h"
#include "osi/windows/wintrospection.h"
#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/common.h"
#include "ipanda/ipanda.h"
#include "ipanda/manager.h"
#include "ipanda/types.h"
#include "panda/plugins/syscalls2/syscalls2.h"
#include "panda/plugins/syscalls2/syscalls_ext_typedefs.h"
#include "panda/plugins/hooks2/hooks2.h"
#include "callstack/callstack.h"
#include "callstack/prog_point.h"
#include "ipanda/panda_x86.h"
// #include "panda/plugins/callstack_instr/callstack_instr.h"
// #include "panda/plugins/callstack_instr/callstack_instr_ext.h"

extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
}

extern CurrentProcessOSI* g_current_osi = NULL;
static std::shared_ptr<IntroPANDAManager> os_manager;

enum LogFunctions {
    SYSLOG,
    DMESG,
};

bool init_log_detect(CPUState* env) {
    if (!init_ipanda(env, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return false;
    }
    return true;
}


bool context_switch_callback(CPUState* env, target_ulong old_asid, target_ulong new_asid) {
    if (old_asid == new_asid) {
        printf("ASID not changed\n");
    } else {
        printf("ASID changed\n");
    }
    return false;
}

void syslog_hook(CPUState* env, target_ulong pc, int type, target_ulong bufp, int len) {
    if (bufp) {
        uint8_t read_buf[20];
        panda_virtual_memory_read(env, bufp, read_buf, len);
        printf("syslog(%d, %s, %d)", type, (char*) read_buf, len);
    }
}


// int lib_call_hook(CPUState* env, target_ulong pc) {
//     printf("In lib call hook\n");
//     target_ulong asid = panda_current_asid(env);
//     struct symbol sym = resolve_symbol(env, asid, NULL, "syslog");
//     if (pc == sym.address) {
//         printf("syslog() called at 0x%lx\n", pc);
//     }
//     return 0;
// }

void call_insn_callback(CPUState* env, target_ulong func) {
    printf("Here");
}

void register_panda_callbacks(void* self) {
    panda_cb pcb;

    // pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(init_log_detect));
    // panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    pcb.asid_changed = context_switch_callback;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    // pcb.insn_exec = lib_call_hook;
    // panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    // set_callstack_osi(g_current_osi);
    // init_callstack_plugin(self, g_current_osi);
    // register_callstack_callback("on_call", call_insn_callback);

    PPP_REG_CB("syscalls2", on_sys_syslog_enter, syslog_hook);
}


bool init_plugin(void* self)
{
    fflush(stdout);
    printf("In init plugin\n");

    panda_require("syscalls2");
    // panda_require("hooks2");
    register_panda_callbacks(self);

    // const char* profile = panda_os_name;
    // if (!profile) {
    //     fprintf(stderr,
    //             "[%s] Could not find os name. Please re-run with -os <profile> flag\n",
    //             __FILE__);
    //     return false;
    // }


    // panda_require("callstack_instr");
    // assert(init_callstack_instr_api());

    // panda_require("dynamic_symbols");

    // panda_arg_list* args = panda_get_args("logging_events");
    // const char* log_path = strdup(panda_parse_string(args, "output", "logging.jsonl"));
    // fprintf(stdout, "Writing analysis results to %s\n", log_path);
    // g_log_path = (char*)log_path;
    // panda_free_args(args);

    return true;
}

void uninit_plugin(void* self) {
    fprintf(stdout, "uninit");
    panda_arg_list* args = panda_get_args("logging_events");
    panda_free_args(args);
} 
