#define PLUGIN_MAIN
#define __STDC_FORMAT_MACROS
#define OSI_TEST_ON_ASID_CHANGED

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
#include "callstack/callstack.h"
#include "callstack/prog_point.h"
#include "apicall_tracer/trace_filter.h"

extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
    // #include "osi/osi_types.h"
    // #include "panda/plugins/osi/osi_ext.h"
    // #include "panda/plugins/osi/os_intro.h"
    #include "panda/plugins/dynamic_symbols/dynamic_symbols_int_fns.h"
    #include "panda/plugins/hooks/hooks_int_fns.h"  
    #include "panda/plugins/hooks2/hooks2.h"
}

// dynamic_symbols
typedef struct symbol (*__resolve_symbol_t)(CPUState* cpu, target_ulong asid, char* section_name, char* symbol);
__resolve_symbol_t __resolve_symbol = NULL;

typedef struct symbol (*__hook_symbol_resolution_t)(struct hook_symbol_resolve* h);
__hook_symbol_resolution_t __hook_symbol_resolution = NULL;

typedef struct symbol (*__get_best_matching_symbol_t)(CPUState* cpu, target_ulong address, target_ulong asid);
__get_best_matching_symbol_t __get_best_matching_symbol = NULL;

// hooks
typedef void (*__enable_hooking_t)();
__enable_hooking_t __enable_hooking = NULL;

typedef void (*__add_hook_t)(struct hook* h);
__add_hook_t __add_hook = NULL;

typedef void (*__add_symbol_hook_t)(struct symbol_hook* h);
__add_symbol_hook_t __add_symbol_hook = NULL;

// hooks2
typedef void (*__enable_hooks2_t)(int id);
__enable_hooks2_t __enable_hooks2 = NULL;

typedef int (*__add_hooks2_t)(hooks2_func_t hook,
    void *cb_data,
    bool is_kernel,
    const char *procname,
    const char *libname,
    target_ulong trace_start,
    target_ulong trace_stop,
    target_ulong range_begin,
    target_ulong range_end);
__add_hooks2_t __add_hooks2 = NULL;


extern CurrentProcessOSI* g_current_osi = NULL;
static std::shared_ptr<IntroPANDAManager> os_manager;

static int id = 9;
static bool hook_registered = false;


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

void syslog_syscall_hook(CPUState* env, target_ulong pc, int type, target_ulong bufp, int len) {
    if (bufp) {
        uint8_t read_buf[20];
        panda_virtual_memory_read(env, bufp, read_buf, len);
        printf("syslog(%d, %s, %d)", type, (char*) read_buf, len);
    }
}

void syslog_block_hook(CPUState* env, TranslationBlock* tb, struct hook* h) {
    // if (panda_current_pc(env) != tb->pc) {
    //     return;
    // }

    CPUX86State* regs = (CPUX86State*)env;
    target_ulong msg_ptr = regs->regs[R_ESI];  // 2nd arg: message
    target_ulong asid = panda_current_asid(env);

    CPUArchState *CASenv = (CPUArchState *)env->env_ptr;
    target_ulong pc = 0x0;
    target_ulong cs_base = 0x0;
    uint32_t flags = 0x0;
    cpu_get_tb_cpu_state(CASenv, &pc, &cs_base, &flags);
    
    printf("tb pc: 0x%lx\n", tb->pc);
    printf("In kernel: %d\n", panda_in_kernel(env));
    // printf("pc: 0x%lx\n", panda_current_pc(env));
    printf("pc: 0x%lx\n", pc);
    printf("guest pc: 0x%lx\n", env->panda_guest_pc);

    int num_bytes = 24;
    uint8_t buf[num_bytes];
    panda_virtual_memory_read(env, tb->pc, buf, num_bytes);
    printf("[DISASM] tb->pc = 0x%lx | bytes = ", tb->pc);
    for (int i = 0; i < num_bytes; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");


    uint8_t buffer[256] = {0};
    printf("[DEBUG] msg_ptr = 0x%lx\n", msg_ptr);
    if (panda_virtual_memory_read(env, msg_ptr, buffer, sizeof(buffer) - 1)) {
        buffer[255] = '\0';
        printf("[HOOK] syslog(message=\"%s\")\n", buffer);
    } else {
        printf("[HOOK] syslog(message=<unreadable>)\n");
    }
    // return true;
}

// void on_syslog_resolved(struct hook_symbol_resolve* h, struct symbol sym, target_ulong asid) {
//     printf("[RESOLVE] syslog resolved at 0x%lx (section: %s)\n", sym.address, sym.section);

//     // Install hooks2 instruction hook at the resolved address
//     int hook_id = __add_hooks2(
//         syslog_block_hook,
//         NULL,
//         false,
//         NULL,
//         NULL,
//         0, 0,
//         sym.address,
//         sym.address + 1
//     );

//     if (hook_id >= 0) {
//         printf("[HOOKS2] Hook installed with ID %d\n", hook_id);
//         hook_registered = true;
//     } else {
//         printf("[ERROR] Failed to install hook via add_hooks2\n");
//     }
// }

void register_hook(CPUState* env, TranslationBlock* tb) {
    if (hook_registered) {
        return;
    }
    struct symbol_hook h = {0};
    strncpy(h.name, "calloc", 256);
    h.cb.start_block_exec = syslog_block_hook;
    h.offset = false;
    h.type = PANDA_CB_START_BLOCK_EXEC;
    __add_symbol_hook(&h);

    target_ulong asid = panda_current_asid(env);
    // struct symbol sym = __resolve_symbol(env, asid, NULL, (char*)"syslog");
    // printf("[RESOLVE] syslog resolved at address: 0x%lx (section: %s)\n", sym.address, sym.section);
    // struct hook h = {0};
    // h.addr = sym.address;
    // h.asid = asid;
    // h.type = PANDA_CB_START_BLOCK_EXEC;
    // h.cb.start_block_exec = syslog_block_hook;
    // h.km = MODE_ANY;
    // h.enabled = true;
    // h.sym = sym;
    // h.context = NULL;
    // __add_hook(&h);

    hook_registered = true;

    // struct hook_symbol_resolve h = {0};
    // strncpy(h.name, "syslog", 256);
    // h.hook_offset = true;
    // h.enabled = true;
    // h.cb = on_syslog_resolved;
    // h.id = id;

    // __hook_symbol_resolution(&h);
    char* sym_str = "openlog";
    struct symbol sym = __resolve_symbol(env, asid, NULL, sym_str);
    printf("syslog address: 0x%lx\n", sym.address);
    if (sym.address) {
        printf("[FORCE] __resolve_symbol resolved %s at 0x%lx\n", sym.name, sym.address);
    } else {
        printf("[FORCE] __resolve_symbol failed to resolve %s\n", sym_str);
    }

    struct symbol matching = __get_best_matching_symbol(env, 0x7f4a4715e1a0, asid);
    printf("[MATCHING NAME] %s\n", matching.name);
    // return false;
}


bool init_dynamic_symbols_api() {
    void* dynamic_symbols = panda_get_plugin_by_name("dynamic_symbols");
    if (dynamic_symbols == NULL){
        panda_require("dynamic_symbols");
        dynamic_symbols = panda_get_plugin_by_name("dynamic_symbols");
    }
    if (dynamic_symbols != NULL){
        __resolve_symbol = (__resolve_symbol_t) dlsym(dynamic_symbols, "resolve_symbol");
        __hook_symbol_resolution = (__hook_symbol_resolution_t) dlsym(dynamic_symbols, "hook_symbol_resolution");
        __get_best_matching_symbol = (__get_best_matching_symbol_t) dlsym(dynamic_symbols, "get_best_matching_symbol");
        if (__resolve_symbol == NULL || __hook_symbol_resolution == NULL || __get_best_matching_symbol == NULL) {
            return false;
        }
    } else {
        return false;
    }
    return true;
}

bool init_hooks_api() {
    void* hooks = panda_get_plugin_by_name("hooks");
    if (hooks == NULL){
        panda_require("hooks");
        hooks = panda_get_plugin_by_name("hooks");
    }
    if (hooks != NULL){
        __enable_hooking = (__enable_hooking_t) dlsym(hooks, "enable_hooking");
        __add_hook = (__add_hook_t) dlsym(hooks, "add_hook");
        __add_symbol_hook = (__add_symbol_hook_t) dlsym(hooks, "add_symbol_hook");
        if (__enable_hooking == NULL || __add_hook == NULL || __add_symbol_hook == NULL) {
            return false;
        }
    } else {
        return false;
    }
    return true;
}

bool init_hooks2_api() {
    void* hooks2 = panda_get_plugin_by_name("hooks2");
    if (hooks2 == NULL){
        panda_require("hooks2");
        hooks2 = panda_get_plugin_by_name("hooks2");
    }
    if (hooks2 != NULL){
        __enable_hooks2 = (__enable_hooks2_t) dlsym(hooks2, "enable_hooks2");
        __add_hooks2 = (__add_hooks2_t) dlsym(hooks2, "add_hooks2");
        if (__enable_hooks2 == NULL || __add_hooks2 == NULL) {
            return false;
        }
    } else {
        return false;
    }
    return true;
}

void register_panda_callbacks(void* self) {
    panda_cb pcb;

    // pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(init_log_detect));
    // panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    // pcb.asid_changed = register_hook;
    // panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    pcb.before_block_exec = register_hook;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    // set_callstack_osi(g_current_osi);
    // init_callstack_plugin(self, g_current_osi);
    // register_callstack_callback("on_call", call_insn_callback);

    PPP_REG_CB("syscalls2", on_sys_syslog_enter, syslog_syscall_hook);
}


bool init_plugin(void* self)
{
    fflush(stdout);
    printf("In init plugin\n");

    panda_require("syscalls2");

    // panda_enable_precise_pc();

    assert(init_dynamic_symbols_api());

    assert(init_hooks_api());
    __enable_hooking();

    // assert(init_hooks2_api());
    // __enable_hooks2(id);

    register_panda_callbacks(self);

    const char* profile = panda_os_name;
    if (!profile) {
        fprintf(stderr,
                "[%s] Could not find os name. Please re-run with -os <profile> flag\n",
                __FILE__);
        return false;
    }

    panda_arg_list* args = panda_get_args("logging_events");
    const char* log_path = strdup(panda_parse_string(args, "output", "logging.jsonl"));
    fprintf(stdout, "Writing analysis results to %s\n", log_path);
    panda_free_args(args);

    return true;
}

void uninit_plugin(void* self) {
    fprintf(stdout, "uninit");
    panda_arg_list* args = panda_get_args("logging_events");
    panda_free_args(args);
} 
