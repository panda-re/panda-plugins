#define PLUGIN_MAIN
#define __STDC_FORMAT_MACROS
#define OSI_TEST_ON_ASID_CHANGED

extern "C" {
    // #include <Python.h>
    #include <dlfcn.h>
    #include <errno.h>
}

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

#include "syscall_tracer/reporting/reporting.h"
#include "apicall_tracer/trace_filter.h"
#include "apicall_tracer/apicall_tracer.h"
#include "apicall_tracer/trace_engine/current_process_osi.h"
#include "apicall_tracer/trace_engine/trace_engine.h"
#include "typesignature/osi_syscalls.h"

#include "offset/i_t.h"
#include "osi/windows/manager.h"
#include "osi/windows/pe.h"
#include "osi/windows/wintrospection.h"

// // Data Struct Imports
#include "typesignature/tuple_hash.h"
#include <algorithm>
#include <functional>
#include <exception>
#include <unordered_map>

// // BBStats like Process
#include "apicall_tracer/process/block.h"
#include "apicall_tracer/process/common.h"
#include "apicall_tracer/process/image.h"
#include "apicall_tracer/process/process.h"
#include "apicall_tracer/process/range.h"

std::shared_ptr<Windows7IntrospectionManager> g_os_manager;
static struct WindowsKernelOSI* g_kernel_osi = nullptr;
bool g_initialized = false;
char* g_log_path;

int call_total = 0;
int call_instrumented = 0;
int ret_total = 0;
int ret_instrumented = 0;
int target_hits = 0;
int target_misses = 0;
int caller_hits = 0;
int caller_misses = 0;

const size_t MAX_FUNCTION_PROTOTYPE_SIZE = 512;

// Internal data structure for managing callback managers
auto g_syscall_managers =
    std::unique_ptr<std::vector<SyscallManager*>>(new std::vector<SyscallManager*>());

// book keeping
std::map<std::string, std::map<uint64_t, function_export>> g_symbol_map;
std::unordered_map<std::string, std::shared_ptr<Process>> g_process_map;
std::shared_ptr<TraceFilter> g_tracefilter;

// introspection into current process
extern CurrentProcessOSI* g_current_osi;
std::shared_ptr<Process> g_current_process;
uint64_t g_previous_asid;

// record
std::shared_ptr<OsiSyscallInterface> g_syscalls_osi;
std::shared_ptr<RecordingContext> g_reporter;

typedef std::tuple<target_ulong, target_ulong, target_ulong> function_addr_t;
typedef std::tuple<target_ulong, target_ulong, target_ulong> call_invocation_t;
// caches:
//     <asid, caller, callee> -> decision
std::unordered_map<call_invocation_t, bool> g_interesting_call_cache;
//     <asid, pid, address> -> unique ID
std::unordered_map<function_addr_t, struct call_id> g_function_id_cache;

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

typedef bool (*__can_read_current_t)(CPUState* cpu);
__can_read_current_t __can_read_current = NULL;

typedef target_ptr_t (*__default_get_current_task_struct_t)(CPUState* cpu);
__default_get_current_task_struct_t __default_get_current_task_struct = NULL;

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

/**
 * Public API for adding system call managers
 * Client is responsible for freeing manager at uninit
 */
void add_syscall_manager(SyscallManager* manager)
{
    g_syscall_managers->push_back(manager);
}

bool initialize_globals(CPUState* env)
{
    const char* profile = panda_os_name;
    const char* log_path = (const char*)g_log_path;

    std::shared_ptr<IntroPANDAManager> os_manager;
    if (!init_ipanda(env, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return false;
    }

    g_os_manager = std::dynamic_pointer_cast<Windows7IntrospectionManager>(os_manager);
    g_kernel_osi = g_os_manager->get_kosi();
    g_current_process = std::make_shared<Process>();
    g_previous_asid = 0;

    g_syscalls_osi.reset(new OsiSyscallInterface(profile, g_os_manager, "calls.db"));
    if (!g_syscalls_osi) {
        fprintf(stderr, "[%s] Failed to find a syscall profile for %s\n", __FILE__,
                profile);
        return false;
    }

    // g_reporter = create_reporter_ctx(log_path);

    // if (!g_reporter || !g_reporter->is_valid()) {
    //     fprintf(stderr, "[%s] Failed to create a recording context\n", __FILE__);
    //     return false;
    // }

    if (!init_trace_engine(profile, g_syscalls_osi, add_syscall_manager, NULL,
                           g_kernel_osi)) {
        fprintf(stderr, "[%s] Failed to initialize trace engine!\n", __FILE__);
        return false;
    }

    if (g_current_osi == nullptr) {
        fprintf(stderr, "[%s] The trace engine did not update introspection structure\n",
                __FILE__);
        return false;
    }

    g_initialized = true;
    fprintf(stdout, "Trace engine initialized\n");
    set_callstack_osi(g_current_osi);
    return g_initialized;
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


void nt_trace_event_hook(CPUState* env, target_ulong pc, target_ulong handle, unsigned int flags, unsigned int size, target_ulong fields) {
    uint8_t read_buf[size];
    panda_virtual_memory_read(env, fields, read_buf, size);
    printf("[NtTraceEvent] Flags: %u, Buffer (hex): ", flags);
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", read_buf[i]);
    }
    printf("\n");
    printf("[Fields] %i\n", fields);
}

void nt_write_file_hook(CPUState* env, target_ulong pc, target_ulong handle, target_ulong event, target_ulong ApcRoutine, target_ulong ApcContext,
        target_ulong IoStatusBlock, target_ulong buffer, unsigned int length, target_ulong offset, target_ulong key) {
    
    uint8_t read_buf[length + offset];
    panda_virtual_memory_read(env, buffer, read_buf, length + offset);
    printf("[NtWriteFile] %s\n", (char*) read_buf);
    // printf("[NtWriteFile] %d\n", offset);
}

void nt_trace_control_hook(CPUState* env, target_ulong pc, unsigned int function_code, target_ulong in_buf,
        unsigned int in_buf_len, target_ulong out_buf, unsigned int out_buf_len, target_ulong return_len) {
    
    printf("[NtTraceControl] Function code: %u\n", function_code);
    uint8_t read_buf[in_buf_len + 1];
    panda_virtual_memory_read(env, in_buf, read_buf, in_buf_len);
    read_buf[in_buf_len] = '\0';

    // for (unsigned int i = 0; i < in_buf_len; i++) {
    //     if (read_buf[i] == '\0') {
    //         break;
    //     }
    //     if (read_buf[i] < 32 || read_buf[i] > 126) {
    //         printf("[NtTraceControl] Buffer contains non-printable characters, not a valid string\n");
    //         return;
    //     }
    // }
    printf("[NtTraceControl] %s\n", (char*) read_buf);
}

static const uint8_t _zero_block[1024] = {0};
static void actually_dump_physical_memory(FILE* out, size_t len)
{
    hwaddr addr = 0;
    uint8_t block[sizeof(_zero_block)];

    if (!out)
        return;

    while (len != 0)
    {
        size_t l = sizeof(block);
        if (l > len)
            l = len;
        if (panda_physical_memory_read(addr, block, l) == MEMTX_OK)
            fwrite(block, 1, l, out);
        else
            fwrite(_zero_block, 1, l, out);
        addr += l;
        len -= l;
    }
}

static void dump_memory(char* filename, char* register_filename, uint64_t pmem_len){
    FILE* out = fopen(filename, "wb");

    if (pmem_len == 0){
        // dump all memory if not specified as arg
        pmem_len = ram_size;
    }

    actually_dump_physical_memory(out, pmem_len);
    fclose(out);
    if (register_filename)
    {
        if ((out = fopen(register_filename, "w")) != NULL)
        {
            CPUState* cpu;
            CPU_FOREACH(cpu)
            {
                fprintf(out, "CPU#%d\n", cpu->cpu_index);
                cpu_dump_state(cpu, out, fprintf, CPU_DUMP_FPU);
            }
            fclose(out);
        }
    }

    panda_replay_end();
}

// void syslog_block_hook(CPUState* env, TranslationBlock* tb, struct hook* h) {
//     // if (panda_current_pc(env) != tb->pc) {
//     //     return;
//     // }

//     CPUX86State* regs = (CPUX86State*) env;
//     target_ulong msg_ptr = regs->regs[R_ESI];  // 2nd arg: message
//     target_ulong asid = panda_current_asid(env);

//     CPUArchState *CASenv = (CPUArchState *)env->env_ptr;
//     target_ulong pc = 0x0;
//     target_ulong cs_base = 0x0;
//     uint32_t flags = 0x0;
//     cpu_get_tb_cpu_state(CASenv, &pc, &cs_base, &flags);

//     uint8_t read_buf[20];
//     int status = panda_virtual_memory_read(env, 0x4191d5, read_buf, sizeof(read_buf) - 1);
//     printf("Status: %d\n", status);
//     if (status == 0) {
//         read_buf[255] = '\0';
//         printf("[HOOK] syslog(message=\"%s\")\n", read_buf);
//     } else {
//         printf("[HOOK] syslog(message=<unreadable>)\n");
//     }
    
//     printf("rr count: %lu\n", rr_get_guest_instr_count());
//     printf("tb pc: 0x%lx\n", tb->pc);
//     printf("In kernel: %d\n", panda_in_kernel(env));
//     // printf("pc: 0x%lx\n", panda_current_pc(env));
//     printf("pc: 0x%lx\n", pc);
//     printf("guest pc: 0x%lx\n", env->panda_guest_pc); // probably from savevm state (begin record)
//     // dump_memory("mem2.ram", "mem2.regs.txt", 0);

//     int num_bytes = 24;
//     uint8_t buf[num_bytes];
//     panda_virtual_memory_read(env, tb->pc, buf, num_bytes);
//     printf("[DISASM] tb->pc = 0x%lx | bytes = ", tb->pc);
//     for (int i = 0; i < num_bytes; i++) {
//         printf("%02x ", buf[i]);
//     }
//     printf("\n");

//     // char* sym_str = "syslog";
//     // struct symbol sym = __resolve_symbol(env, asid, NULL, sym_str);
//     // printf("syslog address: 0x%lx\n", sym.address);
//     // if (sym.address) {
//     //     printf("[FORCE] __resolve_symbol resolved %s at 0x%lx %s 0x%lx\n", sym.name, sym.address, sym.section, sym.value);
//     // } else {
//     //     printf("[FORCE] __resolve_symbol failed to resolve %s\n", sym_str);
//     // }

//     struct {
//         const char* name;
//         const target_ulong* ptr;
//     } cpudata[] = {
//         {"RAX", &regs->regs[R_EAX]},
//         {"RBX", &regs->regs[R_EBX]},
//         {"RCX", &regs->regs[R_ECX]},
//         {"RDX", &regs->regs[R_EDX]},
//         {"R8", &regs->regs[8]},
//         {"R9", &regs->regs[9]},
//         {"RSI", &regs->regs[R_ESI]},
//         {"RDI", &regs->regs[R_EDI]},
//         {"RSP", &regs->regs[R_ESP]},
//         {"RBP", &regs->regs[R_EBP]},
//     };
//     // for (size_t i = 0; i < sizeof(cpudata)/sizeof(cpudata[0]); ++i)
//     // {
//     //     uint8_t buffer[256] = {0};
//     //     printf("[DEBUG] msg_ptr (%s) = %#18lx\n", cpudata[i].name, *cpudata[i].ptr);
//     //     if (panda_virtual_memory_read(env, *cpudata[i].ptr, buffer, sizeof(buffer) - 1)) {
//     //         buffer[255] = '\0';
//     //         printf("[HOOK] syslog(message=\"%s\")\n", buffer);
//     //     } else {
//     //         printf("[HOOK] syslog(message=<unreadable>)\n");
//     //     }
//     // }
//     // target_ulong start = regs->regs[R_ESP] - (8 * sizeof(uint64_t));
//     // for (size_t i = 0; i < 16; ++i)
//     // {
//     //     uint64_t stkdata = 0;
//     //     target_ulong target = start + (i * sizeof(stkdata));
//     //     if (panda_virtual_memory_read(env, target, (uint8_t*)&stkdata, sizeof(stkdata)))
//     //     {
//     //         printf("[Stack Dump] %#18lx: %#18lx\n", target, stkdata);
//     //     }
//     //     else
//     //     {
//     //         printf("[Stack Dump] %#18lx: <Unreadable>\n", target);
//     //     }
//     // }
//     uint8_t buffer[256] = {0};
//     printf("[DEBUG] msg_ptr = 0x%lx\n", msg_ptr);
//     status = panda_virtual_memory_read(env, msg_ptr, buffer, sizeof(buffer) - 1);
//     printf("Status: %d\n", status);
//     if (status == 0) {
//         buffer[255] = '\0';
//         printf("[HOOK] syslog(message=\"%s\")\n", buffer);
//     } else {
//         printf("[HOOK] syslog(message=<unreadable>)\n");
//     }
// }

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

void report_event_hook(CPUState* env, TranslationBlock* tb, struct hook* h) {
    fprintf(stdout, "[REPORT EVENT HOOK]\n");
}

bool register_hook(CPUState* env) {
    // if (hook_registered) {
    //     return;
    // }
    // struct symbol_hook sh = {0};
    // strncpy(sh.name, "CreateFileW", 256);
    // sh.cb.start_block_exec = report_event_hook;
    // sh.type = PANDA_CB_START_BLOCK_EXEC;
    // sh.hook_offset = false;
    // strncpy(sh.section, "advapi32.dll", 256);
    // __add_symbol_hook(&sh);

    target_ulong asid = panda_current_asid(env);
    char* symbol = "ReportEventA";
    struct symbol sym = __resolve_symbol(env, asid, "ADVAPI", symbol);
    printf("[RESOLVE] %s resolved at address: 0x%lx (section: %s)\n", symbol, sym.address, sym.section);
    struct hook h = {0};
    h.addr = sym.address;
    h.asid = asid;
    h.type = PANDA_CB_BEFORE_BLOCK_EXEC;
    h.cb.start_block_exec = report_event_hook;
    h.km = MODE_ANY;
    h.enabled = true;
    h.sym = sym;
    h.context = NULL;
    __add_hook(&h);

    // hook_registered = true;

    // struct hook_symbol_resolve h = {0};
    // strncpy(h.name, "syslog", 256);
    // h.hook_offset = true;
    // h.enabled = true;
    // h.cb = on_syslog_resolved;
    // h.id = id;

    // __hook_symbol_resolution(&h);
    // char* sym_str = "syslog";
    // struct symbol sym = __resolve_symbol(env, asid, NULL, sym_str);
    // printf("syslog address: 0x%lx\n", sym.address);
    // if (sym.address) {
    //     printf("[FORCE] __resolve_symbol resolved %s at 0x%lx\n", sym.name, sym.address);
    // } else {
    //     printf("[FORCE] __resolve_symbol failed to resolve %s\n", sym_str);
    // }

    // struct symbol matching = __get_best_matching_symbol(env, 0x7f4a4715e1a0, asid);
    // printf("[MATCHING NAME] %s\n", matching.name);

    return false;
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

// bool init_osi_linux_api() {
//     void* osi_linux = panda_get_plugin_by_name("osi_linux");
//     if (osi_linux == NULL) {
//         panda_require("osi_linux");
//         osi_linux = panda_get_plugin_by_name("osi_linux");
//     }
//     if (osi_linux != NULL){
//         __can_read_current = (__can_read_current_t) dlsym(osi_linux, "can_read_current");
//         __default_get_current_task_struct = (__default_get_current_task_struct_t) dlsym(osi_linux, "default_get_current_task_struct");
//         if (__can_read_current == NULL || __default_get_current_task_struct == NULL) {
//             printf("can read current is null\n");
//             return false;
//         }
//     } else {
//         printf("osi linux is null\n");
//         return false;
//     }
//     return true;
// }

void update_current_process(CPUState* env)
{
    if (panda_current_asid(env) != g_previous_asid) {

        uint64_t addr = kosi_get_current_process_address(g_kernel_osi);
        if (addr == 0) {
            return;
        }

        auto manager = WindowsProcessManager();
        if (!manager.initialize(g_kernel_osi, addr)) {
            fprintf(stderr, "[%s] failed to switch to current process\n", __FILE__);
            return;
        }

        auto curr_asid = manager.get_process_object()->vmem->get_asid();
        if (curr_asid != g_previous_asid) {
            g_previous_asid = curr_asid;

            osi::i_t eprocess = manager.get_process();
            std::shared_ptr<Process> p =
                std::make_shared<Process>(eprocess, std::shared_ptr<guid_set>(nullptr));

            auto r = g_process_map.insert(std::make_pair(p->key(), p));
            std::unordered_map<std::string, std::shared_ptr<Process>>::iterator it =
                r.first;
            if (r.second) {
                p->walk_images(g_kernel_osi, env);
            } else {
                p = (*it).second;
            }

            g_current_process = p;
        }
    }
}

bool windows_interesting_call_check(CPUState* env, target_ulong func, uint64_t tid)
{
    auto pid = g_current_process->get_pid();
    auto asid = g_current_process->get_asid();

    if (!g_tracefilter->checkThread(pid, tid, asid)) {
        return false;
    }

    // grab the target module
    std::shared_ptr<Image> call_target_image =
        g_current_process->get_image(func, g_kernel_osi, env);

    // we are never interested if the target is unknown
    if (call_target_image == nullptr) {
        target_misses++;
        return false;
    }
    target_hits++;

    target_ulong caller;
    get_callers(&caller, 1, env);
    if (caller == 0) {
        // caller is unknown but we do have a target
        return true;
    }

    // Check a cached decision based on caller and function
    auto search = g_interesting_call_cache.find(std::make_tuple(asid, caller, func));
    if (search != g_interesting_call_cache.end()) {
        return search->second;
    }

    // now find the caller module
    std::shared_ptr<Image> caller_image =
        g_current_process->get_image(caller, g_kernel_osi, env);

    if (caller_image == nullptr) {
        // caller is unknown but we do have a target
        caller_misses++;
        return true;
    }
    caller_hits++;

    // only cache from here down, since this is a decision with all info
    bool decision;
    if (!g_tracefilter->checkModule(caller_image)) {
        // the module is in the module blacklist
        decision = false;
    } else {
        // are we crossing module boundaries
        decision =
            caller_image->get_base_address() != call_target_image->get_base_address();
    }

    g_interesting_call_cache[std::make_tuple(asid, caller, func)] = decision;

    return decision;
}

struct call_id get_call_unique_id(CPUState* env, target_ulong func, uint64_t tid)
{
    auto key = std::make_tuple(g_current_process->get_asid(),
                               g_current_process->get_pid(), func);

    auto search = g_function_id_cache.find(key);
    if (search != g_function_id_cache.end()) {
        return search->second;
    }

    std::shared_ptr<Image> mod = g_current_process->get_image(func, g_kernel_osi, env);

    // normalize path as windows is case insensitive
    auto target_path = mod->get_full_path();

    // fill in the call_id with default values so we can return on error
    struct call_id identifier;
    identifier.unique_id = 0;
    identifier.target_module = target_path;
    identifier.target_function = std::string("unknown");
    identifier.caller = tid;

    // transform the module name to the form its in in our prototype database
    auto target_name = mod->get_name();
    std::transform(target_name.begin(), target_name.end(), target_name.begin(),
                   ::toupper);
    target_name = target_name.substr(0, target_name.find("."));

    target_ulong target_rva = func - mod->get_base_address();

    // destination buffer that we will fill with a name we can use
    // to look up the prototype in the database
    char call_search_name[MAX_FUNCTION_PROTOTYPE_SIZE];

    // look up the function name in our symbol map
    bool lookup_success = false;
    auto search_path = g_symbol_map.find(target_path);

    if (search_path != g_symbol_map.end()) {
        auto search_rva = search_path->second.find(target_rva);

        if (search_rva != search_path->second.end()) {
            lookup_success = true;
            auto function = search_rva->second;

            if (function.name.empty()) {
                // there was no name for this function, use ordinal
                if (snprintf(call_search_name, MAX_FUNCTION_PROTOTYPE_SIZE, "%u__%s",
                             function.ordinal, target_name.c_str()) < 0) {
                    lookup_success = false;
                }
            }

            else {
                if (snprintf(call_search_name, MAX_FUNCTION_PROTOTYPE_SIZE, "%s__%s",
                             function.name.c_str(), target_name.c_str()) < 0) {
                    lookup_success = false;
                }
                identifier.target_function = function.name;
            }
        }
    }

    if (!lookup_success) {
        if (snprintf(call_search_name, MAX_FUNCTION_PROTOTYPE_SIZE, "%lx__%s",
                     (uint64_t)target_rva, target_name.c_str()) < 0) {
            return identifier;
        }
    }

    SyscallID cid = 0;
    g_syscalls_osi->lookup_syscall_id_by_name((const char*)call_search_name,
                                                    cid);
    g_syscalls_osi->lookup_syscall_id_by_name((const char*)call_search_name,
                                                    cid);
    // if (!(g_syscalls_osi->lookup_syscall_id_by_name((const char*)call_search_name,
    //                                                 cid))) {
    //     g_reporter->reregister_syscalls(g_syscalls_osi.get());
    // }

    identifier.unique_id = cid;

    if (lookup_success) {
        g_function_id_cache[key] = identifier;
    }

    return identifier;
}

void return_insn_callback(CPUState* env, target_ulong func)
{
    ret_total++;

    if (!g_initialized) {
        return;
    }

    // we aren't interested if this call has been in the kernel
    if (panda_in_kernel(env)) {
        return;
    }

    update_current_process(env);
    auto tid = kosi_get_current_tid(g_kernel_osi);

    // this should filter us down to only processes we are interested
    // in and make sure we are crossing moudle boundaries
    if (windows_interesting_call_check(env, func, tid)) {
        ret_instrumented++;

	int i = 0;
        for (auto& manager : *g_syscall_managers) {
	    manager->handle_potential_syscall_exit(env, func);
	    i++;
        }
    }
}

void call_insn_callback(CPUState* env, target_ulong func)
{
    call_total++;

    if (!g_initialized) {
        return;
    }

    // we don't care about calls happening within the kernel
    if (panda_in_kernel(env)) {
        return;
    }

    update_current_process(env);
    auto tid = kosi_get_current_tid(g_kernel_osi);

    // this should filter us down to only processes we are interested
    // in and make sure we are crossing moudle boundaries
    if (windows_interesting_call_check(env, func, tid)) {
        call_instrumented++;

        auto call_id = get_call_unique_id(env, func, tid);
        for (auto& manager : *g_syscall_managers) {
            manager->handle_sysenter(env, func, call_id);
        }
    }
}

bool update_symbols(CPUState* env, target_ulong oldval, target_ulong newval)
{
    if (!g_initialized) {
        if (!initialize_globals(env)) {
            return 0;
        }
    }

    // create a list of modules using the current process
    auto process = kosi_get_current_process(g_kernel_osi);
    auto module_list = get_module_list(g_kernel_osi, process_get_eprocess(process),
                                       process_is_wow64(process));
    free_process(process);

    if (module_list == nullptr) {
        return 0;
    }

    // iterate over the modules
    auto curr = module_list_next(module_list);
    while (curr != nullptr) {
        // get this module's path -- lower to normalize as Windows
        // is case insensitive
        std::string path = std::string(module_entry_get_dllpath(curr));
        std::transform(path.begin(), path.end(), path.begin(), ::tolower);

        // if this module has not been parsed before, get the mapped image
        auto match = g_symbol_map.find(path);
        if (match == g_symbol_map.end()) {
            uint64_t base = module_entry_get_base_address(curr);

            auto in_memory_pe =
                init_mem_pe(module_list_get_osi(module_list), base, false);

            if (!in_memory_pe || !parse_exports(in_memory_pe)) {
                free_mem_pe(in_memory_pe);

                free_module_entry(curr);
                curr = module_list_next(module_list);

                continue;
            }

            // for each export, get its rva and function name
            size_t len = MAX_FUNCTION_PROTOTYPE_SIZE;
            char fn_name[MAX_FUNCTION_PROTOTYPE_SIZE];

            auto total = mem_pe_export_table_get_numberoffunctions(in_memory_pe);
            for (uint32_t i = 0; i < total; i++) {
                auto rva = mem_pe_export_table_get_rva_by_table_idx(in_memory_pe, i);

                memset(fn_name, '\0', len);
                if (mem_pe_export_table_get_name_by_table_idx(in_memory_pe, fn_name, &len,
                                                              i)) {
                    struct function_export function;
                    function.ordinal = i + mem_pe_export_table_get_base(in_memory_pe);
                    if (strstr(fn_name, "Evt") || strstr(fn_name, "Event")) {
                        printf("Function name: %s\n", fn_name);
                    }
                    if (strcmp(fn_name, "ReportEventA") == 0) {
                        printf("Tracing ReportEventA\n");
                        // uint64_t arg_val = g_os_manager->get_argument_value(env, 7, false);
                        // uint64_t len = g_os_manager->get_argument_value(env, 6, false);
                        CPUX86State* regs = (CPUX86State*) env;
                        target_ulong rsp = regs->regs[R_ESP];
                        target_ulong arg7_addr = rsp + 0x38;
                        uint8_t read_buf[20];
                        panda_virtual_memory_read(env, arg7_addr, read_buf, 20);
                        printf("ReportEvent %s\n", (char*) read_buf);
                    }
                    function.name = std::string(fn_name);
                    g_symbol_map[path][rva] = function;
                }
            }
            free_mem_pe(in_memory_pe);
        }

        // iterate
        free_module_entry(curr);
        curr = module_list_next(module_list);
    }
    free_module_list(module_list);

    return 0;
}

void register_panda_callbacks(void* self) {
    panda_cb pcb;

    // pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(init_log_detect));
    // panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(register_hook));
    panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    // pcb.before_block_exec = register_hook;
    // panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    // set_callstack_osi(g_current_osi);
    // init_callstack_plugin(self, g_current_osi);
    // register_callstack_callback("on_call", call_insn_callback);

    // PPP_REG_CB("syscalls2", on_sys_syslog_enter, syslog_syscall_hook);
    // PPP_REG_CB("syscalls2", on_NtTraceEvent_enter, nt_trace_event_hook);
    // PPP_REG_CB("syscalls2", on_NtWriteFile_enter, nt_write_file_hook);
    PPP_REG_CB("syscalls2", on_NtTraceControl_enter, nt_trace_control_hook);
    
    // pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(initialize_globals));
    // panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);
    // pcb.asid_changed = update_symbols;
    // panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    // init_callstack_plugin(self, g_current_osi);
    // register_callstack_callback("on_call", call_insn_callback);
    // register_callstack_callback("on_ret", return_insn_callback);
}


bool init_plugin(void* self)
{
    fflush(stdout);
    printf("In init plugin\n");

    panda_require("syscalls2");

    panda_enable_precise_pc();

    assert(init_dynamic_symbols_api());
    // assert(init_osi_linux_api());

    assert(init_hooks_api());
    __enable_hooking();

    // assert(init_hooks2_api());
    // __enable_hooks2(id);

    const char* profile = panda_os_name;
    if (!profile) {
        fprintf(stderr,
                "[%s] Could not find os name. Please re-run with -os <profile> flag\n",
                __FILE__);
        return false;
    }

    panda_arg_list* filter_args = panda_get_args("trace_filter");
    const char* filter_file = strdup(panda_parse_string(filter_args, "file", ""));

    if (filter_file[0] == '\0') {
        g_tracefilter.reset(new TraceFilter());
    } else {
        g_tracefilter.reset(new TraceFilter(filter_file));
    }

    panda_free_args(filter_args);

    panda_arg_list* args = panda_get_args("logging_events");
    const char* log_path = strdup(panda_parse_string(args, "output", "logging.jsonl"));
    fprintf(stdout, "Writing analysis results to %s\n", log_path);
    g_log_path = (char*)log_path;
    panda_free_args(args);

    register_panda_callbacks(self);

    return true;
}

void uninit_plugin(void* self) {
    fprintf(stdout, "uninit");

    uninit_trace_engine();
    g_tracefilter.reset();
    
    panda_arg_list* args = panda_get_args("logging_events");
    panda_free_args(args);
} 
