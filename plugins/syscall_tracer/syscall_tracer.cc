/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */

#define __STDC_FORMAT_MACROS

#include <cstring>
#include <stdexcept>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include <ipanda/panda_x86.h>
#include "ipanda/ipanda.h"
#include "ipanda/manager.h"

#include "syscall_tracer/reporting/reporting.h"
#include "syscall_tracer/syscall_tracer.h"
#include "syscall_tracer/trace_engine/trace_engine.h"
#include "typesignature/osi_syscalls.h"

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
}

// Internal data structure for managing callback managers
auto g_syscall_managers =
    std::unique_ptr<std::vector<SyscallManager*>>(new std::vector<SyscallManager*>());

auto g_syscalls_osi = std::shared_ptr<OsiSyscallInterface>();
auto g_reporter = std::shared_ptr<RecordingContext>();

std::shared_ptr<IntroPANDAManager> g_os_manager;
struct WindowsKernelOSI* g_kernel_osi = nullptr;
bool g_initialized = false;
char* g_log_path;

// Public API for adding system call managers
// Client is responsible for freeing manager at uninit
void add_syscall_manager(SyscallManager* manager)
{
    g_syscall_managers->push_back(manager);
}

/**
 * insn_translate callback to flag sysenter and syscall
 * instructions for instrumentation with syscall_insn_callback
 */
static bool is_syscall_insn(CPUState* env, target_ptr_t pc)
{
#if defined(TARGET_I386)
    if (!g_initialized) {
        return false;
    }
    unsigned char buf[2] = {};
    panda_virtual_memory_rw(env, pc, buf, 2, 0);
    // Check if the instruction is syscall (0F 05)
    if (buf[0] == 0x0F && buf[1] == 0x05) {
        return true;
    }
    // Check if the instruction is sysenter (0F 34)
    else if (buf[0] == 0x0F && buf[1] == 0x34) {
        return true;
    } else {
        return false;
    }
#endif
    return false;
}

/**
 * Callback to before_block_exec for invoking syscall return
 * handlers. Each syscall manager maintains a list of return
 * points ((asid, pc) tuples) that it compares against this
 * program point to determine if it represents a return from
 * a system call.
 */
void before_block_exec(CPUState* env, TranslationBlock* tb)

{
    if (!g_initialized) {
        return;
    }

    for (auto& manager : *g_syscall_managers) {
        manager->handle_potential_syscall_exit(env, tb->pc);
    }
    return;
}

/**
 * insn_exec callback that dispatches sysenter events to all of the
 * system call managers
 */
static int syscall_insn_callback(CPUState* env, target_ptr_t pc)
{
    if (!g_initialized) {
        return 0;
    }
    for (auto& manager : *g_syscall_managers) {
        manager->handle_sysenter(env, pc);
    }
    return 0;
}

void register_panda_callbacks(void* self)
{
    panda_cb pcb;
    pcb.insn_translate = is_syscall_insn;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = syscall_insn_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
}

bool init_plugin(void* self)
{
// Don't bother if we're not on a supported target
#if defined(TARGET_I386)
    register_panda_callbacks(self);

    if (!init_ipanda(self, g_os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return false;
    }

    const char* profile = panda_os_name;
    if (!profile) {
        fprintf(stderr,
                "[%s] Could not find os name. Please re-run with -os <profile> flag\n",
                __FILE__);
        return false;
    }

    panda_arg_list* args = panda_get_args("syscall_tracer");
    const char* log_path = strdup(panda_parse_string(args, "output", "syscalls.jsonl"));
    fprintf(stdout, "Writing analysis results to %s\n", log_path);
    g_log_path = (char*)log_path;
    panda_free_args(args);

    g_syscalls_osi.reset(new OsiSyscallInterface(profile, g_os_manager, "syscalls.db"));
    if (!g_syscalls_osi) {
        fprintf(stderr, "[%s] Failed to find a syscall profile for %s\n", __FILE__,
                profile);
        return false;
    }

    g_reporter = create_reporter_ctx(log_path);
    if (!g_reporter || !g_reporter->is_valid()) {
        fprintf(stderr, "[%s] Failed to create a recording context\n", __FILE__);
        return false;
    }

    if (!init_trace_engine(profile, g_syscalls_osi, add_syscall_manager, g_reporter)) {
        fprintf(stderr, "[%s] Failed to initialize trace engine!\n", __FILE__);
        return false;
    }

#else
    fprintf(stderr, "[%s] This platform is not currently supported.\n", __FILE__);
    return false;
#endif
    return true;
}

void uninit_plugin(void* self) { uninit_trace_engine(); }
