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

#include <algorithm>
#include <dlfcn.h>
#include <iterator>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include <ipanda/panda_x86.h>

#include "ipanda/manager.h"
#include "ipanda/types.h"

#include "typesignature/arguments.h"

#include "syscall_tracer/reporting/reporting.h"
#include "syscall_tracer/syscall_tracer.h"
#include "typesignature/osi_syscalls.h"

#include "syscall_cb.h"
#include "syscall_dispatcher.h"
#include "syscall_manager.h"
#include "trace_engine.h"

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
#define TUL "%x"
#define SID "%05d"
#else
#define TUL "%lx"
#define SID "%05ld"
#endif

// Module globals
#if defined(TARGET_I386)
auto g_manager = std::shared_ptr<SyscallManager>(nullptr);
auto g_dispatcher = std::shared_ptr<SyscallDispatcher>(nullptr);
auto g_syscall_osi = std::shared_ptr<OsiSyscallInterface>(nullptr);
auto g_reporting = std::shared_ptr<RecordingContext>(nullptr);

/****************************************************
 *              Default handlers
 *
 * These callbacks are invoked for any system calls
 * that do not have specific handlers
 ****************************************************/

bool enter_cb(CPUState* env, target_ulong pc, CallContext* ctx)
{
    auto manager = g_syscall_osi->get_introspection_manager();

    auto current = ipanda_types::Process();
    manager->get_current_process(env, current);

    auto tid = manager->get_current_tid(env);
    auto guid = g_reporting->get_guid();

    // Record the tid in the context to catch rare cases of mismatched syscalls
    ctx->set_tid(tid);

    int64_t syscall_id =
        record_syscall_invocation(g_reporting.get(), current.pid, current.asid, tid,
                                  true, // is_entry
                                  -1,   // return_value
                                  rr_get_guest_instr_count(), ctx->call_id(), guid);

    ctx->set_guid(guid);
    auto args_vector = ctx->args();
    if (args_vector) {
        std::vector<Argument*> args; // drop the unique_ptr for args
        std::transform(args_vector->begin(), args_vector->end(), std::back_inserter(args),
                       [](std::unique_ptr<Argument>& arg) { return arg.get(); });

        for (const auto& arg : args) {
            auto value = arg->value();
            auto aspec = arg->specification();
            // A null argspec indicates the type is unknown
            auto type = aspec ? aspec->type() : "unknown";
            auto io_type = aspec ? aspec->io_type() : UNKNOWN;
            auto position = aspec ? aspec->position() : -1;

            std::string description;
            bool has_description = io_type == IN || io_type == IN_OPT ||
                                   io_type == INOUT || io_type == INOUT_OPT ||
                                   io_type == UNKNOWN;
            if (has_description) {
                description = g_syscall_osi->stringify_argument(env, ctx, args, position);
            }
            (void)record_syscall_argument(
                g_reporting.get(), type, io_type, value, position, syscall_id,
                has_description ? description.c_str() : nullptr);
        }
    }
    return true;
};

void return_cb(CPUState* env, target_ulong pc, CallContext* ctx)
{
    auto manager = g_syscall_osi->get_introspection_manager();

    auto current = ipanda_types::Process();
    manager->get_current_process(env, current);

    auto tid = manager->get_current_tid(env);
    auto guid = ctx->get_guid();

    X86CPU* cpu = X86_CPU(env);
    CPUX86State* x86_env = &cpu->env;

    target_long return_val = x86_env->regs[R_EAX];
    int64_t syscall_id = record_syscall_invocation(
        g_reporting.get(), current.pid, current.asid, tid, false, // is_entry
        g_syscall_osi->encode_syscall_return(return_val), rr_get_guest_instr_count(),
        ctx->call_id(), guid);

    auto args_vector = ctx->args();
    if (args_vector) {
        std::vector<Argument*> args; // drop the unique_ptr for args
        std::transform(args_vector->begin(), args_vector->end(), std::back_inserter(args),
                       [](std::unique_ptr<Argument>& arg) { return arg.get(); });

        for (const auto& arg : args) {
            auto value = arg->value();
            auto aspec = arg->specification();
            // A null argspec indicates the type is unknown
            auto type = aspec ? aspec->type() : "unknown";
            auto io_type = aspec ? aspec->io_type() : UNKNOWN;
            auto position = aspec ? aspec->position() : -1;

            std::string description;
            bool has_description =
                (io_type == OUT || io_type == OUT_OPT || io_type == INOUT ||
                 io_type == INOUT_OPT || io_type == UNKNOWN);
            if (has_description) {
                description = g_syscall_osi->stringify_argument(env, ctx, args, position);
            }

            (void)record_syscall_argument(
                g_reporting.get(), type, io_type, value, position, syscall_id,
                has_description ? description.c_str() : nullptr);
        }
    }
};

/****************************************************
 *              Specialized handlers
 ****************************************************/

/****************************************************
 *             External APIs
 ****************************************************/
bool init_trace_engine(const char* profile,
                       std::shared_ptr<OsiSyscallInterface> osi_syscall,
                       AddSyscallManagerFunc add_syscall_manager,
                       std::shared_ptr<RecordingContext> recorder)
{
    // Ensure that the io_syscalls3 interface has been initialized
    g_syscall_osi = osi_syscall;
    if (!g_syscall_osi) {
        fprintf(stderr, "[%s] Could not locate osi handler for %s.\n", __FILE__, profile);
        return false;
    }

    // Find a version-specific callback factory based on our profile
    g_dispatcher = createSyscallDispatcher(g_syscall_osi);
    if (!g_dispatcher) {
        fprintf(stderr, "[%s] Could not locate syscall callbacks for %s.\n", __FILE__,
                profile);
        return false;
    }

    // Register a default handler for all system calls
    g_dispatcher->set_default_handler(
        std::make_shared<LambdaSyscallCallbackFactory>(enter_cb, return_cb));

    // Create a manager (interface to syscalls3) for the dispatcher
    g_manager = createSyscallManager(g_syscall_osi, g_dispatcher);
    if (!g_manager) {
        fprintf(stderr, "[%s] Could not create syscall manager\n", __FILE__);
        return false;
    }

    g_reporting = recorder;

    // register our syscall manager
    add_syscall_manager(g_manager.get());

    return true;
}

void uninit_trace_engine() { g_manager.reset(); }

#else
bool init_trace_engine(const char* profile,
                       std::shared_ptr<OsiSyscallInterface> osi_syscall,
                       AddSyscallManagerFunc add_syscall_manager,
                       const char* database_path)
{
    (void)profile;
    (void)osi_windows;
    (void)osi_syscall;
    (void)add_syscall_manager;
    (void)database_path;
    fprintf(stderr, "[%s] This plugin is not supported on this architecture\n", __FILE__);
    return false;
}

void uninit_plugin(void* self)
{
    fprintf(stderr, "[%s] This plugin is not supported on this architecture\n", __FILE__);
}
#endif
