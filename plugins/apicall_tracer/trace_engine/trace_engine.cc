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

extern "C" {
#define __STDC_FORMAT_MACROS
}

#include <algorithm>
#include <dlfcn.h>
#include <iterator>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include "apicall_tracer/apicall_tracer.h"
#include "apicall_tracer/reporting/reporting.h"
#include "apicall_tracer/trace_engine/current_process_osi.h"
#include "apicall_tracer/trace_engine/syscall_cb.h"
#include "apicall_tracer/trace_engine/syscall_dispatcher.h"
#include "apicall_tracer/trace_engine/syscall_manager.h"
#include "apicall_tracer/trace_engine/trace_engine.h"
#include "typesignature/osi_syscalls.h"

extern "C" {
extern uint64_t rr_get_guest_instr_count();
}

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
auto g_current_osi = std::shared_ptr<CurrentProcessOSI>(nullptr);
auto g_reporting = std::shared_ptr<RecordingContext>(nullptr);

/****************************************************
 *              Default handlers
 *
 * These callbacks are invoked for any system calls
 * that do not have specific handlers
 ****************************************************/

bool enter_cb(CPUState* env, target_ulong pc, CallContext* ctx)
{
    auto pid = g_current_osi->current_pid(env);
    auto asid = g_current_osi->current_asid(env);
    auto tid = ctx->get_tid();
    auto guid = g_reporting->get_guid();

    int64_t syscall_id = record_syscall_invocation(
        g_reporting.get(), pid, asid, tid,
        true, // is_entry
        -1,   // return_value
        rr_get_guest_instr_count(), ctx->call_id(), guid, ctx->get_call_module());
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

            // get the path here
            // we've traced this as
            // apicall_tracer.cc:on_call -> syscall_manager.cc:handle_sysenter -> here

            (void)record_syscall_argument(
                g_reporting.get(), type, io_type, value, position, syscall_id,
                has_description ? description.c_str() : nullptr);
        }
    }
    return true;
};

void return_cb(CPUState* env, target_ulong pc, CallContext* ctx)
{
    auto pid = g_current_osi->current_pid(env);
    auto asid = g_current_osi->current_asid(env);
    auto tid = g_current_osi->current_tid(env);

    X86CPU* cpu = X86_CPU(env);
    CPUX86State* cs = &cpu->env;

    target_long return_val = cs->regs[R_EAX];
    int64_t syscall_id = record_syscall_invocation(
        g_reporting.get(), pid, asid, tid,
        false, // is_entry
        g_syscall_osi->encode_syscall_return(return_val), rr_get_guest_instr_count(),
        ctx->call_id(), ctx->get_guid(), ctx->get_call_module());

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
                       std::shared_ptr<RecordingContext> recorder,
                       struct WindowsKernelOSI* kosi)
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

    g_current_osi = create_current_process_osi(profile, kosi);
    if (!g_current_osi) {
        fprintf(stderr, "[%s] Could not locate windows osi handler for %s\n", __FILE__,
                profile);
        return false;
    }

    // Register a default handler for all system calls
    g_dispatcher->set_default_handler(
        std::make_shared<LambdaSyscallCallbackFactory>(enter_cb, return_cb));

    // Create a manager (interface to syscalls3) for the dispatcher
    g_manager = createSyscallManager(g_syscall_osi, g_dispatcher, g_current_osi);
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
