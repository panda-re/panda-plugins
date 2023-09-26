#ifndef _IO_SYSCALLS3_H
#define _IO_SYSCALLS3_H
#include <functional>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

struct function_export {
    std::string name;
    unsigned ordinal;
};

struct call_id {
    int unique_id;
    uint64_t caller;
    std::string target_module;
    std::string target_function;
};

/** A uniform interface for syscall events
 *
 * Each syscall manager recieves all sysenter instructions and all basic
 * block execution events. Each manager is responsible for deciding
 * whether to handle a given system call (for handle_sysenter) and
 * whether the given basic block exec event (potential_syscall_exit)
 * corresponds to a return from a system call of interest.
 *
 * This mechanism allows plugins to easily extend how system call
 * events are dispatched without duplicating the instruction
 * callback code
 */
class SyscallManager
{
public:
    // Callback for each sysenter/syscall instruction
    virtual void handle_sysenter(CPUState* env, target_ulong pc,
                                 struct call_id unique_call_id) = 0;

    /** Callback for each basic_block_exec event
     *
     * The system call manager is responsible for determining whether
     * this basic block represents a return from a system call it is
     * tracking
     */
    virtual void handle_potential_syscall_exit(CPUState* env, target_ulong pc) = 0;

    virtual ~SyscallManager(){};
};

#endif
