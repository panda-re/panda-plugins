#ifndef _SYSCALL_DISPATCHER_H
#define _SYSCALL_DISPATCHER_H

#include "syscall_tracer/syscall_tracer.h"
#include "syscall_tracer/trace_engine/syscall_cb.h"

class SyscallDispatcher
{
public:
    virtual std::shared_ptr<SyscallCallback> createSyscallCallback(CPUState* env) = 0;
    virtual void set_default_handler(std::shared_ptr<SyscallCallbackFactory> factory) = 0;
    virtual bool
    set_specialized_handler(const char* syscall_name,
                            std::shared_ptr<SyscallCallbackFactory> factory) = 0;
};

std::shared_ptr<SyscallDispatcher>
createSyscallDispatcher(std::shared_ptr<OsiSyscallInterface> syscall_osi);

#endif
