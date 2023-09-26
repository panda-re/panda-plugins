#ifndef WIN7_SYSCALL_MANAGER_H
#define WIN7_SYSCALL_MANAGER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "typesignature/osi_syscalls.h"

#include "syscall_tracer/syscall_tracer.h"
#include "syscall_tracer/trace_engine/syscall_cb.h"
#include "syscall_tracer/trace_engine/syscall_dispatcher.h"

#if defined(TARGET_I386)

std::shared_ptr<SyscallManager> createSyscallManager(std::shared_ptr<OsiSyscallInterface>,
                                                     std::shared_ptr<SyscallDispatcher>);

#endif

#endif
