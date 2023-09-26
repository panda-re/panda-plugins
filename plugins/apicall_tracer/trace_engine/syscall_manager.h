#ifndef WIN7_SYSCALL_MANAGER_H
#define WIN7_SYSCALL_MANAGER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "apicall_tracer/apicall_tracer.h"
#include "apicall_tracer/trace_engine/current_process_osi.h"
#include "apicall_tracer/trace_engine/syscall_cb.h"
#include "apicall_tracer/trace_engine/syscall_dispatcher.h"
#include "exec/cpu-defs.h"
#include "typesignature/osi_syscalls.h"

#if defined(TARGET_I386)

std::shared_ptr<SyscallManager> createSyscallManager(std::shared_ptr<OsiSyscallInterface>,
                                                     std::shared_ptr<SyscallDispatcher>,
                                                     std::shared_ptr<CurrentProcessOSI>);

#endif

#endif
