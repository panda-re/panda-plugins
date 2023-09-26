#ifndef _IO_SYSCALL_TRACER_TRACE_ENGINE_H
#define _IO_SYSCALL_TRACER_TRACE_ENGINE_H

#include <memory>

#include "syscall_tracer/reporting/reporting.h"
#include "syscall_tracer/syscall_tracer.h"
#include "typesignature/osi_syscalls.h"

typedef void (*AddSyscallManagerFunc)(SyscallManager*);

bool init_trace_engine(const char* profile,
                       std::shared_ptr<OsiSyscallInterface> osi_syscall,
                       AddSyscallManagerFunc add_syscall_manager,
                       std::shared_ptr<RecordingContext> recorder);

void uninit_trace_engine(void);

#endif
