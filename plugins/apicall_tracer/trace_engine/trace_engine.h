#ifndef _IO_SYSCALL_TRACER_TRACE_ENGINE_H
#define _IO_SYSCALL_TRACER_TRACE_ENGINE_H

#include <memory>

#include "apicall_tracer/apicall_tracer.h"
#include "apicall_tracer/reporting/reporting.h"
#include "typesignature/osi_syscalls.h"

#include <osi/windows/wintrospection.h>

typedef void (*AddSyscallManagerFunc)(SyscallManager*);

bool init_trace_engine(const char* profile,
                       std::shared_ptr<OsiSyscallInterface> osi_syscall,
                       AddSyscallManagerFunc add_syscall_manager,
                       std::shared_ptr<RecordingContext> recorder,
                       struct WindowsKernelOSI* kosi);

void uninit_trace_engine(void);

#endif
