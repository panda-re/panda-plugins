#pragma once

extern "C" {
#define __STDC_FORMAT_MACROS
}

#include <algorithm>
#include <iterator>

#include "panda/plugin.h"
#include "panda/common.h"

#include <osi/windows/wintrospection.h>

class CurrentProcessOSI
{
public:
    virtual bool is_valid() = 0;
    virtual uint64_t current_pid(CPUState* env) = 0;
    virtual uint64_t current_tid(CPUState* env) = 0;
    virtual uint64_t current_asid(CPUState* env) = 0;

    virtual ~CurrentProcessOSI(){};
};

std::shared_ptr<CurrentProcessOSI>
create_current_process_osi(const char* profile, struct WindowsKernelOSI* kosi);
