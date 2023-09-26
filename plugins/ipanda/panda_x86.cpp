#include "ipanda/panda_x86.h"

bool panda_pae_enabled(CPUState* cs)
{
#if (defined(TARGET_I386) && !defined(TARGET_X86_64))
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
    if (((env->cr[4] & 0x20) != 0) && ((env->cr[0] & 0x80000000) != 0)) {
        return true;
    }
    return false;
#else
    return false;
#endif
}

uint64_t panda_get_gdtbase(CPUState* cs)
{
#ifdef TARGET_I386
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
    return env->gdt.base;
#endif
    abort();
}

bool panda_is_lma_set(CPUState* cs)
{
#ifdef TARGET_I386
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
    return !((env->hflags & HF_LMA_MASK) == 0);
#endif
    abort();
}
