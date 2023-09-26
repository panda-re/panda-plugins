#include <panda/plugin.h>
#include <panda/common.h>
#include <exec/cpu-defs.h>

#include <ipanda/manager.h>

uint64_t WindowsIntrospectionManager::get_argument_value(CPUState* cs, uint8_t pos,
                                                         bool syscall)
{
    target_ulong arg;

    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
#if defined(TARGET_I386)
#if defined(TARGET_X86_64)
    switch (pos) {
    case 0:
        return env->regs[R_ECX];
    case 1:
        return env->regs[R_EDX];
    case 2:
        return env->regs[8];
    case 3:
        return env->regs[9];
    }
#else
    if (syscall) {
        // i386 system call - args are at EDX + 8
        panda_virtual_memory_rw(cs,
                                env->regs[R_EDX] + (2 * sizeof(target_ulong)) +
                                    (sizeof(target_ulong) * pos),
                                (uint8_t*)&arg, sizeof(target_ulong), false);
        return arg;
    }
#endif
    // used for extra args on x64 and all args on x86
    panda_virtual_memory_rw(
        cs, env->regs[R_ESP] + sizeof(target_ulong) + (sizeof(target_ulong) * pos),
        (uint8_t*)&arg, sizeof(target_ulong), false);
    return arg;
#endif
    return (uint64_t)(-1);
}

uint64_t WindowsIntrospectionManager::get_syscall_return_address(CPUState* cs,
                                                                 target_ulong pc)
{
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
#if defined(TARGET_I386)
#if defined(TARGET_X86_64)
    return pc + 0x02;
#else
    target_ulong result = 0;
    panda_virtual_memory_rw(cs, env->regs[R_EDX], (uint8_t*)&result, sizeof(target_ulong),
                            false);
    return result;
#endif
#endif
    return 0;
}
