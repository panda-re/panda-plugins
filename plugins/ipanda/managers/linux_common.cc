#include <panda/plugin.h>
#include <panda/common.h>
#include <exec/cpu-defs.h>

#include <ipanda/manager.h>

uint64_t LinuxIntrospectionManager::get_argument_value(CPUState* cs, uint8_t pos,
                                                       bool syscall)
{

#if defined(TARGET_I386)
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
#if defined(TARGET_X86_64)
    int position_3;
    if (syscall) {
        position_3 = 10;
    } else {
        position_3 = R_ECX;
    }

    switch (pos) {
    case 0:
        return env->regs[R_EDI];
    case 1:
        return env->regs[R_ESI];
    case 2:
        return env->regs[R_EDX];
    case 3:
        return env->regs[position_3];
    case 4:
        return env->regs[8];
    case 5:
        return env->regs[9];
    }
#else
    if (syscall) {
        // i386 syscalls are in registers, apicalls on stack
        switch (pos) {
        case 0:
            return env->regs[R_EBX];
        case 1:
            return env->regs[R_ECX];
        case 2:
            return env->regs[R_EDX];
        case 3:
            return env->regs[R_ESI];
        case 4:
            return env->regs[R_EDI];
        case 5:
            return env->regs[R_EBP];
        }
    }
#endif
    // used for extra args on x64 and all args on x86
    target_ulong arg;
    panda_virtual_memory_rw(cs, env->regs[R_EBP] + (sizeof(target_ulong) * (pos + 1)),
                            (uint8_t*)&arg, sizeof(target_ulong), false);
    return arg;
#endif
    return (uint64_t)(-1);
}

uint64_t LinuxIntrospectionManager::get_syscall_return_address(CPUState* cpu,
                                                               target_ulong pc)
{
#if defined(TARGET_I386)
#if defined(TARGET_X86_64)
    return pc + 0x02;
#else
    return pc + 0x0b;
#endif
#endif
    return 0;
}
