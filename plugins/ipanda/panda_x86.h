#ifndef __PANDA_X86
#define __PANDA_X86

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#ifdef __cplusplus
extern "C" {
#endif

enum SegmentRegister {
    PANDA_REG_CS,
    PANDA_REG_DS,
    PANDA_REG_ES,
    PANDA_REG_SS,
    PANDA_REG_FS,
    PANDA_REG_GS,
};

enum X86Register {
    PANDA_REG_EAX,
    PANDA_REG_ECX,
    PANDA_REG_EDX,
    PANDA_REG_EBX,
    PANDA_REG_EDI,
    PANDA_REG_ESI,
    PANDA_REG_ESP,
    PANDA_REG_EBP, // X86
    PANDA_REG_R8,
    PANDA_REG_R9,
    PANDA_REG_R10,
    PANDA_REG_R11,
    PANDA_REG_R12,
    PANDA_REG_R13,
    PANDA_REG_R14,
    PANDA_REG_R15, // X86_64
    PANDA_REG_CR3
};

enum X86Flag { PANDA_HFLAG_CPL };

uint64_t panda_get_kernelgsbase(CPUState* cpu);
uint64_t panda_get_gdtbase(CPUState* cpu);
uint64_t panda_get_hflag(CPUState*, X86Flag flag);
bool panda_pae_enabled(CPUState* cpu);
bool panda_is_lma_set(CPUState* cpu);
#ifdef __cplusplus
}
#endif

#endif
