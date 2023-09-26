#include "panda/plugin.h"
#include <ipanda/panda_x86.h>

#include "osi_syscalls.h"
#include "syscall_database.h"
#include <string.h>

OsiSyscallInterface::OsiSyscallInterface(const char* profile,
                                         std::shared_ptr<IntroPANDAManager> os_manager,
                                         const char* database)
{
    m_os_manager = os_manager;

    if (strncmp(database, "sys", 3) == 0) {
        m_syscall_db = true;
    } else {
        m_syscall_db = false;
    }

    if (!SyscallDatabase::load_syscall_data(profile, database)) {
        throw std::runtime_error("unable to load syscall database");
    }
}

bool OsiSyscallInterface::lookup_syscall_id_by_name(const char* syscall_name,
                                                    SyscallID& sid)
{
    return SyscallDatabase::lookup_syscall_id_by_name(syscall_name, sid);
}

bool OsiSyscallInterface::lookup_syscall_name_by_id(char const** syscall_name,
                                                    SyscallID sid)
{
    return SyscallDatabase::lookup_syscall_name_by_id(syscall_name, sid);
}

int OsiSyscallInterface::lookup_syscall_argument_count(SyscallID sid)
{
    return SyscallDatabase::lookup_syscall_argument_count(sid);
}

const ArgSpec* OsiSyscallInterface::lookup_syscall_argument_specification(SyscallID sid,
                                                                          int pos)
{
    return SyscallDatabase::lookup_syscall_argument_specification(sid, pos);
}

void OsiSyscallInterface::register_types(void (*callback)(const char*))
{
    return SyscallDatabase::register_types(callback);
}

void OsiSyscallInterface::register_syscalls(void (*callback)(int64_t, const char*, int))
{
    return SyscallDatabase::register_syscalls(callback);
}
void OsiSyscallInterface::register_syscall_arguments(
    void (*callback)(int64_t, const ArgSpec* const*, int))
{
    return SyscallDatabase::register_syscall_arguments(callback);
}

uint64_t OsiSyscallInterface::get_syscall_argument_value(CPUState* env, uint8_t pos)
{
    return m_os_manager->get_argument_value(env, pos, m_syscall_db);
}

uint64_t OsiSyscallInterface::get_syscall_return_address(CPUState* env, target_ulong pc)
{
    return m_os_manager->get_syscall_return_address(env, pc);
}

target_ulong OsiSyscallInterface::get_syscall_return_value(CPUState* cs)
{

    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
    return static_cast<target_ulong>(env->regs[R_EAX]);
}

int64_t OsiSyscallInterface::encode_syscall_return(target_long status_code)
{
    target_ulong mask = (target_long)(-1);
    uint64_t temp = (uint64_t)(status_code & mask);
    return static_cast<int64_t>(temp);
}

std::string OsiSyscallInterface::stringify_argument(CPUState* env, CallContext* ctx,
                                                    std::vector<Argument*>& args,
                                                    uint16_t pos)
{
    return m_os_manager->stringify_argument(env, ctx, args, pos);
}

const char* arg_io_type_name(ArgIoType iotype)
{
    switch (iotype) {
    case IN:
        return "__IN";
    case IN_OPT:
        return "__IN_OPT";
    case INOUT:
        return "__INOUT";
    case INOUT_OPT:
        return "__INOUT_OPT";
    case OUT:
        return "__OUT";
    case OUT_OPT:
        return "__OUT_OPT";
    case UNKNOWN:
        return "__UNKNOWN";
    default:
        return "__INVALID";
    }
}
