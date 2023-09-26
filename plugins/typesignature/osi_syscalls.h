#ifndef _OS_SPECIFIC_H
#define _OS_SPECIFIC_H

#include "ipanda/manager.h"

#include "arguments.h"
#include "syscall_database.h"

typedef void (*RegisterTypesCB)(const char*);
typedef void (*RegisterSyscallsCB)(int64_t, const char*, int);
typedef void (*RegisterSyscallArgumentsCB)(int64_t, const ArgSpec* const*, int);

class OsiSyscallInterface
{
private:
    std::shared_ptr<IntroPANDAManager> m_os_manager;
    bool m_syscall_db;

public:
    OsiSyscallInterface(const char* profile,
                        std::shared_ptr<IntroPANDAManager> os_manager,
                        const char* database);
    ~OsiSyscallInterface(){};

    std::shared_ptr<IntroPANDAManager> get_introspection_manager()
    {
        return m_os_manager;
    }

    // typesignature functions for looking up values in database:

    // perform lookup, return true if found
    bool lookup_syscall_id_by_name(const char* syscall_name, SyscallID& sid);
    bool lookup_syscall_name_by_id(char const** syscall_name, SyscallID sid);

    // other lookups
    int lookup_syscall_argument_count(SyscallID sid);
    const ArgSpec* lookup_syscall_argument_specification(SyscallID sid, int pos);

    // registers
    void register_types(void (*)(const char*));
    void register_syscalls(void (*)(int64_t, const char*, int));
    void register_syscall_arguments(void (*)(int64_t, const ArgSpec* const*, int));

    // os-dependent functions, proxied by os manager:

    // get the nth argument to a syscall
    uint64_t get_syscall_argument_value(CPUState* env, uint8_t pos);

    // get the return address of a system call *only at sysenter/syscall*
    uint64_t get_syscall_return_address(CPUState* env, target_ulong pc);

    // get the return value
    target_ulong get_syscall_return_value(CPUState* env);

    // Provide a string representation of the given argument
    std::string stringify_argument(CPUState* env, CallContext* ctx,
                                   std::vector<Argument*>& args, uint16_t pos);

    // encode as int64 for recording
    int64_t encode_syscall_return(target_long status_code);
};

#endif
