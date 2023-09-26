#include <map>
#include <memory>

#include "panda/plugin.h"
#include "panda/common.h"
#include <ipanda/panda_x86.h>
#include "syscall_tracer/trace_engine/syscall_cb.h"
#include "syscall_tracer/trace_engine/syscall_dispatcher.h"
#include "typesignature/osi_syscalls.h"

#if defined(TARGET_I386)

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
#define TUL "%x"
#define SID "%05d"
#else
#define TUL "%lx"
#define SID "%05ld"
#endif

class SyscallDispatcherImpl : public SyscallDispatcher
{
private:
    std::shared_ptr<SyscallCallbackFactory> find_callback(SyscallID sid);
    std::shared_ptr<OsiSyscallInterface> m_syscall_osi;

protected:
    std::shared_ptr<SyscallCallbackFactory> m_default_factory;
    std::map<SyscallID, std::shared_ptr<SyscallCallbackFactory>> m_specialized_factory;

public:
    SyscallDispatcherImpl(std::shared_ptr<OsiSyscallInterface> syscall_osi)
        : m_syscall_osi(syscall_osi)
    {
    }

    void
    set_default_handler(std::shared_ptr<SyscallCallbackFactory> factory) final override;
    bool set_specialized_handler(
        const char* syscall_name,
        std::shared_ptr<SyscallCallbackFactory> factory) final override;
    std::shared_ptr<SyscallCallback> createSyscallCallback(CPUState* env) final override;
};

std::shared_ptr<SyscallCallbackFactory>
SyscallDispatcherImpl::find_callback(SyscallID sid)
{
    // Check whether we have a special handler for this sid
    auto candidate = m_specialized_factory.find(sid);
    if (candidate != m_specialized_factory.end()) {
        return candidate->second;
    }
    // Otherwise return the default handler (or nullptr)
    return m_default_factory;
}

void SyscallDispatcherImpl::set_default_handler(
    std::shared_ptr<SyscallCallbackFactory> scf)
{
    m_default_factory = scf;
}

bool SyscallDispatcherImpl::set_specialized_handler(
    const char* syscall_name, std::shared_ptr<SyscallCallbackFactory> factory)
{
    SyscallID sid = 0;

    if (m_syscall_osi->lookup_syscall_id_by_name(syscall_name, sid)) {
        m_specialized_factory[sid] = factory;
        return true;
    } else {
        fprintf(stderr, "[%s] Could not find syscall id for %s\n", __FILE__,
                syscall_name);
        return false;
    }
}

std::shared_ptr<SyscallCallback>
SyscallDispatcherImpl::createSyscallCallback(CPUState* cs)
{
    // The system call ID is stored in EAX on windows and linux
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
    SyscallID sid = env->regs[R_EAX];

    // Grab the factory for this sid, if it exists
    auto factory = this->find_callback(sid);

    auto retptr = std::shared_ptr<SyscallCallback>(nullptr);
    if (!factory) {
        // No handler for this syscall, return null
        return retptr;
    }

    return factory->createSyscallCallback(cs);
}

std::shared_ptr<SyscallDispatcher>
createSyscallDispatcher(std::shared_ptr<OsiSyscallInterface> syscall_osi)
{
    if (syscall_osi) {
        return std::make_shared<SyscallDispatcherImpl>(syscall_osi);
    }

    return std::shared_ptr<SyscallDispatcherImpl>(nullptr);
}

#endif
