#include "panda/plugin.h"
#include "syscall_tracer/trace_engine/syscall_cb.h"

bool LambdaSyscallCallback::enter_cb(CPUState* env, target_ulong pc, CallContext* args)
{
    if (m_enter) {
        m_enter(env, pc, args);
    }
    return true;
}

void LambdaSyscallCallback::return_cb(CPUState* env, target_ulong pc, CallContext* args)
{
    if (m_return) {
        m_return(env, pc, args);
    }
}

std::shared_ptr<SyscallCallback>
LambdaSyscallCallbackFactory::createSyscallCallback(CPUState* env)
{
    (void)env; // Return a lambda callback unconditionally
    return std::make_shared<LambdaSyscallCallback>(m_enter, m_return);
}
