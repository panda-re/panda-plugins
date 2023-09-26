#ifndef _SYSCALL_CB_H
#define _SYSCALL_CB_H
#include <functional>
#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

#include "typesignature/arguments.h"
#include "typesignature/osi_syscalls.h"
#include "panda/plugin.h"
#include "panda/common.h"

class SyscallCallback
{
public:
    // return false --> don't hook return
    virtual bool enter_cb(CPUState* env, target_ulong pc, CallContext* args) = 0;
    virtual void return_cb(CPUState* env, target_ulong pc, CallContext* args) = 0;
};

class SyscallCallbackFactory
{
public:
    virtual std::shared_ptr<SyscallCallback> createSyscallCallback(CPUState* env) = 0;
};

using EnterCallback =
    std::function<void(CPUState* env, target_ulong pc, CallContext* args)>;
using ReturnCallback =
    std::function<void(CPUState* env, target_ulong pc, CallContext* args)>;

class LambdaSyscallCallback : public SyscallCallback
{
protected:
    EnterCallback m_enter;
    ReturnCallback m_return;

public:
    LambdaSyscallCallback(EnterCallback enter, ReturnCallback exit)
        : m_enter(enter), m_return(exit)
    {
    }

    virtual bool enter_cb(CPUState* env, target_ulong pc, CallContext* args) override;

    virtual void return_cb(CPUState* env, target_ulong pc, CallContext* args) override;
};

class LambdaSyscallCallbackFactory : public SyscallCallbackFactory
{
protected:
    EnterCallback m_enter;
    ReturnCallback m_return;

public:
    LambdaSyscallCallbackFactory(EnterCallback enter, ReturnCallback exit)
        : m_enter(enter), m_return(exit)
    {
    }

    std::shared_ptr<SyscallCallback> createSyscallCallback(CPUState* env) override;
};

template <class CBClass>
class GenericSyscallCallbackFactory : public SyscallCallbackFactory
{
public:
    std::shared_ptr<SyscallCallback> createSyscallCallback(CPUState* env)
    {
        return std::make_shared<CBClass>();
    }
};

template <class CBClass> std::shared_ptr<SyscallCallbackFactory> make_cb_factory()
{
    return std::make_shared<GenericSyscallCallbackFactory<CBClass>>();
}

#endif
