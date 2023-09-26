#include <map>
#include <memory>
#include <string>
#include <vector>

#include "panda/plugin.h"
#include "panda/common.h"
#include "ipanda/panda_x86.h"

#include "typesignature/arguments.h"
#include "typesignature/syscall_database.h"

#include "syscall_tracer/syscall_tracer.h"
#include "syscall_tracer/trace_engine/syscall_manager.h"

#if defined(TARGET_I386)

typedef std::pair<uint64_t, uint64_t> ReturnPointPair;
typedef std::pair<std::shared_ptr<CallContext>, std::shared_ptr<SyscallCallback>>
    CallbackData;

class SyscallManagerImpl : public SyscallManager
{
protected:
    std::map<ReturnPointPair, std::vector<CallbackData>> m_callback_queues;
    std::shared_ptr<OsiSyscallInterface> m_syscall_osi;
    std::shared_ptr<SyscallDispatcher> m_dispatcher;

    std::shared_ptr<std::vector<std::unique_ptr<Argument>>>
    create_arg_vector(CPUState* env, SyscallID sid);

public:
    SyscallManagerImpl(std::shared_ptr<OsiSyscallInterface> syscall_osi,
                       std::shared_ptr<SyscallDispatcher> dispatcher)
        : m_syscall_osi(syscall_osi), m_dispatcher(dispatcher)
    {
    }
    virtual void handle_sysenter(CPUState* env, uint64_t pc) override;
    virtual void handle_potential_syscall_exit(CPUState* env, uint64_t pc) override;
};

class SyscallArg : public Argument
{
protected:
    target_ulong m_value; // Args are all uint64_ts in Windows
    const ArgSpec* m_arg_spec;

public:
    SyscallArg(target_ulong value, const ArgSpec* aspec)
        : m_value(value), m_arg_spec(aspec)
    {
    }

    target_ulong value() const final override { return m_value; }

    const ArgSpec* specification() const final override { return m_arg_spec; }
};

class CallContextImpl : public CallContext
{
private:
    SyscallID m_sid;
    const char* m_syscall_name;
    ArgumentVector m_arg_vector;
    int64_t guid;
    uint64_t tid;

public:
    CallContextImpl(SyscallID sid, const char* syscall_name, ArgumentVector avec)
        : m_sid(sid), m_syscall_name(syscall_name), m_arg_vector(avec)
    {
        // Default value of guid will be -1
        guid = -1;
        tid = -1;
    }

    SyscallID call_id() { return m_sid; }
    const char* call_name() { return m_syscall_name; }
    ArgumentVector args() { return m_arg_vector; }
    void set_guid(int64_t new_guid) { guid = new_guid; }
    int64_t get_guid() { return guid; }

    bool set_tid(uint64_t new_tid)
    {
        tid = new_tid;
        return true;
    }
    uint64_t get_tid() { return tid; }
};

const char* unknown_syscall_name = "unknown";

std::shared_ptr<std::vector<std::unique_ptr<Argument>>>
SyscallManagerImpl::create_arg_vector(CPUState* env, SyscallID sid)
{
    auto nargs = m_syscall_osi->lookup_syscall_argument_count(sid);
    if (nargs < 0) {
        // Unknown types, return a nullptr
        return std::shared_ptr<std::vector<std::unique_ptr<Argument>>>(nullptr);
    }

    auto retvec = std::make_shared<std::vector<std::unique_ptr<Argument>>>();

    uint8_t arg_idx = 0;
    while (arg_idx < (unsigned)nargs) {
        auto aspec = m_syscall_osi->lookup_syscall_argument_specification(sid, arg_idx);
        uint64_t argval = m_syscall_osi->get_syscall_argument_value(env, arg_idx);
        retvec->push_back(std::unique_ptr<Argument>(new SyscallArg(argval, aspec)));
        arg_idx += 1;
    }

    return retvec;
}

void SyscallManagerImpl::handle_sysenter(CPUState* env, uint64_t pc)
{
    uint64_t asid = panda_current_asid(env);
    uint64_t retpc = m_syscall_osi->get_syscall_return_address(env, pc);

    X86CPU* cpu = X86_CPU(env);
    CPUX86State* x86_env = &cpu->env;
    uint64_t syscall_number = x86_env->regs[R_EAX];

    // Create a callback for this system call
    if (!m_dispatcher) {
        // Pass if we don't have a callback factory
        return;
    }

    auto callback = m_dispatcher->createSyscallCallback(env);
    if (!callback) {
        // Pass if we don't have a callback for this system call
        return;
    }

    // Lookup name, TODO make this lazy
    const char* syscall_name = nullptr;
    if (!m_syscall_osi->lookup_syscall_name_by_id(&syscall_name, syscall_number)) {
        syscall_name = unknown_syscall_name;
    }

    // TODO Grab the arguments for the system call, if they are known
    auto arg_vector = create_arg_vector(env, syscall_number);
    auto context =
        std::make_shared<CallContextImpl>(syscall_number, syscall_name, arg_vector);

    if (!callback->enter_cb(env, pc, context.get())) {
        // return false --> don't care about return hook
        return;
    }

    // Store context for the return handler
    CallbackData cb(context, callback);
    ReturnPointPair rp = std::make_pair(asid, retpc);
    m_callback_queues[rp].push_back(cb);
}

void SyscallManagerImpl::handle_potential_syscall_exit(CPUState* env, uint64_t pc)
{
    uint64_t asid = panda_current_asid(env);
    uint64_t tid = -1;

    ReturnPointPair rp(asid, pc);
    auto candidate_queue = m_callback_queues.find(rp);
    if (candidate_queue == m_callback_queues.end()) {
        return; // no callbacks at this return point
    }
    auto& queue = candidate_queue->second;
    if (queue.size() > 0) {
        auto rit = queue.rbegin();
        for (; rit != queue.rend(); ++rit) {
            const auto& cb = *rit;
            auto context = cb.first;
            auto callback = cb.second;

            // Verify that the tid is correct, this should check the whole queue
            // Weirdness on the erase function is because reverse iterators
            // are weird
            tid = m_syscall_osi->get_introspection_manager()->get_current_tid(env);
            if (tid == context.get()->get_tid()) {
                callback->return_cb(env, pc, context.get());
                queue.erase(--(rit.base()));
                return;
            }
        }
    }
}

std::shared_ptr<SyscallManager>
createSyscallManager(std::shared_ptr<OsiSyscallInterface> syscall_osi,
                     std::shared_ptr<SyscallDispatcher> dispatcher)
{
    if (syscall_osi && dispatcher) {
        return std::make_shared<SyscallManagerImpl>(syscall_osi, dispatcher);
    }
    return std::shared_ptr<SyscallManager>(nullptr);
}

#endif
