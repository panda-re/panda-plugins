#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include "apicall_tracer/apicall_tracer.h"
#include "apicall_tracer/trace_engine/current_process_osi.h"
#include "apicall_tracer/trace_engine/syscall_manager.h"

#if defined(TARGET_I386)

typedef std::pair<target_ulong, target_ulong> ReturnPointPair;
typedef std::pair<std::shared_ptr<CallContext>, std::shared_ptr<SyscallCallback>>
    CallbackData;

class SyscallManagerImpl : public SyscallManager
{
protected:
    std::map<ReturnPointPair, std::vector<CallbackData>> m_callback_queues;
    std::shared_ptr<OsiSyscallInterface> m_syscall_osi;
    std::shared_ptr<SyscallDispatcher> m_dispatcher;
    std::shared_ptr<CurrentProcessOSI> m_current_osi;

    std::shared_ptr<std::vector<std::unique_ptr<Argument>>>
    create_arg_vector(CPUState* env, SyscallID sid);

public:
    SyscallManagerImpl(std::shared_ptr<OsiSyscallInterface> syscall_osi,
                       std::shared_ptr<SyscallDispatcher> dispatcher,
                       std::shared_ptr<CurrentProcessOSI> current_osi)
        : m_syscall_osi(syscall_osi), m_dispatcher(dispatcher), m_current_osi(current_osi)
    {
    }
    virtual void handle_sysenter(CPUState* env, target_ulong pc,
                                 struct call_id unique_call_id) override;
    virtual void handle_potential_syscall_exit(CPUState* env, target_ulong pc) override;
};

class SyscallArg : public Argument
{
protected:
    target_ulong m_value; // Args are all target_ulongs in Windows
    const ArgSpec* m_arg_spec;

public:
    SyscallArg(target_ulong value, const ArgSpec* aspec)
        : m_value(value), m_arg_spec(aspec)
    {
    }

    target_ulong value() const final override { return m_value; }

    const ArgSpec* specification() const final override { return m_arg_spec; }
};

class SyscallContextImpl : public CallContext
{
private:
    SyscallID m_cid;
    ArgumentVector m_arg_vector;
    int64_t m_guid;
    uint64_t m_tid;
    std::string m_function_name;
    std::string m_module;

public:
    SyscallContextImpl(struct call_id identifier, ArgumentVector avec)
    {
        m_arg_vector = avec;

        m_cid = identifier.unique_id;
        m_tid = identifier.caller;
        m_function_name = std::string(identifier.target_function);
        m_module = std::string(identifier.target_module);
        m_guid = -1;
    }

    SyscallID call_id() { return m_cid; }
    const char* call_name() { return m_function_name.c_str(); }

    const char* get_call_module() { return m_module.c_str(); }
    ArgumentVector args() { return m_arg_vector; }

    void set_guid(int64_t new_guid) { m_guid = new_guid; }
    int64_t get_guid() { return m_guid; }

    bool set_tid(uint64_t new_tid)
    {
        m_tid = new_tid;
        return true;
    }
    uint64_t get_tid() { return m_tid; }
};

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
        target_ulong argval = m_syscall_osi->get_syscall_argument_value(env, arg_idx);
        retvec->push_back(std::unique_ptr<Argument>(new SyscallArg(argval, aspec)));
        arg_idx += 1;
    }

    return retvec;
}

void SyscallManagerImpl::handle_sysenter(CPUState* env, target_ulong pc,
                                         struct call_id unique_call_id)
{
    if (!m_dispatcher) {
        // Pass if we don't have a callback factory
        return;
    }

    auto callback = m_dispatcher->createSyscallCallback(env);
    if (!callback) {
        // Pass if we don't have a callback for this system call
        return;
    }

    target_ulong asid = panda_current_asid(env);
    target_ulong function_pc = pc;

    target_ulong call_number = unique_call_id.unique_id;

    // TODO Grab the arguments for the system call, if they are known
    auto arg_vector = create_arg_vector(env, call_number);
    auto context = std::make_shared<SyscallContextImpl>(unique_call_id, arg_vector);

    if (!callback->enter_cb(env, pc, context.get())) {
        // don't care about return hook
        return;
    }

    // Store context for the return handler
    CallbackData cb(context, callback);
    ReturnPointPair rp = std::make_pair(asid, function_pc);
    m_callback_queues[rp].push_back(cb);
}

void SyscallManagerImpl::handle_potential_syscall_exit(CPUState* env, target_ulong pc)
{
    target_ulong asid = panda_current_asid(env);

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
            uint64_t tid = m_current_osi->current_tid(env);
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
                     std::shared_ptr<SyscallDispatcher> dispatcher,
                     std::shared_ptr<CurrentProcessOSI> current_osi)
{
    if (syscall_osi && dispatcher && current_osi) {
        return std::make_shared<SyscallManagerImpl>(syscall_osi, dispatcher, current_osi);
    }
    return std::shared_ptr<SyscallManager>(nullptr);
}

#endif
