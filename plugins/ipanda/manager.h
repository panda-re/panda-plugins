#pragma once

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include <string>

#include <osi/linux/lintrospection.h>
#include <osi/windows/manager.h>

#include "typesignature/arguments.h"

#include <offset/offset.h>

#include "memory/pandamemory.h"
#include "types.h"

class IntroPANDAManager
{
protected:
    // INFO
    uint32_t m_pointer_width;
    std::string m_profile;
    bool m_initialized;

    virtual void collect_all_process_modules(ipanda_types::Process& process,
                                             guid_map_t& guid_map) = 0;

public:
    IntroPANDAManager(uint32_t width, const char* profile)
        : m_pointer_width(width), m_profile(std::string(profile))
    {
        m_initialized = false;
    }

    virtual bool initialize(CPUState* env) = 0;

    virtual void
    collect_all_active_processes(CPUState* env,
                                 std::map<process_key_t, ipanda_types::Process>& mapping,
                                 guid_map_t& guid_map) = 0;
    virtual void get_current_process(CPUState* env, ipanda_types::Process& out) = 0;
    virtual uint64_t get_current_tid(CPUState* env) = 0;

    virtual std::string stringify_argument(CPUState* env, CallContext* ctx,
                                           std::vector<Argument*>& args,
                                           uint16_t pos) = 0;

    virtual uint64_t get_argument_value(CPUState* env, uint8_t pos,
                                        bool syscall = true) = 0;
    virtual uint64_t get_syscall_return_address(CPUState* env, target_ulong pc) = 0;
};

class WindowsIntrospectionManager : public IntroPANDAManager
{
protected:
    std::unique_ptr<WindowsKernelManager> m_kernel;

public:
    WindowsIntrospectionManager(uint32_t width, const char* profile)
        : IntroPANDAManager(width, profile)
    {
        m_kernel = std::make_unique<WindowsKernelManager>(m_profile);
    }

    ~WindowsIntrospectionManager()
    {
        // if the kernel has been initialized, it is on us to
        // free the physical memory interface
        if (m_initialized) {
            auto kosi = m_kernel->get_kernel_object();
            kosi->pmem->free(kosi->pmem);
        }
    }

    uint64_t get_argument_value(CPUState* env, uint8_t pos,
                                bool syscall = true) override final;
    uint64_t get_syscall_return_address(CPUState* env, target_ulong pc) override final;
};

class LinuxIntrospectionManager : public IntroPANDAManager
{
protected:
    struct LinuxKernelOSI* m_kosi;

public:
    LinuxIntrospectionManager(uint32_t width, const char* profile)
        : IntroPANDAManager(width, profile)
    {
        m_kosi = new struct LinuxKernelOSI();
        m_kosi->details = new struct LinuxKernelDetails();
    }
    ~LinuxIntrospectionManager()
    {
        if (m_kosi) {
            if (m_kosi->details) {
                delete m_kosi->details;
            }
            auto memory = m_kosi->pmem;
            if (memory)
                m_kosi->pmem->free(memory);
            delete m_kosi;
        }
    }

    uint64_t get_argument_value(CPUState* env, uint8_t pos, bool syscall = true) override;
    uint64_t get_syscall_return_address(CPUState* env, target_ulong pc) override;
};

class Windows7IntrospectionManager final : public WindowsIntrospectionManager
{
protected:
    void collect_all_process_modules(ipanda_types::Process& process,
                                     guid_map_t& guid_map) override final;

public:
    Windows7IntrospectionManager(uint32_t width, const char* profile)
        : WindowsIntrospectionManager(width, profile)
    {
    }
    bool initialize(CPUState* env) override final;

    void
    collect_all_active_processes(CPUState* env,
                                 std::map<process_key_t, ipanda_types::Process>& mapping,
                                 guid_map_t& guid_map) override final;
    void get_current_process(CPUState* env, ipanda_types::Process& out) override final;

    uint64_t get_current_tid(CPUState* env) override final
    {
        auto kosi = m_kernel->get_kernel_object();
        return kosi_get_current_tid(kosi);
    };

    std::string stringify_argument(CPUState* env, CallContext* ctx,
                                   std::vector<Argument*>& args,
                                   uint16_t pos) override final;

    // TODO: remove this function once all plugins have been ported
    // plugins should not need (or want) the windows kernel osi
    WindowsKernelOSI* get_kosi() { return m_kernel->get_kernel_object(); }
};

class Linux3IntrospectionManager final : public LinuxIntrospectionManager
{
protected:
    void collect_all_process_modules(ipanda_types::Process& process,
                                     guid_map_t& guid_map) override final;

public:
    Linux3IntrospectionManager(uint32_t width, const char* profile)
        : LinuxIntrospectionManager(width, profile)
    {
    }

    bool initialize(CPUState* env) override final;

    void
    collect_all_active_processes(CPUState* env,
                                 std::map<process_key_t, ipanda_types::Process>& mapping,
                                 guid_map_t& guid_map) override final;
    void get_current_process(CPUState* env, ipanda_types::Process& out) override final;
    uint64_t get_current_tid(CPUState* env) override final;

    std::string stringify_argument(CPUState* env, CallContext* ctx,
                                   std::vector<Argument*>& args,
                                   uint16_t pos) override final;
};
