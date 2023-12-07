#include <cstring>
#include <map>
#include <string>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include <offset/i_t.h>
#include <osi/linux/iterator.h>
#include <osi/linux/lintrospection.h>

#include "ipanda/stringify/linux/linux3_stringifier.h"
#include "ipanda/stringify/stringify_common.h"

#include <ipanda/manager.h>
#include <ipanda/panda_x86.h>

static std::map<std::string, uint64_t> linux_system_asid_lookup = {
    {"debian-32-8.11", 0x175c000},
    {"debian-64-8.11", 0x1812000},
};

/**
 *   HELPER FUNCTIONS
 */

std::string populate_generic_module(struct LinuxMemoryRegion* m,
                                    ipanda_types::Module& out)
{
    out.path = std::string(region_get_path(m));
    out.path = std::string(region_get_name(m));
    out.timedatestamp = region_get_mtime(m);
    out.base_address = region_get_base_address(m);
    out.image_size = region_get_virtual_size(m);

    return out.path;
}

void populate_generic_process(struct LinuxTask* t, ipanda_types::Process& out,
                              uint64_t rrindex)
{
    // metadata
    out.memory_address = task_get_address(t);
    out.start_rrindex = rrindex;
    out.end_rrindex = rrindex;

    // process info
    out.pid = task_get_pid(t);
    out.ppid = task_get_ppid(t);
    out.asid = task_get_asid(t);
    out.name = std::string(task_get_shortname(t));
}

uint64_t get_fixed_esp0(CPUState* env, uint64_t ptrw)
{
    // we need a kernel stack pointer to get to the current process
    // because there is a thread_info struct at the top of the kernel stack
    uint64_t esp0 = panda_current_ksp(env);
    if (!esp0) {
        fprintf(stderr, "[%s] Could not find the current process.\n", __FILE__);
        return 0;
    }
    // fix since we were not in the kernel
    if (!panda_in_kernel(env)) {
        esp0 -= 20;
    }

    return esp0;
}

/**
 *   INTERNAL FUNCTIONS
 */
void Linux3IntrospectionManager::collect_all_process_modules(
    ipanda_types::Process& process, guid_map_t& guid_map)
{
    /**
     *  Linux doesn't have modules, but it does have contiguous regions backed by
     *  the same file - just have to check if the next region is the same file
     */
    module_map_t current_modules;

    struct LinuxProcessOSI* posi = new struct LinuxProcessOSI;
    if (!init_process_osi(m_kosi, posi, process.memory_address, process.asid)) {
        delete posi;
        return;
    }

    struct LinuxMemoryRegion* curr = get_first_module_entry(posi);
    struct LinuxMemoryRegion* next = nullptr;

    while (curr != nullptr) {
        auto out = ipanda_types::Module();
        auto key = populate_generic_module(curr, out);

        auto search = current_modules.find(key);
        if (search == current_modules.end()) {
            current_modules.insert(std::make_pair(key, out));
        } else {
            // this module is part of an all ready discovered memory region
            auto base = std::min(out.base_address, search->second.base_address);
            auto end = std::max(out.base_address + out.image_size,
                                search->second.base_address + search->second.image_size);
            search->second.base_address = base;
            search->second.image_size = end - base;
        }

        if (guid_map.find(key) == guid_map.end()) {
            // construct a TDS guid like Windows often uses
            std::string result = "";
            result.resize(32);
            snprintf(&(result[0]), 32, "%08lX%08lX", out.timedatestamp, out.image_size);
            guid_map[key] = result;
        }

        next = module_entry_next(posi, curr);
        free_region(curr);
        curr = next;
    }

    process.modules.insert(current_modules.begin(), current_modules.end());

    uninit_process_osi(posi);
    delete posi;
}

/**
 *   PUBLIC API
 */
bool Linux3IntrospectionManager::initialize(CPUState* env)
{

    auto profile = (m_profile).c_str();

    try {
        m_kosi->pmem = create_panda_physical_memory();
    } catch (const std::runtime_error& error) {
        return false;
    }

    m_kosi->kernel_tlib = load_type_library(profile);

    // check that we have a good kernel osi
    if (!(m_kosi->details)) {
        fprintf(stderr, "[%s] Error allocating the Kernel details\n", __FILE__);
    }
    if (!(m_kosi->pmem)) {
        fprintf(stderr, "[%s] Error creating physical memory interface\n", __FILE__);
        return false;
    }
    if (!(m_kosi->kernel_tlib)) {
        fprintf(stderr, "[%s] Could not locate type library for: %s\n", __FILE__,
                profile);
        return false;
    }

    m_kosi->details->pointer_width = m_pointer_width;

    auto asid_entry = linux_system_asid_lookup.find(m_profile);
    if (asid_entry == linux_system_asid_lookup.end()) {
        fprintf(stderr, "[%s] Could not find system asid for %s\n", __FILE__, profile);
        return false;
    }
    m_kosi->details->initial_task_asid = asid_entry->second;

    uint64_t esp0 = get_fixed_esp0(env, m_pointer_width);

    if (!initialize_linux_kernel_osi(m_kosi, esp0, panda_pae_enabled(env))) {
        fprintf(stderr,
                "[%s] Could not initialize the kernel intropsection library for %s\n",
                __FILE__, profile);
        return false;
    }

    return true;
}

void Linux3IntrospectionManager::collect_all_active_processes(
    CPUState* env, std::map<process_key_t, ipanda_types::Process>& mapping,
    guid_map_t& guid_map)
{
    /**
     *   There is no difference between a process and thread. Everything is a
     *   thread In the context of memory protections, we do have groups of threads
     *   and a thread leader
     */
    uint64_t esp0 = get_fixed_esp0(env, m_pointer_width);
    uint64_t addr = get_current_thread_address(m_kosi, esp0);
    uint64_t asid = panda_current_asid(env);

    struct LinuxProcessOSI* posi = new struct LinuxProcessOSI;
    if (!init_process_osi(m_kosi, posi, addr, asid)) {
        delete posi;
        return;
    }

    osi::i_t task_struct(posi->vmem, posi->tlib, posi->process_address, "task_struct");
    osi::task_iterator thread_leader(task_struct, "tasks");

    auto rrindex = rr_get_guest_instr_count();
    do {
        osi::task_iterator thread(*thread_leader, "thread_group");
        do {
            struct LinuxTask* t = create_task_from_memory(*thread);
            auto key = process_key_t(task_get_tid(t), task_get_createtime(t),
                                     task_get_shortname(t));

            auto entry = mapping.find(key);
            if (entry == mapping.end()) {
                auto out = ipanda_types::Process();
                populate_generic_process(t, out, rrindex);

                if (out.memory_address == addr) {
                    // we have to separately update the ASID, since there isn't
                    // any way to get the ASID from the task_struct
                    out.asid = asid;
                    this->collect_all_process_modules(out, guid_map);
                }
                mapping.insert(std::make_pair(key, out));

            } else {
                entry->second.end_rrindex = rrindex;
                if (entry->second.memory_address == addr) {
                    entry->second.asid = asid;
                    this->collect_all_process_modules(entry->second, guid_map);
                }
            }

            free_task(t);
            thread++;
        } while (!thread.is_original_task());

        thread_leader++;
    } while (!thread_leader.is_original_task());

    uninit_process_osi(posi);
    delete posi;
}

void Linux3IntrospectionManager::get_current_process(CPUState* env,
                                                     ipanda_types::Process& out)
{
    uint64_t esp0 = get_fixed_esp0(env, m_pointer_width);
    uint64_t addr = get_current_thread_address(m_kosi, esp0);

    struct LinuxProcessOSI* posi = new struct LinuxProcessOSI;
    init_process_osi(m_kosi, posi, addr, panda_current_asid(env));

    struct LinuxTask* t = create_process(posi);
    populate_generic_process(t, out, rr_get_guest_instr_count());
    free_task(t);
}

uint64_t Linux3IntrospectionManager::get_current_tid(CPUState* env)
{
    uint64_t esp0 = get_fixed_esp0(env, m_pointer_width);
    return get_current_thread_pid(m_kosi, esp0, panda_current_asid(env));
}

std::string Linux3IntrospectionManager::stringify_argument(CPUState* env,
                                                           CallContext* ctx,
                                                           std::vector<Argument*>& args,
                                                           uint16_t pos)
{
    if (pos >= args.size())
        return "";

    auto arg = args[pos];
    if (!arg)
        return "";

    auto argspec = arg ? arg->specification() : nullptr;
    auto type = argspec ? argspec->type() : nullptr;

    if (!type) {
        return stringify_unknown(arg);
    }

    uint64_t esp0 = get_fixed_esp0(env, m_pointer_width);
    uint64_t addr = get_current_thread_address(m_kosi, esp0);

    struct LinuxProcessOSI* posi = new struct LinuxProcessOSI;
    init_process_osi(m_kosi, posi, addr, panda_current_asid(env));

    std::string result;

    // Check if this argument is a file descriptor.
    if (strcmp(argspec->name(), "fd") == 0) {
        result = stringify_file_descriptor(posi, ctx, arg);
    } else {
        auto candidate = g_formatters.find(type);
        if (candidate == g_formatters.end()) {
            result = stringify_unknown(arg);
        } else {
            result = candidate->second(posi, ctx, arg);
        }
    }

    uninit_process_osi(posi);
    delete posi;
    return result;
}
