#include <algorithm>
#include <cstring>
#include <map>
#include <string>

#include "panda/plugin.h"
#include "exec/cpu-defs.h"
#include "panda/common.h"

#include <osi/windows/manager.h>
#include <osi/windows/pe.h>
#include <osi/windows/wintrospection.h>

#include "ipanda/stringify/stringify_common.h"
#include "ipanda/stringify/windows/win7_stringifier.h"

#include <ipanda/manager.h>
#include <ipanda/types.h>
#include <ipanda/panda_x86.h>

static const uint32_t _KMODE_FS32 = 0x030;
static const uint32_t _KPCR_SELF_OFF = 0x018;

static std::map<std::string, uint64_t> windows_system_asid_lookup = {
    {"windows-32-7sp1", 0x185000},
    {"windows-64-7sp1", 0x187000},
};

/**
 *   HELPER FUNCTIONS
 */

/**
 * Get the Kernel Processor Control Region (KPCR) on a 32-bit system
 *
 * The KPCR should be accessible from FS. FS is stored at selector 0x30
 * in the Global Descriptor Table (GDT), so we look here to load it.
 * The base of this segment contains the KPCR.
 *
 */
uint64_t get_kpcr_i386(CPUState* env)
{
    auto gdtbase = panda_get_gdtbase(env);

    // read the FS segment descriptor from the GDT
    uint32_t e1 = 0, e2 = 0;
    panda_virtual_memory_rw(env, gdtbase + _KMODE_FS32, (uint8_t*)&e1, 4, false);
    panda_virtual_memory_rw(env, gdtbase + _KMODE_FS32 + 4, (uint8_t*)&e2, 4, false);

    // get base address from wacky segment
    // see https://wiki.osdev.org/Global_Descriptor_Table
    // for a layout -- we need the upper 16 bits of the first word, and
    // the lowest and highest byte of the second word all together
    uint32_t addr = ((e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000));

    return addr;
}

/**
 * Get the Kernel Processor Control Region (KPCR) on a 64-bit system
 *
 * The KPCR should be stored in the Model Specific Register, KernelGSBase. If
 * it is not there, then it has already been swapped into GS (with swapgs). We
 * know if a KPCR has been found, because a KPCR struct has a pointer to itself
 * at offset 0x18.
 */
uint64_t get_kpcr_amd64(CPUState* cpu)
{
    uint64_t kpcr = 0;
#ifdef TARGET_X86_64
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;

    kpcr = env->kernelgsbase;

    // check if the SelfPcr member is a pointer to itself. if so, we found the
    // KPCR.
    uint64_t base_self;
    panda_virtual_memory_rw(cpu, kpcr + _KPCR_SELF_OFF, (uint8_t*)&base_self, 8, false);
    if (kpcr != base_self) {
        // it has been swapped into GS
        kpcr = env->segs[R_GS].base;
    }
#endif
    return kpcr;
}

std::string populate_generic_module(struct WindowsModuleEntry* m,
                                    ipanda_types::Module& out)
{
    out.name = std::string(module_entry_get_dllname(m));
    out.path = std::string(module_entry_get_dllpath(m));
    out.base_address = module_entry_get_base_address(m);
    out.image_size = module_entry_get_modulesize(m);
    out.timedatestamp = module_entry_get_timedatestamp(m);
    out.entry_point = module_entry_get_entrypoint(m);

    std::transform(out.path.begin(), out.path.end(), out.path.begin(), ::tolower);

    return out.path;
}

void populate_generic_process(struct WindowsProcess* p, ipanda_types::Process& out,
                              uint64_t rrindex)
{
    // metadata
    out.memory_address = process_get_eprocess(p);
    out.process32 = process_is_wow64(p);
    out.start_rrindex = rrindex;
    out.end_rrindex = rrindex;

    // process info
    out.pid = process_get_pid(p);
    out.ppid = process_get_ppid(p);
    out.asid = process_get_asid(p);
    out.name = std::string(process_get_shortname(p));
    out.create_time = process_createtime(p);
    out.base_vba = process_get_base(p);

    // populate cmdline if it was captured
    const char* cmd = process_get_cmdline(p);
    if (cmd) {
        out.cmdline = std::string(cmd);
    }
}

/**
 *   INTERNAL FUNCTIONS
 */

void Windows7IntrospectionManager::collect_all_process_modules(
    ipanda_types::Process& process, guid_map_t& guid_map)
{
    auto kosi = m_kernel->get_kernel_object();
    struct WindowsModuleList* mlist =
        get_module_list(kosi, process.memory_address, process.process32);

    if (!mlist) {
        return;
    }

    struct WindowsProcessOSI* posi = module_list_get_osi(mlist);

    struct WindowsModuleEntry* mentry;
    while ((mentry = module_list_next(mlist)) != nullptr) {
        // add module
        auto out = ipanda_types::Module();
        auto key = populate_generic_module(mentry, out);

        // add the guid for this path if it hasn't been observed
        if (guid_map.find(key) == guid_map.end()) {

            auto in_memory_pe = init_mem_pe(posi, out.base_address, false);
            if (in_memory_pe) {
                auto guid = mem_pe_get_guid(in_memory_pe);
                if (!guid.empty()) {
                    guid_map[key] = guid;
                }
            }
            free_mem_pe(in_memory_pe);
        }
        process.modules.insert(std::make_pair(key, out));

        free_module_entry(mentry);
    }
    free_module_list(mlist);
}

/**
 *   PUBLIC API
 */
bool Windows7IntrospectionManager::initialize(CPUState* env)
{

    auto pmem = create_panda_physical_memory();
    if (!pmem) {
        fprintf(stderr, "[%s] Error creating physical memory interface\n", __FILE__);
        return false;
    }

    auto asid_entry = windows_system_asid_lookup.find(m_profile);
    if (asid_entry == windows_system_asid_lookup.end()) {
        fprintf(stderr, "[%s] %s is an unsupported profile\n", __FILE__,
                m_profile.c_str());
        return false;
    }

    auto kpcr = (m_pointer_width == 8) ? get_kpcr_amd64(env) : get_kpcr_i386(env);

    m_initialized = m_kernel->initialize(pmem, m_pointer_width, asid_entry->second, kpcr,
                                         panda_pae_enabled(env));
    return m_initialized;
}

void Windows7IntrospectionManager::collect_all_active_processes(
    CPUState* env, std::map<process_key_t, ipanda_types::Process>& mapping,
    guid_map_t& guid_map)
{
    // get rrindex outside the loop since it won't change
    uint64_t rrindex = rr_get_guest_instr_count();

    // create our linked list of processes
    auto kosi = m_kernel->get_kernel_object();
    struct WindowsProcessList* plist = get_process_list(kosi);
    struct WindowsProcess* process;
    while ((process = process_list_next(plist)) != nullptr) {
        // have we seen this process before
        auto key = process_key_t(process_get_pid(process), process_createtime(process),
                                 process_get_shortname(process));
        auto entry = mapping.find(key);
        if (entry == mapping.end()) {
            // no, populate it and add it to our map
            auto out = ipanda_types::Process();
            populate_generic_process(process, out, rrindex);

            if (out.asid == panda_current_asid(env)) {
                // time consuming, so there's no point in collecting modules
                // of a process that never executes
                this->collect_all_process_modules(out, guid_map);
            }
            mapping.insert(std::make_pair(key, out));
        } else {
            entry->second.end_rrindex = rrindex;
            if (entry->second.cmdline.empty()) {
                const char* cmd = process_get_cmdline(process);
                if (cmd) {
                    entry->second.cmdline = std::string(cmd);
                }
            }
            if (entry->second.asid == panda_current_asid(env)) {
                // time consuming, so there's no point in collecting modules
                // of a process that never executes
                this->collect_all_process_modules(entry->second, guid_map);
            }
        }

        free_process(process);
    }
    free_process_list(plist);
}

void Windows7IntrospectionManager::get_current_process(CPUState* env,
                                                       ipanda_types::Process& out)
{
    auto kosi = m_kernel->get_kernel_object();

    struct WindowsProcess* p = kosi_get_current_process(kosi);
    populate_generic_process(p, out, rr_get_guest_instr_count());
    free_process(p);
}

std::string Windows7IntrospectionManager::stringify_argument(CPUState* env,
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

    auto kosi = m_kernel->get_kernel_object();

    // Check if the type is one we know how to handle
    auto candidate = g_formatters.find(type);
    if (candidate != g_formatters.end()) {
        return candidate->second(env, kosi, arg);
    } else if (strcmp("PVOID", type) == 0) {
        return stringify_pvoid(env, kosi, ctx, arg, args);
    }
    return stringify_unknown(arg);
}
