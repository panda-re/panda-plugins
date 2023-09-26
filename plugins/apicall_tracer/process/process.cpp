#include "process.h"
#include "panda/plugin.h"
#include "exec/cpu-defs.h"
#include "vad.h"
#include <algorithm>

#include <osi/windows/manager.h>
#include <osi/windows/wintrospection.h>

uint64_t g_ntdll_base = 0;
uint64_t g_ntdll_size = 0;

static void inline sanitize_process_name(char* process_name, size_t nbytes)
{
    bool sanitized = false;
    for (size_t ix = 0; ix < nbytes; ++ix) {
        if (process_name[ix] == 0) {
            break;
        }
        if (!g_ascii_isprint(process_name[ix])) {
            process_name[ix] = '?';
            sanitized = true;
        }
    }
    if (sanitized) {
        std::cerr << "WARNING: sanitizing unicode process name" << std::endl;
    }
}

Process::Process(osi::i_t& eproc, std::shared_ptr<guid_set> target_guids)
{
    asid = eproc["Pcb"]["DirectoryTableBase"].getu();
    pid = eproc["UniqueProcessId"].getu();
    ppid = eproc["InheritedFromUniqueProcessId"].getu();

    char process_name[17] = {0};
    eproc["ImageFileName"].getx(process_name, 16);
    sanitize_process_name(process_name, sizeof process_name);
    name = std::string(process_name);

    m_eprocess_addr = 0;
    m_ldr_table_addr = 0;
    m_target_guids = target_guids;

    // analysis, disable this for now but eventually it may be worth doing more
    // research into why this is the case
    // osi::i_t peb = eproc("Peb");
    // osi::i_t process_params = peb("ProcessParameters");
    // cmdline = osi::ustring(process_params["CommandLine"]).as_utf8();
    cmdline = "";
}

std::ostream& operator<<(std::ostream& os, const Process& p)
{
    return os << "Process("
              << "asid=" << std::hex << p.asid << ", "
              << "pid=" << std::dec << p.pid << ", "
              << "ppid=" << p.ppid << ", "
              << "name='" << p.name << "', "
              << "cmdline='" << p.cmdline << "')";
}

bool Process::operator==(const Process& other) const
{
    return (asid == other.asid) && (pid == other.pid) && (name == other.name);
}

std::string parse_full_path(osi::i_t& ldr_elem)
{
    try {
        osi::ustring ustr(ldr_elem["FullDllName"]);
        std::string modname = ustr.as_utf8();

        std::transform(modname.begin(), modname.end(), modname.begin(), ::tolower);

        // ustr returns the string with null bytes at the end
        modname.erase(std::find(modname.begin(), modname.end(), '\0'), modname.end());

        return modname;
    } catch (...) {
        return std::string("-");
    }
}

std::shared_ptr<Image> Process::add_image(std::shared_ptr<VirtualMemory> vmem,
                                          struct StructureTypeLibrary* tlib,
                                          uint64_t base_address, uint64_t size,
                                          const std::string& name, uint64_t ldr_addr)
{
    std::shared_ptr<Image> i = std::make_shared<Image>(base_address, size, name);

    auto r = images.insert(std::make_pair(i->key(), i));
    std::map<uint64_t, std::shared_ptr<Image>>::iterator it = r.first;

    if (r.second) {
        std::cerr << "INFO: image " << *i << " added to " << *this << std::endl;

        if (ldr_addr != 0) {
            osi::i_t ldr_elem(vmem, tlib, ldr_addr, "_LDR_DATA_TABLE_ENTRY");
            std::string full_path = parse_full_path(ldr_elem);
            i->set_full_path(full_path);
        }
    } else {
        // std::cerr << "DEBUG: duplicate image " << *i << " for " << *this << " not
        // added" << std::endl;
        return (*it).second;
    }

    return i;
}

std::shared_ptr<Image> Process::get_image(uint64_t address,
                                          struct WindowsKernelOSI* kosi = nullptr,
                                          CPUState* env = nullptr)
{
    // returns the image the given address falls within or null if the image
    // wasn't found. This may generate a large number of messages while the
    // process is being initialized since the final stages of loading required
    // modules occurs after execution is handed to the newly spawned process

    auto existing_ptr = find_image(address);
    if (existing_ptr) {
        return existing_ptr;
    }

    // std::cerr << "WARNING: address " << std::hex << address
    //          << " outside of loaded modules for " << *this << std::endl;

    if (kosi != nullptr && env != nullptr) {
        // if CPUState provided, walk the loaded module list again and try the
        // search again
        // std::cerr << "WARNING: walking loaded modules again for " << *this <<
        // std::endl;
        osi::i_t eproc = this->get_eprocess(kosi, env);
        if (is_wow64(eproc)) {
            return nullptr; // Don't trace wow64
        }

        this->walk_images(kosi, env);

        auto new_ptr = find_image(address);
        if (new_ptr) {
            return new_ptr;
        }

        std::cerr << "WARNING: address " << std::hex << address
                  << " outside of loaded modules for " << *this << std::endl;
        auto vad = find_vad_range(eproc, address);
        std::cerr << "WARNING: blacklisting VAD range for " << std::hex << address << " ("
                  << vad.first << ", " << vad.second << ")" << std::endl;
        if (vad.first != 0 || vad.second != 0) {
            m_blacklist.add(vad.first, vad.second - vad.first);
        }

    } else {
        // std::cerr << "WARNING: CPUState not provided, cannot update image list" <<
        // std::endl;
    }

    return nullptr;
}

void Process::walk_images(struct WindowsKernelOSI* kosi, CPUState* env)
{
    osi::i_t eproc = this->get_eprocess(kosi, env);
    this->walk_images(kosi, eproc);
}

void Process::update_blacklist(struct WindowsKernelOSI* kosi, osi::i_t& eproc)
{
    std::cerr << "Updating blacklist for " << pid << std::endl;
    std::map<uint64_t, std::shared_ptr<Image>>::iterator it;

    for (it = images.begin(); it != images.end(); it++) {
        std::shared_ptr<Image> i = it->second;
        if (i->is_header_checked()) {
            continue;
        }
        auto guid = parse_guid(kosi, eproc, i->get_base_address());
        std::string modname = std::string(i->get_name());
        if (m_target_guids && m_target_guids->find(guid) == m_target_guids->end()) {
            std::cerr << "INFO: " << pid << " " << name << ": "
                      << "blacklist " << modname << " " << std::hex
                      << i->get_base_address() << " - "
                      << i->get_base_address() + i->get_size() << " GUID: " << guid.first
                      << " " << guid.second << std::endl;
            m_blacklist.add(i->get_base_address(), i->get_size());
        } else {
            std::cerr << "INFO: Success! Found a target GUID: " << std::hex << name
                      << ": " << modname << " " << std::hex << i->get_base_address()
                      << " - " << i->get_base_address() + i->get_size()
                      << " GUID: " << guid.first << " " << guid.second << std::endl;
        }
        i->set_header_checked(true);
    };
}

void Process::walk_images(struct WindowsKernelOSI* kosi, osi::i_t& eproc)
{
    // std::cerr << "DEBUG: walking images for " << *this << std::endl;

    osi::i_t peb = eproc("Peb");

    try {
        // add the base image file
        osi::i_t LDR_DATA_ENTRY = peb("Ldr")["InLoadOrderModuleList"]("Flink").set_type(
            "_LDR_DATA_TABLE_ENTRY");
        osi::iterator p(LDR_DATA_ENTRY, "InLoadOrderLinks");

        uint64_t exe_base = LDR_DATA_ENTRY["DllBase"].getu();
        uint32_t exe_size = LDR_DATA_ENTRY["SizeOfImage"].get32(); // This is a ULONG
        if (exe_base == 0 || exe_size == 0) {
            // Or these are resource DLLs
            // std::cerr << "ERROR: image isn't fully loaded yet, can't walk images for "
            // << *this << std::endl;
            return;
        }
        std::string exe_name = osi::ustring(LDR_DATA_ENTRY["BaseDllName"]).as_utf8();
        add_image(peb.get_virtual_memory_shared(), peb.get_type_library(), exe_base,
                  exe_size, exe_name, LDR_DATA_ENTRY.get_address());

        // add the rest of the loaded modules
        for (p++; *p != LDR_DATA_ENTRY; p++) {
            try {
                uint64_t base_addr = (*p)["DllBase"].getu();
                uint32_t base_size = (*p)["SizeOfImage"].get32();
                if (base_addr == 0 || base_size == 0) {
                    continue;
                }
                if (base_addr == 0) {
                    p++;
                    if (*p == LDR_DATA_ENTRY) {
                        // we're at the list head again and don't need to continue
                        break;
                    } else {
                        // this isn't the list head and we haven't looped back
                        // around to the beginning of the list - something went wrong
                        std::cerr
                            << "ERROR: invalid image found in LoadOrderModuleList for "
                            << *this << std::endl;
                        p--;
                        continue;
                    }
                }
                std::string base_dll_name = osi::ustring((*p)["BaseDllName"]).as_utf8();
                if (base_dll_name == "ntdll.dll" || base_dll_name == "NTDLL.DLL") {
                    g_ntdll_base = base_addr;
                    g_ntdll_size = base_size;
                }

                std::shared_ptr<Image> i =
                    add_image((*p).get_virtual_memory_shared(), (*p).get_type_library(),
                              base_addr, base_size, base_dll_name, (*p).get_address());
            } catch (...) {
                std::cerr << "ERROR: failed to process LoadOrderModuleList for " << *this
                          << std::endl;
            }
        }
    } catch (...) {
        // std::cerr << "WARNING: peb not yet loaded for " << *this << std::endl;
    }
    update_blacklist(kosi, eproc);

    // std::cerr << "DEBUG: finished walking images for " << *this << std::endl;
}

bool Process::address_in_blacklist(uint64_t address)
{
    return m_blacklist.contains(address);
}

bool Process::is_wow64(osi::i_t& eproc)
{
    if (panda_os_bits == 64) {
        return eproc["Wow64Process"].get64() != 0;
    } else {
        return false;
    }
}

osi::i_t Process::get_eprocess(struct WindowsKernelOSI* kosi, CPUState* env)
{
    auto manager = WindowsProcessManager();
    if (m_eprocess_addr) {
        manager.initialize(kosi, m_eprocess_addr);
        return manager.get_process();
    }

    try {
        auto proc = create_process_from_asid(kosi, panda_current_asid(env));
        if (proc == nullptr)
            exit(-1);

        manager.initialize(kosi, 0, process_get_pid(proc));
        auto eproc = manager.get_process();

        m_eprocess_addr = eproc.get_address();

        return eproc;
    } catch (...) {
        std::cerr << "ERROR: failed to get eprocess for " << *this << std::endl;
        exit(-1);
    }
}

uint64_t Process::get_ldr_table_addr(struct WindowsKernelOSI* kosi, CPUState* env)
{
    if (m_ldr_table_addr == 0) {
        try {
            osi::i_t eproc = this->get_eprocess(kosi, env);
            osi::i_t peb = eproc("Peb");
            m_ldr_table_addr = peb("Ldr")["InLoadOrderModuleList"]("Flink").get_address();
        } catch (...) {
            m_ldr_table_addr = 0;
        }
    }
    return m_ldr_table_addr;
}

std::shared_ptr<Image> Process::find_image(uint64_t address)
{
    auto testkey = images.lower_bound(address);
    if (testkey != images.end()) {
        auto image = testkey->second;
        if (image->address_in(address)) {
            return image;
        }
    }
    return std::shared_ptr<Image>(nullptr);
}
