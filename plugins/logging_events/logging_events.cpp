#define PLUGIN_MAIN
#define __STDC_FORMAT_MACROS

extern "C" {
    #include <dlfcn.h>
}

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "panda/common.h"
#include "ipanda/ipanda.h"
#include "ipanda/manager.h"
#include "ipanda/types.h"
#include "panda/plugins/syscalls2/syscalls2.h"
#include "panda/plugins/syscalls2/syscalls_ext_typedefs.h"

#include "osi/windows/manager.h"
#include "osi/windows/pe.h"
#include "osi/windows/wintrospection.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
    #include "panda/plugins/hooks/hooks_int_fns.h"
}

static const size_t MAX_FUNCTION_PROTOTYPE_SIZE = 512;

std::shared_ptr<IntroPANDAManager> os_manager;
static std::shared_ptr<Windows7IntrospectionManager> g_os_manager;
static struct WindowsKernelOSI* g_kernel_osi = nullptr;
static bool g_initialized = false;

typedef void (*__add_hook_t)(struct hook*);
static __add_hook_t __add_hook = nullptr;

typedef void (*__enable_hooking_t)();
static __enable_hooking_t __enable_hooking = nullptr;

bool initialize_globals(CPUState* env)
{
    if (!init_ipanda(env, os_manager)) {
        fprintf(stderr, "[logging_events] Could not initialize the introspection library.\n");
        return false;
    }

    g_os_manager = std::dynamic_pointer_cast<Windows7IntrospectionManager>(os_manager);
    if (!g_os_manager) {
        fprintf(stderr, "[logging_events] Guest is not Windows; this plugin is Windows-only\n");
        return false;
    }
    g_kernel_osi = g_os_manager->get_kosi();

    g_initialized = true;
    return g_initialized;
}

struct ReportEventRecord {
    uint64_t asid;
    std::string proc;
    std::vector<std::string> strings;
};

static std::vector<ReportEventRecord> g_report_events;
static const char* REPORT_EVENTS_JSON_PATH = "logging_events.json";

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += (char)c;
                }
        }
    }
    return out;
}

static void write_report_events_json(const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "[logging_events] could not open %s for writing\n", path);
        return;
    }

    fprintf(f, "[\n");
    for (size_t i = 0; i < g_report_events.size(); i++) {
        const ReportEventRecord& rec = g_report_events[i];
        fprintf(f, "  {\n");
        fprintf(f, "    \"asid\": \"0x%lx\",\n", (unsigned long)rec.asid);
        fprintf(f, "    \"proc\": \"%s\",\n", json_escape(rec.proc).c_str());
        fprintf(f, "    \"strings\": [");
        for (size_t j = 0; j < rec.strings.size(); j++) {
            fprintf(f, "\"%s\"%s", json_escape(rec.strings[j]).c_str(),
                    j + 1 < rec.strings.size() ? ", " : "");
        }
        fprintf(f, "]\n");
        fprintf(f, "  }%s\n", i + 1 < g_report_events.size() ? "," : "");
    }
    fprintf(f, "]\n");

    fclose(f);
}

// x64 calling convention: args 1-4 in RCX/RDX/R8/R9, args 5+ spill to the
// stack past the 0x20 shadow space.
// BOOL ReportEventA(HANDLE hEventLog, WORD wType, WORD wCategory,
//     DWORD dwEventID, PSID lpUserSid, WORD wNumStrings,
//     DWORD dwDataSize, LPCSTR *lpStrings, LPVOID lpRawData)
static void read_report_event_strings(CPUState* env, std::vector<std::string>* out_strings) {
    CPUX86State* regs = (CPUX86State*) env->env_ptr;
    target_ulong rsp = regs->regs[R_ESP];
    target_ulong num_strings_addr = rsp + 0x30;  // arg6: wNumStrings
    target_ulong lp_strings_addr = rsp + 0x40;   // arg8: lpStrings

    uint16_t num_strings = 0;
    panda_virtual_memory_read(env, num_strings_addr, (uint8_t*)&num_strings, sizeof(num_strings));

    target_ulong lp_strings = 0;
    panda_virtual_memory_read(env, lp_strings_addr, (uint8_t*)&lp_strings, sizeof(lp_strings));

    printf("[ReportEventA] %u string(s) at 0x%lx\n", num_strings, (uint64_t)lp_strings);

    for (uint16_t i = 0; i < num_strings && lp_strings; i++) {
        target_ulong str_ptr = 0;
        target_ulong entry_addr = lp_strings + i * sizeof(target_ulong);
        if (panda_virtual_memory_read(env, entry_addr, (uint8_t*)&str_ptr,
                                       sizeof(str_ptr)) != 0 || !str_ptr) {
            printf("  [%u] <unreadable pointer>\n", i);
            out_strings->push_back("<unreadable pointer>");
            continue;
        }

        uint8_t buf[256] = {0};
        if (panda_virtual_memory_read(env, str_ptr, buf, sizeof(buf) - 1) == 0) {
            printf("  [%u] %s\n", i, (char*)buf);
            out_strings->push_back(std::string((char*)buf));
        } else {
            printf("  [%u] <unreadable string>\n", i);
            out_strings->push_back("<unreadable string>");
        }
    }
}

void report_event_hook(CPUState* env, TranslationBlock* tb, struct hook* h) {
    fprintf(stdout, "[REPORT EVENT HOOK]\n");

    const char* proc_name = "<unknown>";
    struct WindowsProcess* process = kosi_get_current_process(g_kernel_osi);
    if (process) {
        proc_name = process_get_shortname(process);
    }
    uint64_t asid = (uint64_t) panda_current_asid(env);
    printf("asid: 0x%lx, proc: %s\n", asid, proc_name);

    ReportEventRecord record;
    record.asid = asid;
    record.proc = proc_name;
    free_process(process);

    read_report_event_strings(env, &record.strings);
    g_report_events.push_back(std::move(record)); // Avoids copy-constructing the vector and every string in it
}

// A PE export's "RVA" can point at real code, or -- if the export is a
// forwarder (common for advapi32.dll APIs that Windows moved into
// sechost.dll/kernelbase.dll but kept a compat export for) -- at a
// null-terminated ASCII string of the form "ModuleName.FunctionName"
// instead. Hooking a forwarder's advertised address directly is a no-op:
// callers never actually execute there, since import resolution follows
// the forwarder at load time and jumps straight to the real target. This
// reads that address and, if it looks like a forwarder string rather than
// code, splits it into the module/function it points to.
static bool try_read_forwarder(CPUState* env, target_ulong addr,
                                std::string* out_module, std::string* out_func) {
    char buf[128] = {0};
    if (panda_virtual_memory_read(env, addr, (uint8_t*)buf, sizeof(buf) - 1) != 0) {
        return false;
    }

    size_t dot = std::string::npos;
    size_t len = 0;
    for (; len < sizeof(buf) - 1 && buf[len]; len++) {
        if (!isprint((unsigned char)buf[len])) {
            return false;
        }
        if (buf[len] == '.' && dot == std::string::npos) {
            dot = len;
        }
    }
    if (len == 0 || dot == std::string::npos || dot == 0 || dot == len - 1) {
        return false;
    }

    *out_module = std::string(buf, dot);
    *out_func = std::string(buf + dot + 1, len - dot - 1);
    return true;
}

// Windows-native replacement for dynamic_symbols' resolve_symbol, which only
// understands Linux ELF .so exports and always returns a zeroed symbol here.
// Walks the current process's module list (same libosi path update_symbols
// uses) and looks up func_name's RVA in the PE export table of the first
// module whose path contains module_substr. Follows forwarder exports (see
// try_read_forwarder) into whichever module they actually point at.
static bool find_export_address(CPUState* env, const char* module_substr,
                                 const char* func_name, target_ulong* out_addr,
                                 int depth = 0) {
    if (depth > 4) {
        // Forwarder chains this long mean something is misparsed -- bail
        // rather than loop.
        return false;
    }

    auto process = kosi_get_current_process(g_kernel_osi);
    auto module_list = get_module_list(g_kernel_osi, process_get_eprocess(process),
                                       process_is_wow64(process));
    free_process(process);

    if (module_list == nullptr) {
        return false;
    }

    bool found = false;
    std::string fwd_module, fwd_func;
    bool is_forward = false;
    auto curr = module_list_next(module_list);
    while (curr != nullptr) {
        std::string path = std::string(module_entry_get_dllpath(curr));
        std::transform(path.begin(), path.end(), path.begin(), ::tolower);

        if (!found && path.find(module_substr) != std::string::npos) {
            uint64_t base = module_entry_get_base_address(curr);
            auto in_memory_pe = init_mem_pe(module_list_get_osi(module_list), base, false);

            if (in_memory_pe && parse_exports(in_memory_pe)) {
                size_t len = MAX_FUNCTION_PROTOTYPE_SIZE;
                char fn_name[MAX_FUNCTION_PROTOTYPE_SIZE];
                auto total = mem_pe_export_table_get_numberoffunctions(in_memory_pe);

                for (uint32_t i = 0; i < total; i++) {
                    memset(fn_name, '\0', len);
                    if (mem_pe_export_table_get_name_by_table_idx(in_memory_pe, fn_name, &len, i) &&
                        strcmp(fn_name, func_name) == 0) {
                        auto rva = mem_pe_export_table_get_rva_by_table_idx(in_memory_pe, i);
                        target_ulong candidate = base + rva;

                        if (try_read_forwarder(env, candidate, &fwd_module, &fwd_func)) {
                            is_forward = true;
                        } else {
                            *out_addr = candidate;
                        }
                        found = true;
                        break;
                    }
                }
            }
            free_mem_pe(in_memory_pe);
        }

        free_module_entry(curr);
        curr = module_list_next(module_list);
    }
    free_module_list(module_list);

    if (found && is_forward) {
        std::transform(fwd_module.begin(), fwd_module.end(), fwd_module.begin(), ::tolower);
        if (fwd_module.find(".dll") == std::string::npos) {
            fwd_module += ".dll";
        }
        printf("[RESOLVE] %s is a forwarder -> %s!%s\n", func_name, fwd_module.c_str(),
               fwd_func.c_str());
        return find_export_address(env, fwd_module.c_str(), fwd_func.c_str(), out_addr, depth + 1);
    }

    return found;
}

static std::unordered_set<target_ulong> g_report_event_hooked_asids;

bool register_hook(CPUState* env, target_ulong oldval, target_ulong newval) {
    if (!g_initialized) {
        if (!initialize_globals(env)) {
            return false;
        }
    }

    target_ulong asid = panda_current_asid(env);
    if (g_report_event_hooked_asids.count(asid)) {
        return false;
    }

    target_ulong address = 0;
    if (!find_export_address(env, "advapi32.dll", "ReportEventA", &address)) {
        return false;
    }

    struct symbol sym = {0};
    sym.address = address;
    strncpy(sym.name, "ReportEventA", sizeof(sym.name) - 1);
    strncpy(sym.section, "advapi32.dll", sizeof(sym.section) - 1);

    struct hook h = {0};
    h.addr = address;
    h.asid = asid;
    h.type = PANDA_CB_BEFORE_BLOCK_EXEC;
    h.cb.start_block_exec = report_event_hook;
    h.km = MODE_ANY;
    h.enabled = true;
    h.sym = sym;
    h.context = NULL;
    __add_hook(&h);

    g_report_event_hooked_asids.insert(asid);
    return false;
}

// NtMapViewOfSection is the syscall the Windows loader uses to map any PE
// image -- including a DLL -- into a process's address space. Its return
// guarantees the mapping is complete, so retrying hook installation here
// closes the race where advapi32.dll gets mapped and ReportEventA gets
// called before the next PANDA_CB_ASID_CHANGED ever fires for this asid.
// This fires on every section mapped in every process (not just
// advapi32.dll), so until this asid resolves it costs a full module-list
// walk per mapped section rather than per context switch -- more work per
// event, but closes a gap the asid_changed-only approach can permanently miss.
void on_dll_mapped_hook(CPUState* env, target_ulong pc, target_ulong SectionHandle, target_ulong ProcessHandle,
        target_ulong BaseAddress, target_ulong ZeroBits, target_ulong CommitSize, target_ulong SectionOffset,
        target_ulong ViewSize, uint32_t InheritDisposition, uint32_t AllocationType, uint32_t Win32Protect) {
    register_hook(env, 0, 0);
}

bool init_hooks_api() {
    void* hooks = panda_get_plugin_by_name("hooks");
    if (hooks == NULL){
        panda_require("hooks");
        hooks = panda_get_plugin_by_name("hooks");
    }
    if (hooks != NULL){
        __enable_hooking = (__enable_hooking_t) dlsym(hooks, "enable_hooking");
        __add_hook = (__add_hook_t) dlsym(hooks, "add_hook");
        if (__enable_hooking == NULL || __add_hook == NULL) {
            return false;
        }
    } else {
        return false;
    }
    return true;
}

void register_panda_callbacks(void* self) {
    panda_cb pcb;

    pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(initialize_globals));
    panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    // ReportEventA's address is per-process (module base is ASLR'd), so it
    // must be re-resolved whenever we land on a new process rather than once
    // at load time -- retried on every asid change until advapi32.dll is
    // actually mapped and the export is found.
    pcb.asid_changed = register_hook;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    // Closes the install-before-call race: catches the moment advapi32.dll
    // (or any DLL) gets mapped into a process, instead of waiting for the
    // next asid_changed.
    PPP_REG_CB("syscalls2", on_NtMapViewOfSection_return, on_dll_mapped_hook);
}

bool init_plugin(void* self)
{
    // Read arguments
    if (!panda_os_name) {
        fprintf(stderr, "[%s] The -os <profile> flag is required\n", __FILE__);
        return false;
    }

    // make sure we are on Windows
    if (panda_os_familyno != OS_WINDOWS) {
        fprintf(stderr, "[%s] Currently, only Windows is supported.\n", __FILE__);
        return false;
    }
    
    panda_require("syscalls2");
    panda_enable_precise_pc();

    assert(init_hooks_api());
    __enable_hooking();

    register_panda_callbacks(self);

    return true;
}

void uninit_plugin(void* self) {
    write_report_events_json(REPORT_EVENTS_JSON_PATH);
}
