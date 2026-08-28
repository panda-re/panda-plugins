#define PLUGIN_MAIN
#define __STDC_FORMAT_MACROS

extern "C" {
    #include <dlfcn.h>
}

#include "panda/plugin.h"
#include "panda/common.h"
#include "ipanda/ipanda.h"
#include "ipanda/manager.h"
#include "osi/windows/manager.h"
#include "osi/windows/pe.h"
#include "osi/windows/wintrospection.h"

extern "C" {
    #include "panda/plugins/dynamic_symbols/dynamic_symbols_int_fns.h"
    #include "panda/plugins/hooks/hooks_int_fns.h"
}

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <unordered_set>

// This is a from-scratch replacement for the ReportEventA hooking in
// logging_events.cpp. Same underlying idea (resolve the export, hook it via
// the `hooks` plugin, read the args off the stack) but:
//   - covers both ReportEventA and ReportEventW
//   - follows forwarder exports (advapi32.dll re-exports a lot of its API
//     to sechost.dll/kernelbase.dll on modern Windows -- hooking the
//     forwarder's advertised RVA directly is a silent no-op, since callers
//     never actually execute there)
//   - resolves per-asid off PANDA_CB_ASID_CHANGED instead of once at load,
//     since module base addresses are per-process

extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
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

static bool init_hooks_api() {
    void* hooks = panda_get_plugin_by_name("hooks");
    if (hooks == nullptr) {
        panda_require("hooks");
        hooks = panda_get_plugin_by_name("hooks");
    }
    if (hooks == nullptr) {
        return false;
    }
    __add_hook = (__add_hook_t) dlsym(hooks, "add_hook");
    __enable_hooking = (__enable_hooking_t) dlsym(hooks, "enable_hooking");
    return __add_hook != nullptr && __enable_hooking != nullptr;
}

static bool initialize_globals(CPUState* env) {
    if (!init_ipanda(env, os_manager)) {
        fprintf(stderr, "[logging_events] Could not initialize introspection library\n");
        return false;
    }
    g_os_manager = std::dynamic_pointer_cast<Windows7IntrospectionManager>(os_manager);
    if (!g_os_manager) {
        fprintf(stderr, "[logging_events] Guest is not Windows; this plugin is Windows-only\n");
        return false;
    }
    g_kernel_osi = g_os_manager->get_kosi();
    g_initialized = true;
    return true;
}

// A PE export's table entry is normally an RVA to code. If the export is a
// forwarder instead (e.g. advapi32.dll!SomeApi -> sechost.dll!SomeApi), that
// RVA points at a null-terminated ASCII "ModuleName.FunctionName" string
// rather than an instruction stream. Detect that case so we can chase it to
// the real implementation instead of hooking dead address space.
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

// Windows-native PE export lookup: walks the current process's module list
// and finds func_name's address in the export table of whichever module's
// path contains module_substr. dynamic_symbols (this codebase's vendored
// copy) only understands Linux ELF .so exports, so it can't be used here --
// it would always return a zeroed symbol for a Windows DLL lookup.
static bool find_export_address(CPUState* env, const char* module_substr,
                                 const char* func_name, target_ulong* out_addr,
                                 int depth = 0) {
    if (depth > 4) {
        // A forwarder chain this deep means something is misparsed --
        // bail rather than loop.
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
    bool is_forward = false;
    std::string fwd_module, fwd_func;
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

// x64 calling convention: args 1-4 in RCX/RDX/R8/R9, args 5+ spill to the
// stack past the 0x20 shadow space. ReportEventA/W share this layout:
//   BOOL ReportEventX(HANDLE hEventLog, WORD wType, WORD wCategory,
//       DWORD dwEventID, PSID lpUserSid, WORD wNumStrings, DWORD dwDataSize,
//       LPCXSTR *lpStrings, LPVOID lpRawData)
// so at function entry (RSP == pointer to the return address), wNumStrings
// (arg6) is at rsp+0x30 and lpStrings (arg8) is at rsp+0x40.
static void read_report_event_strings(CPUState* env, const char* api_name, bool wide) {
    CPUX86State* regs = (CPUX86State*) env->env_ptr;
    target_ulong rsp = regs->regs[R_ESP];
    target_ulong num_strings_addr = rsp + 0x30;
    target_ulong lp_strings_addr = rsp + 0x40;

    const char* proc_name = "<unknown>";
    struct WindowsProcess* process = nullptr;
    if (g_initialized) {
        process = kosi_get_current_process(g_kernel_osi);
        if (process) {
            proc_name = process_get_shortname(process);
        }
    }

    uint8_t stack_dump[0x60] = {0};
    bool have_dump = panda_virtual_memory_read(env, rsp, stack_dump, sizeof(stack_dump)) == 0;

    uint16_t num_strings = 0;
    panda_virtual_memory_read(env, num_strings_addr, (uint8_t*)&num_strings, sizeof(num_strings));

    target_ulong lp_strings = 0;
    panda_virtual_memory_read(env, lp_strings_addr, (uint8_t*)&lp_strings, sizeof(lp_strings));

    printf("[%s] proc=%s asid=0x%lx rsp=0x%lx %u string(s) at 0x%lx\n", api_name, proc_name,
           (uint64_t)panda_current_asid(env), (uint64_t)rsp, num_strings, (uint64_t)lp_strings);

    if (have_dump) {
        printf("  stack [rsp, rsp+0x60):");
        for (size_t i = 0; i < sizeof(stack_dump); i++) {
            if (i % 8 == 0) printf("\n   +0x%02zx:", i);
            printf(" %02x", stack_dump[i]);
        }
        printf("\n");
    } else {
        printf("  stack [rsp, rsp+0x60): <unreadable>\n");
    }

    if (process) {
        free_process(process);
    }

    for (uint16_t i = 0; i < num_strings && lp_strings; i++) {
        target_ulong str_ptr = 0;
        target_ulong entry_addr = lp_strings + i * sizeof(target_ulong);
        if (panda_virtual_memory_read(env, entry_addr, (uint8_t*)&str_ptr, sizeof(str_ptr)) != 0 ||
            !str_ptr) {
            printf("  [%u] <unreadable pointer>\n", i);
            continue;
        }

        if (!wide) {
            uint8_t buf[512] = {0};
            if (panda_virtual_memory_read(env, str_ptr, buf, sizeof(buf) - 1) == 0) {
                printf("  [%u] %s\n", i, (char*)buf);
            } else {
                printf("  [%u] <unreadable string>\n", i);
            }
        } else {
            uint16_t wbuf[512] = {0};
            if (panda_virtual_memory_read(env, str_ptr, (uint8_t*)wbuf, sizeof(wbuf) - 2) == 0) {
                std::string decoded;
                for (size_t j = 0; j < 511 && wbuf[j]; j++) {
                    decoded += (wbuf[j] < 128) ? (char)wbuf[j] : '?';
                }
                printf("  [%u] %s\n", i, decoded.c_str());
            } else {
                printf("  [%u] <unreadable string>\n", i);
            }
        }
    }
}

void report_event_a_hook(CPUState* env, TranslationBlock* tb, struct hook* h) {
    read_report_event_strings(env, "ReportEventA", false);
}

void report_event_w_hook(CPUState* env, TranslationBlock* tb, struct hook* h) {
    read_report_event_strings(env, "ReportEventW", true);
}

typedef void (*report_event_cb_t)(CPUState*, TranslationBlock*, struct hook*);

static bool resolve_and_hook(CPUState* env, target_ulong asid, const char* func_name,
                              report_event_cb_t cb) {
    target_ulong address = 0;
    if (!find_export_address(env, "advapi32.dll", func_name, &address)) {
        return false;
    }

    const char* proc_name = "<unknown>";
    struct WindowsProcess* process = kosi_get_current_process(g_kernel_osi);
    if (process) {
        proc_name = process_get_shortname(process);
    }
    printf("[RESOLVE] %s resolved at 0x%lx (asid: 0x%lx, proc: %s)\n", func_name, (uint64_t)address,
           (uint64_t)asid, proc_name);
    if (process) {
        free_process(process);
    }

    struct hook h = {0};
    h.addr = address;
    h.asid = asid;
    h.type = PANDA_CB_BEFORE_BLOCK_EXEC;
    h.cb.before_block_exec = cb;
    h.km = MODE_ANY;
    h.enabled = true;
    strncpy(h.sym.name, func_name, sizeof(h.sym.name) - 1);
    strncpy(h.sym.section, "advapi32.dll", sizeof(h.sym.section) - 1);
    h.sym.address = address;
    __add_hook(&h);
    return true;
}

static std::unordered_set<target_ulong> g_hooked_asids;

bool register_report_event_hooks(CPUState* env, target_ulong oldval, target_ulong newval) {
    if (!g_initialized && !initialize_globals(env)) {
        return false;
    }

    target_ulong asid = panda_current_asid(env);
    if (g_hooked_asids.count(asid)) {
        return false;
    }

    // advapi32.dll might not be mapped into this process yet -- if neither
    // export resolves, leave this asid out of g_hooked_asids so we retry on
    // the next switch back into it.
    bool found_a = resolve_and_hook(env, asid, "ReportEventA", report_event_a_hook);
    bool found_w = resolve_and_hook(env, asid, "ReportEventW", report_event_w_hook);
    if (found_a || found_w) {
        g_hooked_asids.insert(asid);
    }

    return false;
}

bool init_plugin(void* self) {
    panda_require("hooks");
    if (!init_hooks_api()) {
        fprintf(stderr, "[logging_events_new] Failed to resolve hooks plugin API\n");
        return false;
    }

    panda_cb pcb;
    pcb.asid_changed = register_report_event_hooks;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);
    pcb.after_loadvm = (reinterpret_cast<void (*)(CPUState*)>(initialize_globals));
    panda_register_callback(self, PANDA_CB_AFTER_LOADVM, pcb);

    __enable_hooking();
    return true;
}

void uninit_plugin(void* self) {}
