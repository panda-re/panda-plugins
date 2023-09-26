/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include "ipanda/panda_x86.h"

#include "apicall_tracer/apicall_tracer.h"
#include "apicall_tracer/reporting/reporting.h"
#include "apicall_tracer/trace_engine/current_process_osi.h"
#include "apicall_tracer/trace_engine/trace_engine.h"
#include "typesignature/osi_syscalls.h"

// Callstack_instr includes
#include "callstack/callstack.h"
#include "callstack/prog_point.h"

#include "ipanda/ipanda.h"
#include "ipanda/manager.h"

#include "offset/i_t.h"
#include "osi/windows/manager.h"
#include "osi/windows/pe.h"
#include "osi/windows/wintrospection.h"

// Data Struct Imports
#include "typesignature/tuple_hash.h"
#include <algorithm>
#include <exception>
#include <unordered_map>

// BBStats like Process
#include "process/block.h"
#include "process/common.h"
#include "process/image.h"
#include "process/process.h"
#include "process/range.h"

// Trace Filtering
#include "apicall_tracer/trace_filter.h"

extern "C" {

#define __STDC_FORMAT_MACROS
bool init_plugin(void*);
void uninit_plugin(void*);
}

typedef std::tuple<target_ulong, target_ulong, target_ulong> function_addr_t;
typedef std::tuple<target_ulong, target_ulong, target_ulong> call_invocation_t;

const size_t MAX_FUNCTION_PROTOTYPE_SIZE = 512;

std::shared_ptr<Windows7IntrospectionManager> g_os_manager;
static struct WindowsKernelOSI* g_kernel_osi = nullptr;

int call_total = 0;
int call_instrumented = 0;
int ret_total = 0;
int ret_instrumented = 0;
int target_hits = 0;
int target_misses = 0;
int caller_hits = 0;
int caller_misses = 0;

// Internal data structure for managing callback managers
auto g_syscall_managers =
    std::unique_ptr<std::vector<SyscallManager*>>(new std::vector<SyscallManager*>());

// book keeping
std::map<std::string, std::map<uint64_t, function_export>> g_symbol_map;
std::unordered_map<std::string, std::shared_ptr<Process>> g_process_map;
std::shared_ptr<TraceFilter> g_tracefilter;

// introspection into current process
extern CurrentProcessOSI* g_current_osi;
std::shared_ptr<Process> g_current_process;
uint64_t g_previous_asid;

// record
std::shared_ptr<OsiSyscallInterface> g_syscalls_osi;
std::shared_ptr<RecordingContext> g_reporter;

// caches:
//     <asid, caller, callee> -> decision
std::unordered_map<call_invocation_t, bool> g_interesting_call_cache;
//     <asid, pid, address> -> unique ID
std::unordered_map<function_addr_t, struct call_id> g_function_id_cache;

/**
 * Public API for adding system call managers
 * Client is responsible for freeing manager at uninit
 */
void add_syscall_manager(SyscallManager* manager)
{
    g_syscall_managers->push_back(manager);
}

void update_current_process(CPUState* env)
{
    if (panda_current_asid(env) != g_previous_asid) {

        uint64_t addr = kosi_get_current_process_address(g_kernel_osi);
        if (addr == 0) {
            return;
        }

        auto manager = WindowsProcessManager();
        if (!manager.initialize(g_kernel_osi, addr)) {
            fprintf(stderr, "[%s] failed to switch to current process\n", __FILE__);
            return;
        }

        auto curr_asid = manager.get_process_object()->vmem->get_asid();
        if (curr_asid != g_previous_asid) {
            g_previous_asid = curr_asid;

            osi::i_t eprocess = manager.get_process();
            std::shared_ptr<Process> p =
                std::make_shared<Process>(eprocess, std::shared_ptr<guid_set>(nullptr));

            auto r = g_process_map.insert(std::make_pair(p->key(), p));
            std::unordered_map<std::string, std::shared_ptr<Process>>::iterator it =
                r.first;
            if (r.second) {
                p->walk_images(g_kernel_osi, env);
            } else {
                p = (*it).second;
            }

            g_current_process = p;
        }
    }
}

bool windows_interesting_call_check(CPUState* env, target_ulong func, uint64_t tid)
{
    auto pid = g_current_process->get_pid();
    auto asid = g_current_process->get_asid();

    if (!g_tracefilter->checkThread(pid, tid, asid)) {
        return false;
    }

    // grab the target module
    std::shared_ptr<Image> call_target_image =
        g_current_process->get_image(func, g_kernel_osi, env);

    // we are never interested if the target is unknown
    if (call_target_image == nullptr) {
        target_misses++;
        return false;
    }
    target_hits++;

    target_ulong caller;
    get_callers(&caller, 1, env);
    if (caller == 0) {
        // caller is unknown but we do have a target
        return true;
    }

    // Check a cached decision based on caller and function
    auto search = g_interesting_call_cache.find(std::make_tuple(asid, caller, func));
    if (search != g_interesting_call_cache.end()) {
        return search->second;
    }

    // now find the caller module
    std::shared_ptr<Image> caller_image =
        g_current_process->get_image(caller, g_kernel_osi, env);

    if (caller_image == nullptr) {
        // caller is unknown but we do have a target
        caller_misses++;
        return true;
    }
    caller_hits++;

    // only cache from here down, since this is a decision with all info
    bool decision;
    if (!g_tracefilter->checkModule(caller_image)) {
        // the module is in the module blacklist
        decision = false;
    } else {
        // are we crossing module boundaries
        decision =
            caller_image->get_base_address() != call_target_image->get_base_address();
    }

    g_interesting_call_cache[std::make_tuple(asid, caller, func)] = decision;

    return decision;
}

struct call_id get_call_unique_id(CPUState* env, target_ulong func, uint64_t tid)
{
    auto key = std::make_tuple(g_current_process->get_asid(),
                               g_current_process->get_pid(), func);

    auto search = g_function_id_cache.find(key);
    if (search != g_function_id_cache.end()) {
        return search->second;
    }

    std::shared_ptr<Image> mod = g_current_process->get_image(func, g_kernel_osi, env);

    // normalize path as windows is case insensitive
    auto target_path = mod->get_full_path();

    // fill in the call_id with default values so we can return on error
    struct call_id identifier;
    identifier.unique_id = 0;
    identifier.target_module = target_path;
    identifier.target_function = std::string("unknown");
    identifier.caller = tid;

    // transform the module name to the form its in in our prototype database
    auto target_name = mod->get_name();
    std::transform(target_name.begin(), target_name.end(), target_name.begin(),
                   ::toupper);
    target_name = target_name.substr(0, target_name.find("."));

    target_ulong target_rva = func - mod->get_base_address();

    // destination buffer that we will fill with a name we can use
    // to look up the prototype in the database
    char call_search_name[MAX_FUNCTION_PROTOTYPE_SIZE];

    // look up the function name in our symbol map
    bool lookup_success = false;
    auto search_path = g_symbol_map.find(target_path);

    if (search_path != g_symbol_map.end()) {
        auto search_rva = search_path->second.find(target_rva);

        if (search_rva != search_path->second.end()) {
            lookup_success = true;
            auto function = search_rva->second;

            if (function.name.empty()) {
                // there was no name for this function, use ordinal
                if (snprintf(call_search_name, MAX_FUNCTION_PROTOTYPE_SIZE, "%u__%s",
                             function.ordinal, target_name.c_str()) < 0) {
                    lookup_success = false;
                }
            }

            else {
                if (snprintf(call_search_name, MAX_FUNCTION_PROTOTYPE_SIZE, "%s__%s",
                             function.name.c_str(), target_name.c_str()) < 0) {
                    lookup_success = false;
                }
                identifier.target_function = function.name;
            }
        }
    }

    if (!lookup_success) {
        if (snprintf(call_search_name, MAX_FUNCTION_PROTOTYPE_SIZE, "%lx__%s",
                     (uint64_t)target_rva, target_name.c_str()) < 0) {
            return identifier;
        }
    }

    SyscallID cid = 0;
    if (!(g_syscalls_osi->lookup_syscall_id_by_name((const char*)call_search_name,
                                                    cid))) {
        g_reporter->reregister_syscalls(g_syscalls_osi.get());
    }

    identifier.unique_id = cid;

    if (lookup_success) {
        g_function_id_cache[key] = identifier;
    }

    return identifier;
}

void return_insn_callback(CPUState* env, target_ulong func)
{
    ret_total++;

    // we aren't interested if this call has been in the kernel
    if (panda_in_kernel(env)) {
        return;
    }

    update_current_process(env);
    auto tid = kosi_get_current_tid(g_kernel_osi);

    // this should filter us down to only processes we are interested
    // in and make sure we are crossing moudle boundaries
    if (windows_interesting_call_check(env, func, tid)) {
        ret_instrumented++;

        for (auto& manager : *g_syscall_managers) {
            manager->handle_potential_syscall_exit(env, func);
        }
    }
}

void call_insn_callback(CPUState* env, target_ulong func)
{
    call_total++;

    // we don't care about calls happening within the kernel
    if (panda_in_kernel(env)) {
        return;
    }

    update_current_process(env);
    auto tid = kosi_get_current_tid(g_kernel_osi);

    // this should filter us down to only processes we are interested
    // in and make sure we are crossing moudle boundaries
    if (windows_interesting_call_check(env, func, tid)) {
        call_instrumented++;

        auto call_id = get_call_unique_id(env, func, tid);
        for (auto& manager : *g_syscall_managers) {
            manager->handle_sysenter(env, func, call_id);
        }
    }
}

bool update_symbols(CPUState* env, target_ulong oldval, target_ulong newval)
{
    // create a list of modules using the current process
    auto process = kosi_get_current_process(g_kernel_osi);
    auto module_list = get_module_list(g_kernel_osi, process_get_eprocess(process),
                                       process_is_wow64(process));
    free_process(process);

    if (module_list == nullptr) {
        return 0;
    }

    // iterate over the modules
    auto curr = module_list_next(module_list);
    while (curr != nullptr) {
        // get this module's path -- lower to normalize as Windows
        // is case insensitive
        std::string path = std::string(module_entry_get_dllpath(curr));
        std::transform(path.begin(), path.end(), path.begin(), ::tolower);

        // if this module has not been parsed before, get the mapped image
        auto match = g_symbol_map.find(path);
        if (match == g_symbol_map.end()) {
            uint64_t base = module_entry_get_base_address(curr);

            auto in_memory_pe =
                init_mem_pe(module_list_get_osi(module_list), base, false);

            if (!in_memory_pe || !parse_exports(in_memory_pe)) {
                free_mem_pe(in_memory_pe);

                free_module_entry(curr);
                curr = module_list_next(module_list);

                continue;
            }

            // for each export, get its rva and function name
            size_t len = MAX_FUNCTION_PROTOTYPE_SIZE;
            char fn_name[MAX_FUNCTION_PROTOTYPE_SIZE];

            auto total = mem_pe_export_table_get_numberoffunctions(in_memory_pe);
            for (uint32_t i = 0; i < total; i++) {
                auto rva = mem_pe_export_table_get_rva_by_table_idx(in_memory_pe, i);

                memset(fn_name, '\0', len);
                if (mem_pe_export_table_get_name_by_table_idx(in_memory_pe, fn_name, &len,
                                                              i)) {
                    struct function_export function;
                    function.ordinal = i + mem_pe_export_table_get_base(in_memory_pe);
                    function.name = std::string(fn_name);
                    g_symbol_map[path][rva] = function;
                }
            }
            free_mem_pe(in_memory_pe);
        }

        // iterate
        free_module_entry(curr);
        curr = module_list_next(module_list);
    }
    free_module_list(module_list);

    return 0;
}

bool init_plugin(void* self)
{
#if defined(TARGET_I386)
    fprintf(stdout, "Initializing plugin apicall_tracer\n");

    // we need a profile
    const char* profile = panda_os_name;
    if (!profile) {
        fprintf(stderr,
                "[%s] Could not find os name. Please re-run with -os <profile> flag\n",
                __FILE__);
        return false;
    }

    // Configure API Call Trace Filter
    // Check if a trace filter file has been specified. If not, all calls will be traced
    panda_arg_list* filter_args = panda_get_args("trace_filter");
    const char* filter_file = strdup(panda_parse_string(filter_args, "file", ""));

    if (filter_file[0] == '\0') {
        g_tracefilter.reset(new TraceFilter());
    } else {
        g_tracefilter.reset(new TraceFilter(filter_file));
    }

    panda_free_args(filter_args);

    // Configure output sqlite database
    panda_arg_list* tracer_args = panda_get_args("apicall_tracer");

    const char* database_path =
        strdup(panda_parse_string(tracer_args, "output", "results"));
    fprintf(stdout, "Writing analysis results to %s\n", database_path);

    panda_free_args(tracer_args);

    std::shared_ptr<IntroPANDAManager> os_manager;

    if (!init_ipanda(self, os_manager)) {
        fprintf(stderr, "Could not initialize the introspection library.\n");
        return false;
    }

    // temporary -- forcing to be windows specific so i don't have to edit any more code
    // in this plugin
    g_os_manager = std::dynamic_pointer_cast<Windows7IntrospectionManager>(os_manager);
    g_kernel_osi = g_os_manager->get_kosi();

    g_current_process = std::make_shared<Process>();
    g_previous_asid = 0;

    g_syscalls_osi.reset(new OsiSyscallInterface(profile, g_os_manager, "calls.db"));
    if (!g_syscalls_osi) {
        fprintf(stderr, "[%s] Failed to find a syscall profile for %s\n", __FILE__,
                profile);
        return false;
    }

    g_reporter = create_reporter_ctx(database_path, g_syscalls_osi.get());
    if (!g_reporter || !g_reporter->is_valid()) {
        fprintf(stderr, "[%s] Failed to create a recording context\n", __FILE__);
        return false;
    }

    if (!init_trace_engine(profile, g_syscalls_osi, add_syscall_manager, g_reporter,
                           g_kernel_osi)) {
        fprintf(stderr, "[%s] Failed to initialize trace engine!\n", __FILE__);
        return false;
    }

    if (g_current_osi == nullptr) {
        fprintf(stderr, "[%s] The trace engine did not update introspection structure\n",
                __FILE__);
        return false;
    }

    // Call Backs
    panda_cb pcb;
    pcb.asid_changed = update_symbols;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    init_callstack_plugin(self, g_current_osi);
    register_callstack_callback("on_call", call_insn_callback);
    register_callstack_callback("on_ret", return_insn_callback);
#else
    fprintf(stderr, "[%s] This platform is not supported\n", __FILE__);
    return false;
#endif
    fprintf(stdout, "apicall_tracer initialized\n");
    return true;
}

void uninit_plugin(void* self)
{
    // cleanup
    uninit_trace_engine();
    g_tracefilter.reset();

    fprintf(stdout, "Call Stats:\n");
    fprintf(stdout, "\tCalls: Instrumented / Found: %d / %d\n", call_instrumented,
            call_total);
    fprintf(stdout, "\tReturns: Instrumented / Found: %d / %d\n", ret_instrumented,
            ret_total);
    fprintf(stdout, "Module Stats:\n");
    fprintf(stdout, "\tCall Targets: %d Hits and %d Misses\n", target_hits,
            target_misses);
    fprintf(stdout, "\tCallers: %d Hits and %d Misses\n", caller_hits, caller_misses);
}
