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
#define __STDC_FORMAT_MACROS

#include <distorm3/distorm.h>
namespace distorm
{
#include <distorm3/mnemonics.h>
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include "ipanda/panda_x86.h"
#include <algorithm>
#include <cstdlib>
#include <map>
#include <set>
#include <vector>

#include "callstack.h"
#include "prog_point.h"

#include "apicall_tracer/trace_filter.h"

extern "C" {

bool translate_callback(CPUState* env, target_ulong pc);
int exec_callback(CPUState* env, target_ulong pc);
void before_block_exec(CPUState* env, TranslationBlock* tb);
void after_block_exec(CPUState* env, TranslationBlock* tb, uint8_t exitCode);
void after_block_translate(CPUState* env, TranslationBlock* tb);

bool init_plugin(void*);
void uninit_plugin(void*);
}

enum instr_type {
    INSTR_UNKNOWN = 0,
    INSTR_CALL,
    INSTR_RET,
    INSTR_SYSCALL,
    INSTR_SYSRET,
    INSTR_SYSENTER,
    INSTR_SYSEXIT,
    INSTR_INT,
    INSTR_IRET,
};

struct stack_entry {
    uint64_t pc;
    instr_type kind;
};

#define MAX_STACK_DIFF 5000

// Trace filter to choose what pids to actually look at and instrument
auto g_tracefilter = std::shared_ptr<TraceFilter>();

CurrentProcessOSI* g_current_osi;

// Global switch that should be turned on and off during asid switch
bool g_enable_trace = true;
bool g_needs_update = true;

// Track the different stacks we have seen to handle multiple threads
// within a single process.
std::map<target_ulong, std::set<target_ulong>> stacks_seen;

// Listener Functions for callbacks provided by on_call and on_ret
std::vector<callback_function_pointer> on_call;
std::vector<callback_function_pointer> on_ret;

// This function execute callbacks with the appropriate vector of registered callbacks
void execute_callbacks(std::vector<callback_function_pointer>* callbacks, CPUState* env,
                       target_ulong parameter)
{

    for (std::vector<callback_function_pointer>::iterator it = callbacks->begin();
         it != callbacks->end(); ++it) {
        try {
            (*it)(env, parameter);
        } catch (...) {
            if (callbacks == (std::vector<callback_function_pointer>*)&on_call)
                fprintf(stderr, "[%s] Failed to execute callback registered to on_call\n",
                        __FILE__);
            else if (callbacks == (std::vector<callback_function_pointer>*)&on_ret)
                fprintf(stderr, "[%s] Failed to execute callback registered to on_ret\n",
                        __FILE__);
            else
                fprintf(
                    stderr,
                    "[%s] Failed to execute callback registered to unknown callback\n",
                    __FILE__);
        }
    }
}

int register_callstack_callback(const std::string callback_type,
                                callback_function_pointer new_pointer)
{
    if (new_pointer == NULL) {
        return -1;
    }

    if (callback_type == "on_call") {
        on_call.push_back(new_pointer);
        fprintf(stdout, "Registered on_call callback. # of callbacks is now %lu\n",
                (uint64_t)on_call.size());
    } else if (callback_type == "on_ret") {
        on_ret.push_back(new_pointer);
        fprintf(stdout, "Registered on_ret callback. # of callbacks is now %lu\n",
                (uint64_t)on_ret.size());
    } else {
        fprintf(stderr, "[%s] No matching function callbacks for %s\n", __FILE__,
                callback_type.c_str());
        return -1;
    }
    return 0;
}

// Use a typedef here so we can switch between the stack heuristic and
// the original code easily
#ifdef USE_STACK_HEURISTIC
typedef std::pair<target_ulong, target_ulong> stackid;
target_ulong cached_sp = 0;
target_ulong cached_asid = 0;
#else
typedef target_ulong stackid;
#endif

// stackid -> shadow stack
std::map<stackid, std::vector<stack_entry>> callstacks;
// stackid -> function entry points
std::map<stackid, std::vector<target_ulong>> function_stacks;
// EIP -> instr_type
std::map<target_ulong, instr_type> call_cache;
int last_ret_size = 0;

static inline bool in_kernelspace(CPUState* cs)
{
#if defined(TARGET_I386)
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
    return (env->hflags & HF_CPL_MASK == 0);
#endif
    abort();
}

#ifdef TARGET_ARM
// ARM: stolen from target-arm/helper.c
// static uint32_t arm_get_vaddr_table(CPUState *env, uint32_t address)
//{
//    uint32_t table;
//
//    if (address & env->cp15.c2_mask)
//        table = env->cp15.c2_base1 & 0xffffc000;
//    else
//        table = env->cp15.c2_base0 & env->cp15.c2_base_mask;
//
//    return table;
//}
#endif

// static inline target_ulong get_asid(CPUState *env, target_ulong addr) {
// #if defined(TARGET_I386)
//     return panda_get_register(env, PANDA_REG_CR3);
// #elif defined(TARGET_ARM)
//     //return arm_get_vaddr_table(env, addr);
// #else
//     abort();
//     return 0;
// #endif
// }
static inline target_ulong get_asid(CPUState* env, target_ulong addr)
{
    return panda_current_asid(env);
}

static inline target_ulong get_stack_pointer(CPUState* cs)
{
#if defined(TARGET_I386)
    X86CPU* cpu = X86_CPU(cs);
    CPUX86State* env = &cpu->env;
    return env->regs[R_ESP];
#elif defined(TARGET_ARM)
    // return env->regs[13];
#else
    abort() return 0;
#endif
}

static stackid get_stackid(CPUState* env, target_ulong addr)
{
#ifdef USE_STACK_HEURISTIC
    target_ulong asid;

    // Track all kernel-mode stacks together
    if (in_kernelspace(env))
        asid = 0;
    else
        asid = get_asid(env, addr);

    // Invalidate cached stack pointer on ASID change
    if (cached_asid == 0 || cached_asid != asid) {
        cached_sp = 0;
        cached_asid = asid;
    }

    target_ulong sp = get_stack_pointer(env);

    // We can short-circuit the search in most cases
    if (std::abs(sp - cached_sp) < MAX_STACK_DIFF) {
        return std::make_pair(asid, cached_sp);
    }

    auto& stackset = stacks_seen[asid];
    if (stackset.empty()) {
        stackset.insert(sp);
        cached_sp = sp;
        return std::make_pair(asid, sp);
    } else {
        // Find the closest stack pointer we've seen
        auto lb = std::lower_bound(stackset.begin(), stackset.end(), sp);
        target_ulong stack1 = *lb;
        lb--;
        target_ulong stack2 = *lb;
        target_ulong stack =
            (std::abs(stack1 - sp) < std::abs(stack2 - sp)) ? stack1 : stack2;
        int diff = std::abs(stack - sp);
        if (diff < MAX_STACK_DIFF) {
            return std::make_pair(asid, stack);
        } else {
            stackset.insert(sp);
            cached_sp = sp;
            return std::make_pair(asid, sp);
        }
    }
#else
    return get_asid(env, addr);
#endif
}

instr_type disas_block(CPUState* env, target_ulong pc, int size)
{
    unsigned char* buf = (unsigned char*)malloc(size);
    int err = panda_virtual_memory_rw(env, pc, buf, size, 0);
    if (err == -1)
        fprintf(stdout, "Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    _DInst dec[256];
    unsigned int dec_count = 0;
    _DecodeType dt = panda_is_lma_set(env) ? Decode64Bits : Decode32Bits;

    _CodeInfo ci;
    ci.code = buf;
    ci.codeLen = size;
    ci.codeOffset = pc;
    ci.dt = dt;
    ci.features = DF_NONE;

    distorm_decompose(&ci, dec, 256, &dec_count);
    for (int i = dec_count - 1; i >= 0; i--) {
        if (dec[i].flags == FLAG_NOT_DECODABLE) {
            continue;
        }

        if (META_GET_FC(dec[i].meta) == FC_CALL) {
            res = INSTR_CALL;
            goto done;
        } else if (META_GET_FC(dec[i].meta) == FC_RET) {
            // Ignore IRETs
            if (dec[i].opcode == distorm::I_IRET) {
                res = INSTR_UNKNOWN;
            } else {
                // For debugging only
                if (dec[i].ops[0].type == O_IMM)
                    last_ret_size = dec[i].imm.sdword;
                else
                    last_ret_size = 0;
                res = INSTR_RET;
            }
            goto done;
        } else if (META_GET_FC(dec[i].meta) == FC_SYS) {
            res = INSTR_UNKNOWN;
            goto done;
        } else {
            res = INSTR_UNKNOWN;
            goto done;
        }
    }
#elif defined(TARGET_ARM)
    abort();
#endif

done:
    free(buf);
    return res;
}

void update_filter(CPUState* env)
{
    // perform a quick check for tracing
    g_enable_trace = g_tracefilter->quickCheck(g_current_osi->current_pid(env),
                                               g_current_osi->current_asid(env));
    g_needs_update = false;
}

void after_block_translate(CPUState* env, TranslationBlock* tb)
{
    if (g_needs_update) {
        update_filter(env);
    }

    if (!g_enable_trace) {
        return;
    }

    auto pc = tb->pc;
    auto size = tb->size;
    call_cache[pc] = disas_block(env, pc, size);

    return;
}

void before_block_exec(CPUState* env, TranslationBlock* tb)
{
    if (g_needs_update) {
        update_filter(env);
    }

    if (!g_enable_trace) {
        return;
    }

    auto pc = tb->pc;
    std::vector<stack_entry>& v = callstacks[get_stackid(env, pc)];
    std::vector<target_ulong>& w = function_stacks[get_stackid(env, pc)];
    if (v.empty())
        return;

    for (int i = v.size() - 1; i > ((int)(v.size() - 10)) && i >= 0; i--) {
        if (pc == v[i].pc) {
            // fprintf(stdout, "Matched at depth %d\n", v.size()-i);
            v.erase(v.begin() + i, v.end());

            execute_callbacks(&on_ret, env, w[i]);
            w.erase(w.begin() + i, w.end());

            break;
        }
    }

    return;
}

void after_block_exec(CPUState* env, TranslationBlock* tb, uint8_t exitCode)
{
    if (g_needs_update) {
        update_filter(env);
    }

    if (!g_enable_trace) {
        return;
    }

    auto tb_pc = tb->pc;
    auto tb_size = tb->size;

    instr_type tb_type = call_cache[tb_pc];

    if (tb_type == INSTR_CALL) {
        stack_entry se = {tb_pc + tb_size, tb_type};
        callstacks[get_stackid(env, tb_pc)].push_back(se);

        // Also track the function that gets called
        uint64_t pc = panda_current_pc(env);
        // This retrieves the pc in an architecture-neutral way
        function_stacks[get_stackid(env, tb_pc)].push_back(pc);

        execute_callbacks(&on_call, env, pc);
    } else if (tb_type == INSTR_RET) {
        // fprintf(stdout, "Just executed a RET in TB " TARGET_FMT_lx "\n", tb_pc);
        // if (next) fprintf(stdout, "Next TB: " TARGET_FMT_lx "\n", next->pc);
    }

    return;
}

// Public interface implementation
int get_callers(target_ulong callers[], int n, CPUState* env)
{
    std::vector<stack_entry>& v =
        callstacks[get_stackid(env, rr_get_guest_instr_count())];
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        callers[i] = rit->pc;
    }
    return i;
}

int get_functions(target_ulong functions[], int n, CPUState* env)
{
    std::vector<target_ulong>& v =
        function_stacks[get_stackid(env, rr_get_guest_instr_count())];
    if (v.empty()) {
        return 0;
    }
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        functions[i] = *rit;
    }
    return i;
}

void get_prog_point(CPUState* env, prog_point* p)
{
    if (!p)
        return;

    // Get address space identifier
    target_ulong asid = get_asid(env, rr_get_guest_instr_count());
    // Lump all kernel-mode CR3s together

    if (!in_kernelspace(env))
        p->cr3 = asid;

    // Try to get the caller
    int n_callers = 0;
    n_callers = get_callers(&p->caller, 1, env);

    if (n_callers == 0) {
#ifdef TARGET_I386
        // fall back to EBP on x86
        int word_size = panda_is_lma_set(env) ? 8 : 4;
        X86CPU* cpu = X86_CPU(env);
        CPUX86State* cs = &cpu->env;
        panda_virtual_memory_rw(env, cs->regs[R_EBP] + word_size, (uint8_t*)&p->caller,
                                word_size, 0);
#endif
    }

    p->pc = rr_get_guest_instr_count();
}

bool context_switch(CPUState* env, target_ulong oldval, target_ulong newval)
{
    // in testing, it is very unclear when this callback occurs. sometimes
    // it happens after the context register has been updated, sometimes before
    // and sometimes the value of the context register doesn't match old or new
    // so we wait until the next basic block and do our work there
    g_needs_update = true;
    return 0;
}

void set_callstack_osi(CurrentProcessOSI* call_tracer_current_process_osi)
{
    g_current_osi = call_tracer_current_process_osi;
    g_needs_update = true;
}

bool init_callstack_plugin(void* self, CurrentProcessOSI* call_tracer_current_process_osi)
{
    fprintf(stdout, "Initializing plugin callstack_instr\n");
    panda_cb pcb;

    g_current_osi = call_tracer_current_process_osi;

    panda_arg_list* filter_args = panda_get_args("trace_filter");
    const char* filter_file = strdup(panda_parse_string(filter_args, "file", ""));
    if (filter_file[0] == '\0') {
        g_tracefilter.reset(new TraceFilter());
    } else {
        g_tracefilter.reset(new TraceFilter(filter_file));
    }
    panda_free_args(filter_args);

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.asid_changed = context_switch;
    panda_register_callback(self, PANDA_CB_ASID_CHANGED, pcb);

    return true;
}

void uninit_plugin(void* self) {}

bool init_callstack_plugin(void* self)
{
    fprintf(stdout, "Initializing plugin callstack_instr\n");
    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}
