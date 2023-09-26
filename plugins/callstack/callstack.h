#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

#include "apicall_tracer/trace_engine/current_process_osi.h"
#include "panda/plugin.h"
#include "panda/common.h"
#include "prog_point.h"

typedef void (*on_call_t)(CPUState* env, target_ulong func);
typedef void (*on_ret_t)(CPUState* env, target_ulong func);

typedef void (*callback_function_pointer)(CPUState* env, target_ulong);

int register_callstack_callback(const std::string callback_type,
                                callback_function_pointer new_pointer);
bool init_callstack_plugin(void* self,
                           CurrentProcessOSI* call_tracer_current_process_osi);

#ifdef __cplusplus
extern "C" {
#endif

void get_prog_point(CPUState* env, prog_point* p);
int get_callers(target_ulong callers[], int n, CPUState* env);

#ifdef __cplusplus
}
#endif

#endif
