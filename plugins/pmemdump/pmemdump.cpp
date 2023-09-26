/*
 * Originally based on the PANDA memstrings plugin
 */

// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include <string>

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void*);
void uninit_plugin(void*);
void before_block_exec(CPUState* env, TranslationBlock* tb);
}

static bool did_memdump;
static std::string filename;
static uint64_t target_recording_index;

void before_block_exec(CPUState* env, TranslationBlock* tb)
{
    auto rrindex = rr_get_guest_instr_count();
    if ((rrindex >= target_recording_index) && !did_memdump) {
        did_memdump = true;

        FILE* fp = fopen(filename.c_str(), "wb");
        if (!fp) {
            fprintf(stderr, "[%s] Could not open file %s for writing\n", __FILE__,
                    filename.c_str());
            return;
        }
        fprintf(stdout, "Saving memory at index=%lx to %s.\n", rrindex, filename.c_str());
        panda_memsavep(fp);
    }
    return;
}

bool init_plugin(void* self)
{
    panda_cb pcb = {.before_block_exec = before_block_exec};
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list* args = panda_get_args("pmemdump");
    filename = std::string(panda_parse_string(args, "file", "pmemdump.raw"));
    target_recording_index = panda_parse_uint64(args, "recording_index", 0);
    did_memdump = false;

    return true;
}

void uninit_plugin(void* self)
{
    if (!did_memdump) {
        fprintf(stderr, "[%s] plugin never triggered!\n", __FILE__);
    }
}
