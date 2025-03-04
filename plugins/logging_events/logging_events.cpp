#include "logging_events.h"
#include <osi/osi_types.h>


extern "C" {
    bool init_plugin(void*);
    void uninit_plugin(void*);
    bool process_change(CPUState*, target_ulong, target_ulong);
}



bool init_plugin(void* self)
{
register_panda_callbacks(self);

const char* profile = panda_os_name;
if (!profile) {
    fprintf(stderr,
            "[%s] Could not find os name. Please re-run with -os <profile> flag\n",
            __FILE__);
    return false;
}

panda_require("osi");
assert(init_os_api());

panda_arg_list* args = panda_get_args("logging_events");
const char* log_path = strdup(panda_parse_string(args, "output", "logging.jsonl"));
fprintf(stdout, "Writing analysis results to %s\n", log_path);
g_log_path = (char*)log_path;
panda_free_args(args);

return true;
}

void uninit_plugin(void* self) {} 