#include <functional>
#include <stdio.h>

#include <set>
#include "panda/plugin.h"
#include "typesignature/syscall_database.h"

#include "syscall_tracer/reporting/reporting.h"

// Forward decls
class RecordingContextImpl;
void register_syscalls(RecordingContextImpl* rctx);
void register_syscall_arguments(RecordingContextImpl* rctx);

class RecordingContextImpl : public RecordingContext
{
private:
    RecordingContextImpl();
    int64_t invocation_guid;

public:
    FILE* logfile;
    std::set<std::string> m_type_set;
    std::set<int64_t> m_sid_set;

    RecordingContextImpl(const RecordingContext& other) = delete;
    RecordingContextImpl& operator=(const RecordingContext& other) = delete;

    RecordingContextImpl(const char* fpath)
    {
        this->logfile = fopen(fpath, "w");
        if (!this->logfile) {
            this->logfile = nullptr;
        }

        RecordingContextImpl* tp = this;
        register_syscalls(tp);
        register_syscall_arguments(tp);

        // Guid to track new call invocations
        invocation_guid = 0;
    }

    ~RecordingContextImpl()
    {
        if (logfile) {
            fclose(logfile);
        }
    }

    bool is_valid() const override { return this->logfile != nullptr; }

    int64_t get_guid() override { return ++invocation_guid; }
};

// Another hack to avoid having carrying a global reference
// to the recording ctx in multiple translation units. Wraps
// a local lambda in register_syscallsthat captures rctx
std::function<void(int64_t, const char*, int)> g_reg_syscalls_cb;
void register_syscall_callback(int64_t sid, const char* name, int nargs)
{
    if (g_reg_syscalls_cb) {
        g_reg_syscalls_cb(sid, name, nargs);
    }
}

// Another hack to avoid having carrying a global reference
// to the recording ctx in multiple translation units. Wraps
// a local lambda in register_syscallsthat captures rctx
std::function<void(int64_t, const ArgSpec* const*, int)> g_reg_syscall_args_cb;
void register_syscall_arguments_callback(int64_t sid, const ArgSpec* const* args,
                                         int nargs)
{
    if (g_reg_syscall_args_cb) {
        g_reg_syscall_args_cb(sid, args, nargs);
    }
}

void register_syscalls(RecordingContextImpl* rctx)
{
    // Register all the system calls themselves
    g_reg_syscalls_cb = [rctx](int64_t sid, const char* name, int nargs) -> void {
        auto& smap = rctx->m_sid_set;
        if (smap.find(sid) != smap.end()) {
            return; // Already seen this syscall, skip
        }
        smap.insert(sid);

        fprintf(rctx->logfile,
                "{\"type\": \"syscall-definition\", \"sid\": %ld, \"name\": \"%s\", "
                "\"nargs\": %d}\n",
                sid, name, nargs);
    };
    SyscallDatabase::register_syscalls(register_syscall_callback);
    g_reg_syscalls_cb = nullptr;
}

void register_syscall_arguments(RecordingContextImpl* rctx)
{
    g_reg_syscall_args_cb = [rctx](int64_t sid, const ArgSpec* const* args,
                                   int nargs) -> void {
        for (int argpos = 0; argpos < nargs; ++argpos) {
            auto arg = args[argpos];

            fprintf(rctx->logfile,
                    "{\"type\": \"syscall-argument-definition\", \"sid\": %ld, "
                    "\"argpos\": %d, \"argtype\": \"%s\", \"iotype\": %d}\n",
                    sid, argpos, arg->type(), arg->io_type());
        }
    };
    SyscallDatabase::register_syscall_arguments(register_syscall_arguments_callback);
    g_reg_syscall_args_cb = nullptr;
}

int64_t record_syscall_invocation(RecordingContext* ctx, int64_t pid, int64_t asid,
                                  int64_t tid, bool is_entry, int64_t return_val,
                                  int64_t recording_index, int64_t syscall_id,
                                  int64_t guid)
{
    auto rctx = dynamic_cast<RecordingContextImpl*>(ctx);

    fprintf(rctx->logfile,
            "{\"type\": \"syscall\", \"pid\": %ld, \"tid\": %ld, \"asid\": %ld, "
            "\"entry\": %d, \"return\": %ld, \"index\": %ld, \"sid\": %ld}\n",
            pid, tid, asid, is_entry, return_val, recording_index, syscall_id);

    return 0;
}

int64_t record_syscall_argument(RecordingContext* ctx, const char* type,
                                ArgIoType io_type, int64_t arg_value, int position,
                                int64_t syscall_invocation_id, const char* description)
{
    auto rctx = dynamic_cast<RecordingContextImpl*>(ctx);

    if (description == NULL) {
        description = "{}";
    }

    fprintf(rctx->logfile,
            "{\"type\": \"syscall-argument\", \"position\": %d, \"value\": %s}\n",
            position, description);

    return 0;
}

std::shared_ptr<RecordingContext> create_reporter_ctx(const char* fpath)
{
    return std::make_shared<RecordingContextImpl>(fpath);
}
