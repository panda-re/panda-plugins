#include <functional>
#include <stdio.h>

#include <map>
#include "panda/plugin.h"
#include "typesignature/syscall_database.h"

#include "syscall_tracer/reporting/reporting.h"
#include "syscall_tracer/reporting/sqlite_model.h"

// Forward decls
class RecordingContextImpl;
void register_types(RecordingContextImpl* rctx);
void register_io_types(RecordingContextImpl* rctx);
void register_syscalls(RecordingContextImpl* rctx);
void register_syscall_arguments(RecordingContextImpl* rctx);
sqlite3_int64 lookup_io_type_dbid(RecordingContextImpl* rctx, ArgIoType io_type);
sqlite3_int64 lookup_type_dbid(RecordingContextImpl* rctx, const char* type);
sqlite3_int64 lookup_syscall_dbid(RecordingContextImpl* rctx, int64_t sid);

class RecordingContextImpl : public RecordingContext
{
private:
    RecordingContextImpl();
    int64_t invocation_guid;

public:
    sqlite3* db;
    sqlite3_stmt* si_stmt;
    sqlite3_stmt* arg_stmt;
    std::map<const std::string, sqlite3_int64> m_type_map;
    std::map<ArgIoType, sqlite3_int64> m_io_type_map;
    std::map<int64_t, sqlite3_int64> m_sid_map;

    RecordingContextImpl(const RecordingContext& other) = delete;
    RecordingContextImpl& operator=(const RecordingContext& other) = delete;

    RecordingContextImpl(const char* fpath)
    {
        this->db = create_database(fpath);
        if (!this->db) {
            this->db = nullptr;
        }

        this->si_stmt = create_invocation_stmt(this->db);
        this->arg_stmt = create_argument_stmt(this->db);

        RecordingContextImpl* tp = this;
        register_types(tp);
        register_io_types(tp);
        register_syscalls(tp);
        register_syscall_arguments(tp);

        // Guid to track new call invocations
        invocation_guid = 0;
    }

    ~RecordingContextImpl()
    {
        if (si_stmt) {
            finalize_statement(si_stmt);
            si_stmt = nullptr;
        }

        if (arg_stmt) {
            finalize_statement(arg_stmt);
            arg_stmt = nullptr;
        }

        if (db) {
            close_database(db);
        }
    }

    bool is_valid() const override
    {
        return this->db != nullptr && si_stmt != nullptr && arg_stmt != nullptr;
    }

    int64_t get_guid() override { return ++invocation_guid; }
};

// Hack to avoid having carrying a global reference
// to the recording ctx in multiple translation units. Wraps
// a local lambda in register_types that captures rctx
std::function<void(const char*)> g_reg_types_cb;
void register_type_callback(const char* name)
{
    if (g_reg_types_cb) {
        g_reg_types_cb(name);
    }
}

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

void register_types(RecordingContextImpl* rctx)
{
    // Register all the names of the types that show up as system call args
    g_reg_types_cb = [rctx](const char* name) -> void {
        auto& tmap = rctx->m_type_map;
        if (tmap.find(name) != tmap.end()) {
            return; // Already seen this type, skip
        }
        auto type_id = create_type(rctx->db, name);
        tmap[std::string(name)] = type_id;
    };
    SyscallDatabase::register_types(register_type_callback);
    g_reg_types_cb = nullptr;
}

void register_io_types(RecordingContextImpl* rctx)
{
    auto& imap = rctx->m_io_type_map;
    imap[IN] = create_iotype(rctx->db, arg_io_type_name(IN));
    imap[IN_OPT] = create_iotype(rctx->db, arg_io_type_name(IN_OPT));
    imap[INOUT] = create_iotype(rctx->db, arg_io_type_name(INOUT));
    imap[INOUT_OPT] = create_iotype(rctx->db, arg_io_type_name(INOUT_OPT));
    imap[OUT] = create_iotype(rctx->db, arg_io_type_name(OUT));
    imap[OUT_OPT] = create_iotype(rctx->db, arg_io_type_name(OUT_OPT));
    imap[UNKNOWN] = create_iotype(rctx->db, arg_io_type_name(UNKNOWN));
}

void register_syscalls(RecordingContextImpl* rctx)
{
    // Register all the system calls themselves
    g_reg_syscalls_cb = [rctx](int64_t sid, const char* name, int nargs) -> void {
        auto& smap = rctx->m_sid_map;
        if (smap.find(sid) != smap.end()) {
            return; // Already seen this syscall, skip
        }
        auto sid_dbid = create_syscall(rctx->db, sid, name, nargs);
        smap[sid] = sid_dbid;
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
            auto type_dbid = lookup_type_dbid(rctx, arg->type());
            auto io_type_dbid = lookup_io_type_dbid(rctx, arg->io_type());
            auto sid_dbid = lookup_syscall_dbid(rctx, sid);
            (void)create_syscall_argument(rctx->db, argpos, type_dbid, io_type_dbid,
                                          sid_dbid);
        }
    };
    SyscallDatabase::register_syscall_arguments(register_syscall_arguments_callback);
    g_reg_syscall_args_cb = nullptr;
}

sqlite3_int64 lookup_syscall_dbid(RecordingContextImpl* rctx, int64_t syscall_id)
{
    auto& smap = rctx->m_sid_map;
    auto candidate = smap.find(syscall_id);
    if (candidate != smap.end()) {
        return candidate->second;
    } else {
        // If we don't know this syscall, add a placeholder
        auto sid_dbid = create_syscall(rctx->db, syscall_id, "unknown", -1);
        smap[syscall_id] = sid_dbid;
        return sid_dbid;
    }
}

sqlite3_int64 lookup_type_dbid(RecordingContextImpl* rctx, const char* type)
{

    auto& tmap = rctx->m_type_map;
    auto candidate = tmap.find(type);
    if (candidate != tmap.end()) {
        return candidate->second;
    } else {
        // If we don't know this type, add it to the database
        auto type_dbid = create_type(rctx->db, type);
        tmap[type] = type_dbid;
        return type_dbid;
    }
}

sqlite3_int64 lookup_io_type_dbid(RecordingContextImpl* rctx, ArgIoType io_type)
{
    auto& imap = rctx->m_io_type_map;
    auto candidate = imap.find(io_type);
    if (candidate != imap.end()) {
        return candidate->second;
    } else {
        return lookup_io_type_dbid(rctx, UNKNOWN);
    }
}

int64_t record_syscall_invocation(RecordingContext* ctx, int64_t pid, int64_t asid,
                                  int64_t tid, bool is_entry, int64_t return_val,
                                  int64_t recording_index, int64_t syscall_id,
                                  int64_t guid)
{
    auto rctx = dynamic_cast<RecordingContextImpl*>(ctx);
    auto syscall_dbid = lookup_syscall_dbid(rctx, syscall_id);
    return create_syscall_invocation(rctx->db, rctx->si_stmt, pid, asid, tid, is_entry,
                                     return_val, recording_index, syscall_dbid, guid);
}

int64_t record_syscall_argument(RecordingContext* ctx, const char* type,
                                ArgIoType io_type, int64_t arg_value, int position,
                                int64_t syscall_invocation_id, const char* description)
{
    auto rctx = dynamic_cast<RecordingContextImpl*>(ctx);
    auto type_dbid = lookup_type_dbid(rctx, type);
    auto io_type_dbid = lookup_io_type_dbid(rctx, io_type);

    return create_argument(rctx->db, rctx->arg_stmt, type_dbid, io_type_dbid, arg_value,
                           position, syscall_invocation_id, description);
}

std::shared_ptr<RecordingContext> create_reporter_ctx(const char* fpath)
{
    return std::make_shared<RecordingContextImpl>(fpath);
}
