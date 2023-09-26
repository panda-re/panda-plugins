#ifndef _TRACE_ENGINE_RECORDER_H
#define _TRACE_ENGINE_RECORDER_H

#include <functional>
#include <stdio.h>

#include <map>

#include "apicall_tracer/reporting/sqlite_model.h"
#include "typesignature/osi_syscalls.h"

class RecordingContext
{
public:
    RecordingContext() {}
    RecordingContext(const RecordingContext& other) = delete;
    RecordingContext& operator=(const RecordingContext& other) = delete;

    virtual ~RecordingContext(){};
    virtual bool is_valid() const = 0;
    virtual int64_t get_guid() = 0;
    virtual bool reregister_syscalls(OsiSyscallInterface* osi) = 0;
};

std::shared_ptr<RecordingContext> create_reporter_ctx(const char* fpath,
                                                      OsiSyscallInterface* osi);

int64_t record_syscall_invocation(RecordingContext*, int64_t pid, int64_t asid,
                                  int64_t tid, bool is_entry, int64_t return_val,
                                  int64_t recording_index, int64_t syscall_id,
                                  int64_t guid, const char* module);

int64_t record_syscall_argument(RecordingContext*, const char* type, ArgIoType io_type,
                                int64_t arg_value, int position,
                                int64_t syscall_invocation_id, const char* description);
// Forward decls
class RecordingContextImpl;
void register_types(RecordingContextImpl* rctx, OsiSyscallInterface* osi);
void register_io_types(RecordingContextImpl* rctx, OsiSyscallInterface* osi);
void register_syscalls(RecordingContextImpl* rctx, OsiSyscallInterface* osi);
void register_syscall_arguments(RecordingContextImpl* rctx, OsiSyscallInterface* osi);
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

    RecordingContextImpl(const char* fpath, OsiSyscallInterface* osi)
    {
        this->db = create_database(fpath);
        if (!this->db) {
            this->db = nullptr;
        }

        this->si_stmt = create_invocation_stmt(this->db);
        this->arg_stmt = create_argument_stmt(this->db);

        RecordingContextImpl* tp = this;
        register_types(tp, osi);
        register_io_types(tp, osi);
        register_syscalls(tp, osi);
        register_syscall_arguments((RecordingContextImpl*)tp, osi);

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

    bool reregister_syscalls(OsiSyscallInterface* osi) override
    {
        register_syscalls(this, osi);
        return true;
    }
};

#endif
