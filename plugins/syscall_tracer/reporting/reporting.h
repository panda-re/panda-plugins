#ifndef _TRACE_ENGINE_RECORDER_H
#define _TRACE_ENGINE_RECORDER_H

#include "typesignature/arguments.h"

class RecordingContext
{
public:
    RecordingContext() {}
    RecordingContext(const RecordingContext& other) = delete;
    RecordingContext& operator=(const RecordingContext& other) = delete;

    virtual ~RecordingContext(){};
    virtual bool is_valid() const = 0;
    virtual int64_t get_guid() = 0;
};

std::shared_ptr<RecordingContext> create_reporter_ctx(const char* fpath);

int64_t record_syscall_invocation(RecordingContext*, int64_t pid, int64_t asid,
                                  int64_t tid, bool is_entry, int64_t return_val,
                                  int64_t recording_index, int64_t syscall_id,
                                  int64_t guid);

int64_t record_syscall_argument(RecordingContext*, const char* type, ArgIoType io_type,
                                int64_t arg_value, int position,
                                int64_t syscall_invocation_id, const char* description);

#endif
