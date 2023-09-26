#ifndef _SQLITE_LOGGING_H
#define _SQLITE_LOGGING_H

#include <iostream>
#include <vector>

#include <cstring>
#include <errno.h>
#include <sqlite3.h>
#include <unistd.h>

sqlite3_int64 create_type(sqlite3* db, const char* name);

sqlite3_int64 create_iotype(sqlite3* db, const char* name);

sqlite3_int64 create_syscall(sqlite3* db, int64_t syscall_id, const char* name,
                             int nargs);

sqlite3_int64 create_syscall_argument(sqlite3* db, int64_t position, int64_t type_id,
                                      int64_t io_type_id, int64_t syscall_id);

sqlite3_int64 create_syscall_invocation(sqlite3* db, sqlite3_stmt* si_stmt, int64_t pid,
                                        int64_t asid, int64_t tid, bool is_entry,
                                        int64_t return_val, int64_t recording_index,
                                        sqlite3_int64 syscall_id, int64_t guid);

sqlite3_int64 create_argument(sqlite3* db, sqlite3_stmt* arg_stmt, int64_t type_id,
                              int64_t io_type_id, int64_t arg_value, int position,
                              int64_t syscall_invocation_id, const char* description);

sqlite3* create_database(const char* fpath);

sqlite3_stmt* create_invocation_stmt(sqlite3* db);

sqlite3_stmt* create_argument_stmt(sqlite3* db);

void finalize_statement(sqlite3_stmt*);
void close_database(sqlite3* db);

#endif
