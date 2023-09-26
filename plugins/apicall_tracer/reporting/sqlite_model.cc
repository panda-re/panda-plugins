#include <iostream>
#include <vector>

#include <cstring>
#include <errno.h>
#include <sqlite3.h>
#include <unistd.h>

#include "sqlite_model.h"

const char* CREATE_TYPE_TABLE_SQL = "CREATE TABLE type ("
                                    "   id INTEGER PRIMARY KEY ASC,  "
                                    "   name TEXT);";

const char* CREATE_IOTYPE_TABLE_SQL = "CREATE TABLE io_type ( "
                                      "    id INTEGER PRIMARY KEY ASC, "
                                      "    name TEXT "
                                      ");";

const char* CREATE_SYSCALL_TABLE_SQL = "CREATE TABLE syscall ("
                                       "    id INTEGER PRIMARY KEY ASC,"
                                       "    syscall_id INTEGER,"
                                       "    name TEXT,"
                                       "    nargs INTEGER"
                                       ");";

const char* CREATE_SYSCALL_ARGUMENT_TABLE_SQL =
    "CREATE TABLE syscall_argument ("
    "    id INTEGER PRIMARY KEY ASC,"
    "    position INTEGER,"
    "    type_id INTEGER,"
    "    io_type_id INTEGER,"
    "    syscall_id INTEGER,"
    "    FOREIGN KEY (syscall_id) REFERENCES syscall(id),"
    "    FOREIGN KEY (type_id) REFERENCES type(id),"
    "    FOREIGN KEY (io_type_id) REFERENCES io_type(id)"
    ");";

const char* CREATE_SYSCALL_INVOCATION_TABLE_SQL =
    "CREATE TABLE syscall_invocation ("
    "    id INTEGER PRIMARY KEY ASC,"
    "    pid INTEGER,"
    "    asid INTEGER,"
    "    tid INTEGER,"
    "    is_entry BOOLEAN,"
    "    return_val INTEGER,"
    "    recording_index INTEGER,"
    "    syscall_id INTEGER,"
    "    guid INTEGER,"
    "    module TEXT,"
    "    FOREIGN KEY (syscall_id) REFERENCES Syscall(id)"
    ");";

const char* CREATE_ARGUMENT_TABLE_SQL =
    "CREATE TABLE argument ("
    "    id INTEGER PRIMARY KEY ASC,"
    "    type INTEGER,"
    "    io_type INTEGER,"
    "    arg_value INTEGER,"
    "    position INTEGER,"
    "    syscall_invocation_id INTEGER, "
    "    description TEXT,"
    "    FOREIGN KEY(type) REFERENCES Type(id),"
    "    FOREIGN KEY (io_type) REFERENCES IoType(id),"
    "    FOREIGN KEY (syscall_invocation_id) REFERENCES SyscallInvocation(id)"
    ");";

const char* INSERT_TYPE_NAME_SQL = "INSERT INTO type (name) VALUES (?1);";
const char* INSERT_IOTYPE_NAME_SQL = "INSERT INTO io_type (name) VALUES (?1);";
const char* INSERT_SYSCALL_SQL =
    "INSERT INTO syscall (syscall_id, name, nargs) VALUES (?1, ?2, ?3);";
const char* INSERT_SYSCALL_ARGUMENT_SQL =
    "INSERT INTO syscall_argument (position, type_id, io_type_id, syscall_id) "
    "VALUES (?1, ?2, ?3, ?4);";
const char* INSERT_SYSCALL_INVOCATION_SQL =
    "INSERT INTO syscall_invocation "
    "(pid, asid, tid, is_entry, return_val, recording_index, syscall_id, guid, module) "
    "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);";
const char* INSERT_ARGUMENT_SQL =
    "INSERT INTO argument"
    "(type, io_type, arg_value, position, syscall_invocation_id, description) "
    "VALUES (?1, ?2, ?3, ?4, ?5, ?6);";

const std::vector<const char*> table_stmts = {CREATE_TYPE_TABLE_SQL,
                                              CREATE_IOTYPE_TABLE_SQL,
                                              CREATE_SYSCALL_TABLE_SQL,
                                              CREATE_SYSCALL_ARGUMENT_TABLE_SQL,
                                              CREATE_SYSCALL_INVOCATION_TABLE_SQL,
                                              CREATE_ARGUMENT_TABLE_SQL};

// Allows sqlite to use async IO when writing to the database.
// This is less safe if the application crashes, but we discard
// the database in that case anyway. Reduces the time spent doing
// I/O by an order of magnitude (110s -> 7s) for a 30 second recording
const char* PRAGMA_SYNC_OFF_SQL = "PRAGMA synchronous = OFF;";

// Disables the journal, which improves performance at the cost
// of not being able to rollback transactions (which we do not
// do anyway)
const char* PRAGMA_JOURNAL_OFF_SQL = "PRAGMA journal_mode = OFF;";

const std::vector<const char*> pragma_stmts = {PRAGMA_SYNC_OFF_SQL,
                                               PRAGMA_JOURNAL_OFF_SQL};

const int MAX_RETRY = 10;

#define check_status(STATUS, TARGET_STATUS)                                              \
    {                                                                                    \
        int status_macro_var = (STATUS);                                                 \
        if (status_macro_var != (TARGET_STATUS)) {                                       \
            fprintf(stderr, "[E] %s:%d %s\n", __FILE__, __LINE__,                        \
                    sqlite3_errstr(status_macro_var));                                   \
            abort();                                                                     \
        }                                                                                \
    }

void call_with_retries(sqlite3_stmt* stmt, int target_status)
{
    int status = sqlite3_step(stmt);
    int attempts = 0;
    while ((status == SQLITE_ROW || status == SQLITE_BUSY) && (attempts++ < MAX_RETRY)) {
        status = sqlite3_step(stmt);
    }
    check_status(status, target_status);
}

sqlite3_int64 create_item_by_arg1_name(sqlite3* db, const char* sql, const char* name)
{
    sqlite3_stmt* stmt;
    // Create our SQL query and bind name to name
    check_status(sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr), SQLITE_OK);
    check_status(sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT), SQLITE_OK);

    // execute the query
    call_with_retries(stmt, SQLITE_DONE);

    // cleanup the prepared statement
    check_status(sqlite3_reset(stmt), SQLITE_OK);
    check_status(sqlite3_finalize(stmt), SQLITE_OK);

    return sqlite3_last_insert_rowid(db);
}

sqlite3_int64 create_type(sqlite3* db, const char* name)
{
    return create_item_by_arg1_name(db, INSERT_TYPE_NAME_SQL, name);
}

sqlite3_int64 create_iotype(sqlite3* db, const char* name)
{
    return create_item_by_arg1_name(db, INSERT_IOTYPE_NAME_SQL, name);
}

sqlite3_int64 create_syscall(sqlite3* db, int64_t syscall_id, const char* name, int nargs)
{
    sqlite3_stmt* stmt;
    // Create our SQL query and bind name to name. Doesn't get called enough to be
    // performance critical
    check_status(sqlite3_prepare_v2(db, INSERT_SYSCALL_SQL, -1, &stmt, nullptr),
                 SQLITE_OK);

    check_status(sqlite3_bind_int64(stmt, 1, syscall_id), SQLITE_OK);

    check_status(sqlite3_bind_text(stmt, 2, name, -1, SQLITE_TRANSIENT), SQLITE_OK);

    check_status(sqlite3_bind_int(stmt, 3, nargs), SQLITE_OK);

    // execute the query
    call_with_retries(stmt, SQLITE_DONE);

    // cleanup the prepared statement
    check_status(sqlite3_reset(stmt), SQLITE_OK);
    check_status(sqlite3_finalize(stmt), SQLITE_OK);

    return sqlite3_last_insert_rowid(db);
}

sqlite3_int64 create_syscall_argument(sqlite3* db, int64_t position, int64_t type_id,
                                      int64_t io_type_id, int64_t syscall_id)
{
    sqlite3_stmt* stmt;
    // Create our SQL query and bind name to name. Doesn't get called enough to be
    // performance critical
    check_status(sqlite3_prepare_v2(db, INSERT_SYSCALL_ARGUMENT_SQL, -1, &stmt, nullptr),
                 SQLITE_OK);

    check_status(sqlite3_bind_int64(stmt, 1, position), SQLITE_OK);
    check_status(sqlite3_bind_int64(stmt, 2, type_id), SQLITE_OK);
    check_status(sqlite3_bind_int64(stmt, 3, io_type_id), SQLITE_OK);
    check_status(sqlite3_bind_int64(stmt, 4, syscall_id), SQLITE_OK);

    // execute the query
    call_with_retries(stmt, SQLITE_DONE);

    // cleanup the prepared statement
    check_status(sqlite3_reset(stmt), SQLITE_OK);
    check_status(sqlite3_finalize(stmt), SQLITE_OK);

    return sqlite3_last_insert_rowid(db);
}

sqlite3_int64 create_syscall_invocation(sqlite3* db, sqlite3_stmt* si_stmt, int64_t pid,
                                        int64_t asid, int64_t tid, bool is_entry,
                                        int64_t return_val, int64_t recording_index,
                                        sqlite3_int64 syscall_id, int64_t guid,
                                        const char* module)
{
    // Clear out the old arguments
    check_status(sqlite3_clear_bindings(si_stmt), SQLITE_OK);

    // Bind arguments
    check_status(sqlite3_bind_int64(si_stmt, 1, pid), SQLITE_OK);

    check_status(sqlite3_bind_int64(si_stmt, 2, asid), SQLITE_OK);

    check_status(sqlite3_bind_int64(si_stmt, 3, tid), SQLITE_OK);

    check_status(sqlite3_bind_int(si_stmt, 4, is_entry), SQLITE_OK);

    if (!is_entry) {
        check_status(sqlite3_bind_int64(si_stmt, 5, return_val), SQLITE_OK);
    }

    check_status(sqlite3_bind_int64(si_stmt, 6, recording_index), SQLITE_OK);

    check_status(sqlite3_bind_int64(si_stmt, 7, syscall_id), SQLITE_OK);

    if (guid < 0) {
        check_status(sqlite3_bind_null(si_stmt, 8), SQLITE_OK);
    } else {
        check_status(sqlite3_bind_int64(si_stmt, 8, guid), SQLITE_OK);
    }

    check_status(sqlite3_bind_text(si_stmt, 9, module, -1, SQLITE_TRANSIENT), SQLITE_OK);

    // execute the query
    call_with_retries(si_stmt, SQLITE_DONE);

    // cleanup the prepared statement
    check_status(sqlite3_reset(si_stmt), SQLITE_OK);

    return sqlite3_last_insert_rowid(db);
}

sqlite3_int64 create_argument(sqlite3* db, sqlite3_stmt* arg_stmt, int64_t type,
                              int64_t io_type, int64_t arg_value, int position,
                              int64_t syscall_invocation_id, const char* description)
{
    // Clear out the old arguments
    check_status(sqlite3_clear_bindings(arg_stmt), SQLITE_OK);

    // Bind arguments
    check_status(sqlite3_bind_int64(arg_stmt, 1, type), SQLITE_OK);

    check_status(sqlite3_bind_int64(arg_stmt, 2, io_type), SQLITE_OK);

    check_status(sqlite3_bind_int64(arg_stmt, 3, arg_value), SQLITE_OK);

    check_status(sqlite3_bind_int(arg_stmt, 4, position), SQLITE_OK);

    check_status(sqlite3_bind_int64(arg_stmt, 5, syscall_invocation_id), SQLITE_OK);

    check_status(sqlite3_bind_text(arg_stmt, 6, description, -1, SQLITE_TRANSIENT),
                 SQLITE_OK);

    // execute the query
    call_with_retries(arg_stmt, SQLITE_DONE);

    // cleanup the prepared statement
    check_status(sqlite3_reset(arg_stmt), SQLITE_OK);

    return sqlite3_last_insert_rowid(db);
}

sqlite3* create_database(const char* fpath)
{
    sqlite3* db;
    sqlite3_stmt* pstmt;

    // Ensure that filename does not exist
    if (access(fpath, F_OK) != -1) {
        if (unlink(fpath) == -1) {
            fprintf(stderr, "[%s] Could not delete existing database, %s\n", __FILE__,
                    fpath);
            fprintf(stderr, "[E] %s\n", strerror(errno));
            abort();
        }
    }

    // Open the database using the default file system handler
    check_status(sqlite3_open_v2(fpath, &db,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                                     SQLITE_OPEN_EXCLUSIVE,
                                 nullptr),
                 SQLITE_OK);

    // Create all of the required tables
    for (auto stmt_sql : table_stmts) {
        check_status(sqlite3_prepare_v2(db, stmt_sql, -1, &pstmt, nullptr), SQLITE_OK);
        call_with_retries(pstmt, SQLITE_DONE);
        check_status(sqlite3_finalize(pstmt), SQLITE_OK);
    }

    // Performance tuning
    for (auto pragma_sql : pragma_stmts) {
        check_status(sqlite3_prepare_v2(db, pragma_sql, -1, &pstmt, nullptr), SQLITE_OK);
        call_with_retries(pstmt, SQLITE_DONE);
        check_status(sqlite3_finalize(pstmt), SQLITE_OK);
    }
    return db;
}

sqlite3_stmt* create_invocation_stmt(sqlite3* db)
{
    sqlite3_stmt* si_stmt;
    check_status(
        sqlite3_prepare_v2(db, INSERT_SYSCALL_INVOCATION_SQL, -1, &si_stmt, nullptr),
        SQLITE_OK);

    return si_stmt;
}

sqlite3_stmt* create_argument_stmt(sqlite3* db)
{
    sqlite3_stmt* arg_stmt;
    check_status(sqlite3_prepare_v2(db, INSERT_ARGUMENT_SQL, -1, &arg_stmt, nullptr),
                 SQLITE_OK);

    return arg_stmt;
}

void finalize_statement(sqlite3_stmt* stmt)
{
    check_status(sqlite3_finalize(stmt), SQLITE_OK);
}

void close_database(sqlite3* db) { check_status(sqlite3_close_v2(db), SQLITE_OK); }
