#include <cstring>
#include <dlfcn.h>
#include <libgen.h>
#include <unistd.h>

#include "find_syscall_database.h"

std::string find_syscall_database(std::string database)
{
    Dl_info dl_info;
    dladdr((void*)find_syscall_database, &dl_info);

    if (dl_info.dli_sname == NULL) {
        fprintf(stderr, "[%s] Failed to locate shared database object\n", __FILE__);
        return "";
    }

    const char* lib_path = dl_info.dli_fname;
    char* tmp_lib = strdup(lib_path);
    char* dir_path = dirname(dirname(tmp_lib));

    // first check next
    auto path = std::string(dir_path) + "/res/" + database;
    free(tmp_lib);

    if (access(path.c_str(), R_OK) != 0) {
        return "";
    }

    return path;
}
