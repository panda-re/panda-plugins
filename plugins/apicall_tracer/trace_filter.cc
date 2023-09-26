#include "trace_filter.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <set>
#include <string>

#include "panda/plugin.h"
#include "panda/common.h"

#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>

/*
Expected Tracefilter format should be a json-formatted file:

    {
        "thread_whitelist" : [ [uint32 pid, uint32 tid, ulong asid], [uint32 pid, uint32
tid, ulong asid] ...], "process_name_whitelist" : [ASCII String, ASCII String, ...],
        "module_path_blacklist" : [UTF-8 String, UTF-8 String, ...]
    }

Note the encodings expected. This is to stay consistent across other plugins.
UTF-16 is not supported by any plugin.
*/
#define THREAD_WHITELIST "thread_whitelist"
#define PROCESS_NAME_WHITELIST "process_name_whitelist"
#define MODULE_PATH_BLACKLIST "module_path_blacklist"

TraceFilter::TraceFilter()
{
    enabled = false;
    fprintf(stdout, "No trace filter found - tracing all calls\n");
}

TraceFilter::TraceFilter(const char* filter_file)
{
    FILE* fp = fopen(filter_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "[%s] Failed to find file: %s\n", __FILE__, filter_file);
        throw std::invalid_argument("filter file not found");
    }
    enabled = true;

    // Pull out into JSON doc
    std::string stringToAdd = "";
    char read_buffer[65536];
    rapidjson::FileReadStream is(fp, read_buffer, sizeof(read_buffer));
    rapidjson::Document filter_document;
    filter_document.ParseStream(is);

    // Parse the threads into private set of (pid, tid, asid)
    rapidjson::Value::ConstMemberIterator itr =
        filter_document.FindMember(THREAD_WHITELIST);
    if (itr != filter_document.MemberEnd()) {
        assert(itr->value.IsArray());
        for (rapidjson::SizeType i = 0; i < itr->value.Size();
             i++) // Uses SizeType instead of size_t
        {
            // pid, asid
            auto key =
                std::make_pair(itr->value[i][0].GetUint(), itr->value[i][2].GetUint64());
            uint32_t tid = itr->value[i][1].GetUint();
            threadWhitelist[key].push_back(tid);

            fprintf(stdout, "Adding tid %u to be traced\n", tid);
        }
    }
    if (threadWhitelist.empty()) {
        fprintf(stdout, "No threads were set to be traced\n");
    }

    // Parse the module paths into our private set of std::string objects
    // The image.h file does a lower and utf-8 pass for all the paths, so we need to be
    // careful here, for now just do the lower on input
    itr = filter_document.FindMember(MODULE_PATH_BLACKLIST);
    if (itr != filter_document.MemberEnd()) {
        assert(itr->value.IsArray());
        for (rapidjson::SizeType i = 0; i < itr->value.Size(); i++) {
            stringToAdd =
                std::string(itr->value[i].GetString(), itr->value[i].GetStringLength());
            std::transform(stringToAdd.begin(), stringToAdd.end(), stringToAdd.begin(),
                           ::tolower);
            modulePathBlacklist.insert(stringToAdd);
            fprintf(stdout, "Adding module path %s to be ignored\n", stringToAdd.c_str());
        }
    }
    if (modulePathBlacklist.empty()) {
        fprintf(stdout, "No module paths set to be ignored\n");
    }
}

/* Check for a pid in the thread_whitelist */
bool TraceFilter::checkPid(uint32_t pid, uint64_t asid)
{
    return threadWhitelist.find(std::make_pair(pid, asid)) != threadWhitelist.end();
}

/* Check for a module path in the module_path_blacklist */
bool TraceFilter::checkModulePath(std::string path)
{
    std::transform(path.begin(), path.end(), path.begin(), ::tolower);
    return modulePathBlacklist.find(path) == modulePathBlacklist.end();
}

/* Check for thread in the thread_whitelist */
bool TraceFilter::checkTid(uint32_t pid, uint32_t tid, uint64_t asid)
{
    if (threadWhitelist.find(std::make_pair(pid, asid)) != threadWhitelist.end()) {
        auto threads = threadWhitelist[std::make_pair(pid, asid)];
        if (std::find(threads.begin(), threads.end(), tid) != threads.end()) {
            return true;
        }
    }
    return false;
}

/* check for module path in blacklist */
bool TraceFilter::checkModule(std::shared_ptr<Image> module)
{
    if (!enabled)
        return true;
    return checkModulePath(module->get_full_path());
}

/* Check for pid,tid,asid in whitelist */
bool TraceFilter::checkThread(uint32_t pid, uint32_t tid, uint64_t asid)
{
    if (!enabled)
        return true;
    return checkTid(pid, tid, asid);
}

/* Quick check to be called from callstack plugin. Should determine if we are in a process
that could possibly be traced before the heavyweight checks of thread, memory region,
and/or module path */
bool TraceFilter::quickCheck(uint32_t pid, uint64_t asid)
{
    if (!enabled)
        return true;
    return checkPid(pid, asid);
}
