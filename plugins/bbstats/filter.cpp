#include <algorithm>
#include <map>
#include <set>
#include <utility>
#include <vector>

#include "filter.h"

#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>

#define THREAD_WHITELIST "thread_whitelist"
#define MODULE_GUID_WHITELIST "guid_whitelist"

InstrumentationFilter::InstrumentationFilter(const char* filter_file)
{
    FILE* fp = fopen(filter_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "[%s] Failed to find file: %s\n", __FILE__, filter_file);
        throw std::invalid_argument("filter file not found");
    }

    // Pull out into JSON doc
    std::string stringToAdd = "";
    char read_buffer[65536];
    rapidjson::FileReadStream is(fp, read_buffer, sizeof(read_buffer));
    rapidjson::Document filter_document;
    filter_document.ParseStream(is);

    // thread whitelist (pid, tid, asid)
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

            target_threads[key].push_back(tid);

            fprintf(stdout, "Adding tid %u to be instrumented\n", tid);
        }
    }
    if (target_threads.empty()) {
        fprintf(stdout, "No threads were set to be instrumented\n");
    }

    // module guids
    itr = filter_document.FindMember(MODULE_GUID_WHITELIST);
    if (itr != filter_document.MemberEnd()) {
        assert(itr->value.IsArray());
        for (rapidjson::SizeType i = 0; i < itr->value.Size(); i++) {
            stringToAdd =
                std::string(itr->value[i].GetString(), itr->value[i].GetStringLength());
            std::transform(stringToAdd.begin(), stringToAdd.end(), stringToAdd.begin(),
                           ::toupper);
            target_modules.insert(stringToAdd);
            fprintf(stdout, "Adding module guid %s to be instrumented\n",
                    stringToAdd.c_str());
        }
    }
    if (target_modules.empty()) {
        fprintf(stdout, "No module paths set to be instrumented\n");
    }
}

bool InstrumentationFilter::thread_check(uint32_t pid, uint64_t asid, uint32_t tid)
{
    auto check = target_threads.find(std::make_pair(pid, asid));
    if (check != target_threads.end()) {
        if (tid != 0) {
            auto threads = check->second;
            return std::find(threads.begin(), threads.end(), tid) != threads.end();
        }
        return true;
    }
    return false;
}

bool InstrumentationFilter::module_check(const char* guid)
{
    return target_modules.find(std::string(guid)) != target_modules.end();
}
