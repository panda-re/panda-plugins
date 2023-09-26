#include <algorithm>
#include <map>
#include <utility>

#include "filter.h"

#include <rapidjson/document.h>
#include <rapidjson/filereadstream.h>

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

    // threads (pid, tid, asid)
    rapidjson::Value::ConstMemberIterator itr = filter_document.FindMember("threads");

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

void InstrumentationFilter::remove_thread(uint32_t pid, uint64_t asid, uint32_t tid)
{
    auto it = target_threads.find(std::make_pair(pid, asid));
    if (it != target_threads.end()) {
        it->second.erase(std::remove(it->second.begin(), it->second.end(), tid),
                         it->second.end());

        if (it->second.empty()) {
            target_threads.erase(it);
        }
    }
}
