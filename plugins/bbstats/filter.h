#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#ifndef INSTRUMENTATION_FILTER
#define INSTRUMENTATION_FILTER

class InstrumentationFilter
{
public:
    InstrumentationFilter(const char* filter_file);

    /**
     *  Check if we are in a targeted thread or module
     *  Return true if we are, false otherwise
     */
    bool thread_check(uint32_t pid, uint64_t asid, uint32_t tid = 0);
    bool module_check(const char* guid);

private:
    std::map<std::pair<uint32_t, uint64_t>, std::vector<uint32_t>> target_threads;
    std::set<std::string> target_modules;
};

#endif
