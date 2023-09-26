#include <map>
#include <utility>
#include <vector>

#ifndef INSTRUMENTATION_FILTER_VOLATILITY
#define INSTRUMENTATION_FILTER_VOLATILITY

class InstrumentationFilter
{
public:
    InstrumentationFilter(const char* filter_file);

    /**
     *  Check if we are in a targeted thread or process
     */
    bool thread_check(uint32_t pid, uint64_t asid, uint32_t tid = 0);

    /**
     *  Remove a thread from the targeted threads, if it exists
     */
    void remove_thread(uint32_t pid, uint64_t asid, uint32_t tid);

private:
    std::map<std::pair<uint32_t, uint64_t>, std::vector<uint32_t>> target_threads;
};

#endif
