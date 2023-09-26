#ifndef TRACE_FILTER
#define TRACE_FILTER

#include "panda/plugin.h"
#include "panda/common.h"
#include "process/image.h"

#include <map>
#include <set>
#include <string>
#include <utility>

class TraceFilter
{
public:
    TraceFilter();
    TraceFilter(const char* filter_file);

    bool quickCheck(uint32_t pid, uint64_t asid);
    bool checkThread(uint32_t pid, uint32_t tid, uint64_t asid);
    bool checkModule(std::shared_ptr<Image> module);

private:
    bool enabled;

    bool checkTid(uint32_t pid, uint32_t tid, uint64_t asid);
    bool checkModulePath(std::string path);
    bool checkPid(uint32_t pid, uint64_t asid);

    std::map<std::pair<uint32_t, uint64_t>, std::vector<uint32_t>> threadWhitelist;
    std::set<std::string> modulePathBlacklist;
};
#endif
