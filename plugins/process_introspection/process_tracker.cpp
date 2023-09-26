#include "process_tracker.h"
#include <cstring>
#include <ipanda/types.h>
#include <map>
#include <vector>

void ProcessTracker::asid_updated() { m_needs_update = true; }

void ProcessTracker::before_basic_block_exec(CPUState* env)
{
    if (m_needs_update) {
        m_os_manager->collect_all_active_processes(env, m_full_process_map,
                                                   m_guid_lookup);
        m_needs_update = false;
    }
}

const std::map<process_key_t, ipanda_types::Process>& ProcessTracker::results()
{
    return m_full_process_map;
}

std::string ProcessTracker::lookup_guid(std::string path)
{
    // Guids are tracked separately to ensure we only collect them once,
    // with the time consuming task of parsing a PE file in memory
    auto match = m_guid_lookup.find(path);
    if (match == m_guid_lookup.end()) {
        return "";
    }
    return match->second;
}
