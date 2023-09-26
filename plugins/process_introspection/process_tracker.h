#ifndef __PROCESS_TRACKER_H
#define __PROCESS_TRACKER_H

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <ipanda/manager.h>
#include <ipanda/types.h>

class ProcessTracker
{
private:
    bool m_needs_update;
    std::shared_ptr<IntroPANDAManager> m_os_manager;
    std::map<process_key_t, ipanda_types::Process> m_full_process_map;
    guid_map_t m_guid_lookup;

public:
    ProcessTracker(std::shared_ptr<IntroPANDAManager>& manager)
        : m_needs_update(true), m_os_manager(manager)
    {
    }
    void asid_updated();
    void before_basic_block_exec(CPUState* env);
    const std::map<process_key_t, ipanda_types::Process>& results();
    std::string lookup_guid(std::string path);
};

#endif
