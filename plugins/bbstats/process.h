#include <memory>
#include <string>

#include <osi/windows/wintrospection.h>

#include "image.h"
#include "range.h"

#ifndef __PROCESS__

class Process
{
private:
    uint64_t asid;
    uint32_t pid;
    uint32_t ppid;
    std::string name;
    bool wow64;

    uint64_t eprocess_address;

    std::shared_ptr<Image> find_image(uint64_t address);
    void walk_images(struct WindowsKernelOSI* kosi, struct WindowsProcess* proc);

    AddressRangeList blacklist;

public:
    std::map<uint64_t, std::shared_ptr<Image>> images;

    Process(struct WindowsProcess* proc)
    {
        asid = process_get_asid(proc);
        pid = process_get_pid(proc);
        ppid = process_get_ppid(proc);
        name = std::string(process_get_shortname(proc));
        wow64 = process_is_wow64(proc);
        eprocess_address = process_get_eprocess(proc);
    };

    bool operator==(const Process& other) const;
    bool operator!=(const Process& other) const { return !(*this == other); };

    std::string key() const;

    uint64_t get_asid() { return asid; };
    uint32_t get_pid() { return pid; };
    uint32_t get_ppid() { return ppid; };
    const std::string& get_name() { return name; }
    bool is_wow64() { return wow64; }
    uint64_t get_eprocess() { return eprocess_address; };

    std::shared_ptr<Image> get_image(struct WindowsKernelOSI* kosi,
                                     struct WindowsProcess* proc, uint64_t address);
};

#define __PROCESS__
#endif
