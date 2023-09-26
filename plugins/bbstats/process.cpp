#include "process.h"

#include <stdio.h>

bool Process::operator==(const Process& other) const
{
    return (asid == other.asid) && (pid == other.pid);
}

std::string Process::key() const
{
    // stringstreams are too slow
    char* key = NULL;
    size_t size = 0;
    FILE* a = open_memstream(&key, &size);
    fprintf(a, "%016lx:%d:%s", asid, pid, name.c_str());
    fclose(a);

    std::string r(key);

    free(key);
    return r;
}

void Process::walk_images(struct WindowsKernelOSI* kosi, struct WindowsProcess* proc)
{
    auto module_list =
        get_module_list(kosi, process_get_eprocess(proc), process_is_wow64(proc));

    if (module_list == nullptr) {
        return;
    }

    auto curr = module_list_next(module_list);
    while (curr != nullptr) {
        auto key =
            module_entry_get_base_address(curr) + module_entry_get_modulesize(curr);

        if (images.find(key) != images.end()) {
            free_module_entry(curr);
            curr = module_list_next(module_list);
            continue;
        }

        images.insert(std::make_pair(
            key, std::make_shared<Image>(curr, module_list_get_osi(module_list))));

        free_module_entry(curr);
        curr = module_list_next(module_list);
    }
    free_module_list(module_list);
}

std::shared_ptr<Image> Process::find_image(uint64_t address)
{
    auto check = images.lower_bound(address);
    if (check != images.end()) {
        auto image = check->second;
        if (image->address_in(address)) {
            return image;
        }
    }
    return nullptr;
}

std::shared_ptr<Image> Process::get_image(struct WindowsKernelOSI* kosi,
                                          struct WindowsProcess* proc, uint64_t address)
{
    auto image = this->find_image(address);
    if (image) {
        return image;
    }

    this->walk_images(kosi, proc);

    image = this->find_image(address);
    if (image) {
        return image;
    }

    return nullptr;
}
