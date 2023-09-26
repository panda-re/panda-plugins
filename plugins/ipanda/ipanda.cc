#include <memory>
#include <string.h>

#include "panda/plugin.h"
#include "panda/common.h"
#include "ipanda.h"
#include "manager.h"
#include <ipanda/panda_x86.h>

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
}
static std::shared_ptr<IntroPANDAManager> g_introspection_manager;

bool create_introspection_manager(std::shared_ptr<IntroPANDAManager>& manager)
{
    const char* profile = panda_os_name;

    fprintf(stdout, "Profile name = %s \n", profile);

    if (!profile || strlen(profile) == 0) {
        fprintf(stderr, "To access introspection capabilities, set the -os flag!\n");
        return false;
    }

    auto width = panda_os_bits == 64 ? 8 : 4;

    auto ost = panda_os_familyno;
    if (ost == OS_WINDOWS) {
        // currently only support Wndows 7, but more checks would be added here
        g_introspection_manager.reset(new Windows7IntrospectionManager(width, profile));
    } else if (ost == OS_LINUX) {
        // currently only support Linux Kernel v3, but more checks would be added here
        g_introspection_manager.reset(new Linux3IntrospectionManager(width, profile));
    } else {
        fprintf(stderr, "OS Introspection does not currently support this platform\n");
        return false;
    }

    manager = g_introspection_manager;
    return true;
}

void initialize_manager(CPUState* env)
{
    if (!g_introspection_manager) {
        fprintf(stderr, "The Introspection Manager has not been created\n");
        exit(3);
    } else if (!(g_introspection_manager->initialize(env))) {
        fprintf(stderr, "Failed to initialize the OS Introspection library\n");
        exit(4);
    }
    fprintf(stdout, "Successfully initialized the OS Introspection library\n");
}

bool init_ipanda(void* target, std::shared_ptr<IntroPANDAManager>& manager)
{
    panda_cb pcb;
    pcb.after_loadvm = initialize_manager;
    panda_register_callback(target, PANDA_CB_AFTER_LOADVM, pcb);

    return create_introspection_manager(manager);
}
bool init_plugin(void* self)
{
    const char* profile = panda_os_name;

    fprintf(stdout, "[+] INSIDE ipanda.cc ! \n");
    fprintf(stdout, "Profile name = %s \n", profile);
    auto width = panda_os_bits == 64 ? 8 : 4;
    fprintf(stdout, "panda_os_bits width = %d \n", width);
    auto ost = panda_os_familyno;
    fprintf(stdout, "panda_os_familyno ost = %s \n", ost);
    return true;
}

void uninit_plugin(void* self) {}
