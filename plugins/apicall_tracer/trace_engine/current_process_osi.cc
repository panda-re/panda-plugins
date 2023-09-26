extern "C" {
#define __STDC_FORMAT_MACROS
}

#include <algorithm>
#include <iterator>
#include <memory>

#include "panda/plugin.h"
#include "exec/cpu-defs.h"
#include "panda/common.h"
#include "ipanda/panda_x86.h"
#include "current_process_osi.h"

#include "ipanda/ipanda.h"
#include "ipanda/manager.h"

#include "offset/i_t.h"
#include "osi/windows/wintrospection.h"

class WindowsCurrentProcessOSI : public CurrentProcessOSI
{
private:
    struct WindowsKernelOSI* win_kosi;

public:
    WindowsCurrentProcessOSI(const char* profile, struct WindowsKernelOSI* kosi)
    {
        win_kosi = kosi;
    }

    bool is_valid() override final { return true; }

    uint64_t current_pid(CPUState* env) override final
    {
        osi::i_t kpcr = osi::i_t(win_kosi->system_vmem, win_kosi->kernel_tlib,
                                 win_kosi->details.kpcr, "_KPCR");
        osi::i_t eprocess;
        if (win_kosi->system_vmem->get_pointer_width() == 4) {
            auto ethread = kpcr["PrcbData"]("CurrentThread");
            eprocess = ethread.set_type("_KTHREAD")("Process").set_type("_EPROCESS");
        } else {
            auto ethread = kpcr["Prcb"]("CurrentThread").set_type("_ETHREAD");
            eprocess = ethread.set_type("_KTHREAD")("Process").set_type("_EPROCESS");
        }
        return eprocess["UniqueProcessId"].getu();
    }

    uint64_t current_tid(CPUState* env) override final
    {
        try {
            osi::i_t kpcr = osi::i_t(win_kosi->system_vmem, win_kosi->kernel_tlib,
                                     win_kosi->details.kpcr, "_KPCR");
            osi::i_t ethread;

            if (win_kosi->system_vmem->get_pointer_width() == 4) {
                ethread = kpcr["PrcbData"]("CurrentThread").set_type("_ETHREAD");
            } else {
                ethread = kpcr["Prcb"]("CurrentThread").set_type("_ETHREAD");
            }
            return ethread["Cid"]["UniqueThread"].getu();

        } catch (const std::runtime_error& e) {
            return (target_ulong)(-1);
        }
    }

    uint64_t current_asid(CPUState* env) override final
    {
        osi::i_t kpcr = osi::i_t(win_kosi->system_vmem, win_kosi->kernel_tlib,
                                 win_kosi->details.kpcr, "_KPCR");

        osi::i_t eprocess;
        if (win_kosi->system_vmem->get_pointer_width() == 4) {
            auto ethread = kpcr["PrcbData"]("CurrentThread");
            eprocess = ethread.set_type("_KTHREAD")("Process").set_type("_EPROCESS");
        } else {
            auto ethread = kpcr["Prcb"]("CurrentThread").set_type("_ETHREAD");
            eprocess = ethread.set_type("_KTHREAD")("Process").set_type("_EPROCESS");
        }
        return eprocess["Pcb"]["DirectoryTableBase"].getu();
    }
};

std::shared_ptr<CurrentProcessOSI>
create_current_process_osi(const char* profile, struct WindowsKernelOSI* kosi)
{
    auto panda_os_type = panda_os_familyno;

    if (panda_os_type == OS_WINDOWS) {
        return std::make_shared<WindowsCurrentProcessOSI>(profile, kosi);
    }
    return std::shared_ptr<CurrentProcessOSI>(nullptr);
}
