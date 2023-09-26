// panda
#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"
#include <ipanda/panda_x86.h>

// wintrospection
#include "offset/i_t.h"
#include "osi/windows/ustring.h"
#include "osi/windows/wintrospection.h"

// data
#include <glib.h>
#include <string.h>

// Memory Region
#include "region.h"

static void sanitize_process_name(char* process_name, size_t nbytes)
{
    for (size_t ix = 0; ix < nbytes; ++ix) {
        if (process_name[ix] == 0) {
            break;
        }
        if (!g_ascii_isprint(process_name[ix])) {
            process_name[ix] = '?';
        }
    }
}

Region::Region(osi::i_t curr_vad, struct WindowsProcessOSI* posi,
               struct WindowsKernelOSI* kosi)
{
    // init attributes
    this->vad = curr_vad;
    this->pid = 0;
    this->asid = 0;
    this->start_addr = 0;
    this->end_addr = 0;
    this->start_rec = 0;
    this->end_rec = 0;
    this->valid_metadata = false;
    this->mdata = metadata{};
    this->executes = false;

    // collect info
    this->populate(posi, kosi);
}

void Region::populate(struct WindowsProcessOSI* posi, struct WindowsKernelOSI* kosi)
{
    // where in the recording are we and
    // what memory region are we considering
    this->add_location_info(posi, kosi);

    // page at 0 will not have meta information
    // pid of 0 is used by the kernel to do paging
    if (this->start_addr == 0 || this->pid == 0) {
        this->valid_metadata = false;
    } else {
        this->valid_metadata = true;
        this->add_meta_info();
    }
}

void Region::add_location_info(struct WindowsProcessOSI* posi,
                               struct WindowsKernelOSI* kosi)
{
    osi::i_t eproc =
        osi::i_t(posi->vmem, posi->tlib, posi->eprocess_address, "_EPROCESS");

    osi::i_t pcb = eproc["Pcb"].set_type("_KPROCESS");
    osi::i_t node = this->vad;
    node.set_type("_MMVAD");

    // what region are we in
    this->asid = pcb["DirectoryTableBase"].getu();
    this->start_addr = node["StartingVpn"].getu() << PAGE_SHIFT;
    this->end_addr = ((node["EndingVpn"].getu() + 1) << PAGE_SHIFT) - 1;

    // what process are we running in
    this->pid = eproc["UniqueProcessId"].getu();

    // where in the recording are we
    //      make the current index be the start AND end
    //      then, as we encounter this region repeatedly,
    //      we will update the ending index
    target_ulong rridx = rr_get_guest_instr_count();
    this->start_rec = rridx;
    this->end_rec = rridx;

    // what process are we in?
    char process_name[17] = {'\0'};
    eproc["ImageFileName"].getx(process_name, 16);
    sanitize_process_name(process_name, sizeof process_name);
    this->process = std::string(process_name);
}

void Region::add_subsection_info(osi::i_t node)
{
    try {
        osi::i_t control_area =
            node("Subsection")("ControlArea").set_type("_CONTROL_AREA");

        if (control_area.get_address() != 0) {
            target_ulong backing_file_address =
                control_area["FilePointer"]["Value"].getu() & FP_ALIGN;

            if (backing_file_address != 0) {
                osi::i_t backing_file(node.get_virtual_memory_shared(),
                                      node.get_type_library(), backing_file_address,
                                      "_FILE_OBJECT");
                osi::ustring filename(
                    backing_file["FileName"].set_type("_UNICODE_STRING"));
                this->mdata.backing_file = filename.as_utf8().c_str();
            }
        }
    } catch (...) {
        // adding this try/catch so that we are still trying to get a backing
        // file even for memory that shouldn't have one to catch suspicious behavior
        this->mdata.backing_file.clear();
    }
}

void Region::add_meta_info()
{
    osi::i_t curr_node = this->vad;

    // get the pooltag - is this a short or long VAD
    uint8_t* tagname = (uint8_t*)malloc(VADTAG_SIZE + 1);
    memset(tagname, '\0', VADTAG_SIZE + 1);

    auto vmem = curr_node.get_virtual_memory_shared();
    vmem->read((curr_node.get_address() - VADTAG_OFFSET), tagname, VADTAG_SIZE);

    // mark the vad
    if (strncmp((char*)tagname, "VadS", 4) == 0 ||
        strncmp((char*)tagname, "VadF", 4) == 0) {
        this->mdata.vad_long = false;
        curr_node.set_type("_MMVAD_SHORT");
    } else { // Vadl or Vadm or Vad
        this->mdata.vad_long = true;
        curr_node.set_type("_MMVAD_LONG");
    }

    // Get flags (exist for all VAD types)
    target_ulong flags = curr_node["u"]["LongFlags"].getu();

    // parse out other flags
    this->mdata.vad_type = flags >> TYPE_FLAG_SHIFT & TYPE_FLAG_MASK;
    this->mdata.private_mem = (1 == (flags >> PRIVATE_FLAG_SHIFT));
    this->mdata.mem_commit = (1 == ((flags >> MC_FLAG_SHIFT) & MC_FLAG_MASK));
    this->mdata.initial_protections =
        flags >> PROTECTION_FLAG_SHIFT & PROTECTION_FLAG_MASK;

    // subsection only exists for _MMVAD_LONG structures
    if (this->mdata.vad_long) {
        this->add_subsection_info(curr_node);
    }
}

void Region::update_end_rec() { this->end_rec = rr_get_guest_instr_count(); }

std::tuple<bool, bool, target_ulong> Region::get_rkey()
{
    return std::make_tuple(this->mdata.vad_long, this->mdata.private_mem,
                           this->mdata.initial_protections);
}

void Region::does_execute(struct WindowsKernelOSI* kosi)
{
    this->executes = true;
    this->threads.insert(kosi_get_current_tid(kosi));
}
