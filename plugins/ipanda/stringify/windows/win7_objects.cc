#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <offset/i_t.h>
#include <osi/windows/ustring.h>
#include <osi/windows/wintrospection.h>

#include "panda/plugin.h"
#include "exec/cpu-defs.h"

#include "typesignature/arguments.h"

#include "win7_enum.h"
#include "win7_objects.h"

uint64_t set_thread_to_process(osi::i_t& object)
{
    object.set_type("_ETHREAD");
    auto tid = object["Cid"]["UniqueThread"].getu();
    object = object["Tcb"]("Process");
    object.set_type("_EPROCESS");
    return tid;
}

bool resolve_name_by_header(osi::i_t object, std::string& name)
{
    auto address = object.get_address();
    if (address) {
        address -= OBJECT_HEADER_SIZE;
    }

    auto header = object.set_address(address).set_type("_OBJECT_HEADER");
    uint8_t mask = header["InfoMask"].get8();

    target_long name_info = 0;
    if (mask & CREATOR_INFO_MASK) {
        name_info -= CREATOR_INFO_SIZE;
    }
    if (mask & NAME_INFO_MASK) {
        name_info -= NAME_INFO_SIZE;

        header.set_address(address + name_info).set_type("_OBJECT_HEADER_NAME_INFO");

        osi::ustring uname(header["Name"]);
        name = uname.as_utf8();
    }

    if (name.empty()) {
        return false;
    }
    return true;
}

std::string get_key_name(osi::i_t object)
{
    object.set_type("_CM_KEY_BODY");

    osi::i_t nameblock;
    uint8_t compressed;
    uint16_t size;

    std::vector<std::string> keyname;

    auto kcb = object("KeyControlBlock");
    while (kcb.get_address()) {
        nameblock = kcb("NameBlock");
        compressed = nameblock["Compressed"].get8();
        size = nameblock["NameLength"].get16();

        if (compressed) {
            char* temp = new char[size + 1]{'\0'};
            nameblock["Name"].getx(*temp, size);

            size_t total = strnlen(temp, size);
            if (total == size) {
                temp[size] = '\0';
            }

            for (size_t idx = 0; idx < total; idx++) {
                if (!isprint(temp[idx])) {
                    temp[idx] = '?';
                }
            }

            keyname.push_back(std::string(temp, total));
            delete temp;
        } else {
            auto raw_name = osi::ustring(nameblock["Name"].set_type("_UNICODE_STRING"));
            keyname.push_back(raw_name.as_utf8());
        }
        kcb = kcb("ParentKcb");
    }

    std::string full_key;
    for (auto it = keyname.rbegin(); it != keyname.rend(); it++) {
        full_key += "\\" + *it;
    }

    return full_key;
}

/**
 *  kd >> nt!_FILE_OBJECT; IopQueryName = TypeInfo->QueryNameProcedure
 *  kd >> ??
 * (((nt!_OBJECT_TYPE**)@@(nt!ObTypeIndexTable))[28])->TypeInfo.QueryNameProcedure
 *  Additionally, it looks querying the device name requires sending an IRP to
 * the driver in the general case. We try to resolve it via optional headers,
 * but the device name may or may not be here. This is the approach volatility
 * takes
 */
std::string get_file_name(osi::i_t object)
{
    object = object.set_type("_FILE_OBJECT");
    std::string path;
    std::string name;

    if (resolve_name_by_header(object("DeviceObject"), name)) {
        path.append("\\Device\\");
        path.append(name.c_str());
    }

    osi::ustring uname(object["FileName"]);
    path.append(uname.as_utf8());

    return path;
}

std::string extract_handle_name(struct WindowsHandleObject* handle)
{
    auto type = handle_get_type(handle);
    auto posi = handle_get_context(handle);
    auto ptr = handle_get_pointer(handle);

    if (!ptr) {
        return "<null>";
    }

    // you will need to change the type at each stringifier,
    // but everything else is set for convenience
    osi::i_t object(posi->vmem, posi->tlib, ptr, "_EPROCESS");

    std::stringstream ss;
    uint64_t tid = 0;

    switch (type) {
    case OBJECT_TYPE_Directory:
    case OBJECT_TYPE_ALPCPort:
    case OBJECT_TYPE_Event:
    case OBJECT_TYPE_Mutant: {
        std::string name;
        if (!resolve_name_by_header(object, name)) {
            return "";
        }
        return name;
    }

    case OBJECT_TYPE_Key:
        return get_key_name(object);

    case OBJECT_TYPE_File:
        return get_file_name(object);

    case OBJECT_TYPE_Thread:
        tid = set_thread_to_process(object);
    case OBJECT_TYPE_Process: {
        struct WindowsProcess* p = create_process(posi->kosi, object.get_address());

        ss << process_get_pid(p) << ":" << process_get_shortname(p);
        if (tid)
            ss << ":" << tid;

        free_process(p);
        return ss.str();
    }
    default: {
        std::stringstream ss;
        ss << (int64_t)type << ":";
        ss << std::string(translate_object_type(type));
        ss << ":Unknown";
        return ss.str();
    }
    }

    return "NotYetImplemented";
}

void write_handle_information(rapidjson::Writer<rapidjson::StringBuffer>& writer,
                              struct WindowsHandleObject* handle)
{
    auto type = handle_get_type(handle);
    auto posi = handle_get_context(handle);
    auto ptr = handle_get_pointer(handle);

    if (!ptr)
        return;

    writer.Key("handle_type");
    writer.String(translate_object_type(type));

    osi::i_t object(posi->vmem, posi->tlib, ptr, "_EPROCESS");

    std::stringstream ss;
    uint64_t tid = 0;

    switch (type) {
    case OBJECT_TYPE_Thread:
        tid = set_thread_to_process(object);
        // no break on purpose -- we need the operations from process
    case OBJECT_TYPE_Process: {
        struct WindowsProcess* p = create_process(posi->kosi, object.get_address());

        if (!p) {
            writer.Key("handle_name");
            writer.String("UNKNOWN");
            return;
        }

        writer.Key("pid");
        writer.Uint64(process_get_pid(p));
        writer.Key("asid");
        writer.Uint64(process_get_asid(p));

        if (tid) {
            writer.Key("tid");
            writer.Uint64(tid);
        }

        ss << process_get_pid(p) << ":" << process_get_shortname(p);
        if (tid)
            ss << ":" << tid;
        free_process(p);
    }
        writer.Key("handle_name");
        writer.String(ss.str().c_str());
        break;

    default:
        std::string attempt = extract_handle_name(handle);
        writer.Key("handle_name");
        writer.String(attempt.c_str());
        break;
    }
}
