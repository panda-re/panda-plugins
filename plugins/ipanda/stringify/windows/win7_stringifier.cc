#include <functional>
#include <map>
#include <sstream>

#include <panda/plugin.h>
#include <panda/common.h>

#include <offset/i_t.h>
#include <osi/windows/manager.h>
#include <osi/windows/ustring.h>
#include <osi/windows/wintrospection.h>

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "ipanda/stringify/stringify_common.h"
#include "typesignature/arguments.h"

#include "win7_enum.h"
#include "win7_objects.h"
#include "win7_stringifier.h"

#include "base64.h"

// add_*_data:   adds data fields without {start,end}object
// add_*_object: adds an object with {start,end}object

typedef int32_t windows_long;
typedef uint32_t windows_ulong;

template <typename T>
void add_pointer_data(rapidjson::Writer<T>& writer, const char* type_name,
                      target_ulong ptr)
{
    writer.Key(TYPE_KEY);
    writer.String(type_name);
    writer.Key(POINTER_KEY);
    writer.Uint(ptr);
}

template <typename T>
void add_ulong_data(rapidjson::Writer<T>& writer, const char* type_name,
                    target_ulong data)
{
    writer.Key(TYPE_KEY);
    writer.String(type_name);
    writer.Key(VALUE_KEY);
    writer.Uint(data);
}

template <typename T>
void add_string_data(rapidjson::Writer<T>& writer, const char* key_name,
                     const char* value)
{
    writer.Key(key_name);
    writer.String(value);
}

template <typename T>
void add_null_data(rapidjson::Writer<T>& writer, const char* key_name)
{
    writer.Key(key_name);
    writer.Null();
}

template <typename T>
void add_ulong_object(rapidjson::Writer<T>& writer, WindowsKernelOSI* kosi,
                      target_ulong value)
{
    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String("ULONG");
    writer.Key(VALUE_KEY);
    writer.Uint(value);
    writer.EndObject();
}

template <typename T>
void add_handle_object(rapidjson::Writer<T>& writer, WindowsKernelOSI* kosi,
                       target_ulong handle_value)
{
    auto handle = resolve_handle(kosi, handle_value);

    writer.StartObject();
    add_ulong_data(writer, "HANDLE", handle_value);
    if (!handle) {
        add_null_data(writer, "contents");
    } else {
        writer.Key("contents");
        writer.StartObject();
        write_handle_information(writer, handle);
        writer.EndObject();
    }

    free_handle(handle);
    writer.EndObject();
}

template <typename T>
void add_object_attributes_object(rapidjson::Writer<T>& writer, WindowsKernelOSI* kosi,
                                  target_ulong ptr)
{
    auto proc_manager = WindowsProcessManager();
    proc_manager.initialize(kosi, kosi_get_current_process_address(kosi));

    osi::i_t attributes = proc_manager.get_type(ptr, "_OBJECT_ATTRIBUTES");

    target_ulong dir = 0;
    try {
        dir = attributes["RootDirectory"].getu();
    } catch (std::runtime_error const&) {
        writer.Null();
        return;
    }

    std::string parsed;
    try {
        osi::ustring uname(attributes("ObjectName"));
        parsed = uname.as_utf8();
    } catch (std::runtime_error const&) {
        parsed = "";
    }

    if (!dir and parsed.empty()) {
        writer.StartObject();
        add_null_data(writer, "name");
        writer.EndObject();
        return;
    }

    std::string name;
    if (dir) {
        struct WindowsHandleObject* handle = nullptr;
        try {
            handle = resolve_handle(kosi, dir);

            if (handle) {
                auto hname = extract_handle_name(handle);
                name.append(hname.c_str());
                name.append("\\");
            }
        } catch (std::runtime_error const&) {
        }
        free_handle(handle);
    }

    if (!parsed.empty())
        name.append(parsed.c_str());

    writer.StartObject();
    writer.Key("name");
    writer.String(name.c_str());
    writer.EndObject();
}

template <typename T>
void add_access_mask_object(rapidjson::Writer<T>& writer, WindowsKernelOSI* kosi,
                            target_ulong value)
{
    writer.StartObject();
    add_ulong_data(writer, "ACCESS_MASK", value);
    writer.EndObject();
}

template <typename T>
T read_value(WindowsProcessManager& manager, uint64_t ptr, bool* success)
{
    auto reader = manager.get_type(ptr, "UNKNOWN");

    T value = 0;
    *success = false;

    try {
        reader.getx(value, sizeof(T));
        *success = true;
    } catch (std::runtime_error const&) {
    }

    return value;
}

template <typename T>
void add_value_pointer_objects(
    rapidjson::Writer<T>& writer, CPUState* env, WindowsKernelOSI* kosi, target_ulong ptr,
    const char* pointer_name,
    void (*AddDereferencedObject)(rapidjson::Writer<T>&, WindowsKernelOSI*, target_ulong))
{
    writer.StartObject();
    add_pointer_data(writer, pointer_name, ptr);

    auto proc_manager = WindowsProcessManager();
    proc_manager.initialize(kosi, kosi_get_current_process_address(kosi));

    bool success = false;
    auto value = ptr ? read_value<target_ulong>(proc_manager, ptr, &success) : 0;

    writer.Key("contents");
    if (success) {
        AddDereferencedObject(writer, kosi, value);
    } else {
        writer.Null();
    }
    writer.EndObject();
}

template <typename T>
void add_struct_pointer_objects(rapidjson::Writer<T>& writer, WindowsKernelOSI* kosi,
                                target_ulong ptr, const char* pointer_name,
                                void (*AddDereferencedObject)(rapidjson::Writer<T>&,
                                                              WindowsKernelOSI*,
                                                              target_ulong))
{
    writer.StartObject();
    add_pointer_data(writer, pointer_name, ptr);

    writer.Key("contents");
    if (ptr != 0) {
        AddDereferencedObject(writer, kosi, ptr);
    } else {
        writer.Null();
    }
    writer.EndObject();
}

std::string stringify_handle(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    add_handle_object(writer, kosi, arg->value());
    return s.GetString();
}

std::string stringify_phandle(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    add_value_pointer_objects(writer, env, kosi, arg->value(), "PHANDLE",
                              add_handle_object);
    return s.GetString();
}

std::string stringify_ulong(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    add_ulong_object(writer, kosi, arg->value());
    return s.GetString();
}

std::string stringify_pulong(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    add_value_pointer_objects(writer, env, kosi, arg->value(), "PULONG",
                              add_ulong_object);
    return s.GetString();
}

std::string stringify_pobject_attributes(CPUState* env, WindowsKernelOSI* kosi,
                                         Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    add_struct_pointer_objects(writer, kosi, arg->value(), "POBJECT_ATTRIBUTES",
                               add_object_attributes_object);
    return s.GetString();
}

std::string stringify_access_mask(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    add_access_mask_object(writer, kosi, arg->value());
    return s.GetString();
}

std::string stringify_paccess_mask(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    add_value_pointer_objects(writer, env, kosi, arg->value(), "PACCESS_MASK",
                              add_access_mask_object);
    return s.GetString();
}

std::string stringify_key_information_class(CPUState* env, WindowsKernelOSI* kosi,
                                            Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto key_info_cls = arg->value();
    if (key_info_cls == 0) {
        writer.Null();
        return s.GetString();
    }

    writer.StartObject();
    add_ulong_data(writer, "KEY_INFORMATION_CLASS", key_info_cls);
    add_string_data(writer, NAME_KEY, translate_key_information_class(key_info_cls));
    writer.EndObject();
    return s.GetString();
}

std::string stringify_key_value_information_class(CPUState* env, WindowsKernelOSI* kosi,
                                                  Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto key_info_cls = arg->value();
    if (key_info_cls == 0) {
        writer.Null();
        return s.GetString();
    }

    writer.StartObject();
    add_ulong_data(writer, "KEY_VALUE_INFORMATION_CLASS", key_info_cls);
    add_string_data(writer, NAME_KEY,
                    translate_key_value_information_class(key_info_cls));
    writer.EndObject();
    return s.GetString();
}

std::string stringify_file_information_class(CPUState* env, WindowsKernelOSI* kosi,
                                             Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto key_info_cls = arg->value();
    if (key_info_cls == 0) {
        writer.Null();
        return s.GetString();
    }

    writer.StartObject();
    add_ulong_data(writer, "FILE_INFORMATION_CLASS", key_info_cls);
    add_string_data(writer, NAME_KEY, translate_file_information_class(key_info_cls));
    writer.EndObject();
    return s.GetString();
}

std::string stringify_plarge_integer(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto plarge_integer = arg->value();
    if (plarge_integer == 0) {
        writer.Null();
        return s.GetString();
    }

    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String("PLARGE_INTEGER");
    writer.Key(VALUE_KEY);

    auto manager = WindowsProcessManager();
    manager.initialize(kosi, kosi_get_current_process_address(kosi));

    bool success = false;
    uint64_t value = read_value<uint64_t>(manager, plarge_integer, &success);

    if (success) {
        writer.Uint(value);
    } else {
        writer.Null();
    }
    writer.EndObject();

    return s.GetString();
}

std::string read_unicode_string(osi::i_t obj)
{
    osi::ustring unicode_view(obj);

    try {
        return std::string(unicode_view.as_utf8().c_str());
    } catch (...) {
    }
    return std::string("");
}

std::string stringify_puser_process_parameters(CPUState* env, WindowsKernelOSI* kosi,
                                               Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto upp = arg->value();
    if (upp == 0) {
        writer.Null();
        return s.GetString();
    }

    auto manager = WindowsProcessManager();
    manager.initialize(kosi, kosi_get_current_process_address(kosi));

    osi::i_t user_process_params = manager.get_type(upp, "_RTL_USER_PROCESS_PARAMETERS");

    auto dll_path = read_unicode_string(user_process_params["DllPath"]);
    auto img_path = read_unicode_string(user_process_params["ImagePathName"]);
    auto cmd_path = read_unicode_string(user_process_params["CommandLine"]);

    writer.StartObject();
    add_string_data(writer, "DllPath", dll_path.c_str());
    add_string_data(writer, "ImgPath", img_path.c_str());
    add_string_data(writer, "CmdPath", cmd_path.c_str());
    writer.EndObject();

    return s.GetString();
}

std::string stringify_punicode_string(CPUState* env, WindowsKernelOSI* kosi,
                                      Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto pstr = arg->value();
    if (pstr == 0) {
        writer.Null();
        return s.GetString();
    }

    auto manager = WindowsProcessManager();
    manager.initialize(kosi, kosi_get_current_process_address(kosi));
    osi::i_t reader = manager.get_type(pstr, "_UNICODE_STRING");

    auto strval = read_unicode_string(reader);

    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String("PUNICODE_STRING");
    writer.Key(VALUE_KEY);
    writer.Uint(pstr);
    add_string_data(writer, "string_value", strval.c_str());
    writer.EndObject();

    return s.GetString();
}

std::string stringify_wchar_string(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto pstr = arg->value();
    if (pstr == 0) {
        writer.Null();
        return s.GetString();
    }

    auto manager = WindowsProcessManager();
    manager.initialize(kosi, kosi_get_current_process_address(kosi));

    std::string strval;
    try {
        osi::i_t obj = manager.get_type(pstr, "UNKNOWN");
        strval = obj.get_wchar_str(1024);
    } catch (std::runtime_error const&) {
    }

    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String("WCHAR_STRING");
    writer.Key(VALUE_KEY);
    writer.Uint(pstr);
    add_string_data(writer, "string_value", strval.c_str());
    writer.EndObject();
    return s.GetString();
}

std::string stringify_ascii_string(CPUState* env, WindowsKernelOSI* kosi, Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto pstr = arg->value();
    if (pstr == 0) {
        writer.Null();
        return s.GetString();
    }

    auto manager = WindowsProcessManager();
    manager.initialize(kosi, kosi_get_current_process_address(kosi));

    const size_t size = 1024;
    char temp[size + 1] = {'\0'};

    osi::i_t reader = manager.get_type(pstr, "UNKNOWN");

    std::string strval;
    try {
        reader.getx(temp, size);

        for (size_t idx = 0; idx < size; idx++) {
            char curr = temp[idx];

            if (curr == '\0')
                break;

            if (!isprint(curr)) {
                temp[idx] = '?';
            }
        }
        strval = std::string(temp);
    } catch (std::runtime_error const&) {
        strval = "PANDA_FAILED_TO_READ_STRING";
    }

    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String("ASCII_STRING");
    writer.Key(VALUE_KEY);
    writer.Uint(pstr);
    add_string_data(writer, "string_value", strval.c_str());
    writer.EndObject();
    return s.GetString();
}

Argument* maybe_get_related_arg(std::vector<Argument*>& args, Argument* arg,
                                ArgLookupType atype)
{
    if (!arg) {
        return nullptr;
    }

    auto argspec = arg->specification();
    if (!argspec) {
        return nullptr;
    }

    int8_t arg_index;
    switch (atype) {
    case TYPE_ARG:
        arg_index = argspec->type_arg_pos();
        break;
    case INPUT_LENGTH_ARG:
        arg_index = argspec->input_length_arg_pos();
        break;
    case OUTPUT_LENGTH_ARG:
        arg_index = argspec->output_length_arg_pos();
        break;
    default:
        arg_index = -1;
        break;
    }

    if (arg_index < 0 || arg_index > (int64_t)args.size()) {
        return nullptr;
    }

    return args[arg_index];
}

template <typename T>
void add_key_basic_information_object(WindowsProcessManager& posi,
                                      target_ulong KeyInformation,
                                      rapidjson::Writer<T>& writer)
{
    auto reader = posi.get_type(KeyInformation + KEY_BASIC_INFO_NAME_LEN, "UNKNOWN");

    writer.StartObject();
    writer.Key(VALUE_KEY);
    writer.Uint(KeyInformation);
    writer.Key("SubType");
    writer.String("KeyBasicInformation");
    auto NameLength = reader.get32();
    writer.Key("NameLength");
    writer.Uint(NameLength);
    writer.Key(NAME_KEY);
    reader.set_address(KeyInformation + KEY_BASIC_INFO_NAME);
    auto name_str = reader.get_wchar_str(NameLength);
    writer.String(name_str.c_str());
    writer.EndObject();
}

template <typename T>
void add_key_node_information_object(WindowsProcessManager& posi, CPUState* env,
                                     target_ulong KeyInformation,
                                     rapidjson::Writer<T>& writer)
{
    writer.StartObject();
    writer.Key(VALUE_KEY);
    writer.Uint(KeyInformation);
    writer.Key("SubType");
    writer.String("KeyNodeInformation");

    bool success = false;

    auto ClassOffset =
        read_value<windows_ulong>(posi, KeyInformation + KEY_NODE_INFO_CLASS, &success);
    writer.Key("ClassOffset");
    writer.Uint(ClassOffset);
    auto ClassLength = read_value<windows_ulong>(
        posi, KeyInformation + KEY_NODE_INFO_CLASS_LEN, &success);
    writer.Key("ClassLength");
    writer.Uint(ClassLength);
    writer.Key("Class");

    auto reader = posi.get_type(KeyInformation + ClassOffset, "UNKNOWN");
    if (ClassLength > 0) {
        auto class_str = reader.get_wchar_str(ClassLength);
        writer.String(class_str.c_str());
    } else {
        writer.Null();
    }

    auto NameLength = read_value<windows_ulong>(
        posi, KeyInformation + KEY_NODE_INFO_NAME_LEN, &success);
    writer.Key("NameLength");
    writer.Uint(NameLength);
    writer.Key(NAME_KEY);
    if (NameLength > 0) {
        reader.set_address(KeyInformation + KEY_NODE_INFO_NAME);
        auto node_str = reader.get_wchar_str(NameLength);
        writer.String(node_str.c_str());
    } else {
        writer.Null();
    }
    writer.EndObject();
}

template <typename T>
void add_key_full_information_object(WindowsProcessManager& posi, CPUState* env,
                                     target_ulong KeyInformation,
                                     rapidjson::Writer<T>& writer)
{
    writer.StartObject();

    writer.Key(VALUE_KEY);
    writer.Uint(KeyInformation);
    writer.Key("SubType");
    writer.String("KeyFullInformation");

    bool success = false;

    auto ClassOffset =
        read_value<windows_ulong>(posi, KeyInformation + KEY_FULL_INFO_CLASS, &success);
    writer.Key("ClassOffset");
    writer.Uint(ClassOffset);
    auto ClassLength = read_value<windows_ulong>(
        posi, KeyInformation + KEY_FULL_INFO_CLASS_LEN, &success);
    writer.Key("ClassLength");
    writer.Uint(ClassLength);
    writer.Key("Class");

    if (ClassLength > 0) {
        auto reader = posi.get_type(KeyInformation + ClassOffset, "UNKNOWN");
        auto class_str = reader.get_wchar_str(ClassLength);
        writer.String(class_str.c_str());
    } else {
        writer.Null();
    }
    auto SubKeys =
        read_value<windows_ulong>(posi, KeyInformation + KEY_FULL_INFO_SUBKEYS, &success);
    writer.Key("SubKeys");
    writer.Uint(SubKeys);
    target_ulong Values =
        read_value<target_ulong>(posi, KeyInformation + KEY_FULL_INFO_VALUES, &success);
    writer.Key("Values");
    writer.Uint(Values);
    writer.EndObject();
}

template <typename T>
void add_key_name_information_object(WindowsProcessManager& posi, CPUState* env,
                                     target_ulong KeyInformation,
                                     rapidjson::Writer<T>& writer)
{
    writer.StartObject();
    writer.Key(VALUE_KEY);
    writer.Uint(KeyInformation);
    writer.Key("SubType");
    writer.String("KeyNameInformation");

    bool success = false;

    auto NameLength = read_value<windows_ulong>(
        posi, KeyInformation + KEY_NAME_INFO_NAME_LEN, &success);
    writer.Key("NameLength");
    writer.Uint(NameLength);
    writer.Key(NAME_KEY);

    auto reader = posi.get_type(KeyInformation + KEY_NAME_INFO_NAME, "UNKNOWN");
    auto name_str = reader.get_wchar_str(NameLength);
    writer.String(name_str.c_str());
    writer.EndObject();
}

std::string stringify_key_information(CPUState* env, WindowsKernelOSI* kosi,
                                      Argument* arg, Argument* type_arg,
                                      std::vector<Argument*>& args)
{
    auto keyinfoclass = type_arg->value();
    auto output_len_arg = maybe_get_related_arg(args, arg, OUTPUT_LENGTH_ARG);
    if (output_len_arg == nullptr) {
        return "PANDA_ERROR_MissingLengthArg";
    }

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto KeyInformation = arg->value();
    if (KeyInformation == 0) {
        writer.Null();
        return s.GetString();
    }

    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String("KEY_INFORMATION_CLASS");
    writer.Key(VALUE_KEY);

    auto posi = WindowsProcessManager();
    posi.initialize(kosi, kosi_get_current_process_address(kosi));

    switch (keyinfoclass) {
    case KEY_INFO::KEY_INFO_BASIC:
        add_key_basic_information_object(posi, KeyInformation, writer);
        break;
    case KEY_INFO::KEY_INFO_NODE:
        add_key_node_information_object(posi, env, KeyInformation, writer);
        break;
    case KEY_INFO::KEY_INFO_FULL:
        add_key_full_information_object(posi, env, KeyInformation, writer);
        break;
    case KEY_INFO::KEY_INFO_NAME:
        add_key_name_information_object(posi, env, KeyInformation, writer);
        break;
    case KEY_INFO::KEY_INFO_CACHED:
    case KEY_INFO::KEY_INFO_FLAGS:
    case KEY_INFO::KEY_INFO_VIRTUALIZED:
    case KEY_INFO::KEY_INFO_HANDLE_TAGS:
        writer.String("PANDA_NOT_IMPLEMENTED");
        break;
    default:
        writer.Null();
        break;
    }
    writer.EndObject();

    return s.GetString();
}

template <typename T>
void add_base64_string_from_addr(WindowsProcessManager& posi, target_ulong dataptr,
                                 target_ulong DataLength, rapidjson::Writer<T>& writer)
{
    // TODO make sure callers don't fill up the heap...
    if (DataLength > 1024) {
        writer.String("PANDA_INVALID_BASE64_DATA");
        return;
    }

    osi::i_t reader = posi.get_type(dataptr, "UNKNOWN");

    char* buffer = new char[DataLength];
    reader.getx(*buffer, DataLength);
    std::vector<uint8_t> vbuf(buffer, buffer + DataLength);
    auto base64 = base64_encode(vbuf);

    delete buffer;
    auto strval = std::string(base64->data());
    writer.String(strval.c_str());
}

template <typename T>
void add_key_value_data(WindowsProcessManager& posi, target_ulong type,
                        target_ulong dataptr, target_ulong data_length,
                        rapidjson::Writer<T>& writer)
{
    if (dataptr == 0) {
        writer.Null();
        return;
    }

    osi::i_t reader = posi.get_type(dataptr, "UNKNOWN");
    uint8_t result;
    try {
        result = reader.get8();
    } catch (std::runtime_error const&) {
        fprintf(stderr, "[%s] %s was asked to read invalid ptr %lx\n", __FILE__, __func__,
                (uint64_t)dataptr);
        writer.Null();
        return;
    }

    switch (type) {
    case KEY_VALUE_TYPES::REG_DWORD_BIG_ENDIAN:
    case KEY_VALUE_TYPES::REG_DWORD:
        writer.Uint(reader.get32());
        break;
    case KEY_VALUE_TYPES::REG_SZ:
    case KEY_VALUE_TYPES::REG_MULTI_SZ: // TODO: get rest of these, just gets first
    case KEY_VALUE_TYPES::REG_EXPAND_SZ:
    case KEY_VALUE_TYPES::REG_LINK: {
        auto result = reader.get_wchar_str(data_length);
        writer.String(result.c_str());
        break;
    }
    case KEY_VALUE_TYPES::REG_BINARY:
        add_base64_string_from_addr(posi, dataptr, data_length, writer);
        break;
    default:
        writer.Null();
    }
}

template <typename T>
void add_key_value_basic_information_object(CPUState* env, WindowsProcessManager& posi,
                                            target_ulong KeyValueInformation,
                                            rapidjson::Writer<T>& writer)
{
    writer.StartObject();

    writer.Key("KeyValueInformationClass");
    writer.String("KeyValueBasicInformation");
    writer.Key(TYPE_KEY);

    bool success = false;

    auto keyvalue_type = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_BASIC_TYPE, &success);
    auto keyvalue_typename = translate_key_value_type(keyvalue_type);
    writer.String(keyvalue_typename);

    target_ulong NameLength = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_BASIC_NAME_LEN, &success);
    writer.Key("NameLength");
    writer.Uint(NameLength);

    writer.Key(NAME_KEY);
    if (NameLength > 0) {
        auto reader =
            posi.get_type(KeyValueInformation + KEY_VALUE_BASIC_NAME, "UNKNOWN");
        auto name_str = reader.get_wchar_str(NameLength);
        writer.String(name_str.c_str());
    } else {
        writer.Null();
    }

    writer.EndObject();
}

template <typename T>
void add_key_value_full_information_object(CPUState* env, WindowsProcessManager& posi,
                                           target_ulong KeyValueInformation,
                                           rapidjson::Writer<T>& writer, bool is_align64)
{
    if (is_align64) {
        // Sentinel code. Should be removed from production
        assert(false && "Do not know how to handle aligned key information\n");
    }

    writer.StartObject();

    writer.Key("KeyValueInformationClass");
    writer.String("KeyValueFullInformation");

    bool success = false;

    auto keyvalue_type = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_FULL_TYPE, &success);
    target_ulong DataOffset = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_FULL_DATA, &success);
    target_ulong DataLength = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_FULL_DATA_LEN, &success);
    target_ulong NameLength = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_FULL_NAME_LEN, &success);
    target_ulong nameptr = KeyValueInformation + KEY_VALUE_FULL_NAME;

    writer.Key(TYPE_KEY);
    auto keyvalue_typename = translate_key_value_type(keyvalue_type);
    writer.String(keyvalue_typename);
    writer.Key("DataOffset");
    writer.Uint(DataOffset);
    writer.Key("DataLength");
    writer.Uint(DataLength);
    writer.Key("NameLength");
    writer.Uint(NameLength);
    writer.Key(NAME_KEY);
    if (NameLength > 0) {
        auto reader = posi.get_type(nameptr, "UNKNOWN");
        auto name_str = reader.get_wchar_str(NameLength);
        writer.String(name_str.c_str());
    } else {
        writer.Null();
    }

    target_ulong dataptr =
        KeyValueInformation + DataOffset; // DataOffset specifies the offset from the
                                          // the start of this struct to the data values
    writer.Key("Data");
    add_key_value_data(posi, keyvalue_type, dataptr, DataLength, writer);

    writer.Key("Aligned");
    writer.Bool(is_align64);
    writer.EndObject();
}

template <typename T>
void add_key_value_partial_information_object(CPUState* env, WindowsProcessManager& posi,
                                              target_ulong KeyValueInformation,
                                              rapidjson::Writer<T>& writer,
                                              bool is_align64)
{
    if (is_align64) {
        assert(false && "Do not know how to handle aligned key information\n");
    }
    writer.StartObject();

    writer.Key("KeyValueInformationClass");
    writer.String("KeyValuePartialInformation");

    bool success = false;

    auto keyvalue_type = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_PARTIAL_TYPE, &success);
    auto DataLength = read_value<windows_ulong>(
        posi, KeyValueInformation + KEY_VALUE_PARTIAL_DATA_LEN, &success);

    writer.Key(TYPE_KEY);
    auto keyvalue_typename = translate_key_value_type(keyvalue_type);
    writer.String(keyvalue_typename);
    writer.Key("DataLength");
    writer.Uint(DataLength);

    target_ulong dataptr = KeyValueInformation + KEY_VALUE_PARTIAL_DATA;
    writer.Key("Data");
    add_key_value_data(posi, keyvalue_type, dataptr, DataLength, writer);

    writer.Key("Aligned");
    writer.Bool(is_align64);
    writer.EndObject();
}

std::string stringify_key_value_information(CPUState* env, WindowsKernelOSI* kosi,
                                            Argument* arg, Argument* type_arg,
                                            std::vector<Argument*>& args)
{
    auto KeyValueInformationClass = type_arg->value();
    auto output_len_arg = maybe_get_related_arg(args, arg, OUTPUT_LENGTH_ARG);
    if (output_len_arg == nullptr) {
        return "PANDA_ERROR_MissingLengthArg";
    }

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto KeyValueInformation = arg->value();
    if (KeyValueInformation == 0) {
        writer.Null();
        return s.GetString();
    }

    auto posi = WindowsProcessManager();
    posi.initialize(kosi, kosi_get_current_process_address(kosi));

    switch (KeyValueInformationClass) {
    case KEY_VALUE_INFO_BASIC:
        add_key_value_basic_information_object(env, posi, KeyValueInformation, writer);
        break;
    case KEY_VALUE_INFO_FULL:
        add_key_value_full_information_object(env, posi, KeyValueInformation, writer,
                                              false);
        break;
    case KEY_VALUE_INFO_PARTIAL:
        add_key_value_partial_information_object(env, posi, KeyValueInformation, writer,
                                                 false);
        break;
    case KEY_VALUE_INFO_FULL_ALIGN64:
        add_key_value_full_information_object(env, posi, KeyValueInformation, writer,
                                              true);
        break;
    case KEY_VALUE_INFO_PARTIAL_ALIGN64:
        add_key_value_partial_information_object(env, posi, KeyValueInformation, writer,
                                                 true);
        break;
    default:
        writer.Null();
        break;
    }

    return s.GetString();
}

template <typename T>
void add_file_rename_information_object(WindowsKernelOSI* kosi, CPUState* env,
                                        target_ulong FileRenameInformation,
                                        rapidjson::Writer<T>& writer)
{
    writer.StartObject();

    writer.Key("FileInformationClass");
    writer.String("FileRenameInformation");

    auto posi = WindowsProcessManager();
    posi.initialize(kosi, kosi_get_current_process_address(kosi));

    bool success = false;

    auto RootDirectory = read_value<target_ulong>(
        posi, FileRenameInformation + FILE_RENAME_INFORMATION_ROOT_OFFSET, &success);
    auto FileNameLength = read_value<windows_ulong>(
        posi, FileRenameInformation + FILE_RENAME_INFORMATION_LEN_OFFSET, &success);

    auto nameptr = FileRenameInformation + FILE_RENAME_INFORMATION_NAME_OFFSET;

    writer.Key("RootDirectory");
    writer.Uint(RootDirectory);

    writer.Key("FileNameLength");
    writer.Uint(FileNameLength);
    writer.Key(NAME_KEY);
    if (FileNameLength > 0 && FileNameLength < 1024) {
        osi::i_t reader = posi.get_type(nameptr, "UNKNOWN");
        auto strval = reader.get_wchar_str(FileNameLength);

        writer.String(strval.c_str());
    } else {
        writer.Null();
    }
    writer.EndObject();
}

std::string stringify_file_information(CPUState* env, WindowsKernelOSI* kosi,
                                       Argument* arg, Argument* type_arg,
                                       std::vector<Argument*>& args)
{
    auto FileInformationClass = type_arg->value();
    auto input_len_arg = maybe_get_related_arg(args, arg, INPUT_LENGTH_ARG);
    if (input_len_arg == nullptr) {
        return "PANDA_ERROR_MissingLengthArg";
    }

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto FileInformation = arg->value();
    if (FileInformation == 0) {
        writer.Null();
        return s.GetString();
    }
    switch (FileInformationClass) {
    case FILE_INFO_RENAME:
        add_file_rename_information_object(kosi, env, FileInformation, writer);
        break;
    default:
        writer.Null();
        break;
    }
    return s.GetString();
}

std::string stringify_ntsetvaluekey_data(CPUState* env, WindowsKernelOSI* kosi,
                                         Argument* arg, Argument* type_arg,
                                         std::vector<Argument*>& args)
{
    auto keyvaluetype = type_arg->value();
    auto input_len_arg = maybe_get_related_arg(args, arg, INPUT_LENGTH_ARG);
    if (input_len_arg == nullptr) {
        return "PANDA_ERROR_MissingLengthArg";
    }

    auto posi = WindowsProcessManager();
    posi.initialize(kosi, kosi_get_current_process_address(kosi));

    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    writer.StartObject();
    auto keydata = arg->value();
    writer.Key("Data");
    add_key_value_data(posi, keyvaluetype, keydata, input_len_arg->value(), writer);
    writer.EndObject();

    return s.GetString();
}

std::map<const std::string, TypedStringifyFunc> g_typed_formatters{
    {"KEY_INFORMATION_CLASS", stringify_key_information},
    {"KEY_VALUE_INFORMATION_CLASS", stringify_key_value_information},
    {"FILE_INFORMATION_CLASS", stringify_file_information}};

std::map<std::pair<std::string, std::string>, TypedStringifyFunc> g_specific_formatters{
    {{"NtSetValueKey", "ULONG"}, stringify_ntsetvaluekey_data},
};

std::string stringify_pvoid(CPUState* env, WindowsKernelOSI* kosi, CallContext* ctx,
                            Argument* arg, std::vector<Argument*>& args)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    writer.StartObject();
    writer.Key("contents");
    auto pvoid = arg->value();
    if (pvoid == 0) {
        writer.Null();
        writer.EndObject();
        return s.GetString();
    }

    // See if we have another argument we can use to resolve this PVOID
    auto type_arg = maybe_get_related_arg(args, arg, TYPE_ARG);
    if (type_arg == nullptr) {
        writer.String("NotYetImplemented");
        writer.EndObject();
        return s.GetString();
    };

    // Grab the type of the argument we are using to resolve the type of this PVOID
    auto type_arg_spec = type_arg->specification();
    auto arg_type_type = type_arg_spec ? type_arg_spec->type() : nullptr;
    if (!arg_type_type) {
        writer.String("NotYetImplemented");
        writer.EndObject();
        return s.GetString();
    }

    // Do we have a generic way to decode this type of type arg?
    auto candidate = g_typed_formatters.find(arg_type_type);
    if (candidate != g_typed_formatters.end()) {
        return candidate->second(env, kosi, arg, type_arg, args);
    }

    // Do we have a handler for this particular system call arg
    auto specific_candidate = g_specific_formatters.find(
        std::pair<std::string, std::string>(ctx->call_name(), arg_type_type));

    if (specific_candidate != g_specific_formatters.end()) {
        return specific_candidate->second(env, kosi, arg, type_arg, args);
    } else {
        fprintf(stdout, "Haven't written handler for %s in syscall %lu:%s\n",
                arg_type_type, (uint64_t)ctx->call_id(), ctx->call_name());
    }

    writer.String("NotYetImplemented");
    writer.EndObject();
    return s.GetString();
}
