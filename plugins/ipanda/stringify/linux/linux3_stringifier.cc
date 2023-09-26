#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

#include <offset/array_t.h>
#include <offset/i_t.h>
#include <osi/linux/lintrospection.h>

#include "ipanda/stringify/stringify_common.h"
#include "linux3_stringifier.h"

#include "typesignature/arguments.h"

// add_*_data:   adds data fields without {start,end}object
// add_*_object: adds an object with {start,end}object

std::string stringify_string(LinuxProcessOSI* posi, struct CallContext* ctx,
                             Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);
    auto pstr = arg->value();
    if (pstr == 0) {
        writer.Null();
        return s.GetString();
    }

    const size_t size = 1024;
    char temp[size + 1]{'\0'};

    osi::i_t reader(posi->vmem, posi->tlib, pstr, "UNKNOWN");

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
    } catch (std::runtime_error const&) {
    }

    std::string strval(temp);

    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String(arg->specification()->type());
    writer.Key(VALUE_KEY);
    writer.Uint(pstr);
    writer.Key("string_value");
    writer.String(strval.c_str());
    writer.EndObject();

    return s.GetString();
}

std::string stringify_string_array(LinuxProcessOSI* posi, struct CallContext* ctx,
                                   Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);

    writer.StartObject();
    writer.Key(TYPE_KEY);
    writer.String(arg->specification()->type());
    writer.Key(POINTER_KEY);
    auto ptr = arg->value();
    writer.Uint(ptr);
    writer.Key(CONTENTS_KEY);
    if (ptr == 0) {
        writer.Null();
    } else {
        writer.String("NotYetImplemented");
    }
    writer.EndObject();
    return s.GetString();
}

std::string get_path_from_fd(LinuxProcessOSI* posi, uint64_t fd)
{
    osi::i_t task(posi->vmem, posi->tlib, posi->process_address, "task_struct");

    auto fd_table = task("files")("fdt");
    if (fd_table["max_fds"].get32() < fd)
        return "";

    osi::array_t table(fd_table["fd"]);
    osi::i_t file = table.get_element(fd);

    char path[4096] = {'\0'};
    get_dentry_path(file["f_path"].set_type("path")("dentry"), path);

    return std::string(path);
}

std::string stringify_file_descriptor(LinuxProcessOSI* posi, struct CallContext* ctx,
                                      Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);

    auto fd = arg->value();
    writer.StartObject();
    writer.Key("type");
    writer.String(arg->specification()->type());
    writer.Key("value");
    writer.Uint(fd);
    writer.Key("is_linux_handle");
    writer.Bool(true);
    writer.Key("contents");

    auto fdpath = get_path_from_fd(posi, fd);

    if (!fdpath.empty()) {
        writer.StartObject();
        writer.Key("handle_name");
        writer.String(fdpath.c_str());
        writer.Key("handle_type");
        writer.String("File");
        writer.EndObject();
    } else {
        writer.Null();
    }
    writer.EndObject();

    return s.GetString();
}
