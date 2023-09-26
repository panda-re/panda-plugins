#include "panda/plugin.h"
#include "exec/cpu-defs.h"
#include "stringify_common.h"

const char* VALUE_KEY = "value";
const char* CONTENTS_KEY = "contents";
const char* POINTER_KEY = "pointer";
const char* TYPE_KEY = "type";
const char* NAME_KEY = "name";
const char* HANDLE_TYPE_KEY = "handle_type";
const char* HANDLE_NAME_KEY = "handle_name";
const char* IS_LINUX_HANDLE_KEY = "is_linux_handle";

std::string stringify_unknown(Argument* arg)
{
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> writer(s);

    writer.StartObject();
    writer.Key(TYPE_KEY);
    auto argspec = arg->specification();
    if (argspec) {
        auto type = argspec->type();
        if (type) {
            writer.String(type);
        } else {
            writer.Null();
        }
    } else {
        writer.Null();
    }
    writer.Key(VALUE_KEY);
    writer.Uint(arg->value());
    writer.EndObject();

    return s.GetString();
}
