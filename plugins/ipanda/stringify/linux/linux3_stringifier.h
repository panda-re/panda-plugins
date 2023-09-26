#ifndef LINUX3_STRINGIFIER_H
#define LINUX3_STRINGIFIER_H

#include <map>
#include <string>

#include <typesignature/arguments.h>

#include <panda/common.h>

#include <osi/linux/lintrospection.h>

typedef std::string (*StringifyFunc)(LinuxProcessOSI*, struct CallContext*, Argument*);

std::string stringify_string(LinuxProcessOSI* posi, struct CallContext* ctx,
                             Argument* arg);
std::string stringify_string_array(LinuxProcessOSI* posi, struct CallContext* ctx,
                                   Argument* arg);
std::string stringify_file_descriptor(LinuxProcessOSI* posi, struct CallContext* ctx,
                                      Argument* arg);

static const std::map<const std::string, StringifyFunc> g_formatters = {
    {"PCHAR_CONST", stringify_string},
    {"PCHAR", stringify_string},
    {"PCHAR_CONST__CONST", stringify_string_array}};

#endif
