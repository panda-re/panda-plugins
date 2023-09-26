#ifndef __STRINGIFY_COMMON_H
#define __STRINGIFY_COMMON_H

#include "typesignature/arguments.h"
#include <rapidjson/writer.h>

extern const char* VALUE_KEY;
extern const char* CONTENTS_KEY;
extern const char* POINTER_KEY;
extern const char* TYPE_KEY;
extern const char* NAME_KEY;
extern const char* HANDLE_TYPE_KEY;
extern const char* HANDLE_NAME_KEY;
extern const char* IS_LINUX_HANDLE_KEY;

std::string stringify_unknown(Argument* arg);

#endif
