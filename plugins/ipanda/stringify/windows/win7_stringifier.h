#ifndef WIN7_STRINGIFIER_H
#define WIN7_STRINGIFIER_H

#include <map>
#include <string>

#include "typesignature/arguments.h"

#include <osi/windows/wintrospection.h>
#include <panda/common.h>

typedef std::string (*StringifyFunc)(CPUState*, WindowsKernelOSI*, Argument*);
typedef std::string (*TypedStringifyFunc)(CPUState*, WindowsKernelOSI*, Argument*,
                                          Argument*, std::vector<Argument*>&);

std::string stringify_handle(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_phandle(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_ulong(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_pulong(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_pobject_attributes(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_punicode_string(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_wchar_string(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_ascii_string(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_access_mask(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_paccess_mask(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_paccess_mask(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_key_information_class(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_file_information_class(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_key_value_information_class(CPUState*, WindowsKernelOSI*,
                                                  Argument*);
std::string stringify_plarge_integer(CPUState*, WindowsKernelOSI*, Argument*);
std::string stringify_puser_process_parameters(CPUState*, WindowsKernelOSI*, Argument*);

std::string stringify_key_information(CPUState*, WindowsKernelOSI*, Argument*, Argument*,
                                      std::vector<Argument*>&);
std::string stringify_key_value_information(CPUState*, WindowsKernelOSI*, Argument*,
                                            Argument*, std::vector<Argument*>&);
std::string stringify_file_information(CPUState*, WindowsKernelOSI*, Argument*, Argument*,
                                       std::vector<Argument*>&);
std::string stringify_ntsetvaluekey_data(CPUState*, WindowsKernelOSI*, Argument*,
                                         Argument*, std::vector<Argument*>&);

static const std::map<const std::string, StringifyFunc> g_formatters = {
    // TODO this should probably be case insensitive
    {"HANDLE", stringify_handle},
    {"PHANDLE", stringify_phandle},
    {"ULONG", stringify_ulong},
    {"PULONG", stringify_pulong},
    {"POBJECT_ATTRIBUTES", stringify_pobject_attributes},
    {"PUNICODE_STRING", stringify_punicode_string},
    {"LPCWSTR", stringify_wchar_string},
    {"LPWSTR", stringify_wchar_string},
    {"PCWSTR", stringify_wchar_string},
    {"PWSTR", stringify_wchar_string},
    {"LPCSTR", stringify_ascii_string},
    {"LPSTR", stringify_ascii_string},
    {"PCSTR", stringify_ascii_string},
    {"PSTR", stringify_ascii_string},
    {"PCHAR", stringify_ascii_string},
    {"ACCESS_MASK", stringify_access_mask},
    {"PACCESS_MASK", stringify_paccess_mask},
    {"KEY_INFORMATION_CLASS", stringify_key_information_class},
    {"KEY_VALUE_INFORMATION_CLASS", stringify_key_value_information_class},
    {"FILE_INFORMATION_CLASS", stringify_file_information_class},
    {"PLARGE_INTEGER", stringify_plarge_integer},
    {"PRTL_USER_PROCESS_PARAMETERS", stringify_puser_process_parameters},
};

std::string stringify_pvoid(CPUState* env, WindowsKernelOSI* kosi, CallContext* ctx,
                            Argument* arg, std::vector<Argument*>& args);

#endif
