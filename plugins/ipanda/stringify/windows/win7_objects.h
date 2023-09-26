#ifndef WIN7_OBJECTS_H
#define WIN7_OBJECTS_H

#include <osi/windows/wintrospection.h>

/**
 *    A collection of type offsets we don't have in liboffset
 *    The offsets do hold true for all Windows7 versions, as the
 *    file name implies
 */

#if defined(TARGET_I386)
#if defined(TARGET_X86_64)
// x86_64
#define FILE_RENAME_INFORMATION_LEN_OFFSET 0x08
#define FILE_RENAME_INFORMATION_NAME_OFFSET 0x10
#define FILE_RENAME_INFORMATION_ROOT_OFFSET 0x14

#define OBJECT_HEADER_SIZE 0x30
#define CREATOR_INFO_SIZE 0x20
#define NAME_INFO_SIZE 0x20

#else
// i386
#define FILE_RENAME_INFORMATION_LEN_OFFSET 0x04
#define FILE_RENAME_INFORMATION_NAME_OFFSET 0x08
#define FILE_RENAME_INFORMATION_ROOT_OFFSET 0x0C

#define OBJECT_HEADER_SIZE 0x18
#define CREATOR_INFO_SIZE 0x10
#define NAME_INFO_SIZE 0x10

#endif
// doesn't matter
#define KEY_BASIC_INFO_NAME_LEN 0x0C
#define KEY_BASIC_INFO_NAME 0x10
#define KEY_NODE_INFO_CLASS_LEN 0x10
#define KEY_NODE_INFO_CLASS 0x0C
#define KEY_NODE_INFO_NAME_LEN 0x14
#define KEY_NODE_INFO_NAME 0x18
#define KEY_FULL_INFO_CLASS 0x0C
#define KEY_FULL_INFO_CLASS_LEN 0x10
#define KEY_FULL_INFO_SUBKEYS 0x14
#define KEY_FULL_INFO_VALUES 0x20
#define KEY_NAME_INFO_NAME 0x04
#define KEY_NAME_INFO_NAME_LEN 0x00
#define KEY_VALUE_BASIC_TYPE 0x04
#define KEY_VALUE_BASIC_NAME 0x0C
#define KEY_VALUE_BASIC_NAME_LEN 0x08
#define KEY_VALUE_PARTIAL_TYPE 0x04
#define KEY_VALUE_PARTIAL_DATA_LEN 0x08
#define KEY_VALUE_PARTIAL_DATA 0x0C
#define KEY_VALUE_FULL_TYPE 0x04
#define KEY_VALUE_FULL_DATA 0x08
#define KEY_VALUE_FULL_DATA_LEN 0x0C
#define KEY_VALUE_FULL_NAME_LEN 0x10
#define KEY_VALUE_FULL_NAME 0x14
#define CREATOR_INFO_MASK 0x01
#define NAME_INFO_MASK 0x02

#endif

void write_handle_information(rapidjson::Writer<rapidjson::StringBuffer>& writer,
                              struct WindowsHandleObject* handle);
std::string extract_handle_name(struct WindowsHandleObject* handle);

#endif
