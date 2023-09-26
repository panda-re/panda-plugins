#ifndef WIN7_ENUMS_H
#define WIN7_ENUMS_H

#include "panda/plugin.h"
#include "panda/common.h"
#include "exec/cpu-defs.h"

/**
 * In real life, the type index is an offset into a table of pointers that leads
 * you to the correct _OBJECT_TYPE structure. Here, we have just mapped the type
 * index to the type of the corresponding _OBJECT_TYPE. The index is one byte,
 * and the first two nums are reserved for errors
 *
 * kd>??  ((nt!_OBJECT_TYPE**)@@(nt!ObTypeIndexTable))[N]
 *
 */
enum ObjectTypeIndex {
    OBJECT_TYPE_Type = 2,
    OBJECT_TYPE_Directory,
    OBJECT_TYPE_SymbolicLink,
    OBJECT_TYPE_Token,
    OBJECT_TYPE_Job,
    OBJECT_TYPE_Process,
    OBJECT_TYPE_Thread,
    OBJECT_TYPE_UserApcReserve,
    OBJECT_TYPE_IoCompletionReserve,
    OBJECT_TYPE_DebugObject,
    OBJECT_TYPE_Event,
    OBJECT_TYPE_EventPair,
    OBJECT_TYPE_Mutant,
    OBJECT_TYPE_Callback,
    OBJECT_TYPE_Semaphore,
    OBJECT_TYPE_Timer,
    OBJECT_TYPE_Profile,
    OBJECT_TYPE_KeyedEvent,
    OBJECT_TYPE_WindowStation,
    OBJECT_TYPE_Desktop,
    OBJECT_TYPE_TpWorkerFactory,
    OBJECT_TYPE_Adapter,
    OBJECT_TYPE_Controller,
    OBJECT_TYPE_Device,
    OBJECT_TYPE_Driver,
    OBJECT_TYPE_IoCompletion,
    OBJECT_TYPE_File,
    OBJECT_TYPE_TmTm,
    OBJECT_TYPE_TmTx,
    OBJECT_TYPE_TmRm,
    OBJECT_TYPE_TmEn,
    OBJECT_TYPE_Section,
    OBJECT_TYPE_Session,
    OBJECT_TYPE_Key,
    OBJECT_TYPE_ALPCPort,
    OBJECT_TYPE_PowerRequest,
    OBJECT_TYPE_WmiGuid,
    OBJECT_TYPE_EtwRegistration,
    OBJECT_TYPE_EtwConsumer,
    OBJECT_TYPE_FilterConnectionPort,
    OBJECT_TYPE_FilterCommunicationPort,
    OBJECT_TYPE_PcwObject
};

enum KEY_INFO {
    KEY_INFO_BASIC,
    KEY_INFO_NODE,
    KEY_INFO_FULL,
    KEY_INFO_NAME,
    KEY_INFO_CACHED,
    KEY_INFO_FLAGS,
    KEY_INFO_VIRTUALIZED,
    KEY_INFO_HANDLE_TAGS
};

enum KEY_VALUE_INFO {
    KEY_VALUE_INFO_BASIC,
    KEY_VALUE_INFO_FULL,
    KEY_VALUE_INFO_PARTIAL,
    KEY_VALUE_INFO_FULL_ALIGN64,
    KEY_VALUE_INFO_PARTIAL_ALIGN64
};

enum FILE_INFO {
    FILE_INFO_DIRECTORY = 1,
    FILE_INFO_DIRECTORY_FULL,
    FILE_INFO_DIRECTORY_BOTH,
    FILE_INFO_BASIC,
    FILE_INFO_STANDARD,
    FILE_INFO_INTERNAL,
    FILE_INFO_EA,
    FILE_INFO_ACCESS,
    FILE_INFO_NAME,
    FILE_INFO_RENAME,
    FILE_INFO_LINK,
    FILE_INFO_NAMES,
    FILE_INFO_DISPOSITION,
    FILE_INFO_POSITION,
    FILE_INFO_EA_FULL,
    FILE_INFO_MODE,
    FILE_INFO_ALIGNMENT,
    FILE_INFO_ALL,
    FILE_INFO_ALLOCATION,
    FILE_INFO_EOF,
    FILE_INFO_ALTERNATE_NAME,
    FILE_INFO_STREAM,
    FILE_INFO_PIPE,
    FILE_INFO_PIPE_LOCAL,
    FILE_INFO_PIPE_REMOTE,
    FILE_INFO_MAIL_SLOT_QUERY,
    FILE_INFO_MAIL_SLOT_SET,
    FILE_INFO_COMPRESSION,
    FILE_INFO_OBJECT_ID,
    FILE_INFO_COMPLETION,
    FILE_INFO_MOVE_CLUSTER,
    FILE_INFO_QUOTA,
    FILE_INFO_REPARSE_POINT,
    FILE_INFO_NETWORK_OPEN,
    FILE_INFO_ATTRIBUTE_TAG,
    FILE_INFO_TRACKING,
    FILE_INFO_ID_DIRECTORY_BOTH,
    FILE_INFO_ID_DIRECTORY_FULL,
    FILE_INFO_VALID_DATA_LENGTH,
    FILE_INFO_SHORT_NAME,
    FILE_INFO_IO_COMPLETION_NOTIFICATION,
    FILE_INFO_IO_STATUS_BLOCK_RANGE,
    FILE_INFO_IO_PRIORITY_HINT,
    FILE_INFO_SFIO_RESERVE,
    FILE_INFO_SFIO_VOLUME,
    FILE_INFO_HARD_LINK,
    FILE_INFO_IDS_USING_FILE,
    FILE_INFO_NORMALIZE_NAME,
    FILE_INFO_NETWORK_PHYSICAL_NAME,
    FILE_INFO_ID_GLOBAL_TX_DIRECTORY,
    FILE_INFO_IS_REMOTE_DEVICE,
    FILE_INFO_UNUSED,
    FILE_INFO_NUMA_NODE,
    FILE_INFO_STANDARD_LINK,
    FILE_INFO_REMOTE_PROTOCOL,
    FILE_INFO_RENAME__BYPASSS_ACCESS_CHECK,
    FILE_INFO_LINK__BYPASS_ACCESS_CHECK,
    FILE_INFO_VOLUME_NAME,
    FILE_INFO_ID,
    FILE_INFO_ID_EXTD_DIRECTORY,
    FILE_INFO_REPLACE_COMPLETION,
    FILE_INFO_HARD_LINK_FULL_ID,
    FILE_INFO_ID_EXTD_BOTH_DIRECTORY,
    FILE_INFO_MAXIMUM
};

enum KEY_VALUE_TYPES {
    REG_NONE,
    REG_SZ,
    REG_EXPAND_SZ,
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_LINK,
    REG_MULTI_SZ,
    REG_RESOURCE_LIST,
    REG_FULL_RESOURCE_DESCRIPTOR,
    REG_RESOURCE_REQUIREMENTS_LIST,
    REG_QWORD
};

const char* translate_object_type(uint8_t type);
const char* translate_key_information_class(target_ulong type);
const char* translate_key_value_information_class(target_ulong type);
const char* translate_file_information_class(target_ulong type);
const char* translate_key_value_type(target_ulong type);

#endif
