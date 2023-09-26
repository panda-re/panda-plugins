#include "win7_enum.h"

const char* translate_object_type(uint8_t type)
{
    switch (type) {
    case OBJECT_TYPE_Type:
        return "Type";
    case OBJECT_TYPE_Directory:
        return "Directory";
    case OBJECT_TYPE_SymbolicLink:
        return "SymbolicLink";
    case OBJECT_TYPE_Token:
        return "Token";
    case OBJECT_TYPE_Job:
        return "Job";
    case OBJECT_TYPE_Process:
        return "Process";
    case OBJECT_TYPE_Thread:
        return "Thread";
    case OBJECT_TYPE_UserApcReserve:
        return "UserApcReserve";
    case OBJECT_TYPE_IoCompletionReserve:
        return "IoCompletionReserve";
    case OBJECT_TYPE_DebugObject:
        return "DebugObject";
    case OBJECT_TYPE_Event:
        return "Event";
    case OBJECT_TYPE_EventPair:
        return "EventPair";
    case OBJECT_TYPE_Mutant:
        return "Mutant";
    case OBJECT_TYPE_Callback:
        return "Callback";
    case OBJECT_TYPE_Semaphore:
        return "Semaphore";
    case OBJECT_TYPE_Timer:
        return "Timer";
    case OBJECT_TYPE_Profile:
        return "Profile";
    case OBJECT_TYPE_KeyedEvent:
        return "KeyedEvent";
    case OBJECT_TYPE_WindowStation:
        return "WindowStation";
    case OBJECT_TYPE_Desktop:
        return "Desktop";
    case OBJECT_TYPE_TpWorkerFactory:
        return "TpWorkerFactory";
    case OBJECT_TYPE_Adapter:
        return "Adapter";
    case OBJECT_TYPE_Controller:
        return "Controller";
    case OBJECT_TYPE_Device:
        return "Device";
    case OBJECT_TYPE_Driver:
        return "Driver";
    case OBJECT_TYPE_IoCompletion:
        return "IoCompletion";
    case OBJECT_TYPE_File:
        return "File";
    case OBJECT_TYPE_TmTm:
        return "TmTm";
    case OBJECT_TYPE_TmTx:
        return "TmTx";
    case OBJECT_TYPE_TmRm:
        return "TmRm";
    case OBJECT_TYPE_TmEn:
        return "TmEn";
    case OBJECT_TYPE_Section:
        return "Section";
    case OBJECT_TYPE_Session:
        return "Session";
    case OBJECT_TYPE_Key:
        return "Key";
    case OBJECT_TYPE_ALPCPort:
        return "ALPCPort";
    case OBJECT_TYPE_PowerRequest:
        return "PowerRequest";
    case OBJECT_TYPE_WmiGuid:
        return "WmiGuid";
    case OBJECT_TYPE_EtwRegistration:
        return "EtwRegistration";
    case OBJECT_TYPE_EtwConsumer:
        return "EtwConsumer";
    case OBJECT_TYPE_FilterConnectionPort:
        return "FilterConnectionPort";
    case OBJECT_TYPE_FilterCommunicationPort:
        return "FilterCommunicationPort";
    case OBJECT_TYPE_PcwObject:
        return "PcwObject";
    default:
        return "UnknownExecutiveObject";
    }
}

const char* translate_key_information_class(target_ulong type)
{
    switch (type) {
    case KEY_INFO_BASIC:
        return "KeyBasicInformation";
    case KEY_INFO_NODE:
        return "KeyNodeInformation";
    case KEY_INFO_FULL:
        return "KeyFullInformation";
    case KEY_INFO_NAME:
        return "KeyNameInformation";
    case KEY_INFO_CACHED:
        return "KeyCachedInformation";
    case KEY_INFO_FLAGS:
        return "KeyFlagsInformation";
    case KEY_INFO_VIRTUALIZED:
        return "KeyVirtualizationInformation";
    case KEY_INFO_HANDLE_TAGS:
        return "KeyHandleTagsInformation";
    default:
        return "UnknownKeyInformationClass";
    }
}

const char* translate_key_value_information_class(target_ulong type)
{
    switch (type) {
    case KEY_VALUE_INFO_BASIC:
        return "KeyValueBasicInformation";
    case KEY_VALUE_INFO_FULL:
        return "KeyValueFullInformation";
    case KEY_VALUE_INFO_PARTIAL:
        return "KeyValuePartialInformation";
    case KEY_VALUE_INFO_FULL_ALIGN64:
        return "KeyValueFullInformationAlign64";
    case KEY_VALUE_INFO_PARTIAL_ALIGN64:
        return "KeyValuePartialInformationAlign64";
    default:
        return "UnknownKeyValueInformationClass";
    }
};

const char* translate_file_information_class(target_ulong type)
{
    switch (type) {
    case FILE_INFO_DIRECTORY:
        return "FileDirectoryInformation";
    case FILE_INFO_DIRECTORY_FULL:
        return "FileFullDirectoryInformation";
    case FILE_INFO_DIRECTORY_BOTH:
        return "FileBothDirectoryInformation";
    case FILE_INFO_BASIC:
        return "FileBasicInformation";
    case FILE_INFO_STANDARD:
        return "FileStandardInformation";
    case FILE_INFO_INTERNAL:
        return "FileInternalInformation";
    case FILE_INFO_EA:
        return "FileEaInformation";
    case FILE_INFO_ACCESS:
        return "FileAccessInformation";
    case FILE_INFO_NAME:
        return "FileNameInformation";
    case FILE_INFO_RENAME:
        return "FileRenameInformation";
    case FILE_INFO_LINK:
        return "FileLinkInformation";
    case FILE_INFO_NAMES:
        return "FileNamesInformation";
    case FILE_INFO_DISPOSITION:
        return "FileDispositionInformation";
    case FILE_INFO_POSITION:
        return "FilePositionInformation";
    case FILE_INFO_EA_FULL:
        return "FileFullEaInformation";
    case FILE_INFO_MODE:
        return "FileModeInformation";
    case FILE_INFO_ALIGNMENT:
        return "FileAlignmentInformation";
    case FILE_INFO_ALL:
        return "FileAllInformation";
    case FILE_INFO_ALLOCATION:
        return "FileAllocationInformation";
    case FILE_INFO_EOF:
        return "FileEndOfFileInformation";
    case FILE_INFO_ALTERNATE_NAME:
        return "FileAlternateNameInformation";
    case FILE_INFO_STREAM:
        return "FileStreamInformation";
    case FILE_INFO_PIPE:
        return "FilePipeInformation";
    case FILE_INFO_PIPE_LOCAL:
        return "FilePipeLocalInformation";
    case FILE_INFO_PIPE_REMOTE:
        return "FilePipeRemoteInformation";
    case FILE_INFO_MAIL_SLOT_QUERY:
        return "FileMailslotQueryInformation";
    case FILE_INFO_MAIL_SLOT_SET:
        return "FileMailslotSetInformation";
    case FILE_INFO_COMPRESSION:
        return "FileCompressionInformation";
    case FILE_INFO_OBJECT_ID:
        return "FileObjectIdInformation";
    case FILE_INFO_COMPLETION:
        return "FileCompletionInformation";
    case FILE_INFO_MOVE_CLUSTER:
        return "FileMoveClusterInformation";
    case FILE_INFO_QUOTA:
        return "FileQuotaInformation";
    case FILE_INFO_REPARSE_POINT:
        return "FileReparsePointInformation";
    case FILE_INFO_NETWORK_OPEN:
        return "FileNetworkOpenInformation";
    case FILE_INFO_ATTRIBUTE_TAG:
        return "FileAttributeTagInformation";
    case FILE_INFO_TRACKING:
        return "FileTrackingInformation";
    case FILE_INFO_ID_DIRECTORY_BOTH:
        return "FileIdBothDirectoryInformation";
    case FILE_INFO_ID_DIRECTORY_FULL:
        return "FileIdFullDirectoryInformation";
    case FILE_INFO_VALID_DATA_LENGTH:
        return "FileValidDataLengthInformation";
    case FILE_INFO_SHORT_NAME:
        return "FileShortNameInformation";
    case FILE_INFO_IO_COMPLETION_NOTIFICATION:
        return "FileIoCompletionNotificationInformation";
    case FILE_INFO_IO_STATUS_BLOCK_RANGE:
        return "FileIoStatusBlockRangeInformation";
    case FILE_INFO_IO_PRIORITY_HINT:
        return "FileIoPriorityHintInformation";
    case FILE_INFO_SFIO_RESERVE:
        return "FileSfioReserveInformation";
    case FILE_INFO_SFIO_VOLUME:
        return "FileSfioVolumeInformation";
    case FILE_INFO_HARD_LINK:
        return "FileHardLinkInformation";
    case FILE_INFO_IDS_USING_FILE:
        return "FileProcessIdsUsingFileInformation";
    case FILE_INFO_NORMALIZE_NAME:
        return "FileNormalizedNameInformation";
    case FILE_INFO_NETWORK_PHYSICAL_NAME:
        return "FileNetworkPhysicalNameInformation";
    case FILE_INFO_ID_GLOBAL_TX_DIRECTORY:
        return "FileIdGlobalTxDirectoryInformation";
    case FILE_INFO_IS_REMOTE_DEVICE:
        return "FileIsRemoteDeviceInformation";
    case FILE_INFO_UNUSED:
        return "FileUnusedInformation";
    case FILE_INFO_NUMA_NODE:
        return "FileNumaNodeInformation";
    case FILE_INFO_STANDARD_LINK:
        return "FileStandardLinkInformation";
    case FILE_INFO_REMOTE_PROTOCOL:
        return "FileRemoteProtocolInformation";
    case FILE_INFO_RENAME__BYPASSS_ACCESS_CHECK:
        return "FileRenameInformationBypassAccessCheck";
    case FILE_INFO_LINK__BYPASS_ACCESS_CHECK:
        return "FileLinkInformationBypassAccessCheck";
    case FILE_INFO_VOLUME_NAME:
        return "FileVolumeNameInformation";
    case FILE_INFO_ID:
        return "FileIdInformation";
    case FILE_INFO_ID_EXTD_DIRECTORY:
        return "FileIdExtdDirectoryInformation";
    case FILE_INFO_REPLACE_COMPLETION:
        return "FileReplaceCompletionInformation";
    case FILE_INFO_HARD_LINK_FULL_ID:
        return "FileHardLinkFullIdInformation";
    case FILE_INFO_ID_EXTD_BOTH_DIRECTORY:
        return "FileIdExtdBothDirectoryInformation";
    case FILE_INFO_MAXIMUM:
        return "FileMaximumInformation";
    default:
        return "UnknownFileInformationClass";
    }
};

const char* translate_key_value_type(target_ulong type)
{
    switch (type) {
    case REG_NONE:
        return "REG_NONE";
    case REG_SZ:
        return "REG_SZ";
    case REG_EXPAND_SZ:
        return "REG_EXPAND_SZ";
    case REG_BINARY:
        return "REG_BINARY";
    case REG_DWORD:
        return "REG_DWORD";
    case REG_DWORD_BIG_ENDIAN:
        return "REG_DWORD_BIG_ENDIAN";
    case REG_MULTI_SZ:
        return "REG_MULTI_SZ";
    case REG_RESOURCE_LIST:
        return "REG_RESOURCE_LIST";
    case REG_FULL_RESOURCE_DESCRIPTOR:
        return "REG_FULL_RESOURCE_DESCRIPTOR";
    case REG_RESOURCE_REQUIREMENTS_LIST:
        return "REG_RESOURCE_REQUIREMENTS_LIST";
    case REG_QWORD:
        return "REG_QWORD";
    }

    static char result[32];
    snprintf(result, 32, "unknown keyval: %lx", (uint64_t)type);
    return (const char*)result;
}
