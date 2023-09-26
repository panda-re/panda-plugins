#ifndef __REGION_METADATA
#define __REGION_METADATA

/*
    Constants for extracting metadata from a VAD entry
    Tested with Windows7-SP1 32/64 bit
*/
#define PAGE_SHIFT 12
#define VADTAG_SIZE 4

#if defined(TARGET_I386) && !defined(TARGET_X86_64)
#define VADTAG_OFFSET 0x4
#define FP_ALIGN 0xfffffff8
#define PRIVATE_FLAG_SHIFT 31
#define MC_FLAG_SHIFT 23
#define TYPE_FLAG_SHIFT 20
#define PROTECTION_FLAG_SHIFT 24
//#define CC_FLAG_MASK          0x0003ffff
#elif defined(TARGET_X86_64)
#define VADTAG_OFFSET 0xc
#define FP_ALIGN 0xfffffffffffffff0
#define PRIVATE_FLAG_SHIFT 63
#define MC_FLAG_SHIFT 55
#define TYPE_FLAG_SHIFT 52
#define PROTECTION_FLAG_SHIFT 56
//#define CC_FLAG_MASK          0x0003ffffffffffff
#endif

#define MC_FLAG_MASK 0x001
#define PROTECTION_FLAG_MASK 0x1f
#define TYPE_FLAG_MASK 0x007

// struct for holding metadata
struct metadata {
    bool vad_long;
    target_ulong vad_type;
    bool private_mem;
    bool mem_commit;
    target_ulong initial_protections;
    std::string backing_file;
};

#endif
