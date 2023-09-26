#ifndef __COMMON__

#define __STDC_FORMAT_MACROS
#include "panda/plugin.h"
#include "exec/cpu-defs.h"
#include "panda/common.h"
#include <zlib.h>

#if defined(TARGET_X86_64)
#define TGTLX "%016lx"
#else
#define TGTLX "%08x"
#endif

#define __COMMON__
#endif
