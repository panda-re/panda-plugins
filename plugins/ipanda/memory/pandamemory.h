#ifndef __PANDA_PHYSICAL_MEMORY_H
#define __PANDA_PHYSICAL_MEMORY_H

#include <iohal/memory/common.h>
#include <iohal/memory/physical_memory.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Load a physical memory snapshot from a file
 *
 * This method is primarily used for testing
 * \param filepath the snapshot file to load
 * \return struct PhysicalMemory*
 */
struct PhysicalMemory* create_panda_physical_memory();

#ifdef __cplusplus
}
#endif

#endif
