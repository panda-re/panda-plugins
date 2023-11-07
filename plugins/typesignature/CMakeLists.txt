set(PANDA_PLUGIN_NAME "typesignature")
set(PLUGIN_TARGET "panda_support_${PANDA_PLUGIN_NAME}")

# Set flags, build and link the actual plugin
add_definitions(-DNEED_CPU_H)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")

set(SRC_FILES find_syscall_database.cc syscall_database.cc osi_syscalls.cc)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(LINK_LIBS -liohal -loffset -losi)
set(LINK_LIBS_I386 ${LINK_LIBS} panda_ipanda-i386)
set(LINK_LIBS_X86_64 ${LINK_LIBS} panda_ipanda-x86_64)

set(TARGET_DEPS_I386 panda_ipanda-i386)
set(TARGET_DEPS_X86_64 panda_ipanda-x86_64)

add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_I386)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_X86_64)

add_dependencies(${PLUGIN_TARGET}-i386 ${TARGET_DEPS_I386})
add_dependencies(${PLUGIN_TARGET}-x86_64 ${TARGET_DEPS_X86_64})
