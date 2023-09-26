set(PANDA_PLUGIN_NAME "pmemdump")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# Set flags, build and link the actual plugin
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
set(LINK_LIBS -lavro)
set(SRC_FILES ${PANDA_PLUGIN_NAME}.cpp)

set(LINK_LIBS_I386 ${LINK_LIBS})
set(LINK_LIBS_X86_64 ${LINK_LIBS})

add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_I386)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_X86_64)

#add_dependencies(${PLUGIN_TARGET}-i386 ${TARGET_DEPS_I386})
#add_dependencies(${PLUGIN_TARGET}-x86_64 ${TARGET_DEPS_X86_64})
