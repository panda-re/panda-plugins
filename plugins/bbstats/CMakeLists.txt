set(PANDA_PLUGIN_NAME "bbstats")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# Set flags, build and link the actual plugin
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(LINK_LIBS -lavro -ldistorm3 liboffset libiohal libosi)
set(SRC_FILES ${PANDA_PLUGIN_NAME}.cpp block.cpp filter.cpp image.cpp process.cpp range.cpp)
set(LINK_LIBS_I386 ${LINK_LIBS} panda_ipanda-i386)
set(LINK_LIBS_X86_64 ${LINK_LIBS} panda_ipanda-x86_64)

set(TARGET_DEPS_I386  panda_ipanda-i386)
set(TARGET_DEPS_X86_64 panda_ipanda-x86_64)

add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_I386)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_X86_64)
add_dependencies(${PLUGIN_TARGET}-i386 ${TARGET_DEPS_I386})
add_dependencies(${PLUGIN_TARGET}-x86_64 ${TARGET_DEPS_X86_64})
