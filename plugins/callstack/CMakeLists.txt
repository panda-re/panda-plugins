set(PANDA_PLUGIN_NAME "callstack")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# Set flags, build and link the actual plugin
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g -std=c++11")

set(LINK_LIBS -ldistorm3 -loffset -losi)
set(SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/${PANDA_PLUGIN_NAME}.cpp ${PANDA_PLUGIN_NAME}.h prog_point.h)

add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS)
