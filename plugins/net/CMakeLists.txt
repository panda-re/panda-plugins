set(PANDA_PLUGIN_NAME "net")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# Set flags, build and link the actual plugin
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
set(SRC_FILES ${PANDA_PLUGIN_NAME}.cpp)
set(LINK_LIBS pcap)
add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS)

