set(PANDA_PLUGIN_NAME "ipanda")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# Set flags, build and link the actual plugin
add_definitions(-DNEED_CPU_H)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -g -std=c++11")

include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(LINK_LIBS -ldistorm3 -lsqlite3 -liohal -loffset -losi)
set(SRC_FILES 
    ipanda.cc
    panda_x86.cpp
    managers/windows_common.cc
    managers/windows7.cc
    managers/linux_common.cc
    managers/linux3.cc
    memory/pandamemory.cc
    stringify/stringify_common.cc
    stringify/linux/linux3_stringifier.cc
    stringify/windows/win7_stringifier.cc
    stringify/windows/win7_objects.cc
    stringify/windows/win7_enum.cc

)

add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS)

