project(panda-plugins-subbuild)
cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/release" CACHE PATH "default install path" FORCE)
endif()


# Locate and include various libraries required to build against PANDA. Most of these
# are artifacts from PANDA/QEMU's tendency to include everything everywhere
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

if (NOT GLIB_PKG_FOUND)
	message(FATAL_ERROR "Could not locate glib-2.0")
else()
	include_directories(${GLIB_PKG_INCLUDE_DIRS})
endif()

# Set directories for build products
set(PLUGIN_DIR   ${CMAKE_BINARY_DIR}/panda)
set(PANDA_PLUGIN_DIR_I386   ${PLUGIN_DIR}/i386)
set(PANDA_PLUGIN_DIR_X86_64 ${PLUGIN_DIR}/x86_64)
set(PANDA_PLUGIN_DIR_RES    ${PLUGIN_DIR}/res)

include("dependencies/CMakeExternal.cmake")


include(ExternalProject)


include("Macros.cmake")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer -DNEED_CPU_H")

message("Building PANDA3 plugins... ")
include_directories(${PANDA_SRC_DIR}/panda-wrapper/include/)
include_directories(${PANDA_SRC_DIR}/panda-wrapper/panda/include/)

include_directories(${CMAKE_BINARY_DIR}/plugins-panda-build/panda-internal-build/)


include_directories(${PANDA_SRC_DIR}/panda-wrapper/target/i386)
include_directories(${PANDA_SRC_DIR}/panda-wrapper/tcg/i386/)
include_directories(${PANDA_SRC_DIR}/panda-wrapper/tcg/)
include_directories(${PANDA_SRC_DIR}/panda-wrapper/)
set(X32_PLUGIN_INCLUDES ${PLUGIN_INCLUDES} ${CMAKE_BINARY_DIR}/plugins-panda-build/panda-internal-build/i386-softmmu)
set(X64_PLUGIN_INCLUDES ${PLUGIN_INCLUDES} ${CMAKE_BINARY_DIR}/plugins-panda-build/panda-internal-build/x86_64-softmmu)


add_subdirectory(net)
add_subdirectory(network)

