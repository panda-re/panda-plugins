project(panda-plugins)
cmake_minimum_required(VERSION 3.2)


set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(PANDA_ARCHS "i386-softmmu,x86_64-softmmu" CACHE STRING "The target architectures to build PANDA")

find_package(PkgConfig REQUIRED)
include(ExternalProject)

ExternalProject_Add(panda-ext
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/plugins"
    BINARY_DIR "${CMAKE_BINARY_DIR}/staging"
    INSTALL_DIR "${CMAKE_BINARY_DIR}/release"
    BUILD_ALWAYS 1
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
	-DPANDA_ARCHS=${PANDA_ARCHS}
        ${USE_PROJECT_CMAKE_MODULE_PATH}
)

install(DIRECTORY ${CMAKE_BINARY_DIR}/release/
        DESTINATION ${CMAKE_INSTALL_PREFIX}
        USE_SOURCE_PERMISSIONS
        PATTERN "CSV" EXCLUDE
        )


include(CPackConfig.txt)
