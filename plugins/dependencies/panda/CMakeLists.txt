project(panda-build)
cmake_minimum_required(VERSION 3.0.2)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/panda-kit" CACHE PATH "default install path" FORCE)
endif()

include(ProcessorCount)
ProcessorCount(NCPU)
if (NOT NCPU EQUAL 0)
    set(EP_BUILD_ACCEL_FLAG -j${NCPU})
endif()

if (DEFINED INCLUDE_DIR)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${INCLUDE_DIR}")
endif()

if (DEFINED LIBRARIES)
    set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} ${LIBRARIES}")
endif()

include(ExternalProject)
ExternalProject_Add(panda-wrapped-ext
    SOURCE_DIR        "${PROJECT_SOURCE_DIR}/panda-wrapper"
    BINARY_DIR        "${CMAKE_BINARY_DIR}/panda-internal-build"
    INSTALL_DIR       "${CMAKE_INSTALL_PREFIX}"
    CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/panda-wrapper/configure
    ARGS
        --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu,aarch64-softmmu,ppc-softmmu,mips-softmmu,mipsel-softmmu
        --enable-llvm
        --with-llvm=/usr/lib/llvm-11
        --prefix=${CMAKE_INSTALL_PREFIX}
        --extra-cxxflags=${CMAKE_CXX_FLAGS}
        --extra-ldflags=${CMAKE_LD_FLAGS}
    BUILD_COMMAND make ${EP_BUILD_ACCEL_FLAG}
)
