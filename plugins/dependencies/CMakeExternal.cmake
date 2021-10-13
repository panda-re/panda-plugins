include(ExternalProject)

set(PANDA_SRC_DIR "${CMAKE_SOURCE_DIR}/dependencies/panda" CACHE PATH "Path to the panda repo")
if(NOT EXISTS "${PANDA_SRC_DIR}")
    message(FATAL_ERROR "Could not find PANDA_SRC_DIR: ${PANDA_SRC_DIR}")
endif()

#############################
# Build the PANDA hypervisor
#############################
ExternalProject_Add(panda-ext
    SOURCE_DIR "${PANDA_SRC_DIR}"
    BINARY_DIR "${CMAKE_BINARY_DIR}/plugins-panda-build"
    INSTALL_DIR "${CMAKE_INSTALL_PREFIX}"
    INSTALL_COMMAND ""
    CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
        -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
        -DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        ${USE_PROJECT_CMAKE_MODULE_PATH}
    BUILD_BYPRODUCTS "${CMAKE_INSTALL_PREFIX}/lib/libpanda-i386.so" "${CMAKE_INSTALL_PREFIX}/lib/libpanda-x86_64.so"
    )

add_library(panda-i386 SHARED IMPORTED)
add_dependencies(panda-i386 panda-ext)
set_target_properties(panda-i386 PROPERTIES IMPORTED_LOCATION ${CMAKE_INSTALL_PREFIX}/lib/libpanda-i386.so)
set_target_properties(panda-i386 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
    ${PANDA_SRC_DIR}/qemu/panda/include)

add_library(panda-x86_64 SHARED IMPORTED)
add_dependencies(panda-x86_64 panda-ext)
set_target_properties(panda-x86_64 PROPERTIES IMPORTED_LOCATION ${CMAKE_INSTALL_PREFIX}/lib/libpanda-x86_64.so)
set_target_properties(panda-x86_64 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES
    ${PANDA_SRC_DIR}/qemu/panda/include)


set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
