set(PANDA_PLUGIN_NAME "volatility")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# The volatility plugin requires linking against python
find_package(PythonLibs 2.7 REQUIRED) 
if (NOT PYTHONLIBS_FOUND)
	message(FATAL_ERROR "Could not find python libraries. Is python-dev installed?")
endif()
include_directories(${PYTHON_INCLUDE_DIRS})

# Set flags, build, and link the actual plugin
add_definitions(-DNEED_CPU_H)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")
set(LINK_LIBS ${PYTHON_LIBRARIES} -lavro liboffset libiohal libosi) 
set(SRC_FILES ${PANDA_PLUGIN_NAME}.cc memory-server.cc filter.cc)

set(LINK_LIBS_I386 ${LINK_LIBS} panda_ipanda-i386)
set(LINK_LIBS_X86_64 ${LINK_LIBS} panda_ipanda-x86_64)

set(TARGET_DEPS_I386  panda_ipanda-i386)
set(TARGET_DEPS_X86_64 panda_ipanda-x86_64)

add_custom_command(OUTPUT ${PANDA_PLUGIN_DIR_I386}/volglue.py
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/volglue.py ${PANDA_PLUGIN_DIR_I386}/volglue.py
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/volglue.py)
add_custom_command(OUTPUT ${PANDA_PLUGIN_DIR_X86_64}/volglue.py
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/volglue.py ${PANDA_PLUGIN_DIR_X86_64}/volglue.py
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/volglue.py)
add_custom_target(volglue-script ALL 
    DEPENDS ${PANDA_PLUGIN_DIR_I386}/volglue.py ${PANDA_PLUGIN_DIR_X86_64}/volglue.py)


add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_I386)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_X86_64)
add_dependencies(${PLUGIN_TARGET}-i386 ${TARGET_DEPS_I386})
add_dependencies(${PLUGIN_TARGET}-x86_64 ${TARGET_DEPS_X86_64})

install(FILES ${PANDA_PLUGIN_DIR_I386}/volglue.py DESTINATION lib/panda/i386)
install(FILES ${PANDA_PLUGIN_DIR_X86_64}/volglue.py DESTINATION lib/panda/x86_64)
