set(PANDA_PLUGIN_NAME "logging_events")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# The logging events plugin requires linking against python
#find_package(PythonLibs 3.8 REQUIRED)
#if (NOT PYTHONLIBS_FOUND)
#	message(FATAL_ERROR "Could not find python libraries. Is python-dev installed?")
#endif()
#include_directories(${PYTHON_INCLUDE_DIRS})

# Set flags, build, and link the actual plugin
add_definitions(-DNEED_CPU_H)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
set(LINK_LIBS ${PYTHON_LIBRARIES} -lavro liboffset libiohal libosi)
set(SRC_FILES ${PANDA_PLUGIN_NAME}.cpp)


set(LINK_LIBS_I386 ${LINK_LIBS} panda_ipanda-i386 panda_callstack-i386 panda_apicall_tracer-i386)
set(LINK_LIBS_X86_64 ${LINK_LIBS} panda_ipanda-x86_64 panda_callstack-x86_64 panda_apicall_tracer-x86_64)

set(TARGET_DEPS_I386 panda_ipanda-i386)
set(TARGET_DEPS_X86_64 panda_ipanda-x86_64)

# add_custom_command(OUTPUT ${PANDA_PLUGIN_DIR_I386}/evtxglue.py
#    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/evtxglue.py ${PANDA_PLUGIN_DIR_I386}/evtxglue.py
#   DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/evtxglue.py)
# add_custom_command(OUTPUT ${PANDA_PLUGIN_DIR_X86_64}/evtxglue.py
#    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/evtxglue.py ${PANDA_PLUGIN_DIR_X86_64}/evtxglue.py
#    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/evtxglue.py)
# add_custom_target(evtxglue-script ALL 
#    DEPENDS ${PANDA_PLUGIN_DIR_I386}/evtxglue.py ${PANDA_PLUGIN_DIR_X86_64}/evtxglue.py)

add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_I386)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_X86_64)

add_dependencies(${PLUGIN_TARGET}-i386 ${TARGET_DEPS_I386})
add_dependencies(${PLUGIN_TARGET}-x86_64 ${TARGET_DEPS_X86_64})

# install(FILES ${PANDA_PLUGIN_DIR_I386}/evtxglue.py DESTINATION lib/panda/i386)
# install(FILES ${PANDA_PLUGIN_DIR_X86_64}/evtxglue.py DESTINATION lib/panda/x86_64)