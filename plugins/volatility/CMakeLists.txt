set(PANDA_PLUGIN_NAME "volatility")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# The volatility plugin requires linking against python
find_package(PythonLibs 3.12 REQUIRED)
if (NOT PYTHONLIBS_FOUND)
	message(FATAL_ERROR "Could not find python libraries. Is python-dev installed?")
endif()
include_directories(${PYTHON_INCLUDE_DIRS})

# Resolve the directory containing libpython so the plugin can find it at
# runtime even when it lives outside the standard linker search paths
# (e.g. a pyenv/venv install).
get_filename_component(PYTHON_LIBRARY_DIR ${PYTHON_LIBRARY} DIRECTORY)

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

foreach(_vol_plugin_target ${PLUGIN_TARGET}-i386 ${PLUGIN_TARGET}-x86_64)
    get_target_property(_vol_existing_rpath ${_vol_plugin_target} INSTALL_RPATH)
    set_target_properties(${_vol_plugin_target} PROPERTIES
        INSTALL_RPATH "${_vol_existing_rpath}:${PYTHON_LIBRARY_DIR}"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
endforeach()

install(FILES ${PANDA_PLUGIN_DIR_I386}/volglue.py DESTINATION lib/panda/i386)
install(FILES ${PANDA_PLUGIN_DIR_X86_64}/volglue.py DESTINATION lib/panda/x86_64)
