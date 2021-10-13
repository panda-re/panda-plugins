macro(add_i386_plugin PLUGIN_NAME SRC_FILES_ARGNAME LINK_LIBS_ARGNAME)
    set(SRC_FILES ${${SRC_FILES_ARGNAME}})
    set(LINK_LIBS ${${LINK_LIBS_ARGNAME}})
    set(DEP_TARGETS ${${DEP_TARGETS_ARGNAME}})
    
    add_library(${PLUGIN_NAME}-i386 SHARED ${SRC_FILES})
    if(LINK_LIBS)
        link_directories(${PLUGIN_SUPPORT_DIR}/i386)
        target_link_libraries(${PLUGIN_NAME}-i386 ${LINK_LIBS})
    endif()
    target_include_directories(${PLUGIN_NAME}-i386 SYSTEM PRIVATE ${X32_PLUGIN_INCLUDES})
    set_target_properties(${PLUGIN_NAME}-i386 PROPERTIES OUTPUT_NAME "${PLUGIN_NAME}")
    set_target_properties(${PLUGIN_NAME}-i386 PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${PANDA_PLUGIN_DIR_I386}")
    set_target_properties(${PLUGIN_NAME}-i386 PROPERTIES INSTALL_RPATH "$ORIGIN:$ORIGIN/../../../lib")
    add_dependencies(${PLUGIN_NAME}-i386 panda-i386)
    get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
    install(TARGETS ${PLUGIN_NAME}-i386
            LIBRARY DESTINATION lib/panda/i386)
endmacro(add_i386_plugin)

macro(add_x86_64_plugin PLUGIN_NAME SRC_FILES_ARGNAME LINK_LIBS_ARGNAME)
    set(SRC_FILES ${${SRC_FILES_ARGNAME}})
    set(LINK_LIBS ${${LINK_LIBS_ARGNAME}})
    
    add_library(${PLUGIN_NAME}-x86_64 SHARED ${SRC_FILES})
    if(LINK_LIBS)
        link_directories(${PLUGIN_SUPPORT_DIR}/x86_64)
        target_link_libraries(${PLUGIN_NAME}-x86_64 ${LINK_LIBS})
    endif()
    target_include_directories(${PLUGIN_NAME}-x86_64 SYSTEM PRIVATE ${X64_PLUGIN_INCLUDES})
    set_target_properties(${PLUGIN_NAME}-x86_64 PROPERTIES OUTPUT_NAME "${PLUGIN_NAME}")
    set_target_properties(${PLUGIN_NAME}-x86_64 PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${PANDA_PLUGIN_DIR_X86_64}")
    set_target_properties(${PLUGIN_NAME}-x86_64 PROPERTIES INSTALL_RPATH "$ORIGIN:$ORIGIN/../../../lib")
    add_dependencies(${PLUGIN_NAME}-x86_64 panda-x86_64)
    install(TARGETS ${PLUGIN_NAME}-x86_64
            LIBRARY DESTINATION lib/panda/x86_64)
endmacro(add_x86_64_plugin)


