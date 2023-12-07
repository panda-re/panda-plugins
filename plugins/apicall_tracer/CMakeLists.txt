set(PANDA_PLUGIN_NAME "apicall_tracer")
set(PLUGIN_TARGET "panda_${PANDA_PLUGIN_NAME}")

# Set flags, build and link the actual plugin
add_definitions(-DNEED_CPU_H)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11")

set(SRC_FILES ${PANDA_PLUGIN_NAME}.cc
                        trace_engine/trace_engine.cc
                        trace_engine/current_process_osi.cc
                        trace_engine/syscall_dispatcher.cc
                        trace_engine/syscall_manager.cc
                        trace_engine/syscall_cb.cc
                        reporting/reporting.cc
                        reporting/sqlite_model.cc
                        process/block.cpp
                        process/image.cpp
                        process/process.cpp
                        process/range.cpp
                        process/vad.cpp
                        trace_filter.cc)

set(LINK_LIBS sqlite3 libosi liboffset libiohal)


set(LINK_LIBS_I386 ${LINK_LIBS}  panda_support_typesignature-i386 panda_ipanda-i386 panda_callstack-i386)
set(LINK_LIBS_X86_64 ${LINK_LIBS} panda_support_typesignature-x86_64 panda_ipanda-x86_64 panda_callstack-x86_64)

set(TARGET_DEPS_I386 panda_support_typesignature-i386
                    panda_ipanda-i386
                     panda_callstack-i386)
set(TARGET_DEPS_X86_64 panda_support_typesignature-x86_64
                       panda_ipanda-x86_64 
                       panda_callstack-x86_64)

add_i386_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_I386)
add_x86_64_plugin(${PLUGIN_TARGET} SRC_FILES LINK_LIBS_X86_64)

add_dependencies(${PLUGIN_TARGET}-i386 ${TARGET_DEPS_I386})
add_dependencies(${PLUGIN_TARGET}-x86_64 ${TARGET_DEPS_X86_64})
