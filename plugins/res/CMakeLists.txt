file(COPY windows_calls.db DESTINATION ${PANDA_PLUGIN_DIR_RES})
file(COPY windows_syscalls.db DESTINATION ${PANDA_PLUGIN_DIR_RES})
file(COPY linux_syscalls.db DESTINATION ${PANDA_PLUGIN_DIR_RES})

install(FILES ${PANDA_PLUGIN_DIR_RES}/windows_calls.db DESTINATION lib/panda/res)
install(FILES ${PANDA_PLUGIN_DIR_RES}/windows_syscalls.db DESTINATION lib/panda/res)
install(FILES ${PANDA_PLUGIN_DIR_RES}/linux_syscalls.db DESTINATION lib/panda/res)
