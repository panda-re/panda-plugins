#ifndef _MEMORY_SERVER
#define _MEMORY_SERVER

/**
 * Start a pmemaccess server listening on a Unix domain socket.
 *
 * Args:
 *   path - Path for the unix domain socket to listen on
 *
 * Return:
 *   false if server fails to start, else true
 */
bool start_memory_server(const char* path);

void stop_memory_server(void);

#endif
