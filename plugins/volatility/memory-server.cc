/*
 * Access guest physical memory via a domain socket.
 *
 */

extern "C" {
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
}
#include "panda/plugin.h"
#include "exec/cpu-defs.h"

#include <vector>

#define QUIT_MESSAGE 0
#define READ_MESSAGE 1
#define QUERY_SIZE_MESSAGE 2

#define SUCCESS_CODE 0x79
#define FAILURE_CODE 0x77

struct __attribute__((__packed__)) request {
    uint64_t type;    // {QUIT, READ, QUERY_SIZE}_MESSAGE, ... rest reserved
    uint64_t address; // address to read from
    uint64_t length;  // number of bytes to read
};

extern "C" {
extern int panda_physical_memory_rw(uint64_t addr, uint8_t* buf, int len, bool is_write);
}

// Forward declarations
uint64_t calculate_physical_memory_size(void);
static void handle_unknown(int connection_fd, struct request* req);
static void handle_read(int connection_fd, struct request* req);
static void handle_query_size(int connection_fd, struct request* req);
static uint64_t connection_read_memory(uint64_t user_paddr, void* retbuf_in,
                                       uint64_t user_len);
static void connection_handler(int connection_fd);
static void* memory_access_thread(void* path);
static void accept_with_timeout(int socket_fd, struct sockaddr* address,
                                socklen_t* address_length);
static int setup_socket(char* path, struct sockaddr_un* address,
                        socklen_t* address_length);

// globals
bool g_accepting_connections = 0;
pthread_t g_thread_id = -1;
std::vector<pthread_t> g_thread_vector;

/**
 * Walk QEMU's internal structures to determine the size of physical memory
 *
 * This function returns the minimum interval that contains all physical
 * memory regions. Because it does not account for gaps between regions,
 * the value it calculates tends to overestimate
 */
uint64_t calculate_physical_memory_size(void) { return ram_size; }

/**
 * Retrieve guest memory for use while responding to a read request
 *
 * Args:
 *   user_paddr - the starting address to read from
 *   retbuf_in  - an array of at least user_len to read into
 *   user_len   - the number of bytes to read
 *
 * Returns:
 *   user_len
 */
static uint64_t connection_read_memory(uint64_t paddr, void* retbuf_in, uint64_t user_len)
{
    uint8_t* retbuf = (uint8_t*)retbuf_in;
    uint8_t buff[1024];
    uint64_t readlen = 0;

    uint64_t addr = paddr;
    uint64_t amount_remaining = user_len;
    uint64_t idx = 0;
    // Scan through physical memory is sizeof(buff) chunks
    while (amount_remaining > 0) {
        readlen = sizeof(buff);
        if (readlen > amount_remaining) {
            readlen = amount_remaining;
        }

        panda_physical_memory_rw(addr, buff, readlen, 0);

        uint64_t tmpidx;
        for (tmpidx = 0; tmpidx < readlen; ++tmpidx) {
            retbuf[idx++] = buff[tmpidx];
        }
        addr += readlen;
        amount_remaining -= readlen;
    }
    return user_len;
}

/**
 * utility function for writing to a socket
 *
 * returns false on failure
 */
inline bool writeall(int connection_fd, char* buff, size_t length)
{
    size_t total_written = 0;
    ssize_t bytes_written = 0;
    do {
        bytes_written =
            write(connection_fd, buff + total_written, length - total_written);
        if (bytes_written == -1) {
            fprintf(stderr, "[%s] %s failed(%lx/%lx\n", __FILE__, __func__, total_written,
                    length);
            fprintf(stderr, "[E] errno is %d: %s\n", errno, strerror(errno));
            return false;
        }
        total_written += bytes_written;
    } while (total_written < length);
    return true;
}

/**
 * Handle an incoming read request
 *
 * Responses take the following form:
 *
 *    [buffer][status]
 *
 * where
 *    buffer - a req->length buffer containing guest RAM
 *    status - byte that is SUCCESS_CODE on success, or FAILURE_CODE on failure
 *
 */
static void handle_read(int connection_fd, struct request* req)
{
    // request to read
    size_t total_length = req->length + 1;
    char* buf = (char*)malloc(total_length);
    uint64_t nbytes = connection_read_memory(req->address, buf, req->length);
    if (nbytes != req->length) {
        // read failure, return failure message
        buf[req->length] = FAILURE_CODE; // set last byte to failure
    } else {
        // read success, return bytes
        buf[req->length] = SUCCESS_CODE; // set last byte to success
    }

    writeall(connection_fd, buf, total_length);
    free(buf);
}

/**
 * Handle an incoming request to query physical memmory size
 *
 * Responses take the following form:
 *
 *    [size][status]
 *
 * where
 *    size   - uint64_t containing the upper bound on RAM addrs
 *    status - byte that is 0x01 on success, or 0x00 on failure
 *
 */
static void handle_query_size(int connection_fd, struct request* req)
{
    size_t message_size = sizeof(uint64_t);
    size_t total_size = message_size + 1;

    char buff[total_size];
    uint64_t pmemsize = calculate_physical_memory_size();

    memcpy(buff, &pmemsize, message_size);
    buff[message_size] =
        (pmemsize == 0) ? FAILURE_CODE : SUCCESS_CODE; // last byte to 1 if success

    if (pmemsize == 0) {
        fprintf(stderr, "[%s] Failed to calculate physical_memory_size\n", __FILE__);
    }

    writeall(connection_fd, buff, total_size);
}

/**
 * Default handler for unknown request types
 *
 * Responses take the following form:
 *
 *    [status]
 *
 * where
 *    status - byte that is always 0x00 to indicate failure
 *
 */
static void handle_unknown(int connection_fd, struct request* req)
{
    uint8_t buf[1];
    buf[0] = FAILURE_CODE;

    if (!writeall(connection_fd, (char*)buf, sizeof buf)) {
        fprintf(stderr, "[%s] Failed to respond to unknown command!\n", __FILE__);
    }
}

/**
 * Dispatches incoming requests to the appropriate handler
 */
static void connection_handler(int connection_fd)
{
    int nbytes;
    struct request req;

    // If the parent thread is no longer accepting connections,
    // we know the plugin is cleaning up and will make no more
    // requests
    while (g_accepting_connections) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(connection_fd, &fds);

        timeval tv;
        tv.tv_sec = 1;

        int selval = select(connection_fd + 1, &fds, NULL, NULL, &tv);
        if (selval > 0) {
            // client request should match the struct request format
            nbytes = read(connection_fd, &req, sizeof(struct request));
            if (nbytes != sizeof(struct request)) {
                // error
                continue;
            }

            switch (req.type) {
            case QUIT_MESSAGE:
                break;
            case READ_MESSAGE:
                handle_read(connection_fd, &req);
                break;
            case QUERY_SIZE_MESSAGE:
                handle_query_size(connection_fd, &req);
                break;
            default:
                handle_unknown(connection_fd, &req);
            }
        } else if (selval == 0) {
            // Timed out, try again
            continue;
        } else {
            // Caught a signal or error, bail out
            break;
        }
    }

    close(connection_fd);
}

/**
 * pthread shim to invoke connection_handler and clean up
 * the arguments passed in
 */
static void* connection_handler_gate(void* fd)
{
    connection_handler(*(int*)fd);
    free(fd);
    return NULL;
}

/**
 * Initializes a unix domain socket to listen on path
 *
 * Returns:
 *   socket_file_descriptor or a negative value for error
 */
static int setup_socket(char* path, struct sockaddr_un* address,
                        socklen_t* address_length)
{
    int socket_fd = -4;

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        fprintf(stderr, "[%s] QemuMemoryAccess: socket failed\n", __FILE__);
        return -1;
    }

    unlink(path);
    address->sun_family = AF_UNIX;
    *address_length =
        sizeof(address->sun_family) + sprintf(address->sun_path, "%s", path);

    if (bind(socket_fd, (struct sockaddr*)address, *address_length) != 0) {
        fprintf(stderr, "[%s] QemuMemoryAccess: bind failed\n", __FILE__);
        return -2;
    }
    if (listen(socket_fd, 0) != 0) {
        fprintf(stderr, "[%s] QemuMemoryAccess: listen failed\n", __FILE__);
        return -3;
    }

    return socket_fd;
}

/**
 * Listens on socket_fd and spawns a connection_handler thread for each
 * incoming connection. Threads are tracked via g_thread_vector.
 */
static void accept_with_timeout(int socket_fd, struct sockaddr* address,
                                socklen_t* address_length)
{
    int connection_fd;
    pthread_t thread;
    int* tmp_fd;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(socket_fd, &fds);

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500;

    int selval = select(socket_fd + 1, &fds, NULL, NULL, &tv);

    if (selval > 0) {
        connection_fd = accept(socket_fd, address, address_length);
        tmp_fd = (int*)calloc(1, sizeof(int));
        *tmp_fd = connection_fd;
        pthread_create(&thread, NULL, connection_handler_gate, tmp_fd);

        g_thread_vector.push_back(thread);

    } else if (selval < 0) {
        // Error occurred
        fprintf(stderr, "[%s] Error occured while listening on socket!\n", __FILE__);
    }
    // Else timeout
}

/* Main thread for memory access server */
static void* memory_access_thread(void* path)
{
    int socket_fd;
    struct sockaddr_un address;
    socklen_t address_length;

    socket_fd = setup_socket((char*)path, &address, &address_length);

    while (g_accepting_connections) {
        accept_with_timeout(socket_fd, (struct sockaddr*)&address, &address_length);
    }

    close(socket_fd);
    unlink((char*)path);
    return NULL;
}

/**
 * Start up the memory server thread.
 *
 * Returns false if the server thread fails to start
 * or has already been started
 */
bool start_memory_server(const char* path)
{
    pthread_t thread;
    sigset_t set, oldset;
    int ret;

    if (g_accepting_connections == true) {
        fprintf(stdout, "Attempting to start the memory server twice!\n");
        return false;
    }

    // create a copy of path that we can safely use
    char* pathcopy = (char*)malloc(strlen(path) + 1);
    memcpy(pathcopy, path, strlen(path) + 1);

    g_accepting_connections = true;

    // start the thread
    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &oldset);
    ret = pthread_create(&thread, NULL, memory_access_thread, pathcopy);
    pthread_sigmask(SIG_SETMASK, &oldset, NULL);

    g_thread_id = thread;
    return (ret == 0) ? true : false;
}

/**
 * Stops the memory server thread and joins on it and all of its
 * children.
 *
 */
void stop_memory_server(void)
{
    // Stop accepting new connections
    g_accepting_connections = false;

    // Cancel and join with all connection handlers
    for (auto& tid : g_thread_vector) {
        pthread_cancel(tid);
        pthread_join(tid, NULL);
    }
    g_thread_vector.clear();

    // Cancel and join with the main memory_access_thread
    pthread_cancel(g_thread_id);
    pthread_join(g_thread_id, NULL);
}
