/*
 * Records every listen() a process tree calls, for scripts/check/check-foxglove-bridge.py.
 *
 * The checker builds this into a shared library with the host's cc and loads it into the bridge with
 * DYLD_INSERT_LIBRARIES on macOS or LD_PRELOAD on Linux. Every process that inherits the environment
 * loads it too, so a listener opened by Python's socket module or by a native library such as zenoh's
 * is recorded. It changes no call's behaviour: each listen() runs as it would, and its outcome is
 * written, after it returns, as one contracts/listen-record/v1 record in a new file
 * listen-PID-N.zti in the directory SLIME_LISTEN_RECORDS names. N counts the process's calls, and
 * the file is created with O_EXCL, so two calls never share or overwrite a record.
 * A program that calls the system directly, or that clears the environment before it starts a child,
 * is not seen; the checker requires the bridge's own servers to be seen on every honest run.
 */

#ifndef __APPLE__
#define _GNU_SOURCE
#include <dlfcn.h>
#endif
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static void note(int fd, int ok) {
    static int calls;
    const char *directory = getenv("SLIME_LISTEN_RECORDS");
    if (directory == NULL) {
        return;
    }
    struct sockaddr_storage address;
    socklen_t size = sizeof address;
    int port = -1;
    if (getsockname(fd, (struct sockaddr *)&address, &size) == 0) {
        if (address.ss_family == AF_INET) {
            port = ntohs(((struct sockaddr_in *)&address)->sin_port);
        } else if (address.ss_family == AF_INET6) {
            port = ntohs(((struct sockaddr_in6 *)&address)->sin6_port);
        }
    }
    char path[4096];
    int named = snprintf(path, sizeof path, "%s/listen-%d-%d.zti", directory, (int)getpid(), ++calls);
    if (named < 0 || (size_t)named >= sizeof path) {
        return;
    }
    char record[160];
    int length = snprintf(record, sizeof record,
                          "{\n  formatVersion = 1;\n  pid = %d;\n  port = %d;\n  succeeded = %s;\n}\n",
                          (int)getpid(), port, ok ? "true" : "false");
    int out = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (out >= 0) {
        (void)write(out, record, (size_t)length);
        close(out);
    }
}

#ifdef __APPLE__
static int recorded_listen(int fd, int backlog) {
    int result = listen(fd, backlog);
    note(fd, result == 0);
    return result;
}

__attribute__((used)) static struct {
    const void *replacement;
    const void *original;
} interposers[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)recorded_listen, (const void *)listen},
};
#else
int listen(int fd, int backlog) {
    static int (*original)(int, int);
    if (original == NULL) {
        original = (int (*)(int, int))dlsym(RTLD_NEXT, "listen");
    }
    int result = original(fd, backlog);
    note(fd, result == 0);
    return result;
}
#endif
