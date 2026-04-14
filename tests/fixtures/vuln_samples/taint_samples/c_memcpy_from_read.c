#include <string.h>
#include <unistd.h>

/* Canonical taint case: data read from fd is copied via memcpy. */
int process_packet(int fd) {
    char buf[64];
    unsigned int n;
    /* SOURCE: read() populates `buf`. `n` is the return value. */
    n = read(fd, buf, sizeof(buf));
    if (n <= 0) return -1;

    char frame[32];
    /* SINK: memcpy's length `n` is tainted (came from read). */
    memcpy(frame, buf, n);
    return frame[0];
}

/* Clean function — no source, no sink. */
int helper(int x) {
    return x * 2;
}
