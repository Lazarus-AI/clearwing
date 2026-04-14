/* Tiny heap-overflow sample for sandbox integration tests.
 *
 * Reads bytes from stdin into a fixed buffer with no length check.
 * Compile with: gcc -fsanitize=address -g -O0 main.c -o main
 * Trigger:      printf 'AAAAAAAAAA...300...AAAA' | ./main
 *
 * ASan should print "heap-buffer-overflow" on stderr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int parse_packet(const char *buf, size_t len) {
    char *frame = malloc(64);
    /* HEAP-BUFFER-OVERFLOW: caller-controlled `len` can exceed 64. */
    memcpy(frame, buf, len);
    int r = frame[0];
    free(frame);
    return r;
}

int main(void) {
    char input[1024];
    ssize_t n = read(0, input, sizeof(input));
    if (n <= 0) return 0;
    return parse_packet(input, (size_t)n);
}
