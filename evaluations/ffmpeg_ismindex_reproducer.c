#include <stdint.h>

#include "libavutil/intreadwrite.h"

/* Include the production tool so its private atom reader can be exercised
 * directly without changing the vulnerable source. */
#define main ffmpeg_ismindex_main
#include "tools/ismindex.c"
#undef main

int main(void)
{
    uint8_t *input = av_mallocz(32);
    AVIOContext *io;
    struct Tracks tracks = { 0 };

    if (!input)
        return 2;
    AV_WB32(input, 0); /* zero-sized atom */
    AV_WB32(input + 4, MKBETAG('t', 'f', 'r', 'a'));
    AV_WB32(input + 12, 1); /* unknown track ID */

    io = avio_alloc_context(input, 32, 0, NULL, NULL, NULL, NULL);
    if (!io)
        return 3;

    while (!read_tfra(&tracks, 0, io)) {
        /* The production read_mfra loop has this same empty body. */
    }

    avio_context_free(&io);
    return 0;
}
