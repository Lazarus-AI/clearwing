#include <stdio.h>

/* Compile the production utility into a dedicated sanitizer binary without
 * changing either sealed FFmpeg checkout. */
#define main ffmpeg_yuvcmp_main
#include "tools/yuvcmp.c"
#undef main

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s first.yuv second.yuv\n", argv[0]);
        return 2;
    }

    char *arguments[] = {
        argv[0], argv[1], argv[2], "17", "16", "pixelcmp", NULL,
    };
    return ffmpeg_yuvcmp_main(6, arguments);
}
