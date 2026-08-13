#include <stdint.h>
#include <unistd.h>

#include "libavformat/avformat.h"
#include "libavutil/intreadwrite.h"

static int write_fixture(char *path)
{
    uint8_t input[107] = { 0 };
    uint8_t *cursor = input;
    int fd;
    ssize_t written;

    memcpy(cursor, "caff", 4); cursor += 4;
    AV_WB16(cursor, 1); cursor += 2;
    AV_WB16(cursor, 0); cursor += 2;

    memcpy(cursor, "desc", 4); cursor += 4;
    AV_WB64(cursor, 32); cursor += 8;
    AV_WB64(cursor, UINT64_C(0x40bf400000000000)); cursor += 8; /* 8000.0 */
    memcpy(cursor, "lpcm", 4); cursor += 4;
    AV_WB32(cursor, 0); cursor += 4;  /* format flags */
    AV_WB32(cursor, 0); cursor += 4;  /* variable packet bytes */
    AV_WB32(cursor, 0); cursor += 4;  /* variable packet frames */
    AV_WB32(cursor, 1); cursor += 4;  /* channels */
    AV_WB32(cursor, 16); cursor += 4; /* bits per channel */

    memcpy(cursor, "data", 4); cursor += 4;
    AV_WB64(cursor, 5); cursor += 8;
    AV_WB32(cursor, 0); cursor += 4;  /* edit count */
    *cursor++ = 0;                    /* one-byte packet */

    memcpy(cursor, "pakt", 4); cursor += 4;
    AV_WB64(cursor, 26); cursor += 8;
    AV_WB64(cursor, 1); cursor += 8;  /* one packet */
    AV_WB64(cursor, 1); cursor += 8;  /* one valid frame */
    AV_WB32(cursor, 0); cursor += 4;  /* priming */
    AV_WB32(cursor, 0); cursor += 4;  /* remainder */
    *cursor++ = 1;                    /* packet size */
    *cursor++ = 1;                    /* packet duration */

    if (cursor != input + sizeof(input))
        return -1;
    fd = mkstemp(path);
    if (fd < 0)
        return -1;
    written = write(fd, input, sizeof(input));
    close(fd);
    return written == sizeof(input) ? 0 : -1;
}

int main(void)
{
    char path[] = "/tmp/ffmpeg-caf-seek-XXXXXX";
    AVFormatContext *format = NULL;
    int ret;

    if (write_fixture(path) < 0)
        return 2;
    ret = avformat_open_input(&format, path, NULL, NULL);
    unlink(path);
    if (ret < 0)
        return 3;

    /* The parsed packet table contains one entry at timestamp zero. A forward
     * search beyond it returns -1, which the CAF callback uses as an index. */
    ret = av_seek_frame(format, 0, 1, 0);

    avformat_close_input(&format);
    return ret < 0 ? 1 : 0;
}
