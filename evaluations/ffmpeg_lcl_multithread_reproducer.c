#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zlib.h>

#include "libavcodec/avcodec.h"
#include "libavutil/frame.h"
#include "libavutil/mem.h"

#define WIDTH 16
#define HEIGHT 16
#define FRAME_BYTES (WIDTH * HEIGHT * 3)
#define HALF_BYTES (FRAME_BYTES / 2)

static void write_le32(uint8_t *dst, uint32_t value)
{
    dst[0] = value;
    dst[1] = value >> 8;
    dst[2] = value >> 16;
    dst[3] = value >> 24;
}

static int make_packet(AVPacket *packet, const uint8_t *first, size_t first_size,
                       const uint8_t *second, size_t second_size,
                       uint32_t claimed_half_size)
{
    uLongf first_bound = compressBound(first_size);
    uLongf second_bound = compressBound(second_size);
    uint8_t *first_compressed = av_malloc(first_bound);
    uint8_t *second_compressed = av_malloc(second_bound);
    int ret = -1;

    if (!first_compressed || !second_compressed)
        goto done;
    if (compress2(first_compressed, &first_bound, first, first_size,
                  Z_BEST_SPEED) != Z_OK ||
        compress2(second_compressed, &second_bound, second, second_size,
                  Z_BEST_SPEED) != Z_OK)
        goto done;
    if (av_new_packet(packet, 8 + first_bound + second_bound) < 0)
        goto done;

    write_le32(packet->data, first_bound);
    write_le32(packet->data + 4, claimed_half_size);
    memcpy(packet->data + 8, first_compressed, first_bound);
    memcpy(packet->data + 8 + first_bound, second_compressed, second_bound);
    ret = 0;

done:
    av_free(first_compressed);
    av_free(second_compressed);
    return ret;
}

static int decode(AVCodecContext *context, AVPacket *packet, AVFrame *frame)
{
    int ret = avcodec_send_packet(context, packet);
    if (ret < 0)
        return ret;
    return avcodec_receive_frame(context, frame);
}

static int get_buffer(AVCodecContext *context, AVFrame *frame, int flags)
{
    int ret = avcodec_default_get_buffer2(context, frame, flags);

    if (ret < 0)
        return ret;
    for (int y = 0; y < context->height; y++)
        memset(frame->data[0] + y * frame->linesize[0], 0xcc,
               context->width * 3);
    return 0;
}

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_ZLIB);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    const uint8_t short_first[] = { 0x11, 0x22, 0x33 };
    const uint8_t short_second[] = { 0x44, 0x55, 0x66 };
    int stale_bytes = 0;
    int fresh_bytes = 0;
    int ret = 1;

    if (!codec)
        return 2;
    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto done;

    context->width = WIDTH;
    context->height = HEIGHT;
    context->thread_count = 1;
    context->get_buffer2 = get_buffer;
    context->extradata = av_mallocz(8 + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!context->extradata)
        goto done;
    context->extradata_size = 8;
    context->extradata[4] = 2;    /* IMGTYPE_RGB24 */
    context->extradata[5] = 0xff; /* COMP_ZLIB_NORMAL */
    context->extradata[6] = 1;    /* FLAG_MULTITHREAD */
    context->extradata[7] = 3;    /* CODEC_ZLIB */
    if (avcodec_open2(context, codec, NULL) < 0)
        goto done;

    if (make_packet(packet, short_first, sizeof(short_first), short_second,
                    sizeof(short_second), sizeof(short_first)) < 0 ||
        decode(context, packet, frame) < 0)
        goto done;

    for (int y = 0; y < HEIGHT; y++) {
        const uint8_t *row = frame->data[0] + y * frame->linesize[0];
        for (int x = 0; x < WIDTH * 3; x++) {
            stale_bytes += row[x] == 0xa5;
            fresh_bytes += row[x] == short_first[0] ||
                           row[x] == short_first[1] ||
                           row[x] == short_first[2] ||
                           row[x] == short_second[0] ||
                           row[x] == short_second[1] ||
                           row[x] == short_second[2];
        }
    }

    printf("fresh_bytes=%d leaked_malloc_fill_bytes=%d frame_bytes=%d\n",
           fresh_bytes, stale_bytes, FRAME_BYTES);
    ret = fresh_bytes == 6 && stale_bytes == FRAME_BYTES - 6 ? 0 : 1;

done:
    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&context);
    return ret;
}
