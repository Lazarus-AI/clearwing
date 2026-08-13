#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/frame.h"

#define WIDTH 64
#define HEIGHT 64
#define VIDEO_SIZE 16

static void write_le32(uint8_t *dst, uint32_t value)
{
    dst[0] = value;
    dst[1] = value >> 8;
    dst[2] = value >> 16;
    dst[3] = value >> 24;
}

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_JV);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
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
    if (avcodec_open2(context, codec, NULL) < 0 ||
        av_new_packet(packet, 5 + VIDEO_SIZE) < 0)
        goto done;

    write_le32(packet->data, VIDEO_SIZE);
    packet->data[4] = 0;
    memset(packet->data + 5, 0xff, VIDEO_SIZE);

    fprintf(stderr, "blocks=%d video_bytes=%d max_recursive_path=1\n",
            WIDTH / 8 * (HEIGHT / 8), VIDEO_SIZE);
    fflush(stderr);
    if (avcodec_send_packet(context, packet) < 0)
        goto done;
    ret = avcodec_receive_frame(context, frame);
    fprintf(stderr, "decoder_return=%d\n", ret);
    ret = 0;

done:
    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&context);
    return ret;
}
