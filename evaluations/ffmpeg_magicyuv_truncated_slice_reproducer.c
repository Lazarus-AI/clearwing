#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/frame.h"

#define TRUNCATED_PACKET_SIZE 300
#define RAW_PACKET_SIZE 556

static void make_packet_data(uint8_t *packet, int raw)
{
    static const uint8_t header[] = {
        0x4d, 0x41, 0x47, 0x59, 0x20, 0x00, 0x00, 0x00,
        0x07, 0x6b, 0x0c, 0x00, 0x00, 0x00, 0x20, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x0a, 0x01, 0x00, 0x00, /* table/slice area starts at 298 */
        0x0a, 0x01, 0x00, 0x00, /* plane zero's only slice starts there */
        0x01, 0x00,             /* one plane and its slice index */
    };

    memcpy(packet, header, sizeof(header));
    packet[42] = 1;
    memset(packet + 43, 9, 254);
    packet[297] = 8;
    packet[298] = raw;
    packet[299] = 1; /* supported left prediction */
    if (raw)
        memset(packet + TRUNCATED_PACKET_SIZE, 0x41, 256);
}

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MAGICYUV);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    uint8_t packet_data[RAW_PACKET_SIZE];
    unsigned transformed_prior_frame_bytes = 0;
    int ret = 1;

    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!codec || !context || !packet || !frame) {
        fprintf(stderr, "allocation_failed=1\n");
        goto done;
    }
    context->width = context->coded_width = 16;
    context->height = context->coded_height = 16;
    ret = avcodec_open2(context, codec, NULL);
    if (ret < 0) {
        fprintf(stderr, "open_failed=%d\n", ret);
        goto done;
    }
    ret = av_new_packet(packet, RAW_PACKET_SIZE);
    if (ret < 0) {
        fprintf(stderr, "packet_allocation_failed=%d\n", ret);
        goto done;
    }
    make_packet_data(packet_data, 1);
    memcpy(packet->data, packet_data, RAW_PACKET_SIZE);

    fprintf(stderr, "raw_packet_size=%d\n", RAW_PACKET_SIZE);
    ret = avcodec_send_packet(context, packet);
    if (ret < 0) {
        fprintf(stderr, "send_failed=%d\n", ret);
        goto done;
    }
    ret = avcodec_receive_frame(context, frame);
    if (ret < 0) {
        fprintf(stderr, "receive_failed=%d\n", ret);
        goto done;
    }
    av_packet_unref(packet);
    av_frame_unref(frame);

    ret = av_new_packet(packet, TRUNCATED_PACKET_SIZE);
    if (ret < 0)
        goto done;
    make_packet_data(packet_data, 0);
    memcpy(packet->data, packet_data, TRUNCATED_PACKET_SIZE);
    ret = avcodec_send_packet(context, packet);
    if (ret < 0) {
        fprintf(stderr, "truncated_send_failed=%d\n", ret);
        goto done;
    }
    ret = avcodec_receive_frame(context, frame);
    if (ret < 0) {
        fprintf(stderr, "truncated_receive_failed=%d\n", ret);
        goto done;
    }
    for (int y = 0; y < frame->height; y++)
        for (int x = 0; x < frame->width; x++)
            transformed_prior_frame_bytes +=
                frame->data[0][y * frame->linesize[0] + x] ==
                (uint8_t)(0x41 * (x + y + 1) * (x + y + 2) / 2);

    fprintf(stderr,
            "truncated_frame_decoded=1 transformed_prior_frame_bytes=%u "
            "total_pixels=256\n",
            transformed_prior_frame_bytes);
    ret = transformed_prior_frame_bytes == 256 ? 0 : 4;

done:
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret;
}
