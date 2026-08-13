#include <stdint.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/channel_layout.h"
#include "libavutil/mem.h"

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MUSEPACK7);
    AVCodecContext *context;
    AVFrame *frame;
    AVPacket *packet;
    volatile uint32_t checksum = 0;
    int ret;

    if (!codec)
        return 2;
    context = avcodec_alloc_context3(codec);
    frame = av_frame_alloc();
    packet = av_packet_alloc();
    if (!context || !frame || !packet)
        return 3;

    context->extradata = av_mallocz(16 + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!context->extradata)
        return 4;
    context->extradata_size = 16;
    context->ch_layout = (AVChannelLayout)AV_CHANNEL_LAYOUT_STEREO;
    context->sample_rate = 44100;

    /* mpc7_decode_init byte-swaps the four 32-bit extradata words. In the
     * resulting bitstream, set gapless=1 and the 11-bit last-frame length to
     * its maximum value, 2047. */
    context->extradata[14] = 0xf8;
    context->extradata[15] = 0xff;

    ret = avcodec_open2(context, codec, NULL);
    if (ret < 0)
        return 5;
    if (av_new_packet(packet, 1024) < 0)
        return 6;
    memset(packet->data, 0, packet->size);
    packet->data[1] = 1; /* last_frame */

    ret = avcodec_send_packet(context, packet);
    if (ret < 0)
        return 7;
    ret = avcodec_receive_frame(context, frame);
    if (ret < 0)
        return 8;
    if (frame->nb_samples != 2047 || frame->format != AV_SAMPLE_FMT_S16P)
        return 9;

    /* A normal consumer trusts the public nb_samples contract. The decoder's
     * backing planes contain only the 1152 samples requested from ff_get_buffer. */
    for (int channel = 0; channel < 2; channel++) {
        const int16_t *samples = (const int16_t *)frame->extended_data[channel];
        for (int sample = 0; sample < frame->nb_samples; sample++)
            checksum += samples[sample];
    }

    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&context);
    return checksum == UINT32_MAX ? 1 : 0;
}
