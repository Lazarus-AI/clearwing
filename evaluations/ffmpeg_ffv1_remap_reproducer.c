#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libavcodec/avcodec.h"
#include "libavformat/avformat.h"

static int decode_packet(const AVCodecParameters *parameters,
                         const AVPacket *source, int byte, int bit)
{
    const AVCodec *codec = avcodec_find_decoder(parameters->codec_id);
    AVCodecContext *context = avcodec_alloc_context3(codec);
    AVFrame *frame = av_frame_alloc();
    AVPacket *packet = av_packet_clone(source);
    int ret = AVERROR(ENOMEM);

    if (!codec || !context || !frame || !packet)
        goto done;
    if ((ret = av_packet_make_writable(packet)) < 0)
        goto done;
    if ((ret = avcodec_parameters_to_context(context, parameters)) < 0 ||
        (ret = avcodec_open2(context, codec, NULL)) < 0)
        goto done;

    packet->data[byte] ^= 1U << bit;
    if ((ret = avcodec_send_packet(context, packet)) >= 0)
        ret = avcodec_receive_frame(context, frame);
    if (ret >= 0)
        fprintf(stderr, "decoded_byte=%d decoded_bit=%d\n", byte, bit);

done:
    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&context);
    return ret;
}

int main(int argc, char **argv)
{
    AVFormatContext *format = NULL;
    AVPacket *packet = av_packet_alloc();
    int stream_index;
    int ret = 1;

    av_log_set_level(AV_LOG_QUIET);
    if ((argc != 2 && argc != 4) || !packet) {
        fprintf(stderr, "usage: %s sample.nut [byte bit]\n", argv[0]);
        goto done;
    }
    if (avformat_open_input(&format, argv[1], NULL, NULL) < 0 ||
        avformat_find_stream_info(format, NULL) < 0)
        goto done;
    stream_index = av_find_best_stream(format, AVMEDIA_TYPE_VIDEO,
                                       -1, -1, NULL, 0);
    if (stream_index < 0)
        goto done;
    while (av_read_frame(format, packet) >= 0) {
        if (packet->stream_index == stream_index)
            break;
        av_packet_unref(packet);
    }
    if (!packet->data)
        goto done;

    fprintf(stderr, "packet_size=%d\n", packet->size);
    if (argc == 4) {
        const int byte = atoi(argv[2]);
        const int bit = atoi(argv[3]);
        if (byte < 0 || byte >= packet->size || bit < 0 || bit > 7)
            goto done;
        fprintf(stderr, "mutation_byte=%d mutation_bit=%d\n", byte, bit);
        decode_packet(format->streams[stream_index]->codecpar,
                      packet, byte, bit);
    } else {
        for (int byte = 0; byte < packet->size; byte++) {
            for (int bit = 0; bit < 8; bit++) {
                fprintf(stderr, "mutation_byte=%d mutation_bit=%d\n", byte, bit);
                decode_packet(format->streams[stream_index]->codecpar,
                              packet, byte, bit);
            }
        }
    }
    ret = 0;

done:
    av_packet_free(&packet);
    avformat_close_input(&format);
    return ret;
}
