#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"

#define RTP_PACKET_SIZE 13
#define H263_PACKET_SIZE 16

static int discard_packet(void *opaque, const uint8_t *buf, int size)
{
    (void)opaque;
    (void)buf;
    return size;
}

int main(void)
{
    AVFormatContext *format = NULL;
    AVIOContext *io = NULL;
    AVPacket *packet = NULL;
    AVStream *stream;
    uint8_t *io_buffer = NULL;
    int ret = 1;

    if (avformat_alloc_output_context2(&format, NULL, "rtp", NULL) < 0)
        goto done;
    stream = avformat_new_stream(format, NULL);
    if (!stream)
        goto done;

    stream->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
    stream->codecpar->codec_id = AV_CODEC_ID_H263;
    stream->codecpar->width = 16;
    stream->codecpar->height = 16;
    stream->time_base = (AVRational){ 1, 25 };

    if (av_opt_set(format->priv_data, "rtpflags", "rfc2190", 0) < 0)
        goto done;
    io_buffer = av_malloc(RTP_PACKET_SIZE);
    if (!io_buffer)
        goto done;
    io = avio_alloc_context(
        io_buffer, RTP_PACKET_SIZE, 1, NULL, NULL, discard_packet, NULL
    );
    if (!io)
        goto done;
    io_buffer = NULL;
    io->max_packet_size = RTP_PACKET_SIZE;
    format->pb = io;
    format->flags |= AVFMT_FLAG_CUSTOM_IO;

    if (avformat_write_header(format, NULL) < 0)
        goto done;
    packet = av_packet_alloc();
    if (!packet || av_new_packet(packet, H263_PACKET_SIZE) < 0)
        goto done;
    memset(packet->data, 0, packet->size);
    packet->data[2] = 0x80;
    packet->stream_index = stream->index;
    packet->pts = packet->dts = 0;
    packet->duration = 1;

    fprintf(
        stderr,
        "rtp_packet_size=%d max_payload_size=%d fragment_size=%d\n",
        RTP_PACKET_SIZE,
        RTP_PACKET_SIZE - 12,
        RTP_PACKET_SIZE - 12 - 8
    );
    fflush(stderr);
    ret = av_write_frame(format, packet);
    fprintf(stderr, "write_return=%d\n", ret);

done:
    av_packet_free(&packet);
    if (format)
        av_write_trailer(format);
    if (io)
        avio_context_free(&io);
    else
        av_free(io_buffer);
    avformat_free_context(format);
    return ret < 0 ? 2 : 0;
}
