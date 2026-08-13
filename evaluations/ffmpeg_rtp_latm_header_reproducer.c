#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavutil/channel_layout.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"

#define RTP_PACKET_SIZE 1472
#define AAC_PACKET_SIZE (1500 * 0xFF)

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

    stream->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
    stream->codecpar->codec_id = AV_CODEC_ID_AAC;
    stream->codecpar->sample_rate = 48000;
    av_channel_layout_default(&stream->codecpar->ch_layout, 2);
    stream->codecpar->extradata = av_mallocz(2 + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!stream->codecpar->extradata)
        goto done;
    stream->codecpar->extradata[0] = 0x11;
    stream->codecpar->extradata[1] = 0x90;
    stream->codecpar->extradata_size = 2;
    stream->time_base = (AVRational){ 1, 48000 };

    if (av_opt_set(format->priv_data, "rtpflags", "latm", 0) < 0)
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
    if (!packet || av_new_packet(packet, AAC_PACKET_SIZE) < 0)
        goto done;
    memset(packet->data, 0, packet->size);
    packet->stream_index = stream->index;
    packet->pts = packet->dts = 0;
    packet->duration = 1024;

    fprintf(
        stderr,
        "rtp_packet_size=%d aac_packet_size=%d latm_header_size=%d\n",
        RTP_PACKET_SIZE,
        AAC_PACKET_SIZE,
        AAC_PACKET_SIZE / 0xFF + 1
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
