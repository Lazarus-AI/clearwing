#include <stdint.h>
#include <string.h>

#include "libavformat/avformat.h"

/* Private rmdec state consumed through the public RMStream pointer. */
struct RMStream {
    AVPacket pkt;
    int videobufsize;
    int videobufpos;
    int curpic_num;
    int cur_slice, slices;
    int64_t pktpos;
    int64_t audiotimestamp;
    int sub_packet_cnt;
    int sub_packet_size, sub_packet_h, coded_framesize;
    int audio_framesize;
    int sub_packet_lengths[16];
    int32_t deint_id;
};

/* Compile the production parser into this translation unit to reach its
 * private payload context and packet callback without modifying FFmpeg. */
#include "libavformat/rdt.c"

int main(void)
{
    const int input_size = RTP_MAX_PACKET_LENGTH + 1024;
    AVFormatContext *format = avformat_alloc_context();
    AVPacket *packet = av_packet_alloc();
    PayloadContext *payload = av_mallocz(sizeof(*payload));
    AVStream *stream;
    uint8_t *input;
    uint32_t timestamp = 0;
    int ret;

    if (!format || !packet || !payload)
        return 2;
    stream = avformat_new_stream(format, NULL);
    input = av_mallocz(input_size);
    if (!stream || !input)
        return 3;
    if (rdt_init(format, stream->index, payload) < 0)
        return 4;

    payload->rmst = av_calloc(1, sizeof(*payload->rmst));
    if (!payload->rmst)
        return 5;
    payload->nb_rmst = 1;
    payload->rmst[0] = ff_rm_alloc_rmstream();
    if (!payload->rmst[0])
        return 6;

    stream->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
    stream->codecpar->codec_id = AV_CODEC_ID_AAC;
    payload->rmst[0]->deint_id = MKTAG('v', 'b', 'r', 'f');

    /* One cached AAC subpacket with a one-byte length. Parsing consumes four
     * bytes, then the RDT wrapper copies the entire remaining record. */
    input[0] = 0;
    input[1] = 0x10;
    input[2] = 0;
    input[3] = 1;

    ret = rdt_parse_packet(
        format, payload, stream, packet, &timestamp, input, input_size, 0, 0
    );

    rdt_close_context(payload);
    av_free(payload);
    av_free(input);
    av_packet_free(&packet);
    avformat_free_context(format);
    return ret < 0 ? 1 : 0;
}
