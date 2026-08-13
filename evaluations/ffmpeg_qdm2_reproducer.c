#include <stdint.h>

#include "libavformat/avformat.h"
#include "libavformat/rtpdec.h"
#include "libavformat/rtpdec_formats.h"
#include "libavutil/mem.h"

int main(void)
{
    AVFormatContext *format = avformat_alloc_context();
    AVPacket *packet = av_packet_alloc();
    AVStream *stream;
    PayloadContext *payload;
    uint32_t timestamp = 0;
    uint8_t input[40] = { 0 };
    int ret;

    if (!format || !packet)
        return 2;
    stream = avformat_new_stream(format, NULL);
    payload = av_mallocz(ff_qdm2_dynamic_handler.priv_data_size);
    if (!stream || !payload)
        return 3;

    input[0] = 0xFF;
    input[1] = 30;   /* configuration item length */
    input[2] = 4;    /* stream configuration with extradata */
    input[30] = 1;   /* big-endian block_size = 1 */
    input[31] = 2;   /* end-item length */
    input[32] = 0;   /* end-item type */
    input[33] = 0;   /* subpacket ordering ID */
    input[34] = 0;   /* one-byte subpacket length */
    input[35] = 1;   /* one byte of data */
    input[36] = 0x41;

    ret = ff_qdm2_dynamic_handler.parse_packet(
        format, payload, stream, packet, &timestamp, input, 37, 1, 0
    );

    av_free(payload);
    av_packet_free(&packet);
    avformat_free_context(format);
    return ret < 0 ? 1 : 0;
}
