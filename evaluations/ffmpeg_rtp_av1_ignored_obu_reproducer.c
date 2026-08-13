#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavformat/rtpdec.h"
#include "libavformat/rtpdec_formats.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"

#define IGNORED_OBU_SIZE 100
#define TRAILING_BYTES 17

int main(void)
{
    AVFormatContext *format = avformat_alloc_context();
    AVStream *stream;
    AVPacket *packet = av_packet_alloc();
    PayloadContext *payload_context = NULL;
    uint8_t payload[1 + 1 + IGNORED_OBU_SIZE + TRAILING_BYTES] = { 0 };
    uint32_t timestamp = 1;
    int ret = 1;

    if (!format || !packet)
        goto done;
    stream = avformat_new_stream(format, NULL);
    if (!stream)
        goto done;
    payload_context = av_mallocz(ff_av1_dynamic_handler.priv_data_size);
    if (!payload_context)
        goto done;

    /* N=1, W=0: first packet, with an explicit length before each OBU. */
    payload[0] = 0x08;
    payload[1] = IGNORED_OBU_SIZE;
    payload[2] = 0x10; /* AV1 temporal delimiter OBU, intentionally ignored. */

    /* Bytes inside the ignored OBU become the next parser input if its input
     * cursor is not advanced.  The ignored size also moves the output cursor
     * far beyond the packet space subsequently grown for these bytes. */
    payload[3] = 0x08;

    fprintf(stderr,
            "ignored_obu_size=%d trailing_bytes=%d expected_output_gap=%d\n",
            IGNORED_OBU_SIZE, TRAILING_BYTES, IGNORED_OBU_SIZE);
    fflush(stderr);
    ret = ff_av1_dynamic_handler.parse_packet(
        format, payload_context, stream, packet, &timestamp,
        payload, sizeof(payload), 1, RTP_FLAG_MARKER
    );
    fprintf(stderr, "parse_return=%d packet_size=%d\n", ret, packet->size);

done:
    if (ff_av1_dynamic_handler.close && payload_context)
        ff_av1_dynamic_handler.close(payload_context);
    av_free(payload_context);
    av_packet_free(&packet);
    avformat_free_context(format);
    return ret < 0 ? 2 : 0;
}
