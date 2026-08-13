#include <stdint.h>
#include <string.h>

#include "libavcodec/packet.h"
#include "libavformat/hls_sample_encryption.h"
#include "libavutil/aes.h"
#include "libavutil/mem.h"

int main(void)
{
    HLSCryptoContext crypto = { 0 };
    AVPacket *packet = av_packet_alloc();
    const int packet_size = 64;
    const int declared_frame_size = 8191;
    uint8_t *adts;
    int ret;

    if (!packet || av_new_packet(packet, packet_size) < 0)
        return 2;
    crypto.aes_ctx = av_aes_alloc();
    if (!crypto.aes_ctx)
        return 3;

    memset(packet->data, 0, packet->size);
    adts = packet->data;
    adts[0] = 0xff;
    adts[1] = 0xf1; /* sync, MPEG-4, no CRC */
    adts[2] = 0x50; /* AAC LC, 44.1 kHz */
    adts[3] = 0x80 | ((declared_frame_size >> 11) & 0x03);
    adts[4] = (uint8_t)(declared_frame_size >> 3);
    adts[5] = (declared_frame_size & 0x07) << 5;
    adts[6] = 0xfc;

    ret = ff_hls_senc_decrypt_frame(AV_CODEC_ID_AAC, &crypto, packet);

    av_free(crypto.aes_ctx);
    av_packet_free(&packet);
    return ret < 0 ? 1 : 0;
}
