#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"

int main(void)
{
    const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_DVD_SUBTITLE);
    AVCodecContext *context = avcodec_alloc_context3(codec);
    AVSubtitleRect rect = { 0 };
    AVSubtitleRect *rects[] = { &rect };
    AVSubtitle subtitle = { 0 };
    uint32_t palette[256] = { 0 };
    uint8_t bitmap[200];
    uint8_t output[142];
    int ret = 2;

    if (!codec || !context)
        goto done;
    context->width = 720;
    context->height = 576;
    context->time_base = (AVRational) { 1, 1000 };
    if (avcodec_open2(context, codec, NULL) < 0)
        goto done;

    memset(bitmap, 1, sizeof(bitmap));
    palette[1] = 0xffffffff;
    rect.x = 0;
    rect.y = 0;
    rect.w = 1;
    rect.h = 200;
    rect.type = SUBTITLE_BITMAP;
    rect.linesize[0] = 1;
    rect.data[0] = bitmap;
    rect.data[1] = (uint8_t *)palette;
    subtitle.num_rects = 1;
    subtitle.rects = rects;
    subtitle.start_display_time = 0;
    subtitle.end_display_time = 1000;

    fprintf(stderr,
            "width=%d height=%d output_capacity=%zu checked_rle_budget=%d actual_rle_bytes=%d\n",
            rect.w, rect.h, sizeof(output), rect.w * rect.h / 2,
            rect.h);
    ret = avcodec_encode_subtitle(context, output, sizeof(output), &subtitle);
    fprintf(stderr, "encode_return=%d\n", ret);

done:
    avcodec_free_context(&context);
    return ret < 0 ? 1 : 0;
}
