#include <stdio.h>

#include "libavfilter/dnn_interface.h"
#include "libavfilter/dnn/dnn_io_proc.h"
#include "libavutil/frame.h"
#include "libavutil/mem.h"
#include "libavutil/pixfmt.h"

#define WIDTH 4
#define HEIGHT 4
#define CHANNELS 1

int main(void)
{
    AVFrame *frame = av_frame_alloc();
    float *tensor = NULL;
    DNNData output = {
        .dims = { 1, CHANNELS, HEIGHT, WIDTH },
        .dt = DNN_FLOAT,
        .layout = DL_NCHW,
        .scale = 255.0f,
        .mean = 0.0f,
    };
    int ret = 1;

    if (!frame)
        return 2;
    frame->format = AV_PIX_FMT_RGB24;
    frame->width = WIDTH;
    frame->height = HEIGHT;
    if (av_frame_get_buffer(frame, 0) < 0)
        goto done;

    /* A model may declare a one-channel output for an RGB input frame. */
    tensor = av_malloc_array(CHANNELS * WIDTH * HEIGHT, sizeof(*tensor));
    if (!tensor)
        goto done;
    for (int i = 0; i < CHANNELS * WIDTH * HEIGHT; i++)
        tensor[i] = (float)i;
    output.data = tensor;

    fprintf(stderr,
            "tensor_channels=%d tensor_elements=%d output_format=rgb24\n",
            output.dims[1], CHANNELS * WIDTH * HEIGHT);
    fflush(stderr);

    /*
     * The production NCHW postprocessor sizes middle_data from dims[1], but
     * unconditionally converts frame->width * 3 elements per row for RGB24.
     * The recorder leaves this one production function uninstrumented only to
     * get past its independent one-pointer plane-array violation; instrumented
     * libswscale then catches the undersized destination allocation.
     */
    ret = ff_proc_from_dnn_to_frame(frame, &output, NULL);
    fprintf(stderr, "postprocess_return=%d\n", ret);

done:
    av_free(tensor);
    av_frame_free(&frame);
    return ret < 0 ? 3 : ret;
}
