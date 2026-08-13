#include <stdint.h>
#include <stdio.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/dict.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/pixfmt.h"

#define INPUT_WIDTH 2
#define INPUT_HEIGHT 2
#define OUTPUT_WIDTH 2
#define OUTPUT_HEIGHT 2
#define FRAME_LIMIT 4096

static int create_filter(AVFilterContext **context, AVFilterGraph *graph,
                         const char *filter_name, const char *instance_name,
                         const char *arguments)
{
    const AVFilter *filter = avfilter_get_by_name(filter_name);

    if (!filter)
        return AVERROR_FILTER_NOT_FOUND;
    return avfilter_graph_create_filter(context, filter, instance_name,
                                        arguments, NULL, graph);
}

static AVFrame *make_input(int64_t pts)
{
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    frame->format = AV_PIX_FMT_YUV420P;
    frame->width = INPUT_WIDTH;
    frame->height = INPUT_HEIGHT;
    frame->pts = pts;
    frame->duration = 1;
    if (av_frame_get_buffer(frame, 0) < 0 ||
        av_dict_set(&frame->metadata, "secondary", "0", 0) < 0) {
        av_frame_free(&frame);
        return NULL;
    }
    return frame;
}

int main(void)
{
    const char *source_args =
        "video_size=2x2:pix_fmt=yuv420p:time_base=1/25:pixel_aspect=1/1";
    const char *drawgraph_args =
        "m1=missing:m2=secondary:size=2x2:mode=dot:slide=frame";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *drawgraph = NULL;
    AVFilterContext *sink = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&drawgraph, graph, "drawgraph", "drawgraph",
                      drawgraph_args) < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, drawgraph, 0) < 0 ||
        avfilter_link(drawgraph, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "missing_primary_metadata=1 secondary_metadata=1 output_width=%d\n",
            OUTPUT_WIDTH);
    fflush(stderr);
    for (int64_t pts = 0; pts < FRAME_LIMIT; pts++) {
        AVFrame *input = make_input(pts);
        AVFrame *output = av_frame_alloc();

        if (!input || !output) {
            av_frame_free(&input);
            av_frame_free(&output);
            fprintf(stderr, "frame_allocation_failed=1\n");
            goto done;
        }
        if (av_buffersrc_add_frame(source, input) < 0 ||
            av_buffersink_get_frame(sink, output) < 0) {
            av_frame_free(&input);
            av_frame_free(&output);
            fprintf(stderr, "frame_processing_failed=1 pts=%lld\n",
                    (long long)pts);
            goto done;
        }
        av_frame_free(&input);
        av_frame_free(&output);
    }

    fprintf(stderr, "frame_limit_reached=1\n");
    ret = 0;

done:
    avfilter_graph_free(&graph);
    return ret;
}
