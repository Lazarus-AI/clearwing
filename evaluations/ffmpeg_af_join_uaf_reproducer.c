#include <stdint.h>
#include <stdio.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/channel_layout.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/samplefmt.h"

#define SAMPLE_RATE 48000
#define NB_SAMPLES 64

static int make_input(AVFrame **frame, float value)
{
    AVChannelLayout mono = AV_CHANNEL_LAYOUT_MONO;
    AVFrame *result = av_frame_alloc();
    int ret;

    if (!result)
        return AVERROR(ENOMEM);
    result->format = AV_SAMPLE_FMT_FLTP;
    result->sample_rate = SAMPLE_RATE;
    result->nb_samples = NB_SAMPLES;
    result->pts = 0;
    if ((ret = av_channel_layout_copy(&result->ch_layout, &mono)) < 0 ||
        (ret = av_frame_get_buffer(result, 0)) < 0) {
        av_frame_free(&result);
        return ret;
    }
    for (int i = 0; i < NB_SAMPLES; i++)
        ((float *)result->extended_data[0])[i] = value;
    *frame = result;
    return 0;
}

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

int main(void)
{
    const char *source_args =
        "time_base=1/48000:sample_rate=48000:sample_fmt=fltp:channel_layout=mono";
    const char *join_args =
        "inputs=2:channel_layout=3.0:map=0.0-FL|0.0-FR|1.0-FC";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source0 = NULL;
    AVFilterContext *source1 = NULL;
    AVFilterContext *join = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input0 = NULL;
    AVFrame *input1 = NULL;
    AVFrame *output = NULL;
    volatile float observed;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source0, graph, "abuffer", "source0", source_args) < 0 ||
        create_filter(&source1, graph, "abuffer", "source1", source_args) < 0 ||
        create_filter(&join, graph, "join", "join", join_args) < 0 ||
        create_filter(&sink, graph, "abuffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source0, 0, join, 0) < 0 ||
        avfilter_link(source1, 0, join, 1) < 0 ||
        avfilter_link(join, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }
    if (make_input(&input0, 1.0f) < 0 || make_input(&input1, 2.0f) < 0) {
        fprintf(stderr, "input_allocation_failed=1\n");
        goto done;
    }

    /* These calls transfer both input buffer references into the graph. */
    if (av_buffersrc_add_frame(source0, input0) < 0 ||
        av_buffersrc_add_frame(source1, input1) < 0) {
        fprintf(stderr, "input_submission_failed=1\n");
        goto done;
    }

    output = av_frame_alloc();
    if (!output || av_buffersink_get_frame(sink, output) < 0) {
        fprintf(stderr, "output_retrieval_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "output_channels=%d duplicate_first_planes=%d "
            "missing_third_plane_owner=%d\n",
            output->ch_layout.nb_channels,
            output->extended_data[0] == output->extended_data[1],
            av_frame_get_plane_buffer(output, 2) == NULL);
    fflush(stderr);

    /*
     * join has already freed the input frames. With the faulty deduplication
     * condition, no AVBufferRef in output owns input 1's plane. This ordinary
     * downstream read therefore accesses its freed allocation under ASan.
     */
    observed = ((float *)output->extended_data[2])[0];
    fprintf(stderr, "third_channel_sample=%f\n", observed);
    ret = 0;

done:
    av_frame_free(&output);
    av_frame_free(&input0);
    av_frame_free(&input1);
    avfilter_graph_free(&graph);
    return ret;
}
