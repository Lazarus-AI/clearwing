#include <stdio.h>

#include "libavfilter/vf_dnn_classify.c"

int main(void)
{
    AVFrame *frame = av_frame_alloc();
    DnnClassifyContext classifier = { 0 };
    AVFilterContext filter = { 0 };
    AVDetectionBBoxHeader *header;
    AVDetectionBBox *bbox;
    float confidence = 0.9f;
    DNNData output = {
        .data = &confidence,
        .dims = { 1, 1, 1, 1 },
        .dt = DNN_FLOAT,
        .layout = DL_NCHW,
    };

    if (!frame)
        return 2;
    header = av_detection_bbox_create_side_data(frame, 1);
    if (!header) {
        av_frame_free(&frame);
        return 3;
    }

    bbox = av_get_detection_bbox(header, 0);
    classifier.confidence = 0.0f;
    classifier.dnnctx.model_filename = "five-output-model";
    filter.priv = &classifier;

    fprintf(stderr,
            "classification_capacity=%d callbacks=5 bbox_count=%u\n",
            AV_NUM_DETECTION_BBOX_CLASSIFY, header->nb_bboxes);
    for (int callback = 0; callback < 5; callback++) {
        fprintf(stderr, "callback=%d classify_count=%u\n",
                callback + 1, bbox->classify_count);
        fflush(stderr);
        if (dnn_classify_post_proc(frame, &output, 0, &filter) < 0) {
            av_frame_free(&frame);
            return 4;
        }
    }

    fprintf(stderr, "unexpected_fifth_classification_success=1\n");
    av_frame_free(&frame);
    return 0;
}
