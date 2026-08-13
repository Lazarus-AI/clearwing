#include <stdio.h>

#include "libavfilter/dnn_filter_common.h"
#include "libavfilter/dnn_interface.h"

const DNNModule *ff_get_dnn_module(DNNBackendType backend_type, void *log_ctx)
{
    (void)backend_type;
    (void)log_ctx;
    return NULL;
}

void *ff_dnn_child_next(DnnContext *ctx, void *prev)
{
    (void)ctx;
    (void)prev;
    return NULL;
}

const AVClass *ff_dnn_child_class_iterate_with_mask(void **iter,
                                                    unsigned int backend_mask)
{
    (void)iter;
    (void)backend_mask;
    return NULL;
}

void ff_dnn_init_child_class(DnnContext *ctx)
{
    (void)ctx;
}

int main(void)
{
    DnnContext context = { 0 };

    context.backend_type = DNN_TF;
    context.model_filename = "unused-model.pb";
    context.model_inputname = "input";
    context.model_outputnames_string = "count&scores&classes&boxes";

    fprintf(stderr, "tensorflow_backend=1 requested_outputs=4\n");
    fflush(stderr);
    if (ff_dnn_init(&context, DFT_ANALYTICS_DETECT, NULL) >= 0) {
        fprintf(stderr, "unexpected_initialization_success=1\n");
        ff_dnn_uninit(&context);
        return 0;
    }

    fprintf(stderr, "initialization_returned_without_overflow=1\n");
    ff_dnn_uninit(&context);
    return 0;
}
