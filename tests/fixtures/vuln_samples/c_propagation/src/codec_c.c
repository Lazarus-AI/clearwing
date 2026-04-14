#include <string.h>
#include "../include/codec_limits.h"

int decode_frame_c(const unsigned char *input, unsigned int input_len) {
    unsigned char frame[MAX_FRAME_BYTES];
    memcpy(frame, input, input_len);
    return frame[0];
}
