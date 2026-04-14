#include <string.h>
#include "../include/codec_limits.h"

/* Decoder for codec A. Trusts MAX_FRAME_BYTES from the header. */
int decode_frame_a(const unsigned char *input, unsigned int input_len) {
    unsigned char frame[MAX_FRAME_BYTES];
    /* HEAP/STACK OVERFLOW: input_len can exceed MAX_FRAME_BYTES — caller
     * is expected to validate but doesn't always. The bug lives in the
     * header, not here. */
    memcpy(frame, input, input_len);
    return frame[0];
}
