#include <stdint.h>

#include "libavformat/rdt.h"

int main(void)
{
    uint8_t input[16] = { 0 };
    int set_id;
    int sequence_number;
    int stream_id;
    int is_keyframe;
    uint32_t timestamp;

    input[0] = 0x80; /* status packet is followed by a data packet */
    input[1] = 0xFF; /* status packet */
    input[3] = 0;    /* big-endian packet length = 0 */
    input[4] = 0;

    return ff_rdt_parse_header(
        input,
        sizeof(input),
        &set_id,
        &sequence_number,
        &stream_id,
        &is_keyframe,
        &timestamp
    );
}
