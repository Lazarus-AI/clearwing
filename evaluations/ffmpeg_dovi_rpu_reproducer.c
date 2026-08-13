#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libavcodec/dovi_rpu.h"
#include "libavutil/dovi_meta.h"
#include "libavutil/mem.h"

typedef struct BitWriter {
    uint8_t data[16384];
    size_t bits;
} BitWriter;

static void write_bits(BitWriter *writer, unsigned count, uint64_t value)
{
    for (unsigned i = count; i > 0; i--) {
        size_t bit = writer->bits++;
        if ((value >> (i - 1)) & 1)
            writer->data[bit >> 3] |= 1U << (7 - (bit & 7));
    }
}

static void write_ue(BitWriter *writer, uint32_t value)
{
    uint64_t code = (uint64_t)value + 1;
    unsigned significant = 64 - __builtin_clzll(code);

    write_bits(writer, significant - 1, 0);
    write_bits(writer, significant, code);
}

static void write_se(BitWriter *writer, int32_t value)
{
    uint32_t code = value > 0 ? 2U * value - 1 : -2U * value;
    write_ue(writer, code);
}

static size_t build_parsed_rpu(BitWriter *writer)
{
    /* This exceeds set_se_golomb()'s documented 16-bit domain, but is
     * accepted by get_se_golomb_long(). Repeating it also exceeds the
     * generator's constant 177-byte allowance for an MMR segment. */
    const int32_t integer_coefficient = 100000000;

    write_bits(writer, 8, 25); /* Dolby Vision NAL prefix */
    write_bits(writer, 6, 2);  /* rpu_type */
    write_bits(writer, 11, 0); /* rpu_format */
    write_bits(writer, 4, 1);  /* vdr_rpu_profile */
    write_bits(writer, 4, 0);  /* vdr_rpu_level */
    write_bits(writer, 1, 1);  /* vdr_seq_info_present */
    write_bits(writer, 1, 0);  /* chroma_resampling_explicit_filter_flag */
    write_bits(writer, 2, RPU_COEFF_FIXED);
    write_ue(writer, 31);      /* high parser-accepted denominator */
    write_bits(writer, 2, 0);  /* vdr_rpu_normalized_idc */
    write_bits(writer, 1, 0);  /* bl_video_full_range_flag */
    write_ue(writer, 2);       /* bl_bit_depth = 10 */
    write_ue(writer, 2);       /* ext_mapping_idc = 0, el_bit_depth = 10 */
    write_ue(writer, 2);       /* vdr_bit_depth = 10 */
    write_bits(writer, 1, 0);  /* spatial_resampling_filter_flag */
    write_bits(writer, 3, 0);  /* dm_compression */
    write_bits(writer, 1, 0);  /* el_spatial_resampling_filter_flag */
    write_bits(writer, 1, 1);  /* disable_residual_flag */
    write_bits(writer, 1, 0);  /* vdr_dm_metadata_present */
    write_bits(writer, 1, 0);  /* use_prev_vdr_rpu */
    write_ue(writer, 0);       /* vdr_rpu_id */
    write_ue(writer, 0);       /* mapping_color_space */
    write_ue(writer, 0);       /* mapping_chroma_format_idc */

    for (int c = 0; c < 3; c++) {
        write_ue(writer, AV_DOVI_MAX_PIECES - 1); /* nine pivots */
        for (int i = 0; i < AV_DOVI_MAX_PIECES + 1; i++)
            write_bits(writer, 10, i ? 1 : 0);
    }

    write_ue(writer, 0); /* num_x_partitions - 1 */
    write_ue(writer, 0); /* num_y_partitions - 1 */

    for (int c = 0; c < 3; c++) {
        for (int i = 0; i < AV_DOVI_MAX_PIECES; i++) {
            write_ue(writer, AV_DOVI_MAPPING_MMR);
            write_bits(writer, 2, 2); /* mmr_order = 3 */
            for (int coefficient = 0; coefficient < 22; coefficient++) {
                write_se(writer, integer_coefficient);
                write_bits(writer, 31, 0); /* fractional component */
            }
        }
    }

    while (writer->bits & 7)
        write_bits(writer, 1, 0);
    write_bits(writer, 32, 0);   /* CRC is optional without AV_EF_CRCCHECK */
    write_bits(writer, 8, 0x80); /* terminator */
    return writer->bits / 8;
}

int main(void)
{
    BitWriter input = { 0 };
    DOVIContext parser = { 0 };
    DOVIContext generator = { 0 };
    AVDOVIMetadata *metadata = NULL;
    uint8_t *rpu = NULL;
    int rpu_size = 0;
    int ret;

    size_t input_size = build_parsed_rpu(&input);
    fprintf(stderr, "parsed_rpu_bytes=%zu segments=%d coefficients_per_segment=%d\n",
            input_size, 3 * AV_DOVI_MAX_PIECES, 22);
    parser.cfg.dv_profile = 8;
    ret = ff_dovi_rpu_parse(&parser, input.data, input_size, 0);
    if (ret < 0)
        return 2;

    ret = ff_dovi_get_metadata(&parser, &metadata);
    if (ret <= 0)
        return 3;

    generator.cfg.dv_profile = 8;
    ret = ff_dovi_rpu_generate(&generator, metadata, 0, &rpu, &rpu_size);

    av_free(rpu);
    av_free(metadata);
    ff_dovi_ctx_unref(&parser);
    ff_dovi_ctx_unref(&generator);
    return ret < 0 ? 1 : 0;
}
