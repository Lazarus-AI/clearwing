#ifndef CODEC_LIMITS_H
#define CODEC_LIMITS_H

/* The "boring" file: just a constants header. surface=1, but every codec
 * trusts MAX_FRAME_BYTES to size its frame buffer. influence=5.
 *
 * If MAX_FRAME_BYTES is smaller than the largest legitimate frame, every
 * downstream memcpy() in src/codec_*.c is a heap overflow waiting to happen.
 * This is the FFmpeg-style propagation case the plan calls out.
 */

#define MAX_FRAME_BYTES 256

#endif
