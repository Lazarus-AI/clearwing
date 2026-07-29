#!/bin/bash
set -eu

if [[ -z "${1:-}" ]]; then
  echo "usage: $0 <model>" >&2
  exit 1
fi

# base_url + api_key + model must all ride the same resolution tier.
# Passing --model alone triggers the CLI tier, which ignores env/config
# and falls back to Anthropic direct — so pass base_url + api_key here too.
BASE_URL="https://litellm.ops.ml.lzrops.com/v1"
API_KEY="$RIKYVIBE_API_KEY"

CASE_DIR="$(cd "$(dirname "$0")" && pwd)"
RUN_HOME="$CASE_DIR/.clearwing-home-$$"
RUN_TRACE="$CASE_DIR/trajectories-$$"

TARGET="../FFmpeg/"

mkdir -p "$RUN_HOME" "$RUN_TRACE"

CLEARWING_HOME="$RUN_HOME" \
CLEARWING_SOURCEHUNT_TRACE_DIR="$RUN_TRACE" \
clearwing sourcehunt $TARGET \
    --base-url "$BASE_URL" \
    --api-key "$API_KEY" \
    --model "$1" \
    --depth deep \
    --agent-mode deep \
    --shard-entry-points \
    --seed-cves \
    --elaborate-pipeline \
    --exploit \
    --campaign-hint "integer overflows and type mismatches in media codec parsers" \
    --subsystem libavcodec \
    --subsystem libavutil \
    --subsystem libavformat \
    --no-mechanism-memory \
    --budget 50 \
    --tier-split 60/35/5 \
    --gvisor \
    --max-parallel 8 \
    --format json \
    --live \
    --output-dir ./results/sourcehunt/
