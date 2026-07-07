#!/bin/bash

if [[ -z "$1" ]]; then
  echo "error"
  exit 1
fi

CLEARWING_BASE_URL="https://litellm.ops.ml.lzrops.com/v1" \
CLEARWING_LLM_BACKEND=python \
clearwing sourcehunt ./working-directory \
    --depth standard \
    --model $1 \
    --output-dir ./working-directory \
    --format json 
