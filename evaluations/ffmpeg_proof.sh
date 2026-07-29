#!/usr/bin/env bash
set -euo pipefail

FFMPEG_DIR="${FFMPEG_DIR:?set FFMPEG_DIR to an FFmpeg checkout}"
CASE_DIR="${CASE_DIR:-$PWD/results/ffmpeg-proof}"
CLEARWING_BIN="${CLEARWING_BIN:-clearwing}"
VULNERABLE_COMMIT="795bccdaf57772b1803914dee2f32d52776518e2"
FIXED_COMMIT="39e1969303a0b9ec5fb5f5eb643bf7a5b69c0a89"

command -v bear >/dev/null || {
  echo "bear is required to produce compile_commands.json" >&2
  exit 2
}
command -v docker >/dev/null || {
  echo "Docker is required for isolated Clang and runtime actions" >&2
  exit 2
}

mkdir -p "$CASE_DIR"

build_database() {
  git -C "$FFMPEG_DIR" clean -fdx
  (
    cd "$FFMPEG_DIR"
    ./configure \
      --cc=clang \
      --cxx=clang++ \
      --disable-doc \
      --enable-decoder=h264 \
      --enable-parser=h264 \
      --disable-stripping \
      --disable-optimizations \
      --enable-debug=3 \
      --extra-cflags='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1' \
      --extra-ldflags='-fsanitize=address,undefined'
    bear -- make -j"${JOBS:-4}"
  )
}

run_snapshot() {
  local label="$1"
  local commit="$2"
  local validation_args=()
  if [[ -n "${VALIDATION_MANIFEST:-}" ]]; then
    validation_args=(--validation-manifest "$VALIDATION_MANIFEST")
  fi
  git -C "$FFMPEG_DIR" switch --detach "$commit"
  build_database
  "$CLEARWING_BIN" sourcehunt "$FFMPEG_DIR" \
    --flow proof \
    --compile-commands compile_commands.json \
    "${validation_args[@]}" \
    --build-configuration asan-debug \
    --depth deep \
    --model-routing local-first \
    --structured-budget 90% \
    --exploration-budget 10% \
    --proof-plan auto \
    --retain-incomplete-certificates \
    --emit-rejection-certificates \
    --falsify \
    --no-mechanism-memory \
    --gvisor \
    --output-dir "$CASE_DIR/$label" \
    --format all
}

# Seal and inspect the vulnerable run before the fixed commit is made
# available to any discovery process.
run_snapshot vulnerable "$VULNERABLE_COMMIT"
if [[ "${RUN_FIXED_CONTROL:-0}" == "1" ]]; then
  run_snapshot fixed "$FIXED_COMMIT"
else
  echo "Vulnerable run sealed. Inspect it, then rerun with RUN_FIXED_CONTROL=1."
fi
