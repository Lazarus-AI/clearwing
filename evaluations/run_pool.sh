#!/usr/bin/env bash
# run_pool.sh — run all cve-*.sh scripts against multiple LLM providers in parallel.
#
# Each provider processes CVEs in independent waves of 2 concurrent jobs.
# A provider advances to the next wave only after both current jobs finish.
# All providers run concurrently with no synchronisation between them.
#
# Usage:
#   ./evaluations/run_pool.sh --providers-file evaluations/providers.csv
#   ./evaluations/run_pool.sh --providers-file evaluations/providers.csv --dry-run
#
# providers.csv: base_url,api_key,model_name  (# comments + blank lines ignored)
# Results:       evaluations/results/<model_slug>/<cve>/<YYYYMMDD-HHMMSS>/
#                evaluations/results/<model_slug>/<cve>/latest  → newest success
set -euo pipefail

# ── helpers ──────────────────────────────────────────────────────────────────────

slugify() { printf '%s' "$1" | tr '/: .' '-' | tr -cd '[:alnum:]-_'; }
log()     { printf '[run_pool] %s\n' "$*"; }

# ── argument parsing ─────────────────────────────────────────────────────────────

PROVIDERS_FILE=""
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --providers-file) PROVIDERS_FILE="$2"; shift 2 ;;
        --dry-run)        DRY_RUN=1;           shift   ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; exit 1 ;;
    esac
done

[[ -z "$PROVIDERS_FILE" ]] && { printf 'Usage: %s --providers-file FILE [--dry-run]\n' "$0" >&2; exit 1; }
[[ -f "$PROVIDERS_FILE" ]] || { printf 'File not found: %s\n'       "$PROVIDERS_FILE" >&2; exit 1; }

# ── load providers ───────────────────────────────────────────────────────────────

PROVIDERS=()
while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"  # ltrim
    line="${line%"${line##*[![:space:]]}"}"  # rtrim
    [[ -z "$line" || "$line" == \#* ]] && continue
    PROVIDERS+=("$line")
done < "$PROVIDERS_FILE"

[[ ${#PROVIDERS[@]} -eq 0 ]] && { log "No providers in $PROVIDERS_FILE" >&2; exit 1; }

# ── discover CVE scripts ──────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mapfile -t SCRIPTS < <(ls -1 "$SCRIPT_DIR"/cve-*.sh 2>/dev/null | sort)

[[ ${#SCRIPTS[@]} -eq 0 ]] && { log "No cve-*.sh found in $SCRIPT_DIR" >&2; exit 1; }

RESULTS_DIR="$SCRIPT_DIR/results"
N_CVE=${#SCRIPTS[@]}
N_PROV=${#PROVIDERS[@]}
WAVES=$(( (N_CVE + 1) / 2 ))

log "providers=$N_PROV  cves=$N_CVE  waves-per-provider=$WAVES  results=$RESULTS_DIR"

# ── dry run ───────────────────────────────────────────────────────────────────────

if [[ $DRY_RUN -eq 1 ]]; then
    log "--- DRY RUN ---"
    for p in "${PROVIDERS[@]}"; do
        IFS=',' read -r base_url _key model <<< "$p"
        slug="$(slugify "$model")"
        for s in "${SCRIPTS[@]}"; do
            printf '  %-32s  %s\n' "$slug" "$(basename "$s" .sh)"
        done
    done
    exit 0
fi

mkdir -p "$RESULTS_DIR"

# ── per-provider worker (runs in background subprocess) ───────────────────────────

run_provider_worker() {
    local base_url="$1" api_key="$2" model="$3"
    local model_slug; model_slug="$(slugify "$model")"
    local n_scripts=${#SCRIPTS[@]}
    local total_waves=$(( (n_scripts + 1) / 2 ))
    local i=0 wave=1 ok_count=0 fail_count=0

    while [[ $i -lt $n_scripts ]]; do
        # collect up to 2 scripts for this wave
        local batch=()
        batch+=("${SCRIPTS[$i]}")
        if [[ $(( i + 1 )) -lt $n_scripts ]]; then
            batch+=("${SCRIPTS[$(( i + 1 ))]}")
        fi

        # pretty-print CVE names for this wave
        local names=()
        for s in "${batch[@]}"; do names+=("$(basename "$s" .sh)"); done
        printf '[%s] WAVE %d/%d → %s\n' "$model_slug" "$wave" "$total_waves" "${names[*]}"

        # launch both jobs in background
        local pids=() out_dirs=() cve_names=()
        local t_wave=$SECONDS

        for script in "${batch[@]}"; do
            local cve_name ts out_dir
            cve_name="$(basename "$script" .sh)"
            ts="$(date -u +%Y%m%d-%H%M%S)"
            out_dir="$RESULTS_DIR/$model_slug/$cve_name/$ts"
            mkdir -p "$out_dir"

            cve_names+=("$cve_name")
            out_dirs+=("$out_dir")

            CLEARWING_BASE_URL="$base_url" \
            CLEARWING_API_KEY="$api_key"   \
            CLEARWING_MODEL="$model"       \
            OUT_DIR="$out_dir"             \
                bash "$script" >> "$out_dir/run.log" 2>&1 &

            pids+=($!)
            printf '[%s] START %s  PID=%d\n' "$model_slug" "$cve_name" "$!"
        done

        # ── barrier: wait for every job in this wave before advancing ─────────
        for j in "${!pids[@]}"; do
            local exit_code=0
            wait "${pids[$j]}" || exit_code=$?

            local elapsed=$(( SECONDS - t_wave ))
            local cve_name="${cve_names[$j]}"
            local out_dir="${out_dirs[$j]}"
            local ts; ts="$(basename "$out_dir")"

            if [[ $exit_code -eq 0 ]]; then
                ln -sfn "$ts" "$RESULTS_DIR/$model_slug/$cve_name/latest"
                printf '[%s] OK   %s  (%dm%02ds)\n' \
                    "$model_slug" "$cve_name" $(( elapsed / 60 )) $(( elapsed % 60 ))
                ok_count=$(( ok_count + 1 ))
            else
                printf '[%s] FAIL %s  exit=%d  log=%s/run.log\n' \
                    "$model_slug" "$cve_name" "$exit_code" "$out_dir"
                fail_count=$(( fail_count + 1 ))
            fi
        done
        # ── all jobs done — advance to next wave ──────────────────────────────

        printf '[%s] wave %d/%d done\n' "$model_slug" "$wave" "$total_waves"
        i=$(( i + 2 ))
        wave=$(( wave + 1 ))
    done

    printf '[%s] DONE — %d ok  %d failed\n' "$model_slug" "$ok_count" "$fail_count"
}

# ── launch all provider workers concurrently ─────────────────────────────────────

WORKER_PIDS=()
for provider in "${PROVIDERS[@]}"; do
    IFS=',' read -r base_url api_key model <<< "$provider"
    run_provider_worker "$base_url" "$api_key" "$model" &
    WORKER_PIDS+=($!)
done

# wait for all providers to finish
for pid in "${WORKER_PIDS[@]}"; do
    wait "$pid" || true
done

log "All providers finished — results in $RESULTS_DIR"