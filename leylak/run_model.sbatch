#!/bin/bash
#SBATCH --job-name=cweft
#SBATCH --partition=GPU_nvrtx6000pro
#SBATCH --nodelist=gpu5
#SBATCH --cpus-per-task=8
#SBATCH --time=12:00:00
#SBATCH --output=/dev/null
#
# One unattended generation job for one vLLM model: start vLLM, wait until it
# answers, run generate.py for that model against it, then stop the server so
# the GPU is freed. See leylak/README.md.
#
#   sbatch [slurm options] leylak/run_model.sbatch MODEL [options] [-- generate.py args]
#
# MODEL is a key of VLLM_MODELS in config.py (e.g. granite-8b-bf16); its
# Hugging Face id and pinned revision (VLLM_REVISIONS) are read from there.
#
# Options:
#   --max-model-len N   vLLM context window, also given to generate.py as
#                       VLLM_MAX_MODEL_LEN (default 65536)
#   --tp N              tensor parallel across the first N cards in
#                       CUDA_VISIBLE_DEVICES (default 1), e.g. --tp 2 with
#                       CUDA_VISIBLE_DEVICES=0,1 for gpu5's two cards.
#   --port N            local port for vLLM (default 8000)
#   --wait-timeout S    seconds to wait for the server to answer (default 1800)
#
# Everything after -- goes to generate.py (--vulns, --levels, --dataset,
# --logs-dir, --dry-run ...). --models is set from MODEL and may not be passed.
#
# Choosing a card: LEYLAK has no GPU gres, so Slurm does not assign cards.
# Set CUDA_VISIBLE_DEVICES when submitting and the job inherits it, e.g.
#   CUDA_VISIBLE_DEVICES=1 sbatch leylak/run_model.sbatch granite-8b-bf16 ...
# Without it the job uses cards 0..N-1 for --tp N.
#
# Time: the GPU partitions cap jobs at 12 h. A longer run is split into several
# jobs; generate.py skips cells already logged, so resubmitting continues it.
#
# Output: ~/cweft_<MODEL>_<jobid>.log, and vLLM's own output in
# ~/cweft_<MODEL>_<jobid>.vllm.log.

set -uo pipefail

MODEL="${1:-}"
JOB="${SLURM_JOB_ID:-local$$}"
LOG="$HOME/cweft_${MODEL:-nomodel}_${JOB}.log"
VLLM_LOG="$HOME/cweft_${MODEL:-nomodel}_${JOB}.vllm.log"
exec >"$LOG" 2>&1

die() { echo "ERROR: $*"; exit 1; }

[[ -n "$MODEL" && "$MODEL" != -* ]] || die "first argument must be the model key (see config.VLLM_MODELS)"
shift

MAX_LEN=65536
TP=1
PORT=8000
WAIT_TIMEOUT=1800
GEN_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-model-len) MAX_LEN="$2"; shift 2 ;;
        --tp)            TP="$2"; shift 2 ;;
        --port)          PORT="$2"; shift 2 ;;
        --wait-timeout)  WAIT_TIMEOUT="$2"; shift 2 ;;
        --)              shift; GEN_ARGS=("$@"); break ;;
        *)               die "unknown option $1 (generate.py arguments go after --)" ;;
    esac
done
for a in ${GEN_ARGS[@]+"${GEN_ARGS[@]}"}; do
    [[ "$a" == --models* ]] && die "--models is set from MODEL; do not pass it after --"
done

CWEFT_DIR="${CWEFT_DIR:-$HOME/cweft}"
CWEFT_VENV="${CWEFT_VENV:-$CWEFT_DIR/venv312}"
# vLLM compiles kernels at start-up and needs `ninja`, which lives in the venv.
export PATH="$CWEFT_VENV/bin:$PATH"
export no_proxy="127.0.0.1,localhost${no_proxy:+,$no_proxy}"
export NO_PROXY="$no_proxy"
cd "$CWEFT_DIR" || die "no repository at $CWEFT_DIR"

# One GPU per tensor-parallel rank. LEYLAK has no GPU gres, so Slurm leaves
# CUDA_VISIBLE_DEVICES alone: use the submitter's value, or cards 0..TP-1.
if [[ -z "${CUDA_VISIBLE_DEVICES:-}" ]]; then
    CUDA_VISIBLE_DEVICES="$(seq -s, 0 $((TP - 1)))"
    export CUDA_VISIBLE_DEVICES
fi
NGPU=$(awk -F, '{print NF}' <<<"$CUDA_VISIBLE_DEVICES")
(( NGPU >= TP )) || die "--tp $TP needs $TP GPUs but CUDA_VISIBLE_DEVICES=$CUDA_VISIBLE_DEVICES; submit with CUDA_VISIBLE_DEVICES set to $TP cards (e.g. 0,1)"

# Model id and revision come from config.py, the single source of truth.
MODEL_INFO="$(python - "$MODEL" <<'PY'
import sys
import config
key = sys.argv[1]
hf_id = config.VLLM_MODELS.get(key)
rev = config.VLLM_REVISIONS.get(key)
if hf_id is None:
    sys.exit(f"{key} is not in config.VLLM_MODELS ({', '.join(config.VLLM_MODELS)})")
if hf_id.startswith(config.VLLM_PLACEHOLDER):
    sys.exit(f"{key} has no Hugging Face id yet; fill it in under VLLM_MODELS in config.py")
if not rev:
    sys.exit(f"{key} has no pinned revision; add it to VLLM_REVISIONS in config.py")
print(hf_id)
print(rev)
PY
)" || die "cannot serve $MODEL (see the message above)"
HF_ID="$(sed -n 1p <<<"$MODEL_INFO")"
REVISION="$(sed -n 2p <<<"$MODEL_INFO")"

echo "=== cweft job $JOB  $(date -Is)  on $(hostname)"
echo "model:        $MODEL = $HF_ID @ $REVISION"
echo "window:       --max-model-len $MAX_LEN   tensor parallel: $TP   port: $PORT"
echo "GPUs:         CUDA_VISIBLE_DEVICES=$CUDA_VISIBLE_DEVICES"
nvidia-smi -L 2>/dev/null || true
echo "repository:   $CWEFT_DIR @ $(git rev-parse --short HEAD 2>/dev/null) ($(git rev-parse --abbrev-ref HEAD 2>/dev/null))"
echo "python:       $(command -v python)   vllm: $(python -c 'import vllm; print(vllm.__version__)' 2>/dev/null)"
echo "generate.py:  --models $MODEL ${GEN_ARGS[*]-}"
echo "vLLM output:  $VLLM_LOG"
echo

SERVER_PID=""
cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "=== stopping vLLM (pid $SERVER_PID)  $(date -Is)"
        kill -TERM -- "-$SERVER_PID" 2>/dev/null || kill -TERM "$SERVER_PID" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 2
        done
        kill -KILL -- "-$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'echo "=== job signalled; shutting down"; exit 143' TERM INT

# --generation-config vllm: plain vLLM sampling defaults, not the model repo's
# generation_config.json, so every model is sampled the same way.
setsid vllm serve "$HF_ID" \
    --revision "$REVISION" \
    --served-model-name "$HF_ID" \
    --generation-config vllm \
    --max-model-len "$MAX_LEN" \
    --tensor-parallel-size "$TP" \
    --host 127.0.0.1 --port "$PORT" \
    >"$VLLM_LOG" 2>&1 &
SERVER_PID=$!
echo "=== vLLM starting (pid $SERVER_PID); waiting up to ${WAIT_TIMEOUT}s"

ready() {
    python - "$PORT" "$HF_ID" <<'PY'
import json, sys, urllib.request
port, hf_id = sys.argv[1], sys.argv[2]
try:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/models", timeout=5) as r:
        ids = [m["id"] for m in json.load(r)["data"]]
except Exception:
    sys.exit(1)
sys.exit(0 if hf_id in ids else 2)
PY
}

START=$SECONDS
while true; do
    ready; rc=$?
    (( rc == 0 )) && break
    if (( rc == 2 )); then
        die "the server on port $PORT answers but does not serve $HF_ID (another server on that port?)"
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "vLLM exited before it was ready. Last lines of $VLLM_LOG:"
        tail -n 60 "$VLLM_LOG"
        exit 1
    fi
    if (( SECONDS - START >= WAIT_TIMEOUT )); then
        echo "vLLM did not answer within ${WAIT_TIMEOUT}s. Last lines of $VLLM_LOG:"
        tail -n 60 "$VLLM_LOG"
        exit 1
    fi
    sleep 10
done
echo "=== vLLM ready after $((SECONDS - START))s"
echo

VLLM_BASE_URL="http://127.0.0.1:$PORT/v1" VLLM_MAX_MODEL_LEN="$MAX_LEN" \
    python generate.py --models "$MODEL" ${GEN_ARGS[@]+"${GEN_ARGS[@]}"}
STATUS=$?
echo
echo "=== generate.py exited with $STATUS  $(date -Is)"
exit "$STATUS"
