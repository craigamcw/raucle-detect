#!/usr/bin/env bash
# Weekend queue: waits for Track D PID, then runs E, F, H sequentially.
# Each track is detached via setsid so SSH disconnects do not kill it.
set -uo pipefail

WAIT_PID="${1:-1405866}"
WORKDIR="/root/raucle-paper/raucle-detect"
LOGROOT="$WORKDIR/runs/_weekend"
mkdir -p "$LOGROOT"
QUEUE_LOG="$LOGROOT/queue.log"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$QUEUE_LOG"; }

cd "$WORKDIR"
source .venv/bin/activate
set -a; source /root/raucle-paper/.secrets/ollama.env; set +a
export PYTHONPATH=.

log "weekend queue started (waiting for PID $WAIT_PID)"
while ps -p "$WAIT_PID" > /dev/null 2>&1; do sleep 60; done
log "PID $WAIT_PID gone"

run_track() {
    local name="$1" script="$2"
    log "TRACK $name START -> $script"
    local trackdir="$LOGROOT/$name"
    mkdir -p "$trackdir"
    python "$script" > "$trackdir/stdout.log" 2> "$trackdir/stderr.log"
    local rc=$?
    log "TRACK $name END rc=$rc"
    return $rc
}

run_track E "$WORKDIR/runs/track_e_v4pro.py"     || log "track E failed (continuing)"
run_track F "$WORKDIR/runs/track_f_crosssuite.py" || log "track F failed (continuing)"
run_track H "$WORKDIR/runs/track_h_attacks.py"    || log "track H failed (continuing)"

log "WEEKEND QUEUE COMPLETE"
