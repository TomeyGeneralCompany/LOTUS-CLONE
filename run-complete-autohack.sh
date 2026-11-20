#!/usr/bin/env bash
# Start the main AutoHack app and the bounded offline worker pipeline together.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export AUTOHACK_ROOT="$ROOT"
source "$ROOT/scripts/node-runtime.sh"
# A kernel-held lock is released after exit/crash; no stale PID cleanup needed.
command -v flock >/dev/null 2>&1 || { echo "flock (util-linux) is required." >&2; exit 127; }
mkdir -p data
exec 9>data/supervisor.lock
flock -n 9 || { echo "AutoHack supervisor is already running in this checkout." >&2; exit 2; }
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 127
fi
# One local deterministic controller owns acquisition, analysis, experimentation
# and review. The former independent model-worker farm is not launched.
export LOCAL_MODEL_ADAPTER=deterministic
unset LOCAL_OLLAMA_MODEL LOCAL_MODEL_PROFILE
exec bash "$ROOT/run-local-autohack.sh"
