#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$EUID" -ne 0 ]]; then
  echo "Run with sudo: sudo env PYTHONPATH=/usr/lib/python3/dist-packages bash experiments/run_failover_retries.sh"
  exit 2
fi

export PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}/usr/lib/python3/dist-packages"
FAILED=0

for trial in 07 08; do
  result="$ROOT/experiments/results/2026-11-13_live_active_failover_trial_${trial}.json"
  echo
  echo "========== LIVE FAILOVER RETRY ${trial} =========="
  NETOPS_FAILOVER_OBSERVATION_SECONDS=90 \
  NETOPS_FAILOVER_RESULT_PATH="$result" \
    "$ROOT/.venv/bin/python" "$ROOT/src/netops_guardrail/testbed/validate_active_failover.py"
  rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "TRIAL ${trial}: PROCESS EXIT ${rc}"
    FAILED=1
  fi
done

echo
echo "========== RETRY SUMMARY =========="
python3 - <<'PY'
import json
from pathlib import Path

base = Path("experiments/results")
for trial in ("02", "03", "06", "07", "08"):
    path = base / f"2026-11-13_live_active_failover_trial_{trial}.json"
    if not path.exists():
        print(f"trial {trial}: MISSING")
        continue
    try:
        data = json.loads(path.read_text())
        print(
            f"trial {trial}: {data.get('result', 'UNKNOWN')} | "
            f"baseline={data.get('baseline_ping_loss_percent')}% | "
            f"recovery={data.get('failover_recovery_time_seconds')}s | "
            f"samples={data.get('observation_window_ping_samples')} | "
            f"post-recovery-loss-samples={data.get('post_recovery_nonzero_loss_samples')}"
        )
    except Exception as exc:
        print(f"trial {trial}: INVALID JSON ({exc})")
PY

exit "$FAILED"
