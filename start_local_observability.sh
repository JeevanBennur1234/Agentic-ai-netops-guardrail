#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ROOT="${NETOPS_HOME:-$SCRIPT_DIR}"
ROOT="$(cd -- "$ROOT" && pwd)"
export NETOPS_HOME="$ROOT"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PY="$PYTHON_BIN"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PY="$VIRTUAL_ENV/bin/python"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="$(command -v python3 || true)"
fi

SECRETS_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/netops-guardrail"
SECRETS_FILE="$SECRETS_DIR/local-secrets.env"

cd "$ROOT"
if [[ ! -x "$PY" ]]; then
  echo "ERROR: project Python environment not found: $PY" >&2
  exit 1
fi

# Keep reusable local operator tokens outside Git and restrict them to this user.
umask 077
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"
if [[ ! -s "$SECRETS_FILE" ]] ||
   ! grep -q '^NETOPS_APPROVER_TOKEN=' "$SECRETS_FILE" ||
   ! grep -q '^NETOPS_CHAOS_API_TOKEN=' "$SECRETS_FILE"; then
  approver_token="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  chaos_token="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  {
    printf 'NETOPS_APPROVER_TOKEN=%s\n' "$approver_token"
    printf 'NETOPS_CHAOS_API_TOKEN=%s\n' "$chaos_token"
  } > "$SECRETS_FILE"
  chmod 600 "$SECRETS_FILE"
fi

set -a
# File values are generated URL-safe tokens, not arbitrary shell input.
source "$SECRETS_FILE"
set +a
export NETOPS_APPROVER_TOKENS="$("$PY" -c 'import json,os; print(json.dumps({"netops-admin":os.environ["NETOPS_APPROVER_TOKEN"]}))')"
# Running observability/server.py sets sys.path[0] to observability/, so explicitly
# expose the repository root for importing testbed.live_connectivity.
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export NETOPS_CONNECTIVITY_CHECKER='testbed.live_connectivity:check_host_connectivity'

if [[ -z "${NETOPS_APPROVER_TOKEN:-}" || -z "${NETOPS_CHAOS_API_TOKEN:-}" ]]; then
  echo "ERROR: required local tokens are missing." >&2
  exit 1
fi

if ss -ltn 2>/dev/null | grep -q ':8000'; then
  echo "ERROR: port 8000 is already in use. Stop the existing observability server first; do not launch a duplicate." >&2
  exit 1
fi

echo "Starting local NetOps Guardrail observability server."
echo "Human Verifier token: $NETOPS_APPROVER_TOKEN"
echo "Lab operator token:   $NETOPS_CHAOS_API_TOKEN"
echo "Tokens are stored in $SECRETS_FILE (directory mode 700, file mode 600)."
echo "Keep this terminal open. These are local development credentials; do not share them."
exec "$PY" observability/server.py
