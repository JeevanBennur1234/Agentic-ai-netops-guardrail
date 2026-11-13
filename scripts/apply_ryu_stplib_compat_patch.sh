#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PATCH_FILE="$ROOT/patches/ryu-4.34-stplib-physical-status-mask.patch"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PY="$PYTHON_BIN"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PY="$VIRTUAL_ENV/bin/python"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  PY="$(command -v python3 || true)"
fi

if [[ ! -x "$PY" ]]; then
  echo "ERROR: Python interpreter not found: $PY" >&2
  exit 1
fi
if [[ ! -f "$PATCH_FILE" ]]; then
  echo "ERROR: Ryu compatibility patch missing: $PATCH_FILE" >&2
  exit 1
fi

RYU_VERSION="$("$PY" -c 'from importlib.metadata import version; print(version("ryu"))')"
if [[ "$RYU_VERSION" != "4.34" ]]; then
  echo "ERROR: this compatibility patch targets Ryu 4.34; found $RYU_VERSION" >&2
  exit 1
fi

RYU_FILE="$("$PY" -c 'import ryu.lib.stplib; print(ryu.lib.stplib.__file__)')"
SITE_PACKAGES="$(cd -- "$(dirname -- "$RYU_FILE")/../.." && pwd)"

if grep -q '_get_port_link_status' "$RYU_FILE"; then
  echo "Ryu 4.34 STP physical-status compatibility patch is already applied."
  exit 0
fi

patch --dry-run -p1 -d "$SITE_PACKAGES" < "$PATCH_FILE"
patch -p1 -d "$SITE_PACKAGES" < "$PATCH_FILE"
"$PY" -m py_compile "$RYU_FILE"
echo "Applied and compiled the Ryu 4.34 STP physical-status compatibility patch."
