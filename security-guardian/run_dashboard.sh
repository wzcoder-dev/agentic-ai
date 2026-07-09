#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

export GUARDIAN_HOST="${GUARDIAN_HOST:-0.0.0.0}"
export GUARDIAN_PORT="${GUARDIAN_PORT:-8511}"

if command -v python3 >/dev/null 2>&1; then
  exec python3 -u openclaw_security_console/app.py
fi

if command -v python >/dev/null 2>&1; then
  exec python -u openclaw_security_console/app.py
fi

echo "python3 or python was not found." >&2
exit 1
