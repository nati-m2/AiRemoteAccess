#!/usr/bin/env bash
# Build Warp for Linux (GUI + CLI). Run on a Linux machine.
set -euo pipefail
cd "$(dirname "$0")"

PY="python3"
# Prefer a local venv if present.
if [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
elif [ -x "myenv/bin/python" ]; then
    PY="myenv/bin/python"
fi

"$PY" -m PyInstaller --version >/dev/null 2>&1 || "$PY" -m pip install pyinstaller
exec "$PY" build.py "$@"
