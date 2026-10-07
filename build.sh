#!/usr/bin/env bash
# Build Warp for Linux (GUI + CLI). Run on a Linux machine.
#
# By default this builds natively on the current host, which links the
# resulting binaries against the host's glibc. glibc is only forward
# compatible, so a binary built on a new glibc (e.g. 2.44) will refuse to
# start on an older target (e.g. Debian 13 / glibc 2.41) with:
#   ImportError: ... version `GLIBC_2.44' not found
#
# To avoid that, pass --docker to build inside a pinned, old-glibc container.
# The container is only a build environment: the binary it produces is a
# normal native Linux executable with full access to whatever host it later
# runs on. The container is discarded after the build.
#
# Usage:
#   ./build.sh                 # native build (both GUI + CLI)
#   ./build.sh --docker        # build in an old-glibc container (portable)
#   ./build.sh --docker --cli  # flags after --docker pass through to build.py
#
# Override the build image (default: glibc 2.36, runs on >= 2.36 targets):
#   WARP_BUILD_IMAGE=python:3.14-slim-bullseye ./build.sh --docker   # glibc 2.31
set -euo pipefail
cd "$(dirname "$0")"

# Default build image: Debian bookworm ships glibc 2.36, so binaries run on
# any target with glibc >= 2.36 (including Debian 13 / 2.41).
WARP_BUILD_IMAGE="${WARP_BUILD_IMAGE:-python:3.14-slim-bookworm}"

if [ "${1:-}" = "--docker" ]; then
    shift
    if ! command -v docker >/dev/null 2>&1; then
        echo "error: --docker requested but docker is not installed or not on PATH" >&2
        exit 1
    fi
    echo "=== Building in container: ${WARP_BUILD_IMAGE} ==="
    # binutils provides objdump/strip (PyInstaller needs objdump for onefile on
    # Linux); libtk8.6 supplies the Tcl/Tk runtime libs the slim image omits, so
    # tkinter (the GUI variants) can be imported and bundled. apt output quieted.
    exec docker run --rm \
        -v "$PWD":/src -w /src \
        "$WARP_BUILD_IMAGE" \
        bash -c 'apt-get -qq update && apt-get -qq install -y binutils libtk8.6 >/dev/null && pip install --quiet pyinstaller && python build.py "$@"' -- "$@"
fi

PY="python3"
# Prefer a local venv if present.
if [ -x ".venv/bin/python" ]; then
    PY=".venv/bin/python"
elif [ -x "myenv/bin/python" ]; then
    PY="myenv/bin/python"
fi

"$PY" -m PyInstaller --version >/dev/null 2>&1 || "$PY" -m pip install pyinstaller
exec "$PY" build.py "$@"
