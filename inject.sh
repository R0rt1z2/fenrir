#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

INJECT_PY="${SCRIPT_DIR}/injector/inject.py"

if [ ! -f "$INJECT_PY" ]; then
    echo "Error: inject.py not found in $SCRIPT_DIR"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is required but not installed"
    exit 1
fi

export PYTHONPATH="${SCRIPT_DIR}:${PYTHONPATH}"

exec python3 "$INJECT_PY" "$@"