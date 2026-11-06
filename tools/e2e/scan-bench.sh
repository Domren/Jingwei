#!/usr/bin/env bash
# All orchestration and validation live in the stdlib Python harness.
set -euo pipefail
SCRIPT_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
python3 -B "$SCRIPT_DIR/scan-bench.py" "$@"
