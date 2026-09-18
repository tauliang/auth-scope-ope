#!/usr/bin/env bash
# Runs the Task 1 five-session first-run usability spike (simulated) and
# verifies the recorded median. Usage:
#   scripts/run-usability-spike.sh                 # run sessions, write docs/usability-spike.md
#   scripts/run-usability-spike.sh --verify <file>  # check the recorded median is under five minutes
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${1:-}" == "--verify" ]]; then
  exec node "$ROOT/scripts/usability-spike-sim.mjs" --verify "${2:?usage: run-usability-spike.sh --verify <markdown>}"
fi

exec node "$ROOT/scripts/usability-spike-sim.mjs"
