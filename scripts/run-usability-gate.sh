#!/usr/bin/env bash
# First-use usability gate (Task 16, Step 6): eight first-time sessions.
#
# Usage:
#   scripts/run-usability-gate.sh --plan            Print the gate procedure.
#   scripts/run-usability-gate.sh --results FILE    Verify a recorded
#       results file against the release thresholds.
#   scripts/run-usability-gate.sh                   Fail closed: conducting
#       real sessions needs a real browser and the real backend. This
#       script never simulates or fabricates sessions.
#
# Results file format (CSV, header required, exactly these columns; the
# gate records only durations, fixed error codes, and outcome):
#
#   session,duration_seconds,decision_views,outcome,error_code
#   1,214,2,launched,OK
#
# Fixed error codes: OK, CRED_FAIL, WS_BOUNDARY_FAIL, TIMEOUT, ABORTED.
# Release requires: eight sessions, median duration under five minutes
# (300s), at most three founder decision views per session, eight
# successful governed launches, and no credential or workspace-boundary
# failure (every error_code must be OK).
set -u

MODE="${1:-}"

print_plan() {
  cat <<'PLAN'
Usability gate: eight first-time sessions (Task 16, Step 6).

Per session, the operator:
  1. Starts the clock at the first product-controlled interaction
     (the first screen the product renders, not the operator's setup).
  2. Bootstraps the instance and enrolls a recovery method.
  3. Verifies the immutable workspace binding.
  4. Selects the repository and the mission issue.
  5. Reviews the shaped proposal.
  6. Approves with a passkey (WebAuthn).
  7. Authorizes the CLI in the browser and completes the exchange.
  8. Stops the clock when the UI displays the confirmed RunID.
  Time on GitHub-hosted authentication pages is subtracted; nothing else is.

Release thresholds (all eight sessions):
  - median duration_seconds < 300
  - decision_views <= 3 per session
  - outcome = launched for all eight (eight successful governed launches)
  - error_code = OK for all eight (no CRED_FAIL, WS_BOUNDARY_FAIL, TIMEOUT, or ABORTED)

Record one CSV row per session with exactly these columns:
  session,duration_seconds,decision_views,outcome,error_code
Then verify with: scripts/run-usability-gate.sh --results <file>
PLAN
}

verify_results() {
  local file="$1"
  [ -f "$file" ] || { echo "usability-gate: results file not found: $file" >&2; exit 2; }
  python3 - "$file" <<'PY'
import csv, statistics, sys

path = sys.argv[1]
with open(path) as f:
    rows = list(csv.DictReader(f))

if rows and set(rows[0].keys()) != {"session", "duration_seconds", "decision_views", "outcome", "error_code"}:
    print(f"FAIL: results file must have exactly the columns session,duration_seconds,decision_views,outcome,error_code; got {sorted(rows[0].keys())}")
    sys.exit(1)
if len(rows) != 8:
    print(f"FAIL: gate needs exactly 8 sessions, got {len(rows)}")
    sys.exit(1)

failures = []
durations = []
for r in rows:
    sid = r["session"]
    try:
        d = int(r["duration_seconds"]); v = int(r["decision_views"])
    except ValueError:
        failures.append(f"session {sid}: duration_seconds and decision_views must be integers")
        continue
    durations.append(d)
    if v > 3:
        failures.append(f"session {sid}: {v} decision views (max 3)")
    if r["outcome"] != "launched":
        failures.append(f"session {sid}: outcome {r['outcome']!r} (need launched)")
    if r["error_code"] != "OK":
        failures.append(f"session {sid}: error_code {r['error_code']!r} (need OK; no credential or workspace-boundary failure allowed)")

median = statistics.median(durations) if durations else None
print(f"sessions: {len(rows)}, median duration: {median}s (budget < 300s)")
if median is not None and median >= 300:
    failures.append(f"median duration {median}s is not under five minutes")

if failures:
    print("FAIL: usability gate did not pass:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("PASS: usability gate met (8 sessions, median under 5 minutes, at most 3 decision views, 8 launches, no credential or workspace-boundary failure)")
PY
}

case "$MODE" in
  --plan)
    print_plan
    ;;
  --results)
    [ -n "${2:-}" ] || { echo "usage: scripts/run-usability-gate.sh --results <file>" >&2; exit 2; }
    verify_results "$2"
    ;;
  "")
    echo "BLOCKED: the usability gate needs eight real first-time sessions with a real browser and the real backend."
    echo "BLOCKED: this environment cannot conduct them, and the gate never simulates sessions."
    echo "BLOCKED: print the procedure with scripts/run-usability-gate.sh --plan, then verify recorded results with scripts/run-usability-gate.sh --results <file>."
    exit 1
    ;;
  *)
    echo "usage: scripts/run-usability-gate.sh [--plan|--results <file>]" >&2
    exit 2
    ;;
esac
