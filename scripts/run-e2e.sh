#!/usr/bin/env bash
# Browser e2e for the three-screen OPE journey.
#
# Boots two API servers and two web servers side by side, then runs the
# Playwright specs in test/e2e/. The specs are tolerant: UI tests skip
# cleanly when no browser executable is installed, while the API-level
# tests run unconditionally. This script exits 0 in both cases; a real
# failure in any executed test fails the run.
#
# Usage: scripts/run-e2e.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Tool locations: prefer the environment, then PATH, then the local
# workspace defaults. CI provides go and pnpm on PATH.
if [ -z "${GO_BIN:-}" ]; then
  if command -v go >/dev/null 2>&1; then
    GO_BIN="$(command -v go)"
  else
    GO_BIN="/home/hatch/workspace/tools/go/bin/go"
  fi
fi
if [ -z "${PNPM:-}" ]; then
  if command -v pnpm >/dev/null 2>&1; then
    PNPM="$(command -v pnpm)"
  else
    PNPM="/usr/bin/pnpm"
  fi
fi

API_A_PORT=18080
API_B_PORT=18081
WEB_A_PORT=15173
WEB_B_PORT=15174
WEB_A="http://localhost:${WEB_A_PORT}"
WEB_B="http://localhost:${WEB_B_PORT}"

TMPDIR_RUN="$(mktemp -d "${TMPDIR:-/tmp}/ope-e2e.XXXXXX")"
BIN="$TMPDIR_RUN/authscope-ope"
DATA_A="$TMPDIR_RUN/data-a"
DATA_B="$TMPDIR_RUN/data-b"
LOG_A="$TMPDIR_RUN/api-a.log"
LOG_B="$TMPDIR_RUN/api-b.log"
WEB_LOG_A="$TMPDIR_RUN/web-a.log"
WEB_LOG_B="$TMPDIR_RUN/web-b.log"

PIDS=""

start_bg() {
  # Start a server in its own process group so cleanup can stop the
  # whole tree: pnpm exec wraps vite in a child process that would
  # otherwise survive a SIGTERM to the parent. With setsid the child
  # PID equals its process group ID.
  setsid "$@" &
  PIDS="$PIDS $!"
}

cleanup() {
  # Kill the servers we started; leave the temp dir for debugging.
  for pid in $PIDS; do
    kill -TERM "-$pid" 2>/dev/null || true
  done
  sleep 2
  for pid in $PIDS; do
    kill -KILL "-$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

fail() {
  echo "run-e2e: $*" >&2
  exit 1
}

echo "run-e2e: building the server"
(
  cd "$ROOT" && \
  GOSUMDB=off "$GO_BIN" build -o "$BIN" ./cmd/authscope-ope
) || fail "go build failed"

start_api() {
  local name="$1" port="$2" data="$3" workspace="$4" hostname="$5" origin="$6" log="$7"
  mkdir -p "$data"
  OPE_MODE=development \
  AUTH_SCOPE_URL=http://127.0.0.1:9 \
  OPE_BIND_ADDR="127.0.0.1:${port}" \
  OPE_DATA_DIR="$data" \
  OPE_ROOT="$ROOT" \
  OPE_WORKSPACE_ID="$workspace" \
  OPE_HOSTNAME="$hostname" \
  OPE_ORIGIN="$origin" \
  OPE_RP_ID=localhost \
  start_bg "$BIN" serve >"$log" 2>&1
  echo "run-e2e: $name api on 127.0.0.1:${port} (log $log)"
}

start_api "a" "$API_A_PORT" "$DATA_A" "ws-e2e-a" "e2e-a.local" "$WEB_A" "$LOG_A"
start_api "b" "$API_B_PORT" "$DATA_B" "ws-e2e-b" "e2e-b.local" "$WEB_B" "$LOG_B"

wait_for() {
  local url="$1" name="$2"
  for _ in $(seq 1 60); do
    if curl -sf -o /dev/null "$url"; then
      echo "run-e2e: $name ready"
      return 0
    fi
    sleep 1
  done
  fail "$name did not become ready; see logs"
}

wait_for "http://127.0.0.1:${API_A_PORT}/api/v1/bootstrap" "api-a"
wait_for "http://127.0.0.1:${API_B_PORT}/api/v1/bootstrap" "api-b"

# The one-time bootstrap codes are printed to each server's log at
# startup. They are one-use; the two-instance spec consumes them.
CODE_A="$(grep -A2 "one-time code" "$LOG_A" | tail -1 | tr -d ' ')"
CODE_B="$(grep -A2 "one-time code" "$LOG_B" | tail -1 | tr -d ' ')"
[ -n "$CODE_A" ] || fail "no bootstrap code captured for instance a"
[ -n "$CODE_B" ] || fail "no bootstrap code captured for instance b"

if [ ! -d "$ROOT/web/node_modules" ]; then
  fail "web/node_modules is missing; run 'pnpm --dir web install' first"
fi

echo "run-e2e: starting the web servers"
# NOTE: these run in the main shell, not a subshell: a subshell would
# inherit the EXIT trap and kill the API servers when it exits.
cd "$ROOT/web"
OPE_API="http://127.0.0.1:${API_A_PORT}" \
  start_bg "$PNPM" exec vite --port "$WEB_A_PORT" --strictPort >"$WEB_LOG_A" 2>&1
OPE_API="http://127.0.0.1:${API_B_PORT}" \
  start_bg "$PNPM" exec vite --port "$WEB_B_PORT" --strictPort >"$WEB_LOG_B" 2>&1
cd "$ROOT"

wait_for "${WEB_A}/" "web-a"
wait_for "${WEB_B}/" "web-b"

BROWSER_NOTE=""
if ! "$PNPM" --dir "$ROOT/web" exec playwright --version >/dev/null 2>&1; then
  BROWSER_NOTE="playwright runner unavailable; skipping browser e2e"
elif ! node -e "const {chromium}=require('$ROOT/web/node_modules/playwright-core');require('fs').existsSync(chromium.executablePath())||process.exit(1)" 2>/dev/null; then
  BROWSER_NOTE="no browser executable installed; UI tests will skip, API tests will run"
fi
if [ -n "$BROWSER_NOTE" ]; then
  echo "run-e2e: $BROWSER_NOTE"
fi

echo "run-e2e: running the specs"
# Inline env, no subshell: a subshell would inherit the EXIT trap.
OPE_E2E_WEB_A="$WEB_A" \
OPE_E2E_WEB_B="$WEB_B" \
OPE_E2E_API_A="http://127.0.0.1:${API_A_PORT}" \
OPE_E2E_API_B="http://127.0.0.1:${API_B_PORT}" \
OPE_E2E_CODE_A="$CODE_A" \
OPE_E2E_CODE_B="$CODE_B" \
"$PNPM" --dir web exec playwright test --config "$ROOT/playwright.config.ts" \
|| fail "playwright specs failed"

echo "run-e2e: done"
