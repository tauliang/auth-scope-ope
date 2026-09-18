#!/usr/bin/env bash
# Release verification aggregator (Task 16, Step 7).
#
# Runs every release gate and reports PASS, FAIL, or BLOCKED per gate:
#   make verify-release
#
# The real-integration and usability gates report BLOCKED (not failed)
# when their real prerequisites are absent; they are never silently
# passed. The release is verified only when every gate reports PASS.
# An operator may point the usability gate at recorded session results
# with OPE_USABILITY_RESULTS=<csv file>.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GO_BIN="${GO_BIN:-/home/hatch/workspace/tools/go/bin/go}"
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
  GO_BIN="go"
fi
if command -v pnpm >/dev/null 2>&1; then
  PNPM="pnpm"
else
  PNPM="$HOME/workspace/tools/pnpm/node_modules/.bin/pnpm"
fi

export GOSUMDB=off

PASS=0
FAIL=0
BLOCKED_COUNT=0
SUMMARY=""

record() { # name, result, detail
  SUMMARY="${SUMMARY}$1: $2${3:+ ($3)}\n"
  case "$2" in
    PASS) PASS=$((PASS + 1)) ;;
    FAIL) FAIL=$((FAIL + 1)) ;;
    BLOCKED) BLOCKED_COUNT=$((BLOCKED_COUNT + 1)) ;;
  esac
  printf 'GATE %-18s %s\n' "$1" "$2"
}

run_gate() { # name, command...
  local name="$1"; shift
  echo "== gate: $name =="
  if "$@" >/tmp/verify-release-last.log 2>&1; then
    record "$name" PASS ""
  else
    echo "--- $name output (tail) ---"
    tail -20 /tmp/verify-release-last.log
    echo "--- end ---"
    record "$name" FAIL "see output above"
  fi
}

# 1. Contract gate: the vendored release contract satisfies the manifest.
run_gate "contract" make contract-ready

# 2-3. Go: race detector over the whole module, then vet.
run_gate "go-tests" "$GO_BIN" test -race ./... -count=1
run_gate "go-vet" "$GO_BIN" vet ./...

# 4. Generated web client matches the OpenAPI document.
if command -v node >/dev/null 2>&1; then
  run_gate "web-client" node scripts/generate-web-client.mjs --check
else
  record "web-client" FAIL "node not found"
fi

# 5. Frontend: install (with the sandbox EPERM workaround), lint,
# typecheck, coverage-tested, and build.
echo "== gate: frontend =="
FRONTEND_OK=1
if [ ! -f web/node_modules/.modules.yaml ] || [ web/pnpm-lock.yaml -nt web/node_modules/.modules.yaml ]; then
  echo "frontend: installing web dependencies"
  if ! (cd web && "$PNPM" install --frozen-lockfile); then
    # Known sandbox quirk: the install finishes with a final EPERM/255
    # after laying down node_modules. Only tolerate it when the tree
    # is actually usable; anything else fails the gate below.
    echo "frontend: install exited nonzero; checking whether node_modules is usable"
  fi
  if [ -d web/node_modules/.bin ]; then
    touch web/node_modules/.modules.yaml
  else
    FRONTEND_OK=0
  fi
fi
if [ "$FRONTEND_OK" = "1" ]; then
  for step in "lint" "typecheck" "test:coverage" "build"; do
    if ! "$PNPM" --dir web "$step" >/tmp/verify-release-last.log 2>&1; then
      echo "--- frontend $step output (tail) ---"
      tail -20 /tmp/verify-release-last.log
      echo "--- end ---"
      FRONTEND_OK=0
      break
    fi
  done
fi
if [ "$FRONTEND_OK" = "1" ]; then record "frontend" PASS ""; else record "frontend" FAIL ""; fi

# 6. Fake e2e (browser specs tolerate a missing browser; API tests run).
run_gate "e2e" make e2e

# 7. Packaging: the release binary builds with the web bundle embedded.
echo "== gate: packaging =="
PKG_TMP="$(mktemp -d)"
if "$GO_BIN" build -tags embedweb -trimpath -o "$PKG_TMP/authscope-ope" ./cmd/authscope-ope >/tmp/verify-release-last.log 2>&1 \
  && [ -x "$PKG_TMP/authscope-ope" ]; then
  record "packaging" PASS "embedweb binary builds"
else
  tail -20 /tmp/verify-release-last.log
  record "packaging" FAIL "embedweb build failed"
fi
rm -rf "$PKG_TMP"

# 8-9. Privacy and credential gates.
run_gate "privacy" make privacy-check
run_gate "credential" make credential-check

# 10. Real integration: PASS only against the pinned real backend;
# BLOCKED (not failed) while prerequisites are absent.
echo "== gate: real-integration =="
if scripts/run-real-integration.sh --preflight >/tmp/verify-release-last.log 2>&1; then
  record "real-integration" PASS "pinned real backend"
else
  if grep -q "^BLOCKED:" /tmp/verify-release-last.log; then
    echo "real-integration prerequisites absent; gate is BLOCKED, not failed:"
    grep "^BLOCKED:" /tmp/verify-release-last.log | head -20
    record "real-integration" BLOCKED "real prerequisites absent"
  else
    tail -20 /tmp/verify-release-last.log
    record "real-integration" FAIL "preflight errored"
  fi
fi

# 11. Usability: verified from recorded session results, otherwise
# BLOCKED until eight real sessions are conducted.
echo "== gate: usability =="
if [ -n "${OPE_USABILITY_RESULTS:-}" ]; then
  if scripts/run-usability-gate.sh --results "$OPE_USABILITY_RESULTS" >/tmp/verify-release-last.log 2>&1; then
    record "usability" PASS "recorded sessions meet the thresholds"
  else
    tail -20 /tmp/verify-release-last.log
    record "usability" FAIL "recorded sessions miss the thresholds"
  fi
else
  if scripts/run-usability-gate.sh >/tmp/verify-release-last.log 2>&1; then
    record "usability" PASS ""
  else
    if grep -q "^BLOCKED:" /tmp/verify-release-last.log; then
      record "usability" BLOCKED "eight real sessions not yet conducted"
    else
      tail -20 /tmp/verify-release-last.log
      record "usability" FAIL "usability gate errored"
    fi
  fi
fi

echo ""
echo "================ release gate summary ================"
printf '%b' "$SUMMARY"
echo "PASS: $PASS  FAIL: $FAIL  BLOCKED: $BLOCKED_COUNT"
echo "======================================================"

if [ "$FAIL" -gt 0 ]; then
  echo "verify-release: $FAIL gate(s) FAILED; the release is not verified."
  exit 1
fi
if [ "$BLOCKED_COUNT" -gt 0 ]; then
  echo "verify-release: $BLOCKED_COUNT gate(s) BLOCKED on absent real prerequisites; the release is not verified."
  exit 1
fi
echo "verify-release: every gate passed."
exit 0
