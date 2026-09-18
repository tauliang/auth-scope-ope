#!/usr/bin/env bash
# Real-integration gate for the OPE Mission Pass release path (Task 16).
#
# Usage:
#   scripts/run-real-integration.sh --preflight   Check every real
#       prerequisite and fail closed, naming each absent or mismatched
#       one. This mode never substitutes a fake, never skips a required
#       operation, and never treats a development commit pin (including
#       76fe961) as a release version.
#   scripts/run-real-integration.sh               Run the preflight, then
#       the Go real-integration suite against the pinned real backend.
#
# Exit codes: 0 when the gate passes; 1 when prerequisites are absent
# or mismatched (BLOCKED) or the suite fails. Lines starting with
# "BLOCKED:" name one missing prerequisite each; "make verify-release"
# uses that marker to report the real gate as blocked rather than failed.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

GO_BIN="${GO_BIN:-/home/hatch/workspace/tools/go/bin/go}"
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
  GO_BIN="go"
fi

BLOCKED=0
ERRORS=0

blocked() { echo "BLOCKED: $*"; BLOCKED=$((BLOCKED + 1)); }
err()     { echo "ERROR: $*" >&2; ERRORS=$((ERRORS + 1)); }
ok()      { echo "ok: $*"; }

need_var() { # name, description
  local val
  val="$(printenv "$1" 2>/dev/null || true)"
  if [ -z "${val// }" ]; then
    blocked "$1 ($2) is not set"
    return 1
  fi
  return 0
}

LOCK="$ROOT/contracts/authscope.lock.json"
OPENAPI="$ROOT/contracts/authscope-v1.yaml"
SIGNING_KEYS="$ROOT/contracts/authscope-signing-keys.json"

lock_field() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ''))" "$LOCK" "$1"
}

preflight() {
  echo "== run-real-integration: preflight =="

  command -v "$GO_BIN" >/dev/null 2>&1 || err "go toolchain not found ($GO_BIN)"
  command -v python3 >/dev/null 2>&1 || err "python3 is required for the preflight checks"
  command -v curl >/dev/null 2>&1 || err "curl is required for the preflight reachability checks"

  # 1. Every required variable is present. Each absence is named.
  need_var "AUTH_SCOPE_URL" "pinned real AuthScope service base URL" || true
  need_var "OPE_GATEWAY_URL" "enforcing AuthScope gateway base URL" || true
  need_var "OPE_RUNTIME_BIN" "supported authscope-agent-run executable" || true
  need_var "OPE_AGENT_KIT" "fixed coding-agent kit as id@version" || true
  need_var "OPE_GITHUB_REPO" "disposable private repository as owner/name" || true
  need_var "OPE_GITHUB_INSTALLATION_ID" "AuthScope-hosted GitHub installation id" || true
  need_var "OPE_SIGNING_KEYS_DIGEST" "expected signing-key-history digest" || true
  need_var "OPE_AUTHSCOPE_VERSION" "pinned immutable AuthScope release version" || true
  need_var "OPE_WORKSPACE_ID" "bound AuthScope workspace id" || true
  need_var "OPE_HOSTNAME" "public hostname of the OPE instance under test" || true
  need_var "OPE_ORIGIN" "exact browser origin of the OPE instance under test" || true
  need_var "OPE_WORKLOAD_SIGNER_REF" "non-exportable workload signer reference" || true
  need_var "OPE_URL" "base URL of the OPE release build under test" || true
  need_var "OPE_REAL_MANIFEST" "JSON manifest of operator-recorded artifacts" || true

  # 2. The pinned release is an immutable release, never a dev commit.
  # Commit 76fe961 is the design and contract-audit baseline only.
  WANT_VERSION="$(lock_field core_version)"
  GOT_VERSION="${OPE_AUTHSCOPE_VERSION:-}"
  if [ -n "$GOT_VERSION" ]; then
    if [ "$GOT_VERSION" = "76fe961" ]; then
      blocked "OPE_AUTHSCOPE_VERSION=76fe961 is the audit baseline commit, not an immutable release"
    elif [[ "$GOT_VERSION" =~ ^[0-9a-f]{7,40}$ ]]; then
      blocked "OPE_AUTHSCOPE_VERSION=$GOT_VERSION looks like a raw commit pin; an immutable release tag is required"
    elif [ "$GOT_VERSION" != "$WANT_VERSION" ]; then
      blocked "OPE_AUTHSCOPE_VERSION=$GOT_VERSION does not match the contract lock ($WANT_VERSION)"
    else
      ok "AuthScope release pin: $GOT_VERSION"
    fi
  fi
  KIND="$(lock_field core_version_kind)"
  if [ -n "$KIND" ] && [ "$KIND" != "release" ]; then
    blocked "contract lock core_version_kind=$KIND is not an immutable release"
  fi

  # 3. The vendored contract matches the lock (Step 5 release inputs).
  if [ -f "$OPENAPI" ]; then
    DIGEST="$(python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$OPENAPI")"
    WANT_OPENAPI="$(lock_field openapi_sha256)"
    if [ "$DIGEST" != "$WANT_OPENAPI" ]; then
      blocked "vendored OpenAPI digest $DIGEST != lock $WANT_OPENAPI"
    else
      ok "vendored OpenAPI digest matches the lock"
    fi
  else
    err "contracts/authscope-v1.yaml is missing"
  fi
  if [ -f "$SIGNING_KEYS" ]; then
    DIGEST="$(python3 -c "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$SIGNING_KEYS")"
    WANT_KEYS="$(lock_field signing_keys_sha256)"
    if [ "$DIGEST" != "$WANT_KEYS" ]; then
      blocked "vendored signing-keys digest $DIGEST != lock $WANT_KEYS"
    else
      ok "vendored signing-keys digest matches the lock"
    fi
  else
    err "contracts/authscope-signing-keys.json is missing"
  fi
  if ! scripts/verify-contract.sh >/dev/null 2>&1; then
    blocked "contract gate (scripts/verify-contract.sh) is not green against the vendored release"
  else
    ok "contract gate is green"
  fi

  # 4. URL shapes: https for the real service and gateway, owner/name
  # for the disposable repository, id@version for the fixed kit.
  for v in AUTH_SCOPE_URL OPE_GATEWAY_URL; do
    val="$(printenv "$v" 2>/dev/null || true)"
    if [ -n "$val" ]; then
      case "$val" in
        https://*) ok "$v uses https" ;;
        *) blocked "$v must use https in release mode: $val" ;;
      esac
    fi
  done
  REPO="${OPE_GITHUB_REPO:-}"
  if [ -n "$REPO" ]; then
    case "$REPO" in
      */*) ok "disposable repository: $REPO" ;;
      *) blocked "OPE_GITHUB_REPO must be owner/name: $REPO" ;;
    esac
  fi
  KIT="${OPE_AGENT_KIT:-}"
  if [ -n "$KIT" ]; then
    case "$KIT" in
      *@*latest*|*":latest"*)
        blocked "OPE_AGENT_KIT must pin an immutable kit version, not latest: $KIT" ;;
      *@*)
        ok "fixed agent kit: $KIT" ;;
      *)
        blocked "OPE_AGENT_KIT must be id@version: $KIT" ;;
    esac
  fi

  # 5. The runtime binary exists and is executable; record its digest
  # so the run report ties the exact build to the evidence.
  if [ -n "${OPE_RUNTIME_BIN:-}" ]; then
    if [ -x "$OPE_RUNTIME_BIN" ]; then
      ok "runtime binary: $OPE_RUNTIME_BIN (sha256 $(sha256sum "$OPE_RUNTIME_BIN" | cut -d' ' -f1 | cut -c1-16)...)"
    else
      blocked "OPE_RUNTIME_BIN is not an executable file: $OPE_RUNTIME_BIN"
    fi
  fi

  # 6. The workload signer reference is a reference, never key material.
  REF="${OPE_WORKLOAD_SIGNER_REF:-}"
  if [ -n "$REF" ]; then
    case "$REF" in
      *"BEGIN "*|*"PRIVATE KEY"*)
        blocked "OPE_WORKLOAD_SIGNER_REF looks like literal key material; a non-exportable reference is required" ;;
      *) ok "workload signer reference is set (non-exportable handle)" ;;
    esac
  fi

  # 7. Reachability: the real AuthScope, gateway, and OPE instance
  # answer over https. The signing-key history digest must match the
  # release input, proving we talk to the expected key history.
  if [ -n "${AUTH_SCOPE_URL:-}" ]; then
    KEYS_URL="${AUTH_SCOPE_URL%/}/.well-known/auth-scope-signing-keys"
    if BODY="$(curl -sf --max-time 15 "$KEYS_URL" 2>/dev/null)"; then
      SERVED_DIGEST="$(printf '%s' "$BODY" | sha256sum | cut -d' ' -f1)"
      if [ "$SERVED_DIGEST" = "${OPE_SIGNING_KEYS_DIGEST:-}" ]; then
        ok "serving signing-key history matches OPE_SIGNING_KEYS_DIGEST"
      else
        blocked "served signing-key history digest $SERVED_DIGEST != OPE_SIGNING_KEYS_DIGEST=${OPE_SIGNING_KEYS_DIGEST:-}"
      fi
    else
      blocked "AUTH_SCOPE_URL is not reachable at $KEYS_URL"
    fi
  fi
  if [ -n "${OPE_GATEWAY_URL:-}" ]; then
    curl -sf --max-time 15 -o /dev/null "${OPE_GATEWAY_URL%/}/healthz" 2>/dev/null \
      && ok "gateway is reachable" \
      || blocked "OPE_GATEWAY_URL is not reachable at ${OPE_GATEWAY_URL%/}/healthz"
  fi
  if [ -n "${OPE_URL:-}" ]; then
    curl -sf --max-time 15 -o /dev/null "${OPE_URL%/}/healthz" 2>/dev/null \
      && ok "OPE instance under test is reachable" \
      || blocked "OPE_URL is not reachable at ${OPE_URL%/}/healthz"
  fi

  # 8. The operator manifest exists and parses.
  if [ -n "${OPE_REAL_MANIFEST:-}" ]; then
    if [ -f "$OPE_REAL_MANIFEST" ]; then
      if python3 - "$OPE_REAL_MANIFEST" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
for k in ("mission_ref", "proposal_digest", "invocation_digest", "agent_kit", "runner_argv"):
    assert m.get(k), f"missing {k}"
PY
      then
        ok "operator manifest parses"
      else
        blocked "OPE_REAL_MANIFEST is not valid JSON or lacks mission_ref/proposal_digest/invocation_digest/agent_kit/runner_argv"
      fi
    else
      blocked "OPE_REAL_MANIFEST file not found: $OPE_REAL_MANIFEST"
    fi
  fi

  if [ "$ERRORS" -gt 0 ]; then
    echo "preflight: $ERRORS tooling error(s); cannot evaluate the gate" >&2
    return 2
  fi
  if [ "$BLOCKED" -gt 0 ]; then
    echo "preflight: $BLOCKED prerequisite(s) absent or mismatched; the real-integration gate is BLOCKED (not failed)"
    return 1
  fi
  echo "preflight: all real prerequisites present and pinned"
  return 0
}

MODE="${1:-}"
if [ "$MODE" = "--preflight" ]; then
  preflight
  exit "$?"
fi
if [ -n "$MODE" ] && [ "$MODE" != "--run" ]; then
  echo "usage: scripts/run-real-integration.sh [--preflight|--run]" >&2
  exit 2
fi

preflight || exit "$?"
echo "== run-real-integration: running the Go real-integration suite =="
export OPE_REAL_INTEGRATION=1
export GOSUMDB=off
exec "$GO_BIN" test ./test/integration/ -v -count=1
