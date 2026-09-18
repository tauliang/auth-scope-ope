#!/bin/bash
# check-secrets.sh: secret-leak scan for the OPE instance.
#
# Seeds canaries (or reuses the OPE_CANARY_* environment values), runs
# the Go credential-leak suite with them, then scans every durable
# surface for the canary values: tracked files, built assets, test
# logs, SQLite/WAL/SHM files, Compose config, and captured HTTP or
# browser artifacts. A canary found anywhere outside its bounded
# channel fails the scan.
#
# Fast by design: the whole run stays well under two minutes.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

GO_BIN="${GO_BIN:-/home/hatch/workspace/tools/go/bin/go}"
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
	GO_BIN="go"
fi

seed() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 8
	else
		# shellcheck disable=SC2006
		cat /dev/urandom | tr -dc 'a-f0-9' | head -c 16
	fi
}

export OPE_CANARY_SIGNER="${OPE_CANARY_SIGNER:-CANARY-$(seed)-signer}"
export OPE_CANARY_ATTESTATION="${OPE_CANARY_ATTESTATION:-CANARY-$(seed)-attestation}"
export OPE_CANARY_RECOVERY="${OPE_CANARY_RECOVERY:-CANARY-$(seed)-recovery}"
export OPE_CANARY_BINDING="${OPE_CANARY_BINDING:-CANARY-$(seed)-binding}"
export OPE_CANARY_PASSKEY="${OPE_CANARY_PASSKEY:-CANARY-$(seed)-passkey}"
export OPE_CANARY_CLI="${OPE_CANARY_CLI:-CANARY-$(seed)-cli}"
export OPE_CANARY_ENVELOPE="${OPE_CANARY_ENVELOPE:-CANARY-$(seed)-envelope}"
export OPE_CANARY_RUNTIME="${OPE_CANARY_RUNTIME:-CANARY-$(seed)-runtime}"
export OPE_CANARY_PRIVATE="${OPE_CANARY_PRIVATE:-CANARY-$(seed)-private}"

CANARIES="$OPE_CANARY_SIGNER $OPE_CANARY_ATTESTATION $OPE_CANARY_RECOVERY $OPE_CANARY_BINDING $OPE_CANARY_PASSKEY $OPE_CANARY_CLI $OPE_CANARY_ENVELOPE $OPE_CANARY_RUNTIME $OPE_CANARY_PRIVATE"

FAIL=0
fail() {
	echo "LEAK: $1"
	FAIL=1
}

echo "== check-secrets: running Go credential-leak suite =="
LOG="$(mktemp)"
export GOSUMDB=off
if "$GO_BIN" test ./test/security/ -count=1 >"$LOG" 2>&1; then
	echo "go security tests: PASS"
else
	echo "go security tests: FAIL"
	tail -30 "$LOG"
	fail "Go credential-leak suite failed (log: $LOG)"
fi

echo "== check-secrets: scanning test log =="
for c in $CANARIES; do
	if grep -qF -- "$c" "$LOG" 2>/dev/null; then
		fail "canary value present in test output log"
	fi
done
rm -f "$LOG"

echo "== check-secrets: scanning working-tree surfaces =="
# Surfaces: every tracked-or-present text file (excluding dependency
# trees and VCS metadata), built assets, logs, SQLite/WAL/SHM,
# Compose config, and captured artifacts.
scan_paths() {
	find "$REPO_ROOT" \
		-path "$REPO_ROOT/node_modules" -prune -o \
		-path "$REPO_ROOT/web/node_modules" -prune -o \
		-path "$REPO_ROOT/.git" -prune -o \
		-type f -print
	# Captured HTTP/browser artifacts and stray databases outside the tree.
	find /tmp -maxdepth 3 \( -name 'ope-*' -o -name '*.har' -o -name '*.db*' \) -type f 2>/dev/null
}

while IFS= read -r f; do
	for c in $CANARIES; do
		if grep -qF -- "$c" "$f" 2>/dev/null; then
			fail "canary value present in $f"
			break
		fi
	done
done < <(scan_paths)

echo "== check-secrets: scanning Compose config =="
for compose in "$REPO_ROOT"/docker-compose*.yml "$REPO_ROOT"/compose*.yaml; do
	[ -f "$compose" ] || continue
	for c in $CANARIES; do
		if grep -qF -- "$c" "$compose" 2>/dev/null; then
			fail "canary value present in $compose"
		fi
	done
done

if [ "$FAIL" -eq 0 ]; then
	echo "check-secrets: CLEAN"
else
	echo "check-secrets: FAILED"
fi
exit "$FAIL"
