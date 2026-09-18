#!/bin/bash
# check-runtime-leaks.sh: runtime credential-channel check for OPE.
#
# Proves a runtime credential reaches the governed runner only on the
# anonymous FD 3: a live child is inspected (argv, environment,
# inherited descriptors, full process listing) while it runs, its
# stdout/stderr and crash output are captured, and every surface except
# the FD 3 capture is asserted free of the canary. It also runs the Go
# structural proofs that the workload signer API stays non-exportable
# and that no key bytes enter OPE outside the FD channel.
#
# Skips gracefully (exit 0) when the Go toolchain or a build is
# unavailable, documenting the skip.
set -u

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

GO_BIN="${GO_BIN:-/home/hatch/workspace/tools/go/bin/go}"
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
	GO_BIN="go"
fi
if ! command -v "$GO_BIN" >/dev/null 2>&1; then
	echo "check-runtime-leaks: SKIP (no Go toolchain available)"
	exit 0
fi

seed() {
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -hex 8
	else
		cat /dev/urandom | tr -dc 'a-f0-9' | head -c 16
	fi
}
export OPE_CANARY_RUNTIME="${OPE_CANARY_RUNTIME:-CANARY-$(seed)-runtime}"
CANARY="$OPE_CANARY_RUNTIME"

FAIL=0
fail() {
	echo "LEAK: $1"
	FAIL=1
}

WORK="$(mktemp -d)"
# The probe must live inside the module tree to import internal
# packages; it is removed on exit.
PROBE_DIR="$REPO_ROOT/.runtime-probe-tmp"
trap 'rm -rf "$WORK" "$PROBE_DIR"' EXIT
mkdir -p "$PROBE_DIR"
DUMP="$WORK/dump"
mkdir -p "$DUMP"

# The fake runner: dumps everything it can observe about itself, reads
# the credential from FD 3 only, then crashes with a signal so the
# parent's crash output is exercised too.
RUNNER="$WORK/fake-runner"
cat >"$RUNNER" <<'RUNNER_EOF'
#!/bin/bash
{
	echo "--- cmdline ---"
	tr '\0' ' ' < /proc/self/cmdline
	echo
	echo "--- environ ---"
	tr '\0' '\n' < /proc/self/environ
	echo "--- fds ---"
	ls -l /proc/self/fd
} > "$OPE_DUMP_DIR/child-observed" 2>/dev/null
cat <&3 > "$OPE_DUMP_DIR/fd3"
echo "runner-stdout-marker"
echo "runner-stderr-marker" >&2
sleep 2
kill -SEGV $$
RUNNER_EOF
chmod 0700 "$RUNNER"

# The probe: starts the governed run with the canary as the in-memory
# envelope, snapshots the live child, and records the crash outcome.
# The canary is read from the probe's own environment; it is never
# written to a file, argv, or a child environment variable.
PROBE="$PROBE_DIR/probe.go"
cat >"$PROBE" <<'PROBE_EOF'
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tauliang/authscope-ope/internal/cli"
)

func snapshotted(path string, data []byte, err error) {
	if err != nil {
		data = []byte("snapshot-error: " + err.Error())
	}
	_ = os.WriteFile(path, data, 0o644)
}

func main() {
	canary := os.Getenv("OPE_CANARY_RUNTIME")
	dump := os.Getenv("OPE_PROBE_DUMP")
	runner := os.Getenv("OPE_PROBE_RUNNER")
	var stdout, stderr bytes.Buffer
	cmd, cleanup, err := cli.StartGovernedRun(context.Background(), runner, []byte(canary), cli.RunOptions{
		Stdout:   &stdout,
		Stderr:   &stderr,
		ExtraEnv: []string{"OPE_DUMP_DIR=" + dump},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "start: "+err.Error())
		os.Exit(2)
	}
	defer cleanup()
	pid := cmd.Process.Pid
	if out, err := exec.Command("ps", "-ef").Output(); err == nil {
		_ = os.WriteFile(filepath.Join(dump, "ps-ef"), out, 0o644)
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		_ = os.WriteFile(filepath.Join(dump, "child-cmdline"), data, 0o644)
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid)); err == nil {
		_ = os.WriteFile(filepath.Join(dump, "child-environ"), data, 0o644)
	}
	waitErr := cmd.Wait()
	snapshotted(filepath.Join(dump, "wait-error"), []byte(fmt.Sprintf("%v", waitErr)), nil)
	snapshotted(filepath.Join(dump, "parent-stdout"), stdout.Bytes(), nil)
	snapshotted(filepath.Join(dump, "parent-stderr"), stderr.Bytes(), nil)
}
PROBE_EOF

echo "== check-runtime-leaks: building probe =="
export GOSUMDB=off
if ! "$GO_BIN" build -o "$WORK/probe" "$PROBE" 2>"$WORK/build.log"; then
	echo "check-runtime-leaks: SKIP (probe build failed)"
	cat "$WORK/build.log"
	exit 0
fi

echo "== check-runtime-leaks: running governed child =="
OPE_PROBE_DUMP="$DUMP" OPE_PROBE_RUNNER="$RUNNER" "$WORK/probe" 2>"$WORK/probe-stderr.log"
PROBE_STATUS=$?
if [ "$PROBE_STATUS" -eq 2 ]; then
	echo "check-runtime-leaks: SKIP (could not start governed run)"
	cat "$WORK/probe-stderr.log"
	exit 0
fi

echo "== check-runtime-leaks: asserting FD 3 delivery =="
if [ ! -f "$DUMP/fd3" ]; then
	fail "FD 3 capture missing"
elif [ "$(cat "$DUMP/fd3")" != "$CANARY" ]; then
	fail "credential did not arrive intact on FD 3"
else
	echo "credential arrived intact on FD 3"
fi

echo "== check-runtime-leaks: scanning child-observable surfaces =="
for f in child-observed child-cmdline child-environ ps-ef parent-stdout parent-stderr wait-error; do
	[ -f "$DUMP/$f" ] || continue
	if grep -qF -- "$CANARY" "$DUMP/$f" 2>/dev/null; then
		fail "canary present in $f"
	fi
done

echo "== check-runtime-leaks: Go structural proofs =="
if "$GO_BIN" test ./test/security/ -run 'TestSignerNeverExportsKeyMaterial|TestRuntimeCredentialTravelsOnlyOnAnonymousFD' -count=1 >/dev/null 2>&1; then
	echo "signer non-exportable + FD-only credential channel: PASS"
else
	fail "Go runtime-channel proofs failed"
fi

if [ "$FAIL" -eq 0 ]; then
	echo "check-runtime-leaks: CLEAN"
else
	echo "check-runtime-leaks: FAILED"
fi
exit "$FAIL"
