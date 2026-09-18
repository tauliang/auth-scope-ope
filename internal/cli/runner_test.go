package cli_test

// Tests for the governed runner starter: the binary is validated before
// every launch (absolute, no symlink, regular file, owned by the current
// user or root, not group- or world-writable), the signed envelope is
// delivered on an anonymous pipe as the child's FD 3, and the child
// environment holds only LANG, an isolated HOME and TMPDIR, and the
// explicit allowlist.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/cli"
)

func writeRunnerScript(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent-run")
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateRunnerPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only validation")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "agent-run")
	if err := os.WriteFile(good, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, err := cli.ValidateRunnerPath(good); err != nil || got != good {
		t.Fatalf("ValidateRunnerPath = %q, %v", got, err)
	}
	link := filepath.Join(dir, "link-run")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.ValidateRunnerPath(link); err == nil {
		t.Fatal("expected error for symlink runner")
	}
	writable := filepath.Join(dir, "writable-run")
	if err := os.WriteFile(writable, []byte("#!/bin/sh\n"), 0o775); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.ValidateRunnerPath(writable); err == nil {
		t.Fatal("expected error for group/world-writable runner")
	}
	if _, err := cli.ValidateRunnerPath(dir); err == nil {
		t.Fatal("expected error for directory runner")
	}
	if _, err := cli.ValidateRunnerPath("relative/path"); err == nil {
		t.Fatal("expected error for relative runner path")
	}
	if _, err := cli.ValidateRunnerPath(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("expected error for missing runner")
	}
	if _, err := cli.ValidateRunnerPath(""); err == nil {
		t.Fatal("expected error for empty runner path")
	}
}

func TestStartGovernedRunDeliversEnvelopeOnFD3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only validation")
	}
	// The script echoes whatever arrives on FD 3 and dumps its
	// environment: the test asserts the envelope bytes arrive intact
	// and the environment is isolated.
	script := writeRunnerScript(t, "cat <&3; echo '---env---'; env | sort", 0o700)
	t.Setenv("OPE_TEST_INHERIT_MARKER", "must-not-inherit")
	var stdout bytes.Buffer
	cmd, cleanup, err := cli.StartGovernedRun(context.Background(), script, []byte("signed-envelope-bytes"),
		cli.RunOptions{Stdout: &stdout, ExtraEnv: []string{"OPE_RUNNER_NOTE=hello"}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer cleanup()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runner: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runner did not finish")
	}
	out := stdout.String()
	parts := strings.SplitN(out, "---env---\n", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "signed-envelope-bytes") {
		t.Fatalf("envelope not delivered on FD 3: %q", out)
	}
	env := parts[1]
	if strings.Contains(env, "OPE_TEST_INHERIT_MARKER") {
		t.Fatal("child inherited process environment")
	}
	if !strings.Contains(env, "LANG=C.UTF-8") {
		t.Fatal("child missing LANG=C.UTF-8")
	}
	if !strings.Contains(env, "OPE_RUNNER_NOTE=hello") {
		t.Fatal("child missing allowlisted variable")
	}
	var home, tmpdir string
	for _, line := range strings.Split(env, "\n") {
		if strings.HasPrefix(line, "HOME=") {
			home = strings.TrimPrefix(line, "HOME=")
		}
		if strings.HasPrefix(line, "TMPDIR=") {
			tmpdir = strings.TrimPrefix(line, "TMPDIR=")
		}
	}
	if home == "" || tmpdir == "" {
		t.Fatal("child missing isolated HOME/TMPDIR")
	}
	if home == os.Getenv("HOME") {
		t.Fatal("child HOME is not isolated")
	}
	for _, d := range []string{home, tmpdir} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			t.Fatalf("isolated dir %q missing", d)
		}
	}
	cleanup()
	for _, d := range []string{home, tmpdir} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Fatalf("isolated dir %q not cleaned up", d)
		}
	}
}

func TestStartGovernedRunRejectsDeniedEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only validation")
	}
	script := writeRunnerScript(t, "true", 0o700)
	for _, kv := range []string{
		"HTTP_PROXY=http://proxy",
		"http_proxy=http://proxy",
		"LD_PRELOAD=/tmp/evil.so",
		"DOCKER_HOST=tcp://x",
		"AWS_SECRET_ACCESS_KEY=secret",
		"GITHUB_TOKEN=secret",
		"ANTHROPIC_API_KEY=secret",
		"SHELL=/bin/bash",
		"MY_API_KEY=secret",
		"nope",
		"1BAD=oops",
	} {
		_, _, err := cli.StartGovernedRun(context.Background(), script, []byte("x"),
			cli.RunOptions{ExtraEnv: []string{kv}})
		if err == nil {
			t.Fatalf("expected error for env entry %q", kv)
		}
	}
}

func TestStartGovernedRunRejectsBadRunner(t *testing.T) {
	_, _, err := cli.StartGovernedRun(context.Background(), "relative/runner", []byte("x"), cli.RunOptions{})
	if err == nil {
		t.Fatal("expected error for relative runner path")
	}
	_, _, err = cli.StartGovernedRun(context.Background(), "/nonexistent/runner", []byte("x"), cli.RunOptions{})
	if err == nil {
		t.Fatal("expected error for missing runner")
	}
}
