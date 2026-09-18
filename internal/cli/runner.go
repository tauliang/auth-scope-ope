// Package cli: governed runner starter.
//
// StartGovernedRun starts the validated agent-runner binary with the
// signed launch envelope delivered on an anonymous pipe as the child's
// FD 3, under a fixed argument. The child inherits nothing: the
// environment holds only LANG, an isolated HOME and TMPDIR, and an
// explicit caller allowlist of non-secret KEY=VALUE entries. No
// user-supplied command or arguments, no shell, and no ambient
// credentials ever reach the child.
package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// launchEnvelopeFD is the fixed child file descriptor carrying the
// signed envelope.
const launchEnvelopeFD = 3

// runnerEnvAllowlistKey validates an allowlist entry key.
var runnerEnvAllowlistKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// deniedEnvPrefixes blocks credential, proxy, loader, container, cloud,
// VCS, and model variables from the explicit allowlist, case-insensitively.
var deniedEnvPrefixes = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"LD_", "DYLD_",
	"DOCKER_",
	"AWS_", "GCP_", "GOOGLE_", "AZURE_",
	"SSH_", "GIT_", "GH_", "GITHUB_",
	"ANTHROPIC_", "OPENAI_",
	"API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL",
}

// deniedEnvExact blocks exact variable names from the allowlist.
var deniedEnvExact = map[string]bool{
	"SHELL": true,
}

// RunOptions configures one governed runner start.
type RunOptions struct {
	// Stdout and Stderr receive the runner's output; they default to the
	// process's own stdout and stderr.
	Stdout io.Writer
	Stderr io.Writer
	// ExtraEnv is the explicit non-secret allowlist, as KEY=VALUE
	// entries. Entries are validated: malformed keys and any
	// credential, proxy, loader, container, cloud, VCS, shell, or model
	// variable is rejected.
	ExtraEnv []string
}

// StartGovernedRun validates the runner binary, builds the isolated
// environment, and starts the runner with the signed envelope on an
// anonymous pipe as FD 3. It returns the started command and a cleanup
// function that removes the isolated HOME and TMPDIR; call cleanup after
// the command finishes. The envelope write runs in the background so a
// large envelope never blocks the start.
func StartGovernedRun(ctx context.Context, runnerPath string, signedEnvelope []byte, opts RunOptions) (*exec.Cmd, func(), error) {
	cleanup := func() {}
	fail := func(err error) (*exec.Cmd, func(), error) {
		cleanup()
		return nil, func() {}, err
	}
	abs, err := ValidateRunnerPath(runnerPath)
	if err != nil {
		return fail(err)
	}
	if len(signedEnvelope) == 0 {
		return fail(fmt.Errorf("cli: signed envelope is empty"))
	}
	extra, err := validateRunnerEnv(opts.ExtraEnv)
	if err != nil {
		return fail(err)
	}
	homeDir, err := os.MkdirTemp("", "ope-run-home-")
	if err != nil {
		return fail(fmt.Errorf("cli: isolate HOME: %w", err))
	}
	tmpDir, err := os.MkdirTemp("", "ope-run-tmp-")
	if err != nil {
		return fail(fmt.Errorf("cli: isolate TMPDIR: %w", err))
	}
	cleanup = func() {
		_ = os.RemoveAll(homeDir)
		_ = os.RemoveAll(tmpDir)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return fail(fmt.Errorf("cli: envelope pipe: %w", err))
	}
	// Direct start: no shell, no lookup, the validated absolute binary
	// with the single fixed argument.
	cmd := exec.CommandContext(ctx, abs, "--launch-envelope-fd=3")
	cmd.ExtraFiles = []*os.File{pr}
	cmd.Stdin = nil
	if opts.Stdout != nil {
		cmd.Stdout = opts.Stdout
	} else {
		cmd.Stdout = os.Stdout
	}
	if opts.Stderr != nil {
		cmd.Stderr = opts.Stderr
	} else {
		cmd.Stderr = os.Stderr
	}
	cmd.Env = append([]string{
		"LANG=C.UTF-8",
		"HOME=" + homeDir,
		"TMPDIR=" + tmpDir,
	}, extra...)
	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return fail(fmt.Errorf("cli: start runner: %w", err))
	}
	// The parent drops its read end so the child sees EOF when the
	// writer closes.
	_ = pr.Close()
	go func() {
		_, _ = io.Copy(pw, bytes.NewReader(signedEnvelope))
		_ = pw.Close()
	}()
	return cmd, cleanup, nil
}

// validateRunnerEnv checks every allowlist entry is a well-formed
// KEY=VALUE pair whose key is not denied.
func validateRunnerEnv(extra []string) ([]string, error) {
	out := make([]string, 0, len(extra))
	for _, kv := range extra {
		key, _, ok := strings.Cut(kv, "=")
		if !ok || !runnerEnvAllowlistKey.MatchString(key) {
			return nil, fmt.Errorf("cli: malformed env entry %q", kv)
		}
		upper := strings.ToUpper(key)
		if deniedEnvExact[upper] {
			return nil, fmt.Errorf("cli: env variable %q is not allowed", key)
		}
		for _, p := range deniedEnvPrefixes {
			if strings.HasPrefix(upper, p) || strings.HasSuffix(upper, p) {
				return nil, fmt.Errorf("cli: env variable %q is not allowed", key)
			}
		}
		out = append(out, kv)
	}
	return out, nil
}
