// Command recover: offline recovery of a workspace-bound OPE instance.
//
// When the founder loses every authentication method, the operator runs
// "authscope-ope recover --data-dir <absolute-path>" on the instance
// host. The command opens the data directory with an exclusive lock
// (refusing while the server holds it), reads the one-time offline
// recovery key from the controlling terminal with echo disabled, asks
// the operator to type the workspace ID exactly, and runs the offline
// recovery: verify the key, attest the fixed workspace-wide containment
// decision, ask AuthScope to bulk-contain the workspace, wait for the
// authoritative active-mission list to come back empty, then reset local
// authentication state and print one ten-minute bootstrap code to the
// controlling terminal. The raw key and the raw code never reach argv,
// the environment, configuration, logs, or the store.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/recovery"
	"github.com/tauliang/authscope-ope/internal/store"
)

// RecoverConfig wires the recover command.
type RecoverConfig struct {
	// DataDir is the instance data directory. It must be absolute.
	DataDir string
	// Mode is "development" or "release".
	Mode string
	// AuthScopeURL is the upstream mission-authority base URL.
	AuthScopeURL string
	// Signer is the non-exportable workload signer used for the
	// containment attestation.
	Signer identity.Signer

	// Terminal is the controlling terminal for prompts, echo-disabled
	// key entry, and the bootstrap code print. Defaults to /dev/tty.
	Terminal Terminal
	// ErrW receives non-interactive diagnostics; defaults to os.Stderr.
	ErrW io.Writer
	// Clock returns the current time; defaults to time.Now.
	Clock func() time.Time

	// OpenStore opens the data directory exclusively; defaults to
	// store.OpenExclusive.
	OpenStore func(dataDir, mode string) (store.Store, error)
	// NewAuthority builds the upstream authority; defaults to
	// coreapi.NewClient.
	NewAuthority func(authScopeURL string, signer identity.Signer, mode string) (coreapi.Authority, error)
	// ReadPassword reads the recovery key with echo disabled; defaults
	// to term.ReadPassword on the terminal fd.
	ReadPassword func(fd int) ([]byte, error)
}

// Terminal is the controlling terminal: prompts go out, the typed
// workspace ID and the echo-disabled key come in, and the bootstrap
// code is printed back.
type Terminal interface {
	io.Reader
	io.Writer
	Fd() uintptr
}

// ttyTerminal opens /dev/tty read-write.
type ttyTerminal struct {
	f *os.File
}

func (t *ttyTerminal) Read(p []byte) (int, error)  { return t.f.Read(p) }
func (t *ttyTerminal) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *ttyTerminal) Fd() uintptr                 { return t.f.Fd() }
func (t *ttyTerminal) Close() error                { return t.f.Close() }

func openControllingTerminal() (*ttyTerminal, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("cli: open controlling terminal: %w", err)
	}
	return &ttyTerminal{f: f}, nil
}

// RunRecover runs the offline recovery command.
func RunRecover(ctx context.Context, cfg RecoverConfig) error {
	if cfg.DataDir == "" {
		return errors.New("recover: --data-dir is required")
	}
	if !filepath.IsAbs(cfg.DataDir) {
		return fmt.Errorf("recover: --data-dir must be an absolute path, got %q", cfg.DataDir)
	}
	mode := cfg.Mode
	if mode == "" {
		mode = "development"
	}
	// The normalized mode feeds the store and the authority builder, so
	// an empty mode never reaches NewClient.
	cfg.Mode = mode
	if cfg.Signer == nil {
		return errors.New("recover: workload signer is required")
	}
	errW := cfg.ErrW
	if errW == nil {
		errW = os.Stderr
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	openStore := cfg.OpenStore
	if openStore == nil {
		openStore = store.OpenExclusive
	}
	newAuthority := cfg.NewAuthority
	if newAuthority == nil {
		newAuthority = func(authScopeURL string, signer identity.Signer, mode string) (coreapi.Authority, error) {
			return coreapi.NewClient(authScopeURL, nil, signer, mode)
		}
	}

	// The exclusive lock refuses while the server owns the data
	// directory: recovery never runs against a live server.
	st, err := openStore(cfg.DataDir, mode)
	if err != nil {
		return fmt.Errorf("recover: open data directory: %w", err)
	}
	defer func() {
		_ = st.Close()
	}()

	inst, err := st.GetInstance(ctx)
	if err != nil {
		return fmt.Errorf("recover: load instance record: %w", err)
	}

	var tty Terminal = cfg.Terminal
	var closeTTY func()
	if tty == nil {
		t, err := openControllingTerminal()
		if err != nil {
			return err
		}
		tty = t
		closeTTY = func() { _ = t.Close() }
	}
	if closeTTY != nil {
		defer closeTTY()
	}
	readPassword := cfg.ReadPassword
	if readPassword == nil {
		readPassword = term.ReadPassword
	}

	fmt.Fprintf(tty, "Offline recovery for workspace %q on instance %q.\n", inst.WorkspaceID, inst.InstanceID)
	fmt.Fprintf(tty, "This contains the workspace at AuthScope, revokes every session,\n")
	fmt.Fprintf(tty, "deletes passkey credentials, and issues a fresh bootstrap code.\n\n")

	fmt.Fprintf(tty, "Offline recovery key: ")
	key, err := readPassword(int(tty.Fd()))
	fmt.Fprintf(tty, "\n")
	if err != nil {
		return fmt.Errorf("recover: read recovery key: %w", err)
	}
	// The key lives only in this slice; it is zeroed before return.
	defer zeroSecret(key)
	if len(key) == 0 {
		return errors.New("recover: empty recovery key")
	}

	fmt.Fprintf(tty, "Type the workspace ID %q to confirm: ", inst.WorkspaceID)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		return fmt.Errorf("recover: read workspace confirmation: %w", err)
	}
	// Exact match: strip exactly one trailing newline (and CR), nothing
	// else. Surrounding spaces do not match.
	confirm := strings.TrimSuffix(line, "\n")
	confirm = strings.TrimSuffix(confirm, "\r")

	svc, err := newRecoveryService(cfg, st, tty, clock, newAuthority)
	if err != nil {
		return err
	}
	res, err := svc.ResetOffline(ctx, recovery.RecoveryRequest{
		WorkspaceID:      inst.WorkspaceID,
		RecoveryKey:      key,
		ConfirmWorkspace: confirm,
	})
	if err != nil {
		return fmt.Errorf("recover: %w", err)
	}
	fmt.Fprintf(errW, "recovery event %s: revoked %d session(s), contained %d mission(s)\n",
		res.RecoveryEventID, res.RevokedSessionCount, res.ContainedMissionCount)
	return nil
}

func newRecoveryService(cfg RecoverConfig, st store.Store, tty Terminal, clock func() time.Time,
	newAuthority func(string, identity.Signer, string) (coreapi.Authority, error)) (*recovery.Service, error) {
	authority, err := newAuthority(cfg.AuthScopeURL, cfg.Signer, cfg.Mode)
	if err != nil {
		return nil, fmt.Errorf("recover: build authority: %w", err)
	}
	return recovery.NewService(recovery.Config{
		Store:     st,
		Authority: authority,
		Attestor:  identity.NewDecisionAttestor(cfg.Signer),
		Clock:     clock,
		BootstrapCodeSink: func(code string, expiresAt time.Time) {
			fmt.Fprintf(tty, "\nWorkspace recovered.\n")
			fmt.Fprintf(tty, "Fresh bootstrap code (valid for ten minutes, shown once):\n\n")
			fmt.Fprintf(tty, "    %s\n\n", code)
			fmt.Fprintf(tty, "Expires at %s. Re-enroll the founder now and choose a\n",
				expiresAt.UTC().Format(time.RFC3339))
			fmt.Fprintf(tty, "replacement recovery method during the ceremony.\n")
		},
	})
}

// zeroSecret clears a secret byte slice.
func zeroSecret(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
