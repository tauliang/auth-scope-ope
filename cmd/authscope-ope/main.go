// Command authscope-ope is the OPE edition server and CLI. It composes the
// local product: configuration, the upstream contract gate, the durable
// instance binding, and the HTTP API. Later tasks add doctor, run, revoke,
// and recover commands.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/cli"
	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/expansion"
	"github.com/tauliang/authscope-ope/internal/httpapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/launch"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/reconcile"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := runServe(); err != nil {
			log.Fatalf("serve: %v", err)
		}
	case "run":
		if err := runLaunch(os.Args[2:]); err != nil {
			log.Fatalf("run: %v", err)
		}
	case "revoke":
		if err := runRevoke(os.Args[2:]); err != nil {
			log.Fatalf("revoke: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: authscope-ope <command>\n\ncommands:\n  serve                        start the local OPE HTTP server\n  run <pass-id>                authorize one launch of an approved pass through the browser\n  revoke <pass-id> <reason>    revoke a governed mission through the founder's browser\n")
}

func runServe() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	report := coreapi.VerifyVendoredContract(cfg.RootDir)
	for _, w := range report.Warnings {
		log.Printf("contract warning: %s", w)
	}
	if !report.DigestMatch {
		return fmt.Errorf("upstream contract digest mismatch: %v", report.Problems)
	}
	st, err := bindInstance(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			log.Printf("close store: %v", err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	signer, err := resolveWorkloadSigner(cfg)
	if err != nil {
		return err
	}
	client, err := coreapi.NewClient(cfg.AuthScopeURL, nil, signer, cfg.Mode)
	if err != nil {
		return fmt.Errorf("authscope client: %w", err)
	}
	// Live compatibility gate: verify the deployed core and the
	// transport-authenticated workload identity before serving, attach
	// the stable identity digest exactly once, and keep re-verifying.
	// An identity mismatch is fatal; any other verification failure
	// leaves /readyz unhealthy until a later check succeeds.
	gate := coreapi.NewGate(client, st)
	if err := gate.Verify(ctx); err != nil {
		if errors.Is(err, coreapi.ErrIdentityMismatch) {
			return fmt.Errorf("workload identity mismatch: %w", err)
		}
		log.Printf("WARNING: upstream compatibility not verified: %v; /readyz stays unhealthy until verification succeeds", err)
	} else {
		log.Printf("upstream compatibility verified; workload identity %s", gate.IdentityDigest())
	}
	gate.StartRefresher(ctx, 10*time.Second, log.Printf)
	gated := coreapi.NewGatedAuthority(client, gate)

	verifier, err := authn.NewWebAuthnVerifier(cfg.RPID, cfg.Origin)
	if err != nil {
		return fmt.Errorf("webauthn verifier: %w", err)
	}
	authnSvc, err := authn.NewService(ctx, st, verifier)
	if err != nil {
		return fmt.Errorf("authn service: %w", err)
	}
	attestor := identity.NewDecisionAttestor(signer)
	cliAuth, err := authn.NewCLIAuthorizationService(authn.CLIAuthorizationConfig{
		Store:          st,
		Authn:          authnSvc,
		Attestor:       attestor,
		BrowserBaseURL: cfg.Origin,
	})
	if err != nil {
		return fmt.Errorf("CLI authorization service: %w", err)
	}
	// Task 9: the launch service exchanges one authorization code plus
	// verifier for exactly one upstream launch preparation. It shares the
	// CLI handoff's in-memory decision attestations and the gated
	// upstream authority. The service cannot open sealed envelopes (only
	// the CLI ephemeral key opens them), but it refuses to adopt
	// artifacts sealed under a signing key the trust pin does not know.
	// The pin file digest is enforced by make contract-ready against the
	// contract lock, so the file itself is the trust root here; the empty
	// expected fingerprint keeps that behavior while the loader still
	// validates the root fingerprint declared inside the file.
	keys, err := trust.LoadSigningKeys(filepath.Join(cfg.RootDir, "contracts", "authscope-signing-keys.json"), "")
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	launchSvc, err := launch.NewService(launch.Config{
		Store:        st,
		WorkspaceID:  cfg.WorkspaceID,
		Authority:    gated,
		Attestations: cliAuth.Attestations(),
		Keys:         keys,
	})
	if err != nil {
		return fmt.Errorf("launch service: %w", err)
	}
	// Task 10: the safe event projector replays the authority's event
	// stream into the local projection with strict allowlisted decoding
	// and durable cursors; the revocation service governs
	// founder-decided mission revocations with canonical passkey
	// binding; the CLI revocation service runs the result-only loopback
	// PKCE handoff. The reconciliation worker keeps projections fresh
	// and retries stuck revocation intents under a single-instance
	// lease.
	projector := missionpass.NewEventProjector(st, gate)
	revocationSvc, err := missionpass.NewRevocationService(missionpass.RevocationConfig{
		Store:     st,
		Authn:     authnSvc,
		Authority: gated,
		Attestor:  attestor,
	})
	if err != nil {
		return fmt.Errorf("revocation service: %w", err)
	}
	cliRevocationSvc, err := missionpass.NewCLIRevocationService(missionpass.CLIRevocationConfig{
		Store:       st,
		Revocation:  revocationSvc,
		WorkspaceID: cfg.WorkspaceID,
		BrowserURL:  cfg.Origin,
	})
	if err != nil {
		return fmt.Errorf("CLI revocation service: %w", err)
	}
	// The expansion service governs the founder's exact one-use
	// expansion decisions through a passkey ceremony.
	expansionSvc, err := expansion.NewService(expansion.Config{
		Store:     st,
		Authn:     authnSvc,
		Authority: gated,
		Attestor:  attestor,
	})
	if err != nil {
		return fmt.Errorf("expansion service: %w", err)
	}
	// The receipt service owns the pass-owned receipt loop: fetching
	// the upstream receipt envelope, verifying it locally against the
	// pinned signing keys, transitioning the pass only on a verified
	// receipt, and publishing the privacy-safe GitHub check exactly
	// once. The worker drives it; the HTTP layer serves the private
	// view.
	receiptSvc, err := receipt.NewService(receipt.Config{
		Store:     st,
		Authority: gated,
		Keys:      keys,
	})
	if err != nil {
		return fmt.Errorf("receipt service: %w", err)
	}
	worker, err := reconcile.NewWorker(reconcile.Config{
		Store:        st,
		Authority:    gated,
		Projector:    projector,
		Revocation:   revocationSvc,
		Expansion:    expansionSvc,
		Receipt:      receiptSvc,
		InstanceID:   cfg.InstanceID,
		WorkspaceID:  cfg.WorkspaceID,
		PollInterval: 10 * time.Second,
		LeaseTTL:     30 * time.Second,
		Log:          log.Printf,
	})
	if err != nil {
		return fmt.Errorf("reconciliation worker: %w", err)
	}
	// The bootstrap code is issued and printed only for an unenrolled
	// instance. EnsureBootstrapCode returns an empty code once a founder
	// is enrolled, so the secret never appears on the terminal again.
	if code, err := authnSvc.EnsureBootstrapCode(ctx); err != nil {
		return fmt.Errorf("bootstrap code: %w", err)
	} else if code != "" {
		fmt.Printf("Founder enrollment is open. Enter this one-time code in the browser:\n\n  %s\n\nThe code expires in ten minutes and is never shown again.\n", code)
	}
	handler := httpapi.New(httpapi.Dependencies{
		Config: cfg, Contract: report, Store: st, Authn: authnSvc,
		Gate: gate, Authority: gated,
		Attestor: attestor,
		CLIAuth:  cliAuth,
		Launch:   launchSvc,
		Revocation: revocationSvc,
		CLIRevocation: cliRevocationSvc,
		Projector:  projector,
		Expansion:  expansionSvc,
		Receipt:    receiptSvc,
	})
	srv := &http.Server{Addr: cfg.BindAddr, Handler: handler}
	// A server start failure (for example, the port is taken) returns
	// from runServe instead of leaving it blocked on the signal.
	serverErr := make(chan error, 1)
	workerErr := make(chan error, 1)
	go func() {
		log.Printf("authscope-ope listening on %s (core %s)", cfg.BindAddr, report.CoreVersion)
		serverErr <- srv.ListenAndServe()
	}()
	go func() { workerErr <- worker.Run(ctx) }()
	select {
	case <-ctx.Done():
		// Signal received: shut down gracefully below.
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			stop()
			if werr := <-workerErr; werr != nil {
				log.Printf("reconciliation worker: %v", werr)
			}
			return fmt.Errorf("http server: %w", err)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
	if err := <-workerErr; err != nil {
		return fmt.Errorf("reconciliation worker: %w", err)
	}
	return nil
}

// runLaunch authorizes one launch of an approved pass through the
// one-use browser PKCE handoff, exchanges the code for the sealed signed
// envelope, opens and verifies the envelope, and starts the governed
// runner with the signed envelope on FD 3. Secrets are zeroed on
// completion, cancellation, timeout, or signal, and are never printed or
// written to disk. No user-supplied command or arguments are accepted:
// everything the runner receives comes from the verified envelope.
func runLaunch(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: authscope-ope run <pass-id>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if cfg.RunnerPath == "" {
		return config.ErrMissingRunnerPath
	}
	runnerPath, err := cli.ValidateRunnerPath(cfg.RunnerPath)
	if err != nil {
		return err
	}
	// The pin file digest is enforced by make contract-ready against the
	// contract lock, so the file itself is the trust root here; the empty
	// expected fingerprint keeps that behavior while the loader still
	// validates the root fingerprint declared inside the file.
	keys, err := trust.LoadSigningKeys(filepath.Join(cfg.RootDir, "contracts", "authscope-signing-keys.json"), "")
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	apiBase := "http://" + cfg.BindAddr
	bundle, err := cli.AuthorizeLaunch(ctx, apiBase, args[0], cli.Options{})
	if err != nil {
		return err
	}
	defer bundle.Destroy()
	fmt.Printf("Authorized one launch of pass %s (authorization %s).\n", bundle.PassID, bundle.AuthorizationID)

	exchange, err := cli.ExchangeLaunch(ctx, apiBase, bundle, nil)
	if err != nil {
		return err
	}
	// The envelope must name exactly the validated binary about to
	// start; anything else fails closed here.
	payload, signed, err := bundle.OpenSealedEnvelope(exchange.SealedEnvelope, keys, runnerPath)
	if err != nil {
		return err
	}
	fmt.Printf("Starting governed run %s (mission %s, kit %s %s).\n",
		payload.RunID, payload.MissionRef, payload.AgentKitID, payload.AgentKitVersion)
	cmd, cleanup, err := cli.StartGovernedRun(ctx, runnerPath, signed, cli.RunOptions{})
	if err != nil {
		return err
	}
	defer cleanup()
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("runner: %w", err)
	}
	fmt.Printf("Governed run %s finished.\n", payload.RunID)
	return nil
}

// runRevoke revokes a governed mission through the founder's browser:
// the CLI registers the revocation with the fixed reason, the founder
// decides in the browser, and the CLI exchanges the one-use result code
// for only the opaque result reference plus the fixed containment
// state. No session or credential is issued; handoff secrets are zeroed
// on completion, cancellation, or signal.
func runRevoke(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: authscope-ope revoke <pass-id>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	apiBase := "http://" + cfg.BindAddr
	// RevokeMission prints the browser URL and the final result; it
	// returns the outcome for callers that need it programmatically.
	_, err = cli.RevokeMission(ctx, apiBase, args[0], cli.RevokeOptions{})
	return err
}

// resolveWorkloadSigner resolves the non-exportable workload signer for
// the AuthScope transport and decision attestations. Release mode fails
// closed: HSM/TEE-backed reference resolution lands in a later task, so
// any configured reference is unresolvable by this build. Development with
// no reference uses an ephemeral in-memory signer, which is generated
// fresh on every start, clearly marked dev-only, and must never be used
// in release mode.
func resolveWorkloadSigner(cfg config.Config) (identity.Signer, error) {
	if cfg.Mode == "release" || cfg.WorkloadSignerRef != "" {
		return nil, fmt.Errorf("%w: %q", identity.ErrUnresolvableSigner, cfg.WorkloadSignerRef)
	}
	log.Printf("WARNING: using an ephemeral dev-only workload signer; it is generated fresh on every start and must never be used in release mode")
	return identity.NewEphemeralSigner(), nil
}

// bindInstance opens the presentation store and establishes the immutable
// instance binding before any route is registered. It fails closed when the
// stored binding differs from configuration, so a misconfigured instance
// can never serve another workspace's state.
func bindInstance(cfg config.Config) (store.Store, error) {
	st, err := store.Open(cfg.DataDir, cfg.Mode)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	ctx := context.Background()
	rec := store.InstanceRecord{
		InstanceID:        cfg.InstanceID,
		WorkspaceID:       cfg.WorkspaceID,
		Hostname:          cfg.Hostname,
		Origin:            cfg.Origin,
		RPID:              cfg.RPID,
		SessionCookieName: cfg.SessionCookieName,
		CreatedAt:         time.Now().UTC(),
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.BindInstance(ctx, rec)
	}); err != nil {
		return nil, fmt.Errorf("bind instance: %w", err)
	}
	log.Printf("instance %s bound to workspace %q", cfg.InstanceID, cfg.WorkspaceID)
	return st, nil
}
