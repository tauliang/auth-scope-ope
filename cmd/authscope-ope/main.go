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
	"syscall"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/cli"
	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/httpapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: authscope-ope <command>\n\ncommands:\n  serve         start the local OPE HTTP server\n  run <pass-id> authorize one launch of an approved pass through the browser\n")
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
	ctx := context.Background()
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
	})
	log.Printf("authscope-ope listening on %s (core %s)", cfg.BindAddr, report.CoreVersion)
	return http.ListenAndServe(cfg.BindAddr, handler)
}

// runLaunch authorizes one launch of an approved pass through the
// one-use browser PKCE handoff. It prints the browser URL, waits for the
// loopback callback, and retains the authorization bundle in memory for
// the Task 9 exchange until interrupted. Secrets are zeroed on completion,
// cancellation, timeout, or signal, and are never printed or written to
// disk.
func runLaunch(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: authscope-ope run <pass-id>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bundle, err := cli.AuthorizeLaunch(ctx, "http://"+cfg.BindAddr, args[0], cli.Options{})
	if err != nil {
		return err
	}
	defer bundle.Destroy()
	fmt.Printf("Authorized one launch of pass %s (authorization %s).\nProposal digest: %s\nHolding the authorization in memory for the launch exchange. Press Ctrl-C to discard it.\n",
		bundle.PassID, bundle.AuthorizationID, bundle.ProposalDigest)
	<-ctx.Done()
	fmt.Println("Discarded the launch authorization.")
	return nil
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
