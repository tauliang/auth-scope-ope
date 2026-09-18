// Command authscope-ope is the OPE edition server and CLI. It composes the
// local product: configuration, the upstream contract gate, the durable
// instance binding, and the HTTP API. Later tasks add doctor, run, revoke,
// and recover commands.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/httpapi"
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: authscope-ope <command>\n\ncommands:\n  serve    start the local OPE HTTP server\n")
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
	handler := httpapi.New(httpapi.Dependencies{Config: cfg, Contract: report, Store: st})
	log.Printf("authscope-ope listening on %s (core %s)", cfg.BindAddr, report.CoreVersion)
	return http.ListenAndServe(cfg.BindAddr, handler)
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
