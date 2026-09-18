// Command authscope-ope is the OPE edition server and CLI. It composes the
// local product: configuration, the upstream contract gate, and the HTTP
// API. Later tasks add doctor, run, revoke, and recover commands.
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/httpapi"
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
	handler := httpapi.New(httpapi.Dependencies{Config: cfg, Contract: report})
	log.Printf("authscope-ope listening on %s (core %s)", cfg.BindAddr, report.CoreVersion)
	return http.ListenAndServe(cfg.BindAddr, handler)
}
