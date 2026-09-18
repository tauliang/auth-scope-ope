// Package config loads strict OPE configuration from the environment.
//
// Two modes are supported. In "development" the operator may iterate
// locally; in "release" every credential must be a non-exportable
// workload-signer or mTLS key-handle reference. Static bearer tokens and
// literal private keys are rejected in release mode.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

var (
	ErrMissingAuthScopeURL          = errors.New("config: AUTH_SCOPE_URL is required")
	ErrInvalidAuthScopeURL          = errors.New("config: AUTH_SCOPE_URL is not a valid URL")
	ErrInsecureAuthScopeURL         = errors.New("config: AUTH_SCOPE_URL must use https in release mode")
	ErrInvalidMode                  = errors.New("config: OPE_MODE must be development or release")
	ErrMissingWorkloadSignerReference = errors.New("config: OPE_WORKLOAD_SIGNER_REF is required in release mode")
	ErrStaticCredentialRejected     = errors.New("config: static credential rejected in release mode")
)

// Config is the validated operator configuration for one OPE instance.
type Config struct {
	// Mode is "development" or "release".
	Mode string
	// AuthScopeURL is the base URL of the upstream mission-authority service.
	AuthScopeURL string
	// WorkloadSignerRef names the non-exportable workload signer or mTLS
	// key handle. Required in release mode; never a literal key.
	WorkloadSignerRef string
	// BindAddr is the local address the HTTP server listens on.
	BindAddr string
	// DataDir is the directory holding the SQLite presentation store.
	DataDir string
	// RootDir is the repository root used to locate contracts/ at runtime.
	RootDir string
}

// Load reads and validates configuration from the environment.
func Load() (Config, error) {
	var c Config

	c.Mode = strings.TrimSpace(getenv("OPE_MODE", "development"))
	if c.Mode != "development" && c.Mode != "release" {
		return Config{}, fmt.Errorf("%w: %q", ErrInvalidMode, c.Mode)
	}

	c.AuthScopeURL = strings.TrimSpace(os.Getenv("AUTH_SCOPE_URL"))
	if c.AuthScopeURL == "" {
		return Config{}, ErrMissingAuthScopeURL
	}
	u, err := url.Parse(c.AuthScopeURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Config{}, fmt.Errorf("%w: %q", ErrInvalidAuthScopeURL, c.AuthScopeURL)
	}

	if c.Mode == "release" {
		if u.Scheme != "https" {
			return Config{}, fmt.Errorf("%w: got %q", ErrInsecureAuthScopeURL, u.Scheme)
		}
		if v := strings.TrimSpace(os.Getenv("OPE_AUTH_SCOPE_TOKEN")); v != "" {
			return Config{}, fmt.Errorf("%w: OPE_AUTH_SCOPE_TOKEN must not be set; use the workload signer", ErrStaticCredentialRejected)
		}
		if v := strings.TrimSpace(os.Getenv("OPE_WORKLOAD_SIGNER_KEY")); v != "" {
			return Config{}, fmt.Errorf("%w: OPE_WORKLOAD_SIGNER_KEY is a literal key; set OPE_WORKLOAD_SIGNER_REF instead", ErrStaticCredentialRejected)
		}
		c.WorkloadSignerRef = strings.TrimSpace(os.Getenv("OPE_WORKLOAD_SIGNER_REF"))
		if c.WorkloadSignerRef == "" {
			return Config{}, ErrMissingWorkloadSignerReference
		}
	} else {
		c.WorkloadSignerRef = strings.TrimSpace(os.Getenv("OPE_WORKLOAD_SIGNER_REF"))
	}

	c.BindAddr = getenv("OPE_BIND_ADDR", "127.0.0.1:8080")
	c.DataDir = getenv("OPE_DATA_DIR", "./var/ope")
	c.RootDir = getenv("OPE_ROOT", ".")
	return c, nil
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
