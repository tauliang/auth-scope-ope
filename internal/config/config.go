// Package config loads strict OPE configuration from the environment.
//
// Two modes are supported. In "development" the operator may iterate
// locally; in "release" every credential must be a non-exportable
// workload-signer or mTLS key-handle reference. Static bearer tokens and
// literal private keys are rejected in release mode.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/tauliang/authscope-ope/internal/store"
)

var (
	ErrMissingAuthScopeURL            = errors.New("config: AUTH_SCOPE_URL is required")
	ErrInvalidAuthScopeURL            = errors.New("config: AUTH_SCOPE_URL is not a valid URL")
	ErrInsecureAuthScopeURL           = errors.New("config: AUTH_SCOPE_URL must use https in release mode")
	ErrInvalidMode                    = errors.New("config: OPE_MODE must be development or release")
	ErrMissingWorkloadSignerReference = errors.New("config: OPE_WORKLOAD_SIGNER_REF is required in release mode")
	ErrStaticCredentialRejected       = errors.New("config: static credential rejected in release mode")
	ErrMissingWorkspaceID             = errors.New("config: OPE_WORKSPACE_ID is required")
	ErrMissingHostname                = errors.New("config: OPE_HOSTNAME is required")
	ErrMissingOrigin                  = errors.New("config: OPE_ORIGIN is required")
	ErrMissingRPID                    = errors.New("config: OPE_RP_ID is required")
	ErrMissingRunnerPath              = errors.New("config: OPE_RUNNER_PATH is required to launch a governed run")
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
	// WorkspaceID is the single AuthScope workspace this instance serves.
	// Personal and business activity use separate instances.
	WorkspaceID string
	// Hostname is the public hostname of this instance.
	Hostname string
	// Origin is the exact browser origin (scheme://host[:port]) served.
	Origin string
	// RPID is the WebAuthn relying-party ID for passkey authentication.
	RPID string
	// InstanceID uniquely identifies this instance deployment. When
	// OPE_INSTANCE_ID is unset it defaults to a stable digest of the
	// workspace and hostname, so restarts rebind the same instance instead
	// of failing closed.
	InstanceID string
	// SessionCookieName is the __Host- session cookie name derived from the
	// instance ID.
	SessionCookieName string
	// RunnerPath is the absolute path of the governed agent-runner
	// executable the CLI starts. Set OPE_RUNNER_PATH; the run command
	// requires it and validates the binary before every launch.
	RunnerPath string
	// TelemetryEnabled is the explicit operator opt-in for
	// privacy-limited product telemetry. Only OPE_TELEMETRY=enabled
	// turns it on; telemetry is off by default in development and stays
	// off in release mode until explicitly configured.
	TelemetryEnabled bool
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
	c.RunnerPath = strings.TrimSpace(os.Getenv("OPE_RUNNER_PATH"))
	// Telemetry is consent-gated: only an explicit OPE_TELEMETRY=enabled
	// turns it on. Development defaults to off, and release mode keeps
	// it off until explicitly configured.
	c.TelemetryEnabled = strings.TrimSpace(os.Getenv("OPE_TELEMETRY")) == "enabled"

	if err := loadInstanceBinding(&c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// loadInstanceBinding reads the immutable instance binding from the
// environment: workspace, hostname, origin, RP ID, and instance ID. The
// session cookie name derives from the instance ID.
func loadInstanceBinding(c *Config) error {
	c.WorkspaceID = strings.TrimSpace(os.Getenv("OPE_WORKSPACE_ID"))
	if c.WorkspaceID == "" {
		return ErrMissingWorkspaceID
	}

	c.Hostname = strings.TrimSpace(os.Getenv("OPE_HOSTNAME"))
	if c.Hostname == "" {
		return ErrMissingHostname
	}
	if err := store.ValidateHostname(c.Hostname); err != nil {
		return fmt.Errorf("config: OPE_HOSTNAME: %w", err)
	}

	c.Origin = strings.TrimSpace(os.Getenv("OPE_ORIGIN"))
	if c.Origin == "" {
		return ErrMissingOrigin
	}
	origin, err := store.ValidateOrigin(c.Origin, c.Mode)
	if err != nil {
		return fmt.Errorf("config: OPE_ORIGIN: %w", err)
	}

	c.RPID = strings.TrimSpace(os.Getenv("OPE_RP_ID"))
	if c.RPID == "" {
		return ErrMissingRPID
	}
	if err := store.ValidateRPID(c.RPID, origin, c.Mode); err != nil {
		return fmt.Errorf("config: OPE_RP_ID: %w", err)
	}

	c.InstanceID = strings.TrimSpace(os.Getenv("OPE_INSTANCE_ID"))
	if c.InstanceID == "" {
		c.InstanceID = defaultInstanceID(c.WorkspaceID, c.Hostname)
	} else if err := store.ValidateInstanceID(c.InstanceID); err != nil {
		return fmt.Errorf("config: OPE_INSTANCE_ID: %w", err)
	}

	c.SessionCookieName = store.DeriveSessionCookieName(c.InstanceID)
	return nil
}

// defaultInstanceID derives a stable instance ID from the workspace and
// hostname. Stability across restarts matters: the store binds the instance
// record once, and a fresh random ID on every start would fail closed with
// ErrInstanceRebind. Distinct hostnames (or workspaces) still yield distinct
// IDs, matching the one-instance-per-workspace deployment model.
func defaultInstanceID(workspaceID, hostname string) string {
	sum := sha256.Sum256([]byte("authscope-ope/instance-id/v1\x00" + workspaceID + "\x00" + hostname))
	return hex.EncodeToString(sum[:16])
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}
