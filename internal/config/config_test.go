package config

import (
	"errors"
	"testing"
)

// setInstanceEnv sets a valid immutable instance binding for tests that do
// not exercise binding validation themselves.
func setInstanceEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OPE_WORKSPACE_ID", "ws-test")
	t.Setenv("OPE_HOSTNAME", "ope.example.com")
	t.Setenv("OPE_ORIGIN", "https://ope.example.com")
	t.Setenv("OPE_RP_ID", "ope.example.com")
	t.Setenv("OPE_INSTANCE_ID", "inst-test-1")
}

func TestLoadRejectsReleaseWithoutWorkloadSignerReference(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "release")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_WORKLOAD_SIGNER_REF", "")
	t.Setenv("OPE_AUTH_SCOPE_TOKEN", "")
	t.Setenv("OPE_WORKLOAD_SIGNER_KEY", "")
	_, err := Load()
	if !errors.Is(err, ErrMissingWorkloadSignerReference) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsStaticTokenInRelease(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "release")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_WORKLOAD_SIGNER_REF", "pkcs11:token=ope;object=workload")
	t.Setenv("OPE_AUTH_SCOPE_TOKEN", "static-bearer-token")
	_, err := Load()
	if !errors.Is(err, ErrStaticCredentialRejected) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsLiteralPrivateKeyInRelease(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "release")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_WORKLOAD_SIGNER_REF", "pkcs11:token=ope;object=workload")
	t.Setenv("OPE_WORKLOAD_SIGNER_KEY", "-----BEGIN PRIVATE KEY-----")
	_, err := Load()
	if !errors.Is(err, ErrStaticCredentialRejected) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsHTTPAuthScopeURLInRelease(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "release")
	t.Setenv("AUTH_SCOPE_URL", "http://authority.example")
	t.Setenv("OPE_WORKLOAD_SIGNER_REF", "pkcs11:token=ope;object=workload")
	_, err := Load()
	if !errors.Is(err, ErrInsecureAuthScopeURL) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsInvalidMode(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "staging")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	_, err := Load()
	if !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsMissingAuthScopeURL(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "")
	_, err := Load()
	if !errors.Is(err, ErrMissingAuthScopeURL) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadAcceptsReleaseConfig(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "release")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_WORKLOAD_SIGNER_REF", "pkcs11:token=ope;object=workload")
	t.Setenv("OPE_AUTH_SCOPE_TOKEN", "")
	t.Setenv("OPE_WORKLOAD_SIGNER_KEY", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Mode != "release" || cfg.WorkloadSignerRef == "" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadAcceptsDevelopmentDefaults(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "http://127.0.0.1:8081")
	t.Setenv("OPE_BIND_ADDR", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.BindAddr != "127.0.0.1:8080" {
		t.Fatalf("default bind addr = %q", cfg.BindAddr)
	}
}

func TestLoadRejectsMissingWorkspaceID(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_WORKSPACE_ID", "")
	_, err := Load()
	if !errors.Is(err, ErrMissingWorkspaceID) {
		t.Fatalf("Load error = %v, want ErrMissingWorkspaceID", err)
	}
}

func TestLoadRejectsInvalidHostname(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_HOSTNAME", "not a host!")
	_, err := Load()
	if err == nil || !errors.Is(err, ErrMissingHostname) && !isHostnameError(err) {
		t.Fatalf("Load error = %v, want hostname validation failure", err)
	}
}

func isHostnameError(err error) bool {
	for err != nil {
		if err.Error() == "store: invalid hostname" {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestLoadRejectsHTTPOriginInRelease(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "release")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_WORKLOAD_SIGNER_REF", "pkcs11:token=ope;object=workload")
	t.Setenv("OPE_ORIGIN", "http://ope.example.com")
	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded with http origin in release mode")
	}
}

func TestLoadAcceptsLoopbackHTTPOriginInDevelopment(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "http://127.0.0.1:8081")
	t.Setenv("OPE_ORIGIN", "http://127.0.0.1:8080")
	t.Setenv("OPE_RP_ID", "127.0.0.1")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.Origin != "http://127.0.0.1:8080" {
		t.Fatalf("Origin = %q", cfg.Origin)
	}
}

func TestLoadRejectsNonLoopbackHTTPOriginInDevelopment(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "http://127.0.0.1:8081")
	t.Setenv("OPE_ORIGIN", "http://ope.example.com")
	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded with non-loopback http origin in development mode")
	}
}

func TestLoadRejectsRPIDMismatch(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_RP_ID", "unrelated.example.org")
	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded with mismatched RP ID")
	}
}

func TestLoadDerivesSessionCookieName(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.SessionCookieName != "__Host-authscope-ope-session-inst-test-1" {
		t.Fatalf("SessionCookieName = %q", cfg.SessionCookieName)
	}
}

func TestLoadGeneratesStableDefaultInstanceID(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_INSTANCE_ID", "")
	first, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if first.InstanceID == "" {
		t.Fatal("InstanceID must have a generated default")
	}
	second, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if first.InstanceID != second.InstanceID {
		t.Fatalf("default instance ID not stable: %q vs %q", first.InstanceID, second.InstanceID)
	}
	if first.SessionCookieName != "__Host-authscope-ope-session-"+first.InstanceID {
		t.Fatalf("SessionCookieName = %q", first.SessionCookieName)
	}
}

func TestLoadDefaultInstanceIDVariesByHostname(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_INSTANCE_ID", "")
	a, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	t.Setenv("OPE_HOSTNAME", "other.example.com")
	b, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if a.InstanceID == b.InstanceID {
		t.Fatal("default instance ID must differ per hostname")
	}
}

func TestLoadReadsRunnerPath(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_RUNNER_PATH", "/opt/runners/authscope-agent-run")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.RunnerPath != "/opt/runners/authscope-agent-run" {
		t.Fatalf("RunnerPath = %q", cfg.RunnerPath)
	}
}

func TestLoadRunnerPathDefaultsEmpty(t *testing.T) {
	setInstanceEnv(t)
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	t.Setenv("OPE_RUNNER_PATH", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load error = %v", err)
	}
	if cfg.RunnerPath != "" {
		t.Fatalf("RunnerPath = %q, want empty", cfg.RunnerPath)
	}
}
