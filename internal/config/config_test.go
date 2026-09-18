package config

import (
	"errors"
	"testing"
)

func TestLoadRejectsReleaseWithoutWorkloadSignerReference(t *testing.T) {
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
	t.Setenv("OPE_MODE", "release")
	t.Setenv("AUTH_SCOPE_URL", "http://authority.example")
	t.Setenv("OPE_WORKLOAD_SIGNER_REF", "pkcs11:token=ope;object=workload")
	_, err := Load()
	if !errors.Is(err, ErrInsecureAuthScopeURL) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsInvalidMode(t *testing.T) {
	t.Setenv("OPE_MODE", "staging")
	t.Setenv("AUTH_SCOPE_URL", "https://authority.example")
	_, err := Load()
	if !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadRejectsMissingAuthScopeURL(t *testing.T) {
	t.Setenv("OPE_MODE", "development")
	t.Setenv("AUTH_SCOPE_URL", "")
	_, err := Load()
	if !errors.Is(err, ErrMissingAuthScopeURL) {
		t.Fatalf("Load error = %v", err)
	}
}

func TestLoadAcceptsReleaseConfig(t *testing.T) {
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
