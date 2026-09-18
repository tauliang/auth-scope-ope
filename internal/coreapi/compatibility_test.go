package coreapi

import (
	"context"
	"errors"
	"testing"
)

func TestCheckCompatibilityRejectsMissingReceiptVerification(t *testing.T) {
	discovery := Discovery{Version: "76fe961", Capabilities: []string{"missions", "leases"}}
	err := CheckCompatibility(context.Background(), discovery, LockedContract(), RequiredManifest())
	if !errors.Is(err, ErrIncompatibleCore) {
		t.Fatalf("compatibility error = %v", err)
	}
}

func TestReleaseRejectsAuditBaseline(t *testing.T) {
	discovery := Discovery{Version: "76fe961", OpenAPISHA256: LockedContract().OpenAPISHA256}
	err := CheckReleaseCompatibility(context.Background(), discovery, LockedContract(), RequiredManifest())
	if !errors.Is(err, ErrAuditBaselineOnly) {
		t.Fatalf("release compatibility error = %v", err)
	}
}

func TestCheckCompatibilityAcceptsLockedRelease(t *testing.T) {
	lock := LockedContract()
	manifest := RequiredManifest()
	caps := make([]string, 0, len(manifest.RequiredOperations))
	seen := map[string]bool{}
	for _, op := range manifest.RequiredOperations {
		if !seen[op.Capability] {
			seen[op.Capability] = true
			caps = append(caps, op.Capability)
		}
	}
	discovery := Discovery{Version: lock.CoreVersion, OpenAPISHA256: lock.OpenAPISHA256, Capabilities: caps}
	if err := CheckReleaseCompatibility(context.Background(), discovery, lock, manifest); err != nil {
		t.Fatalf("release compatibility error = %v", err)
	}
}

func TestCheckCompatibilityRejectsDigestMismatch(t *testing.T) {
	lock := LockedContract()
	manifest := RequiredManifest()
	discovery := Discovery{Version: lock.CoreVersion, OpenAPISHA256: "deadbeef", Capabilities: []string{}}
	if err := CheckCompatibility(context.Background(), discovery, lock, manifest); !errors.Is(err, ErrIncompatibleCore) {
		t.Fatalf("compatibility error = %v", err)
	}
}

func TestCheckCompatibilityRejectsMissingCapability(t *testing.T) {
	lock := LockedContract()
	manifest := RequiredManifest()
	// Advertise every capability except the first one.
	skip := manifest.RequiredOperations[0].Capability
	seen := map[string]bool{}
	var caps []string
	for _, op := range manifest.RequiredOperations {
		if op.Capability == skip || seen[op.Capability] {
			continue
		}
		seen[op.Capability] = true
		caps = append(caps, op.Capability)
	}
	discovery := Discovery{Version: lock.CoreVersion, OpenAPISHA256: lock.OpenAPISHA256, Capabilities: caps}
	err := CheckCompatibility(context.Background(), discovery, lock, manifest)
	if !errors.Is(err, ErrIncompatibleCore) {
		t.Fatalf("compatibility error = %v", err)
	}
}

func TestLockedContractMatchesRelease(t *testing.T) {
	lock := LockedContract()
	if lock.CoreVersion != "ope-v1.0.0" {
		t.Fatalf("locked core version = %q", lock.CoreVersion)
	}
	if len(lock.OpenAPISHA256) != 64 {
		t.Fatalf("locked digest length = %d", len(lock.OpenAPISHA256))
	}
}

func TestRequiredManifestHasOperations(t *testing.T) {
	manifest := RequiredManifest()
	if len(manifest.RequiredOperations) != 36 {
		t.Fatalf("required operations = %d", len(manifest.RequiredOperations))
	}
}

func TestVerifyVendoredContractIsReady(t *testing.T) {
	report := VerifyVendoredContract("../..")
	if !report.DigestMatch {
		t.Fatalf("digest mismatch: %v", report.Problems)
	}
	if !report.Ready() {
		t.Fatalf("contract not ready: %v", report.Problems)
	}
	if report.OperationsPresent != report.OperationsRequired {
		t.Fatalf("operations present %d != required %d", report.OperationsPresent, report.OperationsRequired)
	}
}

func TestVerifyVendoredContractDetectsMissingRoot(t *testing.T) {
	report := VerifyVendoredContract("/nonexistent-root")
	if report.Ready() {
		t.Fatal("expected not ready for missing root")
	}
	if len(report.Problems) == 0 {
		t.Fatal("expected problems for missing root")
	}
}
