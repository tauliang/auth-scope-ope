// Package coreapi is the narrow boundary to the upstream AuthScope
// mission-authority service. It verifies that a deployed core matches the
// locked contract and satisfies the OPE capability manifest. No other
// package in this module sends AuthScope HTTP requests.
package coreapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// contractFile resolves a file under the repository contracts/ directory
// relative to this source file, so both tests and built binaries read the
// same vendored documents the contract gate verifies.
func contractFile(name string) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		panic("coreapi: cannot locate source file")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "contracts", name)
}

var (
	loadContractsOnce sync.Once
	cachedLock       ContractLock
	cachedManifest   CapabilityManifest
	loadContractsErr error
)

func loadContracts() (ContractLock, CapabilityManifest, error) {
	loadContractsOnce.Do(func() {
		raw, err := os.ReadFile(contractFile("authscope.lock.json"))
		if err != nil {
			loadContractsErr = fmt.Errorf("coreapi: cannot read contract lock: %w", err)
			return
		}
		if err := json.Unmarshal(raw, &cachedLock); err != nil {
			loadContractsErr = fmt.Errorf("coreapi: invalid contract lock: %w", err)
			return
		}
		if cachedLock.CoreVersion == "" || cachedLock.OpenAPISHA256 == "" {
			loadContractsErr = fmt.Errorf("coreapi: contract lock is incomplete")
			return
		}
		// The manifest envelope carries documentation fields alongside the
		// operations; decode leniently so notes do not break the gate.
		raw, err = os.ReadFile(contractFile("ope-required-capabilities.json"))
		if err != nil {
			loadContractsErr = fmt.Errorf("coreapi: cannot read capability manifest: %w", err)
			return
		}
		var envelope struct {
			RequiredOperations []RequiredOperation `json:"required_operations"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			loadContractsErr = fmt.Errorf("coreapi: invalid capability manifest: %w", err)
			return
		}
		if len(envelope.RequiredOperations) == 0 {
			loadContractsErr = fmt.Errorf("coreapi: capability manifest has no required operations")
			return
		}
		cachedManifest = CapabilityManifest{RequiredOperations: envelope.RequiredOperations}
	})
	return cachedLock, cachedManifest, loadContractsErr
}

var (
	// ErrIncompatibleCore reports a deployed core that does not match the
	// locked contract or that lacks a required capability.
	ErrIncompatibleCore = errors.New("coreapi: incompatible AuthScope core")
	// ErrAuditBaselineOnly reports the design and contract-audit baseline
	// commit, which is not an immutable release and cannot satisfy the gate.
	ErrAuditBaselineOnly = errors.New("coreapi: audit baseline only; immutable AuthScope release required")
)

// auditBaselineVersion is the design and contract-audit baseline commit.
// It is pinned here so release-mode checks can reject it explicitly.
const auditBaselineVersion = "76fe961"

// ContractLock pins the immutable upstream release OPE was audited against.
type ContractLock struct {
	CoreVersion   string `json:"core_version"`
	OpenAPISHA256 string `json:"openapi_sha256"`
}

// RequiredOperation maps one OPE requirement to an upstream operation.
type RequiredOperation struct {
	Capability     string `json:"capability"`
	Method         string `json:"method"`
	Path           string `json:"path"`
	RequestSchema  string `json:"request_schema"`
	ResponseSchema string `json:"response_schema"`
	SecurityScheme string `json:"security_scheme"`
	ReconcilePath  string `json:"reconcile_path,omitempty"`
}

// CapabilityManifest is the set of upstream operations OPE requires.
type CapabilityManifest struct {
	RequiredOperations []RequiredOperation `json:"required_operations"`
}

// Discovery describes a deployed AuthScope core as observed at runtime.
type Discovery struct {
	Version       string
	OpenAPISHA256 string
	Capabilities  []string
}

// LockedContract returns the contract lock from the vendored contracts/
// directory. It panics when the lock cannot be read: without it the gate
// cannot be evaluated.
func LockedContract() ContractLock {
	lock, _, err := loadContracts()
	if err != nil {
		panic(err)
	}
	return lock
}

// RequiredManifest returns the OPE capability manifest from the vendored
// contracts/ directory. It panics when the manifest cannot be read.
func RequiredManifest() CapabilityManifest {
	_, manifest, err := loadContracts()
	if err != nil {
		panic(err)
	}
	return manifest
}

// CheckCompatibility verifies that a discovered core matches the locked
// contract and advertises every required capability. It fails closed.
func CheckCompatibility(_ context.Context, got Discovery, lock ContractLock, manifest CapabilityManifest) error {
	if got.Version != lock.CoreVersion || got.OpenAPISHA256 != lock.OpenAPISHA256 {
		return fmt.Errorf("%w: deployed core does not match lock", ErrIncompatibleCore)
	}
	available := make(map[string]struct{}, len(got.Capabilities))
	for _, capability := range got.Capabilities {
		available[capability] = struct{}{}
	}
	for _, operation := range manifest.RequiredOperations {
		if _, ok := available[operation.Capability]; !ok {
			return fmt.Errorf("%w: missing %s", ErrIncompatibleCore, operation.Capability)
		}
	}
	return nil
}

// CheckReleaseCompatibility additionally rejects the audit baseline: only an
// immutable release identifier satisfies the gate.
func CheckReleaseCompatibility(ctx context.Context, got Discovery, lock ContractLock, manifest CapabilityManifest) error {
	if got.Version == auditBaselineVersion {
		return fmt.Errorf("%w: %s", ErrAuditBaselineOnly, got.Version)
	}
	return CheckCompatibility(ctx, got, lock, manifest)
}
