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
	"time"

	"github.com/tauliang/authscope-ope/internal/store"
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
	cachedLock        ContractLock
	cachedManifest    CapabilityManifest
	loadContractsErr  error
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

var (
	// ErrMissingAttestorRole reports a workload identity that lacks the
	// decision_attestor role required for OPE decision attestations.
	ErrMissingAttestorRole = errors.New("coreapi: workload identity lacks decision_attestor role")
	// ErrIdentityMismatch reports a workload identity digest that differs
	// from the digest attached to the instance record. It is fatal: the
	// instance is bound to a different identity than the one serving it.
	ErrIdentityMismatch = errors.New("coreapi: workload identity digest mismatch")
	// ErrEmptyIdentityDigest reports an identity verification that returned
	// no stable identity digest.
	ErrEmptyIdentityDigest = errors.New("coreapi: empty workload identity digest")
)

// gateMaxStale is how old a successful verification may be before the gate
// stops trusting it. The refresher re-verifies well inside this window.
const gateMaxStale = 30 * time.Second

// Gate is the fail-closed live compatibility gate. Startup verifies the
// deployed core against the locked contract and the workload identity
// against the instance workspace, attaches the stable identity digest to
// the instance record exactly once, and records the last successful check.
// /readyz and every business mutation consult Healthy: the gate is healthy
// only after a successful verification no older than thirty seconds.
type Gate struct {
	authority Authority
	store     store.Store
	clock     func() time.Time

	mu           sync.RWMutex
	lastVerified time.Time
	digest       string
}

// NewGate builds the gate over an Authority client and the presentation
// store. The lock and manifest come from the vendored contracts.
func NewGate(authority Authority, st store.Store) *Gate {
	return &Gate{authority: authority, store: st, clock: time.Now}
}

// Verify runs one full live verification: it loads the immutable instance
// record, discovers the deployed core, checks release compatibility,
// verifies the transport-authenticated workload identity is restricted to
// the instance workspace and carries decision_attestor, and attaches the
// stable identity digest exactly once. A digest that differs from an
// already-attached one returns ErrIdentityMismatch and is fatal.
func (g *Gate) Verify(ctx context.Context) error {
	lock := LockedContract()
	manifest := RequiredManifest()

	inst, err := g.store.GetInstance(ctx)
	if err != nil {
		return fmt.Errorf("coreapi: gate cannot load instance record: %w", err)
	}

	discovery, err := g.authority.Discover(ctx)
	if err != nil {
		return fmt.Errorf("coreapi: gate discovery failed: %w", err)
	}
	if err := CheckReleaseCompatibility(ctx, discovery, lock, manifest); err != nil {
		return fmt.Errorf("coreapi: gate compatibility failed: %w", err)
	}

	wid, err := g.authority.VerifyWorkspaceIdentity(ctx, inst.WorkspaceID)
	if err != nil {
		return fmt.Errorf("coreapi: gate identity verification failed: %w", err)
	}
	if !wid.HasRole(DecisionAttestorRole) {
		return fmt.Errorf("%w: roles %q", ErrMissingAttestorRole, wid.Roles)
	}
	if wid.IdentityDigest == "" {
		return ErrEmptyIdentityDigest
	}

	err = g.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.AttachWorkloadIdentity(ctx, "", wid.IdentityDigest)
	})
	if err != nil {
		if !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("coreapi: gate cannot attach workload identity: %w", err)
		}
		// Already attached: it must be the same digest. Compare against
		// the stored record; a mismatch is fatal.
		current, rerr := g.store.GetInstance(ctx)
		if rerr != nil {
			return fmt.Errorf("coreapi: gate cannot re-read instance record: %w", rerr)
		}
		if current.WorkloadIdentityDigest != wid.IdentityDigest {
			return fmt.Errorf("%w: instance serves a different identity", ErrIdentityMismatch)
		}
	}

	g.mu.Lock()
	g.lastVerified = g.clock()
	g.digest = wid.IdentityDigest
	g.mu.Unlock()
	return nil
}

// Healthy reports whether a successful verification happened within the
// last thirty seconds. It is false before the first success.
func (g *Gate) Healthy() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.lastVerified.IsZero() {
		return false
	}
	return g.clock().Sub(g.lastVerified) <= gateMaxStale
}

// LastVerified returns the last successful verification time, or the zero
// time when verification never succeeded.
func (g *Gate) LastVerified() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastVerified
}

// IdentityDigest returns the verified workload identity digest, or "" when
// verification never succeeded.
func (g *Gate) IdentityDigest() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.digest
}

// StartRefresher re-verifies the gate on interval until ctx ends. Failures
// leave the last verified time untouched, so the gate decays to unhealthy
// instead of flapping. An identity mismatch is logged loudly; the process
// cannot continue serving another identity's authority.
func (g *Gate) StartRefresher(ctx context.Context, interval time.Duration, logf func(string, ...any)) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := g.Verify(ctx); err != nil {
					if errors.Is(err, ErrIdentityMismatch) {
						logf("FATAL: workload identity mismatch during refresh: %v", err)
					} else {
						logf("compatibility refresh failed (gate decaying): %v", err)
					}
				}
			}
		}
	}()
}
