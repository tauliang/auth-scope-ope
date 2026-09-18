// Package authn enrolls the founder with passkeys and protects founder
// decisions with WebAuthn assertions. It reads the immutable instance
// binding established by the store package (workspace, hostname, origin,
// RP ID, instance ID, cookie name) and never calls AuthScope or verifies
// the workload identity.
//
// Enrollment is a one-use bootstrap: the operator reads a 128-bit code
// from the controlling terminal, opens a short-lived bootstrap ceremony,
// registers a first passkey, then confirms an independent recovery method
// (a second passkey or a one-time offline recovery key). Completing the
// ceremony atomically consumes the code and creates the first founder
// session. Afterwards the bootstrap endpoints are permanently disabled.
//
// Founder sessions are 256-bit opaque tokens; only their SHA-256 hashes
// are stored. Each session carries a session-bound CSRF token. High-impact
// decisions require a fresh passkey assertion bound to the exact decision
// digest through a one-use decision challenge.
package authn

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/store"
)

var (
	// ErrNoInstanceBinding reports a store without the immutable instance
	// binding. The service fails closed until the binding exists.
	ErrNoInstanceBinding = errors.New("authn: instance binding not established")
	// ErrAlreadyEnrolled reports a bootstrap attempt after enrollment.
	ErrAlreadyEnrolled = errors.New("authn: founder already enrolled")
	// ErrNotEnrolled reports an authentication attempt before enrollment.
	ErrNotEnrolled = errors.New("authn: no founder enrolled")
	// ErrBootstrapCode reports a wrong bootstrap code. The comparison is
	// constant time.
	ErrBootstrapCode = errors.New("authn: invalid bootstrap code")
	// ErrBootstrapCodeExpired reports an expired bootstrap code.
	ErrBootstrapCodeExpired = errors.New("authn: bootstrap code expired")
	// ErrCeremonyNotFound reports an unknown ceremony or challenge ID.
	ErrCeremonyNotFound = errors.New("authn: ceremony not found")
	// ErrCeremonyExpired reports an expired ceremony.
	ErrCeremonyExpired = errors.New("authn: ceremony expired")
	// ErrCeremonyConsumed reports a replayed one-use ceremony.
	ErrCeremonyConsumed = errors.New("authn: ceremony already consumed")
	// ErrRecoveryRequired reports bootstrap completion without an
	// independent recovery method.
	ErrRecoveryRequired = errors.New("authn: independent recovery method required")
	// ErrRecoveryNotVerified reports an unconfirmed recovery method.
	ErrRecoveryNotVerified = errors.New("authn: recovery method not verified")
	// ErrDuplicateCredential reports a passkey credential ID that is
	// already registered in this workspace.
	ErrDuplicateCredential = errors.New("authn: credential already registered")
	// ErrSessionNotFound reports an unknown session token.
	ErrSessionNotFound = errors.New("authn: session not found")
	// ErrSessionExpired reports an expired session.
	ErrSessionExpired = errors.New("authn: session expired")
	// ErrSessionRevoked reports a revoked session.
	ErrSessionRevoked = errors.New("authn: session revoked")
	// ErrCSRFMismatch reports a wrong session-bound CSRF token. The
	// comparison is constant time.
	ErrCSRFMismatch = errors.New("authn: CSRF token mismatch")
	// ErrDecisionBinding reports a decision finish whose purpose, subject,
	// session, workspace, or digest does not match the challenge.
	ErrDecisionBinding = errors.New("authn: decision challenge binding mismatch")
	// ErrStaleAssertion reports a decision attempt whose passkey
	// authentication is older than five minutes.
	ErrStaleAssertion = errors.New("authn: passkey assertion older than five minutes")
	// ErrUserVerification reports a ceremony that did not perform user
	// verification.
	ErrUserVerification = errors.New("authn: user verification required")
	// ErrInvalidPurpose reports an unknown decision purpose.
	ErrInvalidPurpose = errors.New("authn: invalid decision purpose")
	// ErrVerificationFailed reports a WebAuthn ceremony the verifier
	// rejected.
	ErrVerificationFailed = errors.New("authn: WebAuthn verification failed")
	// ErrConflict reports a ceremony state race, mirroring
	// store.ErrConflict for storage races.
	ErrConflict = errors.New("authn: conflict")
)

const (
	// bootstrapCodeTTL bounds the terminal bootstrap code.
	bootstrapCodeTTL = 10 * time.Minute
	// bootstrapCeremonyTTL bounds the enrollment ceremony.
	bootstrapCeremonyTTL = 15 * time.Minute
	// registrationCeremonyTTL bounds a passkey registration ceremony.
	registrationCeremonyTTL = 5 * time.Minute
	// loginCeremonyTTL bounds a passkey login ceremony.
	loginCeremonyTTL = 5 * time.Minute
	// decisionChallengeTTL bounds a decision challenge.
	decisionChallengeTTL = 2 * time.Minute
	// sessionTTL bounds a founder session.
	sessionTTL = 12 * time.Hour
	// decisionAuthFreshness is the maximum age of the passkey
	// authentication backing a high-impact decision.
	decisionAuthFreshness = 5 * time.Minute
)

// Principal is the authenticated founder attached to a request context.
// Every field is immutable for the lifetime of the session.
type Principal struct {
	FounderID     string
	WorkspaceID   string
	SessionID     string
	AuthTime      time.Time
	CSRFTokenHash [32]byte
}

type principalKey struct{}

// ContextWithPrincipal attaches the authenticated principal to a context.
func ContextWithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext returns the authenticated principal, if any.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// DecisionPurpose is the fixed set of high-impact decision kinds. Later
// tasks add the resource routes that issue these challenges.
type DecisionPurpose string

const (
	// DecisionPassApproval approves an AuthScope proposal for a pass.
	DecisionPassApproval DecisionPurpose = "pass_approval"
	// DecisionPassRevocation revokes an approved mission.
	DecisionPassRevocation DecisionPurpose = "pass_revocation"
	// DecisionExpansionApproval approves a mission expansion.
	DecisionExpansionApproval DecisionPurpose = "expansion_approval"
)

// validDecisionPurpose reports whether p is a known purpose.
func validDecisionPurpose(p DecisionPurpose) bool {
	switch p {
	case DecisionPassApproval, DecisionPassRevocation, DecisionExpansionApproval:
		return true
	}
	return false
}

// DecisionChallenge is a one-use, short-lived passkey challenge bound to
// the exact decision claims. The binding (workspace, session, subject,
// purpose, digest, nonce) is enforced server-side at finish time; the
// WebAuthn challenge itself is random.
type DecisionChallenge struct {
	ChallengeID string
	WorkspaceID string
	SessionID   string
	SubjectID   string
	Purpose     DecisionPurpose
	Digest      [32]byte
	Nonce       [32]byte
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
}

// Service is the founder authentication service. Ceremony state
// (bootstrap ceremonies and one-use WebAuthn challenges) lives in memory
// guarded by a mutex; durable state (founders, credentials, sessions,
// codes, recovery key hashes) lives in the store.
type Service struct {
	store    store.Store
	verifier Verifier
	instance store.InstanceRecord

	mu               sync.Mutex
	bootstrap        map[string]*bootstrapCeremony // by ceremony ID
	bootstrapByToken map[[32]byte]string           // token hash -> ceremony ID
	ceremonies       map[string]*webauthnCeremony  // by ceremony ID

	now func() time.Time
}

// NewService loads the immutable instance binding and wires the WebAuthn
// verifier. It fails closed when the binding is not established yet.
func NewService(ctx context.Context, st store.Store, v Verifier) (*Service, error) {
	if st == nil {
		return nil, errors.New("authn: store is required")
	}
	if v == nil {
		return nil, errors.New("authn: verifier is required")
	}
	inst, err := st.GetInstance(ctx)
	if err != nil {
		return nil, ErrNoInstanceBinding
	}
	return &Service{
		store:            st,
		verifier:         v,
		instance:         inst,
		bootstrap:        make(map[string]*bootstrapCeremony),
		bootstrapByToken: make(map[[32]byte]string),
		ceremonies:       make(map[string]*webauthnCeremony),
		now:              time.Now,
	}, nil
}

// Instance returns the immutable instance binding the service enforces.
func (s *Service) Instance() store.InstanceRecord {
	return s.instance
}
