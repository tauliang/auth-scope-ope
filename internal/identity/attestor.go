// Package identity signs founder decision attestations with the
// instance's non-exportable workload signer and canonicalizes the exact
// claims AuthScope independently verifies. The signing key never leaves
// the Signer implementation: there is no key export on the interface.
package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// AttestationDomain separates decision-attestation signatures from every
// other signature the workload signer produces.
const AttestationDomain = "authscope-ope/decision-attestation/v1"

// AlgorithmTag is the signature algorithm tag emitted on attestations. It
// matches the upstream DecisionAttestationClaims algorithm enum.
const AlgorithmTag = "Ed25519"

// Decision purposes and their bound audience, subject kind, and required
// authentication method, mirroring the upstream contract's attestation
// rules.
const (
	PurposePassApproval           = "pass_approval"
	PurposeCLILaunchAuthorization = "cli_launch_authorization"
	PurposeMissionRevoke          = "mission_revoke"
	PurposeExpansionDecision      = "expansion_decision"
	PurposeOfflineRecoveryContain = "offline_recovery_contain"
)

// Attestation audiences bound to each purpose.
const (
	AudienceProposalApproval  = "authscope:proposal-approval"
	AudiencePrepareLaunch     = "authscope:prepare-launch"
	AudienceMissionRevoke     = "authscope:mission-revoke"
	AudienceExpansionDecision = "authscope:expansion-decision"
	AudienceWorkspaceContain  = "authscope:workspace-containment"
)

// Authentication methods the attestor accepts. WebAuthn user verification
// covers every online decision; the offline recovery key covers only the
// offline-recovery containment decision after local proof of possession.
const (
	AuthMethodWebAuthnUV      = "webauthn_uv"
	AuthMethodOfflineRecovery = "offline_recovery_key"
)

// maxAttestationTTL bounds how long a signed decision attestation stays
// valid. Decisions are point-in-time approvals, not standing grants.
const maxAttestationTTL = 15 * time.Minute

// maxClockSkew tolerates small clock differences when checking issued_at.
const maxClockSkew = 60 * time.Second

var (
	// ErrInvalidClaims reports decision claims that fail validation before
	// signing. Nothing is signed when claims are invalid.
	ErrInvalidClaims = errors.New("identity: invalid decision claims")
	// ErrNoSigner reports an attestor constructed without a signer.
	ErrNoSigner = errors.New("identity: no workload signer")
	// ErrUnresolvableSigner reports a workload signer reference that this
	// build cannot resolve to a non-exportable key. Real HSM/TEE
	// integration lands in a later task; until then release mode fails
	// closed here.
	ErrUnresolvableSigner = errors.New("identity: workload signer reference cannot be resolved by this build")
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// Signer is a non-exportable workload signer. Sign signs the exact
// domain-separated message it is given. KeyID names the active key and
// IdentityDigest is the stable "sha256:..." digest of the public key that
// AuthScope attaches to the instance record. There is deliberately no
// method that returns key material.
type Signer interface {
	Sign(ctx context.Context, message []byte) ([]byte, error)
	KeyID() string
	IdentityDigest() string
}

// DecisionClaims are the exact claims bound into a signed decision
// attestation. DecisionDigest and InvocationDigest identify the approved
// decision and the invocation it authorizes. AuthenticationProofDigest
// covers the local verified ceremony record (method, challenge, auth
// time); it must never embed the credential ID, the assertion, or the
// recovery key itself.
type DecisionClaims struct {
	WorkspaceID               string
	FounderID                 string
	Audience                  string
	Purpose                   string
	SubjectID                 string
	DecisionDigest            string
	InvocationDigest          string
	AuthenticationMethod      string
	AuthenticationProofDigest string
	Nonce                     [32]byte
	IssuedAt                  time.Time
	ExpiresAt                 time.Time
}

// SignedDecisionAttestation is a decision attestation signed by the
// workspace workload signer. Claims carries the exact claims that were
// canonicalized and signed; Signature is the raw Ed25519 signature over
// the domain-separated canonical claims.
type SignedDecisionAttestation struct {
	Algorithm      string
	KeyID          string
	IdentityDigest string
	Claims         DecisionClaims
	Signature      []byte
}

// purposeBinding pins the audience, subject kind, authentication method,
// and invocation-digest rule for one decision purpose.
type purposeBinding struct {
	audience       string
	subjectKind    string
	method         string
	invocationMode int // 0 = required, 1 = optional, 2 = forbidden
}

const (
	invocationRequired = iota
	invocationOptional
	invocationForbidden
)

var purposeBindings = map[string]purposeBinding{
	PurposePassApproval: {
		audience: AudienceProposalApproval, subjectKind: "mission_proposal",
		method: AuthMethodWebAuthnUV, invocationMode: invocationRequired,
	},
	PurposeCLILaunchAuthorization: {
		audience: AudiencePrepareLaunch, subjectKind: "launch",
		method: AuthMethodWebAuthnUV, invocationMode: invocationRequired,
	},
	PurposeMissionRevoke: {
		audience: AudienceMissionRevoke, subjectKind: "mission",
		method: AuthMethodWebAuthnUV, invocationMode: invocationOptional,
	},
	PurposeExpansionDecision: {
		audience: AudienceExpansionDecision, subjectKind: "expansion_request",
		method: AuthMethodWebAuthnUV, invocationMode: invocationRequired,
	},
	PurposeOfflineRecoveryContain: {
		audience: AudienceWorkspaceContain, subjectKind: "workspace",
		method: AuthMethodOfflineRecovery, invocationMode: invocationForbidden,
	},
}

// DecisionAttestor signs decision claims with the workspace workload
// signer. It accepts only the fixed authentication methods and the exact
// purpose bindings above; anything else fails before signing.
type DecisionAttestor struct {
	signer Signer
}

// NewDecisionAttestor builds an attestor over a non-exportable signer.
func NewDecisionAttestor(signer Signer) *DecisionAttestor {
	return &DecisionAttestor{signer: signer}
}

// validateClaims enforces the exact claim rules before anything is signed.
func validateClaims(c DecisionClaims, now time.Time) (purposeBinding, error) {
	binding, ok := purposeBindings[c.Purpose]
	if !ok {
		return purposeBinding{}, fmt.Errorf("%w: unknown purpose %q", ErrInvalidClaims, c.Purpose)
	}
	if c.Audience != binding.audience {
		return purposeBinding{}, fmt.Errorf("%w: purpose %q requires audience %q, got %q",
			ErrInvalidClaims, c.Purpose, binding.audience, c.Audience)
	}
	if c.AuthenticationMethod != binding.method {
		return purposeBinding{}, fmt.Errorf("%w: purpose %q requires authentication method %q, got %q",
			ErrInvalidClaims, c.Purpose, binding.method, c.AuthenticationMethod)
	}
	if c.WorkspaceID == "" {
		return purposeBinding{}, fmt.Errorf("%w: workspace_id is required", ErrInvalidClaims)
	}
	if c.FounderID == "" {
		return purposeBinding{}, fmt.Errorf("%w: founder_id is required", ErrInvalidClaims)
	}
	if c.SubjectID == "" {
		return purposeBinding{}, fmt.Errorf("%w: subject_id is required", ErrInvalidClaims)
	}
	if !digestPattern.MatchString(c.DecisionDigest) {
		return purposeBinding{}, fmt.Errorf("%w: decision_digest must be sha256:<hex>", ErrInvalidClaims)
	}
	switch binding.invocationMode {
	case invocationRequired:
		if !digestPattern.MatchString(c.InvocationDigest) {
			return purposeBinding{}, fmt.Errorf("%w: invocation_digest is required for purpose %q",
				ErrInvalidClaims, c.Purpose)
		}
	case invocationForbidden:
		if c.InvocationDigest != "" {
			return purposeBinding{}, fmt.Errorf("%w: invocation_digest is forbidden for purpose %q",
				ErrInvalidClaims, c.Purpose)
		}
	case invocationOptional:
		if c.InvocationDigest != "" && !digestPattern.MatchString(c.InvocationDigest) {
			return purposeBinding{}, fmt.Errorf("%w: invocation_digest must be sha256:<hex>", ErrInvalidClaims)
		}
	}
	if !digestPattern.MatchString(c.AuthenticationProofDigest) {
		return purposeBinding{}, fmt.Errorf("%w: authentication_proof_digest must be sha256:<hex>", ErrInvalidClaims)
	}
	var zero [32]byte
	if c.Nonce == zero {
		return purposeBinding{}, fmt.Errorf("%w: nonce must not be zero", ErrInvalidClaims)
	}
	if c.IssuedAt.IsZero() {
		return purposeBinding{}, fmt.Errorf("%w: issued_at is required", ErrInvalidClaims)
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return purposeBinding{}, fmt.Errorf("%w: expires_at must be after issued_at", ErrInvalidClaims)
	}
	if c.ExpiresAt.Sub(c.IssuedAt) > maxAttestationTTL {
		return purposeBinding{}, fmt.Errorf("%w: attestation TTL exceeds %s", ErrInvalidClaims, maxAttestationTTL)
	}
	if c.IssuedAt.After(now.Add(maxClockSkew)) {
		return purposeBinding{}, fmt.Errorf("%w: issued_at is in the future", ErrInvalidClaims)
	}
	return binding, nil
}

// wireSubject is the contract subject object.
type wireSubject struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// wireClaims is the contract DecisionAttestationClaims object in fixed
// field order, so marshaling is canonical without map sorting.
type wireClaims struct {
	Version                   int         `json:"version"`
	Algorithm                 string      `json:"algorithm"`
	KeyID                     string      `json:"key_id"`
	IdentityDigest            string      `json:"identity_digest"`
	WorkspaceID               string      `json:"workspace_id"`
	Founder                   string      `json:"founder"`
	Audience                  string      `json:"audience"`
	Purpose                   string      `json:"purpose"`
	Subject                   wireSubject `json:"subject"`
	DecisionDigest            string      `json:"decision_digest"`
	InvocationDigest          string      `json:"invocation_digest,omitempty"`
	AuthenticationMethod      string      `json:"authentication_method"`
	AuthenticationProofDigest string      `json:"authentication_proof_digest"`
	AuthenticatedAt           int64       `json:"authenticated_at"`
	IssuedAt                  int64       `json:"issued_at"`
	ExpiresAt                 int64       `json:"expires_at"`
	Nonce                     string      `json:"nonce"`
}

// toWireClaims converts validated claims to the contract wire object. The
// nonce is base64url without padding (43 characters for 32 bytes).
// authenticated_at carries issued_at: the claims already bind the
// authentication proof digest, and the wire format requires the field.
func toWireClaims(c DecisionClaims, binding purposeBinding, keyID, identityDigest string) wireClaims {
	return wireClaims{
		Version:                   1,
		Algorithm:                 AlgorithmTag,
		KeyID:                     keyID,
		IdentityDigest:            identityDigest,
		WorkspaceID:               c.WorkspaceID,
		Founder:                   c.FounderID,
		Audience:                  c.Audience,
		Purpose:                   c.Purpose,
		Subject:                   wireSubject{Kind: binding.subjectKind, ID: c.SubjectID},
		DecisionDigest:            c.DecisionDigest,
		InvocationDigest:          c.InvocationDigest,
		AuthenticationMethod:      c.AuthenticationMethod,
		AuthenticationProofDigest: c.AuthenticationProofDigest,
		AuthenticatedAt:           c.IssuedAt.Unix(),
		IssuedAt:                  c.IssuedAt.Unix(),
		ExpiresAt:                 c.ExpiresAt.Unix(),
		Nonce:                     base64.RawURLEncoding.EncodeToString(c.Nonce[:]),
	}
}

// canonicalJSON marshals v to JSON deterministically: fixed struct field
// order and no HTML escaping.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// CanonicalClaimsJSON returns the exact canonical bytes the attestor
// signs for the given claims. Test verifiers use it to check signatures
// without reimplementing canonicalization.
func CanonicalClaimsJSON(c DecisionClaims, keyID, identityDigest string) ([]byte, error) {
	binding, err := validateClaims(c, time.Now())
	if err != nil {
		return nil, err
	}
	return canonicalJSON(toWireClaims(c, binding, keyID, identityDigest))
}

// signedMessage domain-separates the canonical claims.
func signedMessage(canonical []byte) []byte {
	msg := make([]byte, 0, len(AttestationDomain)+1+len(canonical))
	msg = append(msg, AttestationDomain...)
	msg = append(msg, 0x00)
	msg = append(msg, canonical...)
	return msg
}

// Attest validates the claims, canonicalizes them with domain separation,
// and signs them with the non-exportable workload signer.
func (a *DecisionAttestor) Attest(ctx context.Context, claims DecisionClaims) (SignedDecisionAttestation, error) {
	if a.signer == nil {
		return SignedDecisionAttestation{}, ErrNoSigner
	}
	binding, err := validateClaims(claims, time.Now())
	if err != nil {
		return SignedDecisionAttestation{}, err
	}
	keyID := a.signer.KeyID()
	identityDigest := a.signer.IdentityDigest()
	if keyID == "" || identityDigest == "" {
		return SignedDecisionAttestation{}, fmt.Errorf("%w: signer identity is incomplete", ErrInvalidClaims)
	}
	if !digestPattern.MatchString(identityDigest) {
		return SignedDecisionAttestation{}, fmt.Errorf("%w: signer identity digest must be sha256:<hex>", ErrInvalidClaims)
	}
	canonical, err := canonicalJSON(toWireClaims(claims, binding, keyID, identityDigest))
	if err != nil {
		return SignedDecisionAttestation{}, fmt.Errorf("identity: cannot canonicalize claims: %w", err)
	}
	sig, err := a.signer.Sign(ctx, signedMessage(canonical))
	if err != nil {
		return SignedDecisionAttestation{}, fmt.Errorf("identity: workload signer failed: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return SignedDecisionAttestation{}, fmt.Errorf("identity: signer returned %d signature bytes, want %d",
			len(sig), ed25519.SignatureSize)
	}
	return SignedDecisionAttestation{
		Algorithm:      AlgorithmTag,
		KeyID:          keyID,
		IdentityDigest: identityDigest,
		Claims:         claims,
		Signature:      sig,
	}, nil
}

// WireEnvelope renders a signed attestation as the contract
// SignedDecisionAttestation JSON object for request bodies. The signature
// is base64url encoded per the contract pattern.
func WireEnvelope(att SignedDecisionAttestation) (map[string]any, error) {
	binding, err := validateClaims(att.Claims, time.Now())
	if err != nil {
		return nil, err
	}
	wire := toWireClaims(att.Claims, binding, att.KeyID, att.IdentityDigest)
	raw, err := canonicalJSON(wire)
	if err != nil {
		return nil, err
	}
	var claimsObj map[string]any
	if err := json.Unmarshal(raw, &claimsObj); err != nil {
		return nil, err
	}
	return map[string]any{
		"algorithm":       att.Algorithm,
		"key_id":          att.KeyID,
		"identity_digest": att.IdentityDigest,
		"claims":          claimsObj,
		"signature":       base64.RawURLEncoding.EncodeToString(att.Signature),
	}, nil
}

// IdentityDigestForKey returns the stable identity digest for a raw
// Ed25519 public key: "sha256:" + hex(sha256(public key)).
func IdentityDigestForKey(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EphemeralSigner is an in-memory Ed25519 workload signer.
//
// DEV ONLY: it exists so developers can run the OPE server against a local
// fake AuthScope without HSM or TEE hardware. The key lives in process
// memory, is generated fresh on every start, and must never be used in
// release mode. main.go refuses to build one outside development.
type EphemeralSigner struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// NewEphemeralSigner generates a fresh in-memory Ed25519 key pair.
// Callers must ensure this is only used in development.
func NewEphemeralSigner() *EphemeralSigner {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("identity: cannot generate ephemeral key: " + err.Error())
	}
	sum := sha256.Sum256(pub)
	return &EphemeralSigner{
		keyID: "dev-ephemeral-" + hex.EncodeToString(sum[:6]),
		priv:  priv,
		pub:   pub,
	}
}

// Sign implements Signer.
func (s *EphemeralSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	sig := ed25519.Sign(s.priv, message)
	return sig, nil
}

// KeyID implements Signer.
func (s *EphemeralSigner) KeyID() string { return s.keyID }

// IdentityDigest implements Signer.
func (s *EphemeralSigner) IdentityDigest() string { return IdentityDigestForKey(s.pub) }

// PublicKey exposes the public key so tests and the local fake AuthScope
// can verify signatures. It is not key material that must stay secret, but
// production signers need not expose it.
func (s *EphemeralSigner) PublicKey() ed25519.PublicKey { return s.pub }
