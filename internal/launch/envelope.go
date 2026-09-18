// Package launch implements the Task 9 governed-run handoff: OPE exchanges
// one approved authorization code plus the PKCE verifier for exactly one
// upstream launch preparation, keeps the sealed signed envelope opaque,
// and starts the runner with the signed bytes on an anonymous descriptor.
//
// The envelope format: AuthScope signs the canonical launch payload with
// Ed25519, then seals the signed bytes to the CLI ephemeral X25519 public
// key with ChaCha20-Poly1305. OPE never sees the payload in the clear.
package launch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// EnvelopeAudience is the only audience OPE accepts on a launch payload.
const EnvelopeAudience = "authscope-agent-run"

// IsolationEnforced is the only isolation profile OPE accepts.
const IsolationEnforced = "enforced"

// SignedEnvelopeDomain separates envelope signatures from every other
// signature domain.
const SignedEnvelopeDomain = "authscope-launch-envelope/v1"

// SignedEnvelopeFormat is the signed envelope format tag.
const SignedEnvelopeFormat = "authscope-launch-envelope/v1"

// SealedEnvelopeFormat is the sealed envelope format tag.
const SealedEnvelopeFormat = "authscope-sealed-envelope/v1"

// SealAlgorithm is the hybrid seal construction.
const SealAlgorithm = "X25519-ChaCha20-Poly1305"

// LaunchPayload is the governed-run binding AuthScope signs. Every field
// is pinned against the values retained from CLIAuthorizationStart.
type LaunchPayload struct {
	Audience         string   `json:"audience"`
	RunID            string   `json:"run_id"`
	MissionRef       string   `json:"mission_ref"`
	MissionVersion   int64    `json:"mission_version"`
	ProposalDigest   string   `json:"proposal_digest"`
	InvocationDigest string   `json:"invocation_digest"`
	RuntimePolicyID  string   `json:"runtime_policy_id"`
	LeaseID          string   `json:"lease_id"`
	AgentKitID       string   `json:"agent_kit_id"`
	AgentKitVersion  string   `json:"agent_kit_version"`
	RunnerExecutable string   `json:"runner_executable"`
	RunnerArguments  []string `json:"runner_arguments"`
	IsolationProfile string   `json:"isolation_profile"`
	Nonce            string   `json:"nonce"`
	IssuedAt         int64    `json:"issued_at"`
	ExpiresAt        int64    `json:"expires_at"`
}

// ExpectedBinding carries the values retained from CLIAuthorizationStart
// that the opened payload must equal exactly.
type ExpectedBinding struct {
	ProposalDigest   string
	InvocationDigest string
	AgentKitID       string
	AgentKitVersion  string
	RunnerExecutable string
	RunnerArguments  []string
}

type signedEnvelope struct {
	Format    string          `json:"format"`
	KeyID     string          `json:"key_id"`
	Algorithm string          `json:"algorithm"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type sealedEnvelope struct {
	Format             string `json:"format"`
	Algorithm          string `json:"algorithm"`
	KeyID              string `json:"key_id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              string `json:"nonce"`
	Ciphertext         string `json:"ciphertext"`
}

// SealedEnvelopeHead carries the unsealed fields of a sealed envelope:
// the format, the algorithm, and the signing key ID the sealer bound
// into the sealed format. The ciphertext stays opaque: only the CLI's
// ephemeral private key opens it.
type SealedEnvelopeHead struct {
	Format    string
	Algorithm string
	KeyID     string
}

// ParseSealedEnvelopeHead decodes the outer sealed envelope structure
// without touching the ciphertext.
func ParseSealedEnvelopeHead(sealed []byte) (SealedEnvelopeHead, error) {
	var env sealedEnvelope
	if err := strictDecode(sealed, &env); err != nil {
		return SealedEnvelopeHead{}, fmt.Errorf("launch: sealed envelope: %w", err)
	}
	return SealedEnvelopeHead{Format: env.Format, Algorithm: env.Algorithm, KeyID: env.KeyID}, nil
}

// SignLaunchPayload signs the canonical payload JSON and returns the
// signed envelope bytes. The signature covers the domain string, a zero
// byte, and the exact canonical payload bytes.
func SignLaunchPayload(p LaunchPayload, priv ed25519.PrivateKey, keyID string) ([]byte, error) {
	if keyID == "" {
		return nil, errors.New("launch: signing key id is required")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("launch: bad signing private key")
	}
	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("launch: marshal payload: %w", err)
	}
	msg := make([]byte, 0, len(SignedEnvelopeDomain)+1+len(payloadJSON))
	msg = append(msg, SignedEnvelopeDomain...)
	msg = append(msg, 0x00)
	msg = append(msg, payloadJSON...)
	env := signedEnvelope{
		Format:    SignedEnvelopeFormat,
		KeyID:     keyID,
		Algorithm: "Ed25519",
		Payload:   json.RawMessage(payloadJSON),
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("launch: marshal signed envelope: %w", err)
	}
	return raw, nil
}

// SealSignedEnvelope seals already-signed envelope bytes to the CLI
// ephemeral X25519 public key. A fresh ephemeral sender key is generated
// SealSignedEnvelope encrypts already-signed envelope bytes to the CLI
// ephemeral X25519 public key with an X25519 ephemeral key exchange and
// XChaCha20-Poly1305. The signing key ID is bound into the sealed format
// both as a field and inside the AEAD additional data, so the opener
// cannot be talked into verifying the signature under a different key.
func SealSignedEnvelope(signed []byte, keyID string, cliPub [32]byte) ([]byte, error) {
	if len(signed) == 0 {
		return nil, errors.New("launch: nothing to seal")
	}
	if keyID == "" {
		return nil, errors.New("launch: seal requires a signing key id")
	}
	var ephPriv, ephPub [32]byte
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("launch: ephemeral key: %w", err)
	}
	copy(ephPriv[:], raw)
	pub, err := curve25519.X25519(ephPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("launch: ephemeral public key: %w", err)
	}
	copy(ephPub[:], pub)
	shared, err := curve25519.X25519(ephPriv[:], cliPub[:])
	if err != nil {
		return nil, fmt.Errorf("launch: key agreement: %w", err)
	}
	key := sealKey(shared, ephPub, cliPub)
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("launch: aead: %w", err)
	}
	var nonce24 [24]byte
	if _, err := rand.Read(nonce24[:]); err != nil {
		return nil, fmt.Errorf("launch: nonce: %w", err)
	}
	aad := sealAAD(ephPub, nonce24, keyID)
	ct := aead.Seal(nil, nonce24[:], signed, aad)
	env := sealedEnvelope{
		Format:             SealedEnvelopeFormat,
		Algorithm:          SealAlgorithm,
		KeyID:              keyID,
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(ephPub[:]),
		Nonce:              base64.RawURLEncoding.EncodeToString(nonce24[:]),
		Ciphertext:         base64.RawURLEncoding.EncodeToString(ct),
	}
	rawOut, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("launch: marshal sealed envelope: %w", err)
	}
	return rawOut, nil
}

func sealKey(shared []byte, ephPub, cliPub [32]byte) [32]byte {
	h := sha256.New()
	h.Write(shared)
	h.Write(ephPub[:])
	h.Write(cliPub[:])
	h.Write([]byte(SealedEnvelopeFormat))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func sealAAD(ephPub [32]byte, nonce24 [24]byte, keyID string) []byte {
	aad := make([]byte, 0, 160)
	aad = append(aad, SealedEnvelopeFormat...)
	aad = append(aad, 0x00)
	aad = append(aad, SealAlgorithm...)
	aad = append(aad, 0x00)
	aad = append(aad, keyID...)
	aad = append(aad, 0x00)
	aad = append(aad, ephPub[:]...)
	aad = append(aad, 0x00)
	aad = append(aad, nonce24[:]...)
	return aad
}

// SealEnvelope signs the payload and seals it to the CLI ephemeral key.
func SealEnvelope(p LaunchPayload, priv ed25519.PrivateKey, keyID string, cliPub [32]byte) ([]byte, error) {
	signed, err := SignLaunchPayload(p, priv, keyID)
	if err != nil {
		return nil, err
	}
	return SealSignedEnvelope(signed, keyID, cliPub)
}

// NonceCache remembers envelope nonces so a sealed envelope can be
// opened at most once per process.
type NonceCache struct {
	mu   sync.Mutex
	seen map[string]bool
}

// NewNonceCache returns an empty nonce cache.
func NewNonceCache() *NonceCache { return &NonceCache{seen: make(map[string]bool)} }

// checkAndAdd reports false when the nonce was already seen.
func (c *NonceCache) checkAndAdd(nonce string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[nonce] {
		return false
	}
	c.seen[nonce] = true
	return true
}

// OpenEnvelope opens a sealed envelope with the CLI ephemeral private key,
// verifies the AuthScope signature through the pinned key history, and
// validates the payload against the retained binding. It returns the
// payload and the signed envelope bytes to hand to the runner on the
// anonymous descriptor.
func OpenEnvelope(sealed []byte, cliPriv [32]byte, keys *trust.KeyStore, expected ExpectedBinding, nonces *NonceCache, now time.Time) (*LaunchPayload, []byte, error) {
	if len(sealed) < 16 {
		return nil, nil, errors.New("launch: sealed envelope is truncated")
	}
	var env sealedEnvelope
	if err := strictDecode(sealed, &env); err != nil {
		return nil, nil, fmt.Errorf("launch: sealed envelope: %w", err)
	}
	if env.Format != SealedEnvelopeFormat {
		return nil, nil, fmt.Errorf("launch: sealed envelope format %q", env.Format)
	}
	if env.Algorithm != SealAlgorithm {
		return nil, nil, fmt.Errorf("launch: sealed envelope algorithm %q", env.Algorithm)
	}
	if env.KeyID == "" {
		return nil, nil, errors.New("launch: sealed envelope has no key id")
	}
	ephPubRaw, err := base64.RawURLEncoding.DecodeString(env.EphemeralPublicKey)
	if err != nil || len(ephPubRaw) != 32 {
		return nil, nil, errors.New("launch: bad ephemeral public key")
	}
	var ephPub [32]byte
	copy(ephPub[:], ephPubRaw)
	nonceRaw, err := base64.RawURLEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonceRaw) != 24 {
		return nil, nil, errors.New("launch: bad seal nonce")
	}
	var nonce24 [24]byte
	copy(nonce24[:], nonceRaw)
	ct, err := base64.RawURLEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ct) == 0 {
		return nil, nil, errors.New("launch: bad ciphertext")
	}
	shared, err := curve25519.X25519(cliPriv[:], ephPub[:])
	if err != nil {
		return nil, nil, fmt.Errorf("launch: key agreement: %w", err)
	}
	key := sealKey(shared, ephPub, cliPrivToPub(cliPriv))
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, nil, fmt.Errorf("launch: aead: %w", err)
	}
	signed, err := aead.Open(nil, nonce24[:], ct, sealAAD(ephPub, nonce24, env.KeyID))
	if err != nil {
		return nil, nil, errors.New("launch: sealed envelope does not open")
	}

	var senv signedEnvelope
	if err := strictDecode(signed, &senv); err != nil {
		return nil, nil, fmt.Errorf("launch: signed envelope: %w", err)
	}
	if senv.Format != SignedEnvelopeFormat {
		return nil, nil, fmt.Errorf("launch: signed envelope format %q", senv.Format)
	}
	if senv.Algorithm != "Ed25519" {
		return nil, nil, fmt.Errorf("launch: signed envelope algorithm %q", senv.Algorithm)
	}
	if senv.KeyID == "" {
		return nil, nil, errors.New("launch: signed envelope has no key id")
	}
	if senv.KeyID != env.KeyID {
		return nil, nil, errors.New("launch: sealed key id does not match signed key id")
	}
	if keys == nil {
		return nil, nil, errors.New("launch: no signing-key trust store")
	}
	msg := make([]byte, 0, len(SignedEnvelopeDomain)+1+len(senv.Payload))
	msg = append(msg, SignedEnvelopeDomain...)
	msg = append(msg, 0x00)
	msg = append(msg, senv.Payload...)
	sig, err := base64.RawURLEncoding.DecodeString(senv.Signature)
	if err != nil {
		return nil, nil, errors.New("launch: bad envelope signature encoding")
	}
	if err := keys.VerifySignature(senv.KeyID, msg, sig); err != nil {
		return nil, nil, fmt.Errorf("launch: envelope signature: %w", err)
	}
	var p LaunchPayload
	if err := strictDecode(senv.Payload, &p); err != nil {
		return nil, nil, fmt.Errorf("launch: payload: %w", err)
	}
	if err := validatePayload(&p, expected, nonces, now); err != nil {
		return nil, nil, err
	}
	return &p, signed, nil
}

func cliPrivToPub(priv [32]byte) [32]byte {
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [32]byte{}
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}

func strictDecode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func validatePayload(p *LaunchPayload, expected ExpectedBinding, nonces *NonceCache, now time.Time) error {
	if p.Audience != EnvelopeAudience {
		return fmt.Errorf("launch: payload audience %q", p.Audience)
	}
	if p.RunID == "" || p.MissionRef == "" {
		return errors.New("launch: payload is missing run or mission identity")
	}
	if p.ExpiresAt <= now.Unix() {
		return errors.New("launch: payload is expired")
	}
	if p.IssuedAt > p.ExpiresAt {
		return errors.New("launch: payload issued after expiry")
	}
	if p.IsolationProfile != IsolationEnforced {
		return fmt.Errorf("launch: isolation profile %q is not enforced", p.IsolationProfile)
	}
	if p.Nonce == "" {
		return errors.New("launch: payload has no nonce")
	}
	nonceRaw, err := base64.RawURLEncoding.DecodeString(p.Nonce)
	if err != nil || len(nonceRaw) != 32 {
		return errors.New("launch: bad payload nonce")
	}
	if nonces == nil {
		return errors.New("launch: no nonce cache")
	}
	if !nonces.checkAndAdd(p.Nonce) {
		return errors.New("launch: envelope nonce was already consumed")
	}
	if p.ProposalDigest == "" || p.ProposalDigest != expected.ProposalDigest {
		return errors.New("launch: proposal digest does not match the approved authorization")
	}
	if p.AgentKitID != expected.AgentKitID || expected.AgentKitID == "" {
		return errors.New("launch: agent kit id does not match the approved authorization")
	}
	if p.AgentKitVersion != expected.AgentKitVersion || expected.AgentKitVersion == "" {
		return errors.New("launch: agent kit version does not match the approved authorization")
	}
	if p.RunnerExecutable != expected.RunnerExecutable || expected.RunnerExecutable == "" {
		return errors.New("launch: runner executable does not match the approved authorization")
	}
	if !slices.Equal(p.RunnerArguments, expected.RunnerArguments) {
		return errors.New("launch: runner arguments do not match the approved authorization")
	}
	recomputed := authn.InvocationDigestForLaunch(p.AgentKitID, p.AgentKitVersion, p.RunnerArguments)
	if p.InvocationDigest != recomputed {
		return errors.New("launch: invocation digest does not match the payload contents")
	}
	if expected.InvocationDigest != "" && p.InvocationDigest != expected.InvocationDigest {
		return errors.New("launch: invocation digest does not match the approved authorization")
	}
	return nil
}
