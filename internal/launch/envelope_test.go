package launch_test

// Envelope tests: AuthScope signs the launch payload and seals the signed
// bytes to the CLI ephemeral X25519 key. The CLI opens the envelope with
// the in-memory private key and validates algorithm, key ID, signature,
// audience, nonce, expiry, the recomputed invocation digest, and equality
// with every value retained from CLIAuthorizationStart. Unknown fields are
// rejected.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/launch"
	"github.com/tauliang/authscope-ope/internal/trust"
)

type envelopeKeys struct {
	store   *trust.KeyStore
	priv    ed25519.PrivateKey
	keyID   string
	cliPub  [32]byte
	cliPriv [32]byte
}

// newEnvelopeKeys generates a pinned test root plus one chained signing key
// and a CLI ephemeral X25519 keypair.
func newEnvelopeKeys(t *testing.T) envelopeKeys {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigPub, sigPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	newPubB64 := base64.RawURLEncoding.EncodeToString(sigPub)
	stmt, err := json.Marshal(struct {
		Domain        string `json:"domain"`
		PreviousKeyID string `json:"previous_key_id"`
		NewKeyID      string `json:"new_key_id"`
		NewPublicKey  string `json:"new_public_key"`
		IssuedAt      string `json:"issued_at"`
	}{
		Domain:        "authscope-signing-keys/rotation/v1",
		PreviousKeyID: "test-root",
		NewKeyID:      "test-signing",
		NewPublicKey:  newPubB64,
		IssuedAt:      now.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	rootSum := sha256.Sum256(rootPub)
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": "sha256:" + hex.EncodeToString(rootSum[:]),
		"keys": []any{
			map[string]any{
				"key_id":     "test-root",
				"algorithm":  "Ed25519",
				"public_key": base64.RawURLEncoding.EncodeToString(rootPub),
				"valid_from": now.Format(time.RFC3339),
				"root":       true,
			},
			map[string]any{
				"key_id":             "test-signing",
				"algorithm":          "Ed25519",
				"public_key":         newPubB64,
				"valid_from":         now.Format(time.RFC3339),
				"root":               false,
				"rotated_from":       "test-root",
				"rotation_statement": base64.RawURLEncoding.EncodeToString(stmt),
				"rotation_signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(rootPriv, stmt)),
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-keys.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := trust.LoadSigningKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	var cliPriv, cliPub [32]byte
	rawPriv := make([]byte, 32)
	if _, err := rand.Read(rawPriv); err != nil {
		t.Fatal(err)
	}
	copy(cliPriv[:], rawPriv)
	pub, err := curve25519.X25519(cliPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(cliPub[:], pub)
	return envelopeKeys{store: ks, priv: sigPriv, keyID: "test-signing", cliPub: cliPub, cliPriv: cliPriv}
}

func testPayload(now time.Time) launch.LaunchPayload {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	return launch.LaunchPayload{
		Audience:         launch.EnvelopeAudience,
		RunID:            "run-01",
		MissionRef:       "mission-01",
		MissionVersion:   3,
		ProposalDigest:   "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		InvocationDigest: authn.InvocationDigestForLaunch("kit-a", "1.0.0", []string{"--flag", "x"}),
		RuntimePolicyID:  "rp-01",
		LeaseID:          "lease-01",
		AgentKitID:       "kit-a",
		AgentKitVersion:  "1.0.0",
		RunnerExecutable: "/opt/runners/authscope-agent-run",
		RunnerArguments:  []string{"--flag", "x"},
		IsolationProfile: launch.IsolationEnforced,
		Nonce:            base64.RawURLEncoding.EncodeToString(nonce[:]),
		IssuedAt:         now.Add(-time.Minute).Unix(),
		ExpiresAt:        now.Add(time.Hour).Unix(),
	}
}

func testExpected(p launch.LaunchPayload) launch.ExpectedBinding {
	return launch.ExpectedBinding{
		ProposalDigest:   p.ProposalDigest,
		InvocationDigest: p.InvocationDigest,
		AgentKitID:       p.AgentKitID,
		AgentKitVersion:  p.AgentKitVersion,
		RunnerArguments:  append([]string{}, p.RunnerArguments...),
		RunnerExecutable: p.RunnerExecutable,
	}
}

func sealForTest(t *testing.T, k envelopeKeys, p launch.LaunchPayload) []byte {
	t.Helper()
	sealed, err := launch.SealEnvelope(p, k.priv, k.keyID, k.cliPub)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}
	return sealed
}

func openForTest(t *testing.T, k envelopeKeys, sealed []byte, p launch.LaunchPayload) (*launch.LaunchPayload, []byte) {
	t.Helper()
	got, signed, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now())
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}
	return got, signed
}

func TestEnvelopeRoundTrip(t *testing.T) {
	k := newEnvelopeKeys(t)
	now := time.Now()
	p := testPayload(now)
	sealed := sealForTest(t, k, p)
	got, signed := openForTest(t, k, sealed, p)
	if got.RunID != p.RunID || got.MissionRef != p.MissionRef || got.LeaseID != p.LeaseID {
		t.Fatalf("payload mismatch: %+v", got)
	}
	if len(signed) == 0 {
		t.Fatal("expected signed envelope bytes for the runner FD")
	}
	// The sealed bytes are opaque: they must not contain the payload in
	// the clear.
	if bytes.Contains(sealed, []byte(p.RunID)) {
		t.Fatal("sealed envelope leaks the run id in the clear")
	}
}

func TestEnvelopeRejectsWrongPrivateKey(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	sealed := sealForTest(t, k, p)
	var other [32]byte
	if _, err := rand.Read(other[:]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := launch.OpenEnvelope(sealed, other, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for wrong private key")
	}
}

func TestEnvelopeRejectsTamperedCiphertext(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	sealed := sealForTest(t, k, p)
	sealed[len(sealed)-1] ^= 0x01
	if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestEnvelopeRejectsTamperedOuterKeyID(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	sealed := sealForTest(t, k, p)
	var doc map[string]any
	if err := json.Unmarshal(sealed, &doc); err != nil {
		t.Fatal(err)
	}
	doc["key_id"] = "test-root"
	mut, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := launch.OpenEnvelope(mut, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for tampered outer key id")
	}
}

func TestEnvelopeRejectsBadSignature(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	sealed := sealForTest(t, k, p)
	// Re-seal a payload signed by an unknown key: open must fail the
	// signature check, not the box.
	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = otherPub
	bad, err := launch.SealEnvelope(p, otherPriv, "unknown-key", k.cliPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := launch.OpenEnvelope(bad, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for unknown signing key")
	}
	_ = sealed
}

func TestEnvelopeRejectsWrongAudience(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	p.Audience = "authscope:prepare-launch"
	sealed := sealForTest(t, k, p)
	if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestEnvelopeRejectsExpiry(t *testing.T) {
	k := newEnvelopeKeys(t)
	now := time.Now()
	p := testPayload(now)
	p.ExpiresAt = now.Add(-time.Second).Unix()
	sealed := sealForTest(t, k, p)
	if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for expired envelope")
	}
}

func TestEnvelopeRejectsMissingEnforcedIsolation(t *testing.T) {
	k := newEnvelopeKeys(t)
	for _, profile := range []string{"", "observed", "checked"} {
		p := testPayload(time.Now())
		p.IsolationProfile = profile
		sealed := sealForTest(t, k, p)
		if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
			t.Fatalf("expected error for isolation profile %q", profile)
		}
	}
}

func TestEnvelopeRejectsUnknownFields(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	// Inject an unknown field into the payload, sign the mutated payload
	// with a valid key, seal it, and assert OpenEnvelope rejects it at
	// the strict-decoding layer.
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["sneaky_field"] = "sneaky"
	mutPayload, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	msg := append(append([]byte(launch.SignedEnvelopeDomain), 0x00), mutPayload...)
	signedDoc := map[string]any{
		"format":    launch.SignedEnvelopeFormat,
		"key_id":    k.keyID,
		"algorithm": "Ed25519",
		"payload":   json.RawMessage(mutPayload),
		"signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, msg)),
	}
	signed, err := json.Marshal(signedDoc)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := launch.SealSignedEnvelope(signed, k.keyID, k.cliPub)
	if err != nil {
		t.Fatalf("SealSignedEnvelope: %v", err)
	}
	if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for unknown payload field")
	}
}

func TestEnvelopeRejectsMutatedRetainedValues(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	sealed := sealForTest(t, k, p)
	mutations := []func(*launch.ExpectedBinding){
		func(e *launch.ExpectedBinding) {
			e.ProposalDigest = "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
		},
		func(e *launch.ExpectedBinding) {
			e.InvocationDigest = "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
		},
		func(e *launch.ExpectedBinding) { e.AgentKitID = "other-kit" },
		func(e *launch.ExpectedBinding) { e.AgentKitVersion = "9.9.9" },
		func(e *launch.ExpectedBinding) { e.RunnerArguments = []string{"--flag", "y"} },
		func(e *launch.ExpectedBinding) { e.RunnerArguments = []string{"x", "--flag"} },
		func(e *launch.ExpectedBinding) { e.RunnerExecutable = "/tmp/evil-runner" },
	}
	for i, mutate := range mutations {
		expected := testExpected(p)
		mutate(&expected)
		if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, expected, launch.NewNonceCache(), time.Now()); err == nil {
			t.Fatalf("mutation %d: expected error for mutated retained value", i)
		}
	}
}

func TestEnvelopeRejectsInvocationDigestMismatch(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	// The envelope binds an invocation digest that does not match its own
	// kit/version/arguments: recomputation must fail.
	p.InvocationDigest = "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{7}, 32))
	sealed := sealForTest(t, k, p)
	if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for invocation digest mismatch")
	}
}

func TestEnvelopeRejectsTrailingData(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	sealed := sealForTest(t, k, p)
	withTrailing := append(append([]byte{}, sealed...), []byte(" {}")...)
	if _, _, err := launch.OpenEnvelope(withTrailing, k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for trailing data after the sealed envelope")
	}
}

func TestEnvelopeRejectsNonceReplay(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	sealed := sealForTest(t, k, p)
	nonces := launch.NewNonceCache()
	if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), nonces, time.Now()); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, _, err := launch.OpenEnvelope(sealed, k.cliPriv, k.store, testExpected(p), nonces, time.Now()); err == nil {
		t.Fatal("expected error for replayed envelope nonce")
	}
}

func TestEnvelopeRejectsShortSealedBytes(t *testing.T) {
	k := newEnvelopeKeys(t)
	p := testPayload(time.Now())
	if _, _, err := launch.OpenEnvelope([]byte("short"), k.cliPriv, k.store, testExpected(p), launch.NewNonceCache(), time.Now()); err == nil {
		t.Fatal("expected error for truncated sealed envelope")
	}
}
