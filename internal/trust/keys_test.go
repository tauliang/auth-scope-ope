package trust_test

// Tests for the pinned AuthScope signing-key history. The pin file carries
// the signing-root fingerprint plus the initial authenticated key history;
// rotation is accepted only through a statement chained to that root.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/trust"
)

type testKey struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestKey(t *testing.T, id string) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{id: id, pub: pub, priv: priv}
}

func fingerprintOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// rotationStatementBytes is the canonical rotation statement a previous key
// signs when introducing a successor.
func rotationStatementBytes(t *testing.T, prevID, newID string, newPub ed25519.PublicKey, issuedAt time.Time) []byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		Domain        string `json:"domain"`
		PreviousKeyID string `json:"previous_key_id"`
		NewKeyID      string `json:"new_key_id"`
		NewPublicKey  string `json:"new_public_key"`
		IssuedAt      string `json:"issued_at"`
	}{
		Domain:        "authscope-signing-keys/rotation/v1",
		PreviousKeyID: prevID,
		NewKeyID:      newID,
		NewPublicKey:  base64.RawURLEncoding.EncodeToString(newPub),
		IssuedAt:      issuedAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// writePinFile writes a pin file with the given root and one chained
// rotation to a successor key, and returns the path.
func writePinFile(t *testing.T, root, successor testKey) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	stmt := rotationStatementBytes(t, root.id, successor.id, successor.pub, now)
	sig := ed25519.Sign(root.priv, stmt)
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"note":                     "test pin",
		"signing_root_fingerprint": fingerprintOf(root.pub),
		"keys": []any{
			map[string]any{
				"key_id":     root.id,
				"algorithm":  "Ed25519",
				"public_key": base64.RawURLEncoding.EncodeToString(root.pub),
				"valid_from": now.Format(time.RFC3339),
				"root":       true,
			},
			map[string]any{
				"key_id":             successor.id,
				"algorithm":          "Ed25519",
				"public_key":         base64.RawURLEncoding.EncodeToString(successor.pub),
				"valid_from":         now.Format(time.RFC3339),
				"root":               false,
				"rotated_from":       root.id,
				"rotation_statement": base64.RawURLEncoding.EncodeToString(stmt),
				"rotation_signature": base64.RawURLEncoding.EncodeToString(sig),
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
	return path
}

func TestLoadSigningKeys(t *testing.T) {
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	path := writePinFile(t, root, signing)

	// The two-arg load binds the expected root fingerprint from an
	// independent channel; a match loads normally.
	ks, err := trust.LoadSigningKeys(path, fingerprintOf(root.pub))
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	if got := ks.Fingerprint(); got != fingerprintOf(root.pub) {
		t.Fatalf("fingerprint = %q", got)
	}
	msg := []byte("authscope test message")
	sig := ed25519.Sign(signing.priv, msg)
	if err := ks.VerifySignature(signing.id, msg, sig); err != nil {
		t.Fatalf("VerifySignature with chained key: %v", err)
	}
	rootSig := ed25519.Sign(root.priv, msg)
	if err := ks.VerifySignature(root.id, msg, rootSig); err != nil {
		t.Fatalf("VerifySignature with root key: %v", err)
	}
}

func TestLoadSigningKeysRejectsUnknownKeyID(t *testing.T) {
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	ks, err := trust.LoadSigningKeys(writePinFile(t, root, signing), "")
	if err != nil {
		t.Fatal(err)
	}
	other := newTestKey(t, "other")
	sig := ed25519.Sign(other.priv, []byte("msg"))
	if err := ks.VerifySignature("no-such-key", []byte("msg"), sig); err == nil {
		t.Fatal("expected error for unknown key id")
	}
}

func TestLoadSigningKeysRejectsBadSignature(t *testing.T) {
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	ks, err := trust.LoadSigningKeys(writePinFile(t, root, signing), "")
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signing.priv, []byte("right message"))
	if err := ks.VerifySignature(signing.id, []byte("wrong message"), sig); err == nil {
		t.Fatal("expected error for wrong message")
	}
}

func TestLoadSigningKeysRejectsUnchainedRotation(t *testing.T) {
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	rogue := newTestKey(t, "rogue-key")
	now := time.Now().UTC().Truncate(time.Second)
	// The rotation statement is signed by the rogue key itself, not by a
	// key chained to the root.
	stmt := rotationStatementBytes(t, root.id, rogue.id, rogue.pub, now)
	badSig := ed25519.Sign(rogue.priv, stmt)
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": fingerprintOf(root.pub),
		"keys": []any{
			map[string]any{
				"key_id":     root.id,
				"algorithm":  "Ed25519",
				"public_key": base64.RawURLEncoding.EncodeToString(root.pub),
				"valid_from": now.Format(time.RFC3339),
				"root":       true,
			},
			map[string]any{
				"key_id":             rogue.id,
				"algorithm":          "Ed25519",
				"public_key":         base64.RawURLEncoding.EncodeToString(rogue.pub),
				"valid_from":         now.Format(time.RFC3339),
				"root":               false,
				"rotated_from":       root.id,
				"rotation_statement": base64.RawURLEncoding.EncodeToString(stmt),
				"rotation_signature": base64.RawURLEncoding.EncodeToString(badSig),
			},
		},
	}
	raw, _ := json.Marshal(doc)
	path := filepath.Join(t.TempDir(), "signing-keys.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = signing
	if _, err := trust.LoadSigningKeys(path, ""); err == nil {
		t.Fatal("expected error for rotation not chained to the root")
	}
}

func TestLoadSigningKeysRejectsFingerprintMismatch(t *testing.T) {
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	path := writePinFile(t, root, signing)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	other := newTestKey(t, "other-root")
	doc["signing_root_fingerprint"] = fingerprintOf(other.pub)
	raw, _ = json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.LoadSigningKeys(path, ""); err == nil {
		t.Fatal("expected error for root fingerprint mismatch")
	}
}

func TestLoadSigningKeysRejectsMissingFile(t *testing.T) {
	if _, err := trust.LoadSigningKeys(filepath.Join(t.TempDir(), "missing.json"), ""); err == nil {
		t.Fatal("expected error for missing pin file")
	}
}

func TestLoadSigningKeysRejectsTrailingData(t *testing.T) {
	root := newTestKey(t, "test-root")
	successor := newTestKey(t, "test-signing")
	path := writePinFile(t, root, successor)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trailing := filepath.Join(t.TempDir(), "trailing.json")
	if err := os.WriteFile(trailing, append(raw, []byte("\n{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := trust.LoadSigningKeys(trailing, ""); err == nil {
		t.Fatal("expected error for trailing data after the pin file")
	}
}

func TestLoadSigningKeysContractPinFile(t *testing.T) {
	// The vendored contract pin file must load and expose a fingerprint.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	path := filepath.Join(filepath.Dir(thisFile), "..", "..", "contracts", "authscope-signing-keys.json")
	ks, err := trust.LoadSigningKeys(path, "")
	if err != nil {
		t.Fatalf("LoadSigningKeys(contracts/authscope-signing-keys.json): %v", err)
	}
	if fp := ks.Fingerprint(); len(fp) != len("sha256:")+64 {
		t.Fatalf("fingerprint = %q", fp)
	}
	if len(ks.KeyIDs()) == 0 {
		t.Fatal("expected at least one pinned key")
	}
}
