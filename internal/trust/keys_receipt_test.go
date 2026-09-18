package trust_test

// Task 12 additions: signing-time key validity and the refreshed-history
// flow. A receipt verifies against the key that was valid when the
// receipt was signed; refreshed histories are accepted only when every
// key chains to the pinned root.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/trust"
)

// writeWindowPinFile writes a root-only pin with explicit validity
// windows and returns the path.
func writeWindowPinFile(t *testing.T, root testKey, validFrom, validUntil string) string {
	t.Helper()
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": fingerprintOf(root.pub),
		"keys": []any{
			map[string]any{
				"key_id":      root.id,
				"algorithm":   "Ed25519",
				"public_key":  base64.RawURLEncoding.EncodeToString(root.pub),
				"valid_from":  validFrom,
				"valid_until": validUntil,
				"root":        true,
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

func TestLoadSigningKeysRejectsExpectedFingerprintMismatch(t *testing.T) {
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	path := writePinFile(t, root, signing)
	other := newTestKey(t, "other-root")
	if _, err := trust.LoadSigningKeys(path, fingerprintOf(other.pub)); err == nil {
		t.Fatal("expected error for expected root fingerprint mismatch")
	}
}

func TestKeyAtValidityWindows(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	path := writeWindowPinFile(t, root,
		now.Add(-2*time.Hour).Format(time.RFC3339),
		now.Add(-time.Hour).Format(time.RFC3339))
	ks, err := trust.LoadSigningKeys(path, "")
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	// The key was valid an hour and a half ago.
	if _, err := ks.KeyAt(root.id, now.Add(-90*time.Minute)); err != nil {
		t.Fatalf("KeyAt inside window: %v", err)
	}
	// It is expired now.
	if _, err := ks.KeyAt(root.id, now); err == nil {
		t.Fatal("expected error for expired key")
	}
	// And it was not yet valid three hours ago.
	if _, err := ks.KeyAt(root.id, now.Add(-3*time.Hour)); err == nil {
		t.Fatal("expected error for not-yet-valid key")
	}
	if _, err := ks.KeyAt("no-such-key", now); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestKeyAtOpenEndedWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	path := writeWindowPinFile(t, root, now.Add(-time.Hour).Format(time.RFC3339), "")
	ks, err := trust.LoadSigningKeys(path, "")
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	if _, err := ks.KeyAt(root.id, now.Add(time.Hour)); err != nil {
		t.Fatalf("KeyAt without valid_until: %v", err)
	}
}

func TestLoadSigningKeysRejectsBadWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	// valid_until before valid_from.
	path := writeWindowPinFile(t, root,
		now.Format(time.RFC3339),
		now.Add(-time.Hour).Format(time.RFC3339))
	if _, err := trust.LoadSigningKeys(path, ""); err == nil {
		t.Fatal("expected error for inverted validity window")
	}
	// Unparseable valid_from.
	path = writeWindowPinFile(t, root, "not-a-time", "")
	if _, err := trust.LoadSigningKeys(path, ""); err == nil {
		t.Fatal("expected error for unparseable valid_from")
	}
}

func servedKey(t *testing.T, k testKey, validFrom time.Time, rotatedFrom string) trust.ServedKey {
	t.Helper()
	return trust.ServedKey{
		KeyID:       k.id,
		PublicKey:   base64.RawURLEncoding.EncodeToString(k.pub),
		ValidFrom:   validFrom.Unix(),
		RotatedFrom: rotatedFrom,
	}
}

func TestRefreshFromHistoryAcceptsChainedRotation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	ks, err := trust.LoadSigningKeys(writePinFile(t, root, signing), "")
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	next := newTestKey(t, "test-signing-2")
	history := []trust.ServedKey{
		servedKey(t, root, now.Add(-48*time.Hour), ""),
		servedKey(t, next, now.Add(-time.Hour), root.id),
	}
	if err := ks.RefreshFromHistory(history, now, now); err != nil {
		t.Fatalf("RefreshFromHistory: %v", err)
	}
	msg := []byte("after rotation")
	sig := ed25519.Sign(next.priv, msg)
	if _, err := ks.KeyAt(next.id, now); err != nil {
		t.Fatalf("KeyAt rotated key: %v", err)
	}
	pub, err := ks.KeyAt(next.id, now)
	if err != nil {
		t.Fatalf("KeyAt: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("rotated key does not verify")
	}
	// The old signing key is gone after the refresh.
	if _, err := ks.KeyAt(signing.id, now); err == nil {
		t.Fatal("expected old key to be replaced by the refresh")
	}
}

func TestRefreshFromHistoryRejectsUnchainedKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	ks, err := trust.LoadSigningKeys(writePinFile(t, root, signing), "")
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	rogue := newTestKey(t, "rogue-key")
	history := []trust.ServedKey{
		servedKey(t, rogue, now.Add(-time.Hour), "unknown-previous"),
	}
	if err := ks.RefreshFromHistory(history, now, now); err == nil {
		t.Fatal("expected error for history not chained to the pinned root")
	}
	// A failed refresh leaves the previous key set untouched.
	msg := []byte("still pinned")
	sig := ed25519.Sign(signing.priv, msg)
	if err := ks.VerifySignature(signing.id, msg, sig); err != nil {
		t.Fatalf("previous keys must survive a failed refresh: %v", err)
	}
}

func TestRefreshFromHistoryRejectsStaleServedAt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	ks, err := trust.LoadSigningKeys(writePinFile(t, root, signing), "")
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	history := []trust.ServedKey{servedKey(t, root, now.Add(-48*time.Hour), "")}
	if err := ks.RefreshFromHistory(history, now.Add(-48*time.Hour), now); err == nil {
		t.Fatal("expected error for stale served_at")
	}
	if err := ks.RefreshFromHistory(history, now.Add(time.Hour), now); err == nil {
		t.Fatal("expected error for future served_at")
	}
	if err := ks.RefreshFromHistory(nil, now, now); err == nil {
		t.Fatal("expected error for empty history")
	}
}

func TestRefreshFromHistoryRejectsBadKeyMaterial(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	ks, err := trust.LoadSigningKeys(writePinFile(t, root, signing), "")
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	bad := trust.ServedKey{KeyID: "bad", PublicKey: "not-base64!!", ValidFrom: now.Add(-time.Hour).Unix()}
	if err := ks.RefreshFromHistory([]trust.ServedKey{bad}, now, now); err == nil {
		t.Fatal("expected error for malformed key material")
	}
}

// TestConcurrentRefreshAndLookup hammers the key store with concurrent
// readers (signing-time lookups and signature checks) while a refresh
// replaces the key set. It exists for the race detector: the refresh
// path and the read paths must be mutually synchronized.
func TestConcurrentRefreshAndLookup(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := newTestKey(t, "test-root-1")
	signing := newTestKey(t, "test-signing-1")
	ks, err := trust.LoadSigningKeys(writePinFile(t, root, signing), "")
	if err != nil {
		t.Fatalf("LoadSigningKeys: %v", err)
	}
	next := newTestKey(t, "test-signing-2")
	history := []trust.ServedKey{
		servedKey(t, root, now.Add(-48*time.Hour), ""),
		servedKey(t, next, now.Add(-time.Hour), root.id),
	}
	msg := []byte("concurrent")
	sig := ed25519.Sign(signing.priv, msg)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := ks.KeyAt(signing.id, now); err != nil {
					return
				}
				_ = ks.VerifySignature(signing.id, msg, sig)
				_ = ks.KeyIDs()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				_ = ks.RefreshFromHistory(history, now, now)
			}
		}()
	}
	wg.Wait()
	// After the dust settles the refreshed set is in place.
	if _, err := ks.KeyAt(next.id, now); err != nil {
		t.Fatalf("KeyAt rotated key after concurrent refresh: %v", err)
	}
}
