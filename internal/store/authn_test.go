// Tests for founder authentication storage: founders, passkey public
// credentials, hashed sessions, one-use bootstrap codes, and offline
// recovery key hashes.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestAuthnMigrationApplied(t *testing.T) {
	db := openTestStore(t)
	sqldb := testSQLDB(t, db)
	cols, err := tableColumns(sqldb, "sessions")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cols {
		if c == "csrf_token_hash" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sessions columns = %v, want csrf_token_hash", cols)
	}
	for _, table := range []string{"bootstrap_codes", "offline_recovery_keys"} {
		var name string
		if err := sqldb.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name); err != nil {
			t.Fatalf("table %s: %v", table, err)
		}
	}
}

func TestCreateFounderConflict(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	rec := FounderRecord{WorkspaceID: "ws-test", FounderID: "founder-1", CreatedAt: time.Now().UTC()}
	if err := db.WithTx(ctx, func(tx Tx) error { return tx.CreateFounder(ctx, rec) }); err != nil {
		t.Fatalf("CreateFounder: %v", err)
	}
	err := db.WithTx(ctx, func(tx Tx) error { return tx.CreateFounder(ctx, rec) })
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("second CreateFounder = %v, want ErrConflict", err)
	}
	n, err := db.CountFounders(ctx, "ws-test")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("CountFounders = %d, want 1", n)
	}
	founders, err := db.ListFounders(ctx, "ws-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(founders) != 1 || founders[0].FounderID != "founder-1" {
		t.Fatalf("ListFounders = %+v", founders)
	}
}

func createTestFounder(t *testing.T, db Store, workspaceID, founderID string) {
	t.Helper()
	ctx := context.Background()
	err := db.WithTx(ctx, func(tx Tx) error {
		return tx.CreateFounder(ctx, FounderRecord{
			WorkspaceID: workspaceID, FounderID: founderID, CreatedAt: time.Now().UTC(),
		})
	})
	if err != nil {
		t.Fatalf("CreateFounder: %v", err)
	}
}

func TestCredentialDuplicateRejected(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	createTestFounder(t, db, "ws-test", "founder-1")
	rec := WebAuthnCredentialRecord{
		WorkspaceID:  "ws-test",
		CredentialID: "cred-1",
		FounderID:    "founder-1",
		PublicKey:    []byte{1, 2, 3},
		SignCount:    0,
		CreatedAt:    time.Now().UTC(),
	}
	if err := db.WithTx(ctx, func(tx Tx) error { return tx.PutWebAuthnCredential(ctx, rec) }); err != nil {
		t.Fatalf("PutWebAuthnCredential: %v", err)
	}
	err := db.WithTx(ctx, func(tx Tx) error { return tx.PutWebAuthnCredential(ctx, rec) })
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate PutWebAuthnCredential = %v, want ErrConflict", err)
	}
	creds, err := db.ListWebAuthnCredentials(ctx, "ws-test", "founder-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].CredentialID != "cred-1" {
		t.Fatalf("ListWebAuthnCredentials = %+v", creds)
	}
	// A different workspace never sees the credential.
	other, err := db.ListWebAuthnCredentials(ctx, "ws-other", "founder-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("cross-workspace credentials = %+v", other)
	}
}

func TestSignCountMustAdvance(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	createTestFounder(t, db, "ws-test", "founder-1")
	rec := WebAuthnCredentialRecord{
		WorkspaceID: "ws-test", CredentialID: "cred-1", FounderID: "founder-1",
		PublicKey: []byte{1}, SignCount: 5, CreatedAt: time.Now().UTC(),
	}
	if err := db.WithTx(ctx, func(tx Tx) error { return tx.PutWebAuthnCredential(ctx, rec) }); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.UpdateWebAuthnCredentialSignCount(ctx, "ws-test", "cred-1", 9)
	}); err != nil {
		t.Fatalf("advance sign count: %v", err)
	}
	err := db.WithTx(ctx, func(tx Tx) error {
		return tx.UpdateWebAuthnCredentialSignCount(ctx, "ws-test", "cred-1", 9)
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stagnant sign count = %v, want ErrConflict", err)
	}
	err = db.WithTx(ctx, func(tx Tx) error {
		return tx.UpdateWebAuthnCredentialSignCount(ctx, "ws-test", "cred-1", 3)
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("backward sign count = %v, want ErrConflict", err)
	}
	err = db.WithTx(ctx, func(tx Tx) error {
		return tx.UpdateWebAuthnCredentialSignCount(ctx, "ws-test", "missing", 10)
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing credential = %v, want ErrNotFound", err)
	}
}

func TestSessionHashLookupAndRevoke(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	rec := SessionRecord{
		WorkspaceID: "ws-test", SessionID: "sess-1", SessionHash: "hash-1",
		FounderID: "founder-1", CSRFTokenHash: "csrf-1",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.WithTx(ctx, func(tx Tx) error { return tx.CreateSession(ctx, rec) }); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	err := db.WithTx(ctx, func(tx Tx) error { return tx.CreateSession(ctx, rec) })
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate session hash = %v, want ErrConflict", err)
	}
	got, err := db.GetSessionByHash(ctx, "ws-test", "hash-1")
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if got.SessionID != "sess-1" || got.CSRFTokenHash != "csrf-1" || got.Revoked {
		t.Fatalf("GetSessionByHash = %+v", got)
	}
	// A copied session hash does not resolve in another workspace.
	if _, err := db.GetSessionByHash(ctx, "ws-other", "hash-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workspace session lookup = %v, want ErrNotFound", err)
	}
	if err := db.WithTx(ctx, func(tx Tx) error { return tx.RevokeSession(ctx, "ws-test", "sess-1") }); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	got, err = db.GetSessionByHash(ctx, "ws-test", "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Fatal("expected revoked session")
	}
	err = db.WithTx(ctx, func(tx Tx) error { return tx.RevokeSession(ctx, "ws-test", "nope") })
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke missing = %v, want ErrNotFound", err)
	}
}

func TestBootstrapCodeOneUse(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	put := func(hash string, expires time.Time) {
		t.Helper()
		rec := BootstrapCodeRecord{
			WorkspaceID: "ws-test", CodeHash: hash,
			CreatedAt: now, ExpiresAt: expires,
		}
		if err := db.WithTx(ctx, func(tx Tx) error { return tx.PutBootstrapCode(ctx, rec) }); err != nil {
			t.Fatalf("PutBootstrapCode: %v", err)
		}
	}
	put("hash-1", now.Add(10*time.Minute))
	got, err := db.GetBootstrapCode(ctx, "ws-test")
	if err != nil {
		t.Fatalf("GetBootstrapCode: %v", err)
	}
	if got.CodeHash != "hash-1" {
		t.Fatalf("GetBootstrapCode = %+v", got)
	}
	// Replacing the active code drops the old one.
	put("hash-2", now.Add(10*time.Minute))
	got, err = db.GetBootstrapCode(ctx, "ws-test")
	if err != nil {
		t.Fatal(err)
	}
	if got.CodeHash != "hash-2" {
		t.Fatalf("after replace, GetBootstrapCode = %+v", got)
	}
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.ConsumeBootstrapCode(ctx, "ws-test", "hash-2", now)
	}); err != nil {
		t.Fatalf("ConsumeBootstrapCode: %v", err)
	}
	if _, err := db.GetBootstrapCode(ctx, "ws-test"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed code still active: %v", err)
	}
	// Replaying the consumed code fails.
	err = db.WithTx(ctx, func(tx Tx) error {
		return tx.ConsumeBootstrapCode(ctx, "ws-test", "hash-2", now)
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("replay consume = %v, want ErrNotFound", err)
	}
	// An expired code cannot be consumed.
	put("hash-3", now.Add(-time.Minute))
	err = db.WithTx(ctx, func(tx Tx) error {
		return tx.ConsumeBootstrapCode(ctx, "ws-test", "hash-3", now)
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expired consume = %v, want ErrConflict", err)
	}
}

func TestOfflineRecoveryKeyHashOnly(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	raw := "raw-recovery-key-material-never-stored"
	rec := OfflineRecoveryKeyRecord{
		WorkspaceID: "ws-test", FounderID: "founder-1",
		KeyHash: "hash-of-key", CreatedAt: time.Now().UTC(),
	}
	if err := db.WithTx(ctx, func(tx Tx) error { return tx.PutOfflineRecoveryKey(ctx, rec) }); err != nil {
		t.Fatalf("PutOfflineRecoveryKey: %v", err)
	}
	err := db.WithTx(ctx, func(tx Tx) error { return tx.PutOfflineRecoveryKey(ctx, rec) })
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate recovery key = %v, want ErrConflict", err)
	}
	got, err := db.GetOfflineRecoveryKey(ctx, "ws-test", "founder-1")
	if err != nil {
		t.Fatalf("GetOfflineRecoveryKey: %v", err)
	}
	if got.KeyHash != "hash-of-key" {
		t.Fatalf("GetOfflineRecoveryKey = %+v", got)
	}
	if _, err := db.GetOfflineRecoveryKey(ctx, "ws-other", "founder-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-workspace recovery key = %v, want ErrNotFound", err)
	}
	if hits := scanStoreForStrings(t, db, []string{raw}); len(hits) > 0 {
		t.Fatalf("raw recovery key material persisted in %v", hits)
	}
}

func TestRawAuthnSecretsNeverStored(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// The store API only ever receives hashes; this test proves that when
	// callers hash correctly, no raw secret lands in any table.
	rawSession := "raw-session-token-value"
	rawCSRF := "raw-csrf-token-value"
	rawCode := "raw-bootstrap-code-value"
	hash := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	err := db.WithTx(ctx, func(tx Tx) error {
		if err := tx.CreateFounder(ctx, FounderRecord{WorkspaceID: "ws-test", FounderID: "founder-1", CreatedAt: now}); err != nil {
			return err
		}
		return tx.CreateSession(ctx, SessionRecord{
			WorkspaceID: "ws-test", SessionID: "sess-1",
			SessionHash:   hash(rawSession),
			FounderID:     "founder-1",
			CSRFTokenHash: hash(rawCSRF),
			CreatedAt:     now, ExpiresAt: now.Add(time.Hour),
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutBootstrapCode(ctx, BootstrapCodeRecord{
			WorkspaceID: "ws-test", CodeHash: hash(rawCode),
			CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		})
	}); err != nil {
		t.Fatal(err)
	}
	if hits := scanStoreForStrings(t, db, []string{rawSession, rawCSRF, rawCode}); len(hits) > 0 {
		t.Fatalf("raw secrets persisted in %v", hits)
	}
}
