package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRecoveryIntentLifecycle exercises the durable intent state
// machine: pending -> contained -> verified_empty -> completed, with
// exactly-once transitions.
func TestRecoveryIntentLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Second)
	rec := RecoveryIntentRecord{
		WorkspaceID:     "ws-1",
		IdempotencyKey:  "key-1",
		IntentID:        "intent-1",
		CanonicalDigest: "sha256:aaa",
		Nonce:           "nonce-1",
		State:           RecoveryIntentPending,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.PutRecoveryIntent(ctx, rec)
	}); err != nil {
		t.Fatalf("put intent: %v", err)
	}
	// Duplicate insert conflicts.
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.PutRecoveryIntent(ctx, rec)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate put = %v, want ErrConflict", err)
	}

	got, err := st.GetRecoveryIntent(ctx, "ws-1", "key-1")
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if got.State != RecoveryIntentPending {
		t.Fatalf("state = %q", got.State)
	}

	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.SetRecoveryIntentAttestation(ctx, "ws-1", "key-1", "sha256:att", now)
	}); err != nil {
		t.Fatalf("set attestation: %v", err)
	}
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.SetRecoveryIntentContained(ctx, "ws-1", "key-1", 42, now)
	}); err != nil {
		t.Fatalf("set contained: %v", err)
	}
	got, err = st.GetRecoveryIntent(ctx, "ws-1", "key-1")
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if got.State != RecoveryIntentContained || got.ContainmentGeneration != 42 || got.AttestationDigest != "sha256:att" {
		t.Fatalf("bad contained intent: %+v", got)
	}

	// Skipping straight to completed is rejected.
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.SetRecoveryIntentCompleted(ctx, "ws-1", "key-1", "ev-1", 1, 1, now, now)
	}); err == nil {
		t.Fatal("completed from contained: expected error")
	}

	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.SetRecoveryIntentVerifiedEmpty(ctx, "ws-1", "key-1", now)
	}); err != nil {
		t.Fatalf("set verified empty: %v", err)
	}
	exp := now.Add(10 * time.Minute)
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.SetRecoveryIntentCompleted(ctx, "ws-1", "key-1", "ev-1", 3, 2, exp, now)
	}); err != nil {
		t.Fatalf("set completed: %v", err)
	}
	got, err = st.GetRecoveryIntent(ctx, "ws-1", "key-1")
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if got.State != RecoveryIntentCompleted || got.RecoveryEventID != "ev-1" ||
		got.RevokedSessionCount != 3 || got.ContainedMissionCount != 2 {
		t.Fatalf("bad completed intent: %+v", got)
	}

	// Missing intent.
	if _, err := st.GetRecoveryIntent(ctx, "ws-1", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing = %v, want ErrNotFound", err)
	}
}

// TestRecoveryEvents exercises the non-secret event log and its
// idempotency-key uniqueness.
func TestRecoveryEvents(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC().Truncate(time.Second)
	rec := RecoveryEventRecord{
		WorkspaceID:           "ws-1",
		EventID:               "ev-1",
		FounderID:             "founder-1",
		IdempotencyKey:        "key-1",
		ContainedMissionCount: 2,
		ContainmentGeneration: 9,
		AttestationDigest:     "sha256:att",
		RecoveryProofDigest:   "sha256:proof",
		BootstrapCodeHash:     "hash",
		OccurredAt:            now,
	}
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.PutRecoveryEvent(ctx, rec)
	}); err != nil {
		t.Fatalf("put event: %v", err)
	}
	// Same idempotency key twice conflicts.
	rec.EventID = "ev-2"
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.PutRecoveryEvent(ctx, rec)
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key put = %v, want ErrConflict", err)
	}

	got, err := st.GetRecoveryEvent(ctx, "ws-1", "ev-1")
	if err != nil {
		t.Fatalf("get event: %v", err)
	}
	if got.AttestationDigest != "sha256:att" || got.ContainedMissionCount != 2 {
		t.Fatalf("bad event: %+v", got)
	}
	listed, err := st.ListRecoveryEvents(ctx, "ws-1", 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(listed) != 1 || listed[0].EventID != "ev-1" {
		t.Fatalf("listed = %+v", listed)
	}
	if _, err := st.GetRecoveryEvent(ctx, "ws-1", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing = %v, want ErrNotFound", err)
	}
}

// TestRecoveryResetPrimitives exercises session revocation, handoff
// reset, credential deletion, key consumption, and founder deletion.
func TestRecoveryResetPrimitives(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	ws := "ws-1"
	now := time.Now().UTC()
	if err := st.WithTx(ctx, func(tx Tx) error {
		if err := tx.CreateFounder(ctx, FounderRecord{
			WorkspaceID: ws, FounderID: "founder-1", CreatedAt: now,
		}); err != nil {
			return err
		}
		for _, id := range []string{"s1", "s2"} {
			if err := tx.CreateSession(ctx, SessionRecord{
				WorkspaceID: ws, SessionID: id, SessionHash: "h-" + id,
				FounderID: "founder-1", CSRFTokenHash: "c",
				CreatedAt: now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				return err
			}
		}
		// One already-revoked session is not counted again.
		if err := tx.RevokeSession(ctx, ws, "s2"); err != nil {
			return err
		}
		if err := tx.PutCLIAuthorization(ctx, CLIAuthorization{
			WorkspaceID: ws, AuthorizationID: "a1", PassID: "p1",
			State: "st", CodeChallenge: "cc", RedirectURI: "http://127.0.0.1:9/",
			EphemeralPublicKey: "k", ProposalDigest: "pd", InvocationDigest: "id",
			AgentKitID: "kit", MissionRef: "m", MissionVersion: 1,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			return err
		}
		if err := tx.PutWebAuthnCredential(ctx, WebAuthnCredentialRecord{
			WorkspaceID: ws, CredentialID: "c1", FounderID: "founder-1",
			PublicKey: []byte("pk"), CreatedAt: now,
		}); err != nil {
			return err
		}
		return tx.PutOfflineRecoveryKey(ctx, OfflineRecoveryKeyRecord{
			WorkspaceID: ws, FounderID: "founder-1", KeyHash: "kh", CreatedAt: now,
		})
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}

	var revoked int
	if err := st.WithTx(ctx, func(tx Tx) error {
		var err error
		revoked, err = tx.RevokeAllSessions(ctx, ws)
		return err
	}); err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if revoked != 1 {
		t.Fatalf("revoked = %d, want 1 (s2 was already revoked)", revoked)
	}
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.ResetLaunchHandoffs(ctx, ws)
	}); err != nil {
		t.Fatalf("reset handoffs: %v", err)
	}
	if _, err := st.GetCLIAuthorization(ctx, ws, "a1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authorization after reset = %v, want ErrNotFound", err)
	}
	var deleted int
	if err := st.WithTx(ctx, func(tx Tx) error {
		var err error
		deleted, err = tx.DeleteAllWebAuthnCredentials(ctx, ws)
		return err
	}); err != nil {
		t.Fatalf("delete credentials: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	creds, err := st.ListWebAuthnCredentials(ctx, ws, "founder-1")
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("credentials remain: %d", len(creds))
	}
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.ConsumeOfflineRecoveryKey(ctx, ws, "founder-1")
	}); err != nil {
		t.Fatalf("consume key: %v", err)
	}
	if _, err := st.GetOfflineRecoveryKey(ctx, ws, "founder-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key after consume = %v, want ErrNotFound", err)
	}
	// Consuming twice fails: the key is one-use.
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.ConsumeOfflineRecoveryKey(ctx, ws, "founder-1")
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume = %v, want ErrNotFound", err)
	}
	if err := st.WithTx(ctx, func(tx Tx) error {
		return tx.DeleteFounder(ctx, ws, "founder-1")
	}); err != nil {
		t.Fatalf("delete founder: %v", err)
	}
	if n, err := st.CountFounders(ctx, ws); err != nil || n != 0 {
		t.Fatalf("founders = %d, err = %v", n, err)
	}
}

// TestOpenExclusiveLock verifies the second opener refuses while the
// first holds the data directory.
func TestOpenExclusiveLock(t *testing.T) {
	dir := t.TempDir()
	first, err := OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	defer first.Close()

	if _, err := OpenExclusive(dir, "development"); err == nil {
		t.Fatal("second exclusive open succeeded while the first holds the lock")
	}
	// After close, the directory opens again.
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	second, err := OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	second.Close()
}
