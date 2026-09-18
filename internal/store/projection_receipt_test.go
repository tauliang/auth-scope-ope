package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testReceiptViewRecord() ReceiptViewRecord {
	return ReceiptViewRecord{
		WorkspaceID:               "ws-test",
		PassID:                    "pass-1",
		Verification:              ReceiptVerified,
		ReceiptID:                 "rcpt-1",
		GrantID:                   "run-1",
		MissionRef:                "mission-1",
		KeyID:                     "receipt-key-1",
		SignedAt:                  time.Unix(1758260000, 0).UTC(),
		ReceiptDigest:             "ab",
		SettlementDigest:          "",
		Outcome:                   "success",
		MissionVersionsJSON:       "[3]",
		ExpansionDecisionRefsJSON: "[]",
		RepositoryID:              111,
		IssueNumber:               42,
		Branch:                    "authscope/mission-1",
		PullRequestNumber:         7,
		HeadSHA:                   "abc",
		ChecksJSON:                `[{"kind":"unit_tests","outcome":"passed"}]`,
		StartedAt:                 time.Unix(1758256000, 0).UTC(),
		FinishedAt:                time.Unix(1758259000, 0).UTC(),
		AggregateCostMicros:       100,
		BudgetMicros:              100,
		HistoricalEnforcementJSON: `[{"scope":"github","level":"enforced"}]`,
		VerifiedAt:                time.Unix(1758260100, 0).UTC(),
	}
}

func TestReceiptViewRoundTrip(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	want := testReceiptViewRecord()
	want.SettlementDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutReceiptView(ctx, want)
	}); err != nil {
		t.Fatalf("PutReceiptView: %v", err)
	}
	got, err := db.GetReceiptView(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetReceiptView: %v", err)
	}
	if got.Verification != ReceiptVerified || got.ReceiptDigest != "ab" {
		t.Fatalf("round trip = %+v, want verified digest ab", got)
	}
	if got.SettlementDigest != want.SettlementDigest {
		t.Fatalf("settlement digest = %q, want %q", got.SettlementDigest, want.SettlementDigest)
	}
	if got.Outcome != "success" || got.KeyID != "receipt-key-1" {
		t.Fatalf("round trip = %+v", got)
	}
	if got.MissionVersionsJSON != "[3]" || got.ChecksJSON != want.ChecksJSON {
		t.Fatalf("json columns = %q %q", got.MissionVersionsJSON, got.ChecksJSON)
	}
	if !got.SignedAt.Equal(want.SignedAt) || !got.VerifiedAt.Equal(want.VerifiedAt) {
		t.Fatalf("times = %v %v", got.SignedAt, got.VerifiedAt)
	}
}

func TestReceiptViewUnknownPassIsNotFound(t *testing.T) {
	db := openTestStore(t)
	if _, err := db.GetReceiptView(context.Background(), "ws-test", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetReceiptView = %v, want ErrNotFound", err)
	}
}

// TestReceiptViewVerifiedNeverOverwritesUnverifiableDispute covers the
// conflict case: an unverifiable verdict for one receipt digest must
// not be silently replaced by a verified view for a different digest.
func TestReceiptViewVerifiedNeverOverwritesUnverifiableDispute(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	unverifiable := testReceiptViewRecord()
	unverifiable.Verification = ReceiptUnverifiable
	unverifiable.ReasonCode = "bad_signature"
	unverifiable.ReceiptDigest = "digest-a"
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutReceiptView(ctx, unverifiable)
	}); err != nil {
		t.Fatalf("PutReceiptView unverifiable: %v", err)
	}

	conflicting := testReceiptViewRecord()
	conflicting.ReceiptDigest = "digest-b"
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutReceiptView(ctx, conflicting)
	}); err != nil {
		t.Fatalf("PutReceiptView conflicting: %v", err)
	}
	got, err := db.GetReceiptView(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetReceiptView: %v", err)
	}
	if got.Verification != ReceiptUnverifiable || got.ReceiptDigest != "digest-a" {
		t.Fatalf("conflict overwrote the latched verdict: %+v", got)
	}
	if got.ReasonCode != "bad_signature" {
		t.Fatalf("reason code = %q, want bad_signature", got.ReasonCode)
	}
}

// TestReceiptViewSameDigestRefreshIsIdempotent covers the benign
// duplicate: re-storing the same verified digest is a no-op, so a
// retried worker sweep cannot corrupt the latched view.
func TestReceiptViewSameDigestRefreshIsIdempotent(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	rec := testReceiptViewRecord()
	for i := 0; i < 2; i++ {
		if err := db.WithTx(ctx, func(tx Tx) error {
			return tx.PutReceiptView(ctx, rec)
		}); err != nil {
			t.Fatalf("PutReceiptView %d: %v", i, err)
		}
	}
	got, err := db.GetReceiptView(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetReceiptView: %v", err)
	}
	if got.Verification != ReceiptVerified || got.ReceiptDigest != rec.ReceiptDigest {
		t.Fatalf("idempotent rewrite changed the view: %+v", got)
	}
}

func TestCheckPublicationIntentRoundTrip(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	rec := CheckPublicationRecord{
		WorkspaceID:       "ws-test",
		PassID:            "pass-1",
		IdempotencyKey:    "key-1",
		ReceiptDigest:     "ab",
		RepositoryID:      111,
		PullRequestNumber: 7,
		HeadSHA:           "abc",
		BindingID:         "bind-1",
		State:             CheckPublicationInFlight,
		CreatedAt:         time.Unix(1758260000, 0).UTC(),
		UpdatedAt:         time.Unix(1758260000, 0).UTC(),
	}
	var inserted bool
	if err := db.WithTx(ctx, func(tx Tx) error {
		var err error
		inserted, err = tx.PutCheckPublicationIfAbsent(ctx, rec)
		return err
	}); err != nil {
		t.Fatalf("PutCheckPublicationIfAbsent: %v", err)
	}
	if !inserted {
		t.Fatal("first insert should report inserted=true")
	}
	// A duplicate insert with the same idempotency key is a no-op.
	if err := db.WithTx(ctx, func(tx Tx) error {
		var err error
		inserted, err = tx.PutCheckPublicationIfAbsent(ctx, rec)
		return err
	}); err != nil {
		t.Fatalf("duplicate PutCheckPublicationIfAbsent: %v", err)
	}
	if inserted {
		t.Fatal("duplicate insert should report inserted=false")
	}
	got, err := func() (CheckPublicationRecord, error) {
		var rec CheckPublicationRecord
		err := db.WithTx(ctx, func(tx Tx) error {
			var err error
			rec, err = tx.GetCheckPublication(ctx, "ws-test", "key-1")
			return err
		})
		return rec, err
	}()
	if err != nil {
		t.Fatalf("GetCheckPublication: %v", err)
	}
	if got.State != CheckPublicationInFlight || got.BindingID != "bind-1" {
		t.Fatalf("round trip = %+v", got)
	}
	if !got.UpdatedAt.Equal(rec.UpdatedAt) {
		t.Fatalf("updated_at = %v, want injected clock %v", got.UpdatedAt, rec.UpdatedAt)
	}
	// Latest-for-pass and state transitions.
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.SetCheckPublicationState(ctx, "ws-test", "key-1", CheckPublicationSettled, "chk-1", time.Unix(1758260100, 0).UTC())
	}); err != nil {
		t.Fatalf("SetCheckPublicationState: %v", err)
	}
	latest, err := db.GetLatestCheckPublicationForPass(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetLatestCheckPublicationForPass: %v", err)
	}
	if latest.State != CheckPublicationSettled || latest.CheckRunID != "chk-1" {
		t.Fatalf("latest = %+v", latest)
	}
	if _, err := db.GetLatestCheckPublicationForPass(ctx, "ws-test", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown pass = %v, want ErrNotFound", err)
	}
}
