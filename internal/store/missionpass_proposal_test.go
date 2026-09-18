package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestPutMissionPassPersistsProposalFields round-trips the exact upstream
// proposal fields Task 6 stores on a pass: digests, kit identity, ordered
// runner arguments, limits, and reconciliation state.
func TestPutMissionPassPersistsProposalFields(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()
	expires := time.Date(2026, time.September, 17, 23, 0, 0, 0, time.UTC)
	rec := MissionPassRecord{
		WorkspaceID:            "ws-test",
		PassID:                 "pass-1",
		DraftVersion:           1,
		ConnectionID:           "conn-1",
		IssueNumber:            42,
		RepositoryName:         "octo-org/host",
		ProposalID:             "prop-1",
		ProposalDigest:         "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SourceRevision:         "rev-1",
		SourceDigest:           "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BaseSHA:                "cccccccccccccccccccccccccccccccccccccccc",
		MissionBranch:          "authscope/pass-1-42",
		AgentKitID:             "authscope-agent-kit",
		AgentKitVersion:        "1.0.0",
		RunnerArguments:        []string{"authscope-agent-run", "--mission", "pass-1"},
		InvocationDigest:       "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		ExpiresAt:              expires,
		MaxAggregateCostMicros: 10_000_000,
		Objective:              "Add retries",
		AcceptanceCriteria:     []string{"retry with backoff"},
		ShapedDraftJSON:        `{"objective":"Add retries"}`,
		State:                  "draft",
		Reconciliation:         "settled",
		CreatedAt:              time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutMissionPass(ctx, rec, 0)
	}); err != nil {
		t.Fatalf("PutMissionPass: %v", err)
	}
	got, err := db.GetMissionPass(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if got.ProposalID != rec.ProposalID || got.ProposalDigest != rec.ProposalDigest ||
		got.InvocationDigest != rec.InvocationDigest {
		t.Errorf("digests = %q %q %q", got.ProposalID, got.ProposalDigest, got.InvocationDigest)
	}
	if got.ApprovedProposalDigest != "" {
		t.Errorf("ApprovedProposalDigest = %q, want empty", got.ApprovedProposalDigest)
	}
	if got.AgentKitID != rec.AgentKitID || got.AgentKitVersion != rec.AgentKitVersion {
		t.Errorf("kit = %q %q", got.AgentKitID, got.AgentKitVersion)
	}
	if len(got.RunnerArguments) != 3 || got.RunnerArguments[0] != "authscope-agent-run" ||
		got.RunnerArguments[1] != "--mission" || got.RunnerArguments[2] != "pass-1" {
		t.Errorf("RunnerArguments = %v, want exact order and content", got.RunnerArguments)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expires)
	}
	if got.MaxAggregateCostMicros != 10_000_000 {
		t.Errorf("MaxAggregateCostMicros = %d", got.MaxAggregateCostMicros)
	}
	if got.Objective != "Add retries" || len(got.AcceptanceCriteria) != 1 {
		t.Errorf("snapshot = %q %v", got.Objective, got.AcceptanceCriteria)
	}
	if got.MissionBranch != "authscope/pass-1-42" || got.SourceRevision != "rev-1" ||
		got.BaseSHA != rec.BaseSHA || got.ConnectionID != "conn-1" || got.IssueNumber != 42 ||
		got.RepositoryName != "octo-org/host" {
		t.Errorf("source identity = %+v", got)
	}
	if got.Reconciliation != "settled" {
		t.Errorf("Reconciliation = %q", got.Reconciliation)
	}
	// A revision overwrites every proposal field through CAS.
	rec.ProposalID = "prop-2"
	rec.DraftVersion = 2
	rec.Reconciliation = "pending"
	if err := db.WithTx(ctx, func(tx Tx) error {
		return tx.PutMissionPass(ctx, rec, 1)
	}); err != nil {
		t.Fatalf("PutMissionPass revision: %v", err)
	}
	got, err = db.GetMissionPass(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if got.StoreRevision != 2 || got.DraftVersion != 2 || got.ProposalID != "prop-2" ||
		got.Reconciliation != "pending" {
		t.Errorf("revision = %+v", got)
	}
}

// TestClaimMissionPassRequestKeyIsInsertOrIgnore verifies that the first
// claim wins and a racing second claim resolves to the same pass.
func TestClaimMissionPassRequestKeyIsInsertOrIgnore(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()

	winner, err := db.ClaimMissionPassRequestKey(ctx, "ws-test", "key-1", "pass-a")
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if winner != "pass-a" {
		t.Fatalf("winner = %q, want pass-a", winner)
	}
	winner, err = db.ClaimMissionPassRequestKey(ctx, "ws-test", "key-1", "pass-b")
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if winner != "pass-a" {
		t.Fatalf("second winner = %q, want pass-a", winner)
	}
	got, err := db.GetMissionPassIDByRequestKey(ctx, "ws-test", "key-1")
	if err != nil || got != "pass-a" {
		t.Fatalf("lookup = %q, %v", got, err)
	}
	// Keys are workspace-qualified.
	winner, err = db.ClaimMissionPassRequestKey(ctx, "ws-other", "key-1", "pass-c")
	if err != nil || winner != "pass-c" {
		t.Fatalf("other workspace winner = %q, %v", winner, err)
	}
	// Unknown keys resolve to "".
	got, err = db.GetMissionPassIDByRequestKey(ctx, "ws-test", "key-missing")
	if err != nil || got != "" {
		t.Fatalf("missing lookup = %q, %v", got, err)
	}
	// Deleting a dangling mapping lets a retry claim cleanly.
	if err := db.DeleteMissionPassRequestKey(ctx, "ws-test", "key-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	winner, err = db.ClaimMissionPassRequestKey(ctx, "ws-test", "key-1", "pass-d")
	if err != nil || winner != "pass-d" {
		t.Fatalf("reclaim winner = %q, %v", winner, err)
	}
}

// TestGetMissionPassRequestKeyClaimedAt verifies the claim timestamp
// used to tell a still-running owner apart from a dangling mapping.
func TestGetMissionPassRequestKeyClaimedAt(t *testing.T) {
	db := openTestStore(t)
	ctx := context.Background()

	before := time.Now().Add(-time.Minute)
	if _, err := db.ClaimMissionPassRequestKey(ctx, "ws-test", "key-ts", "pass-a"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	claimedAt, err := db.GetMissionPassRequestKeyClaimedAt(ctx, "ws-test", "key-ts")
	if err != nil {
		t.Fatalf("claimed at: %v", err)
	}
	if claimedAt.Before(before) || claimedAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("claimed at = %v, want near now", claimedAt)
	}
	if _, err := db.GetMissionPassRequestKeyClaimedAt(ctx, "ws-test", "key-missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing key err = %v, want ErrNotFound", err)
	}
}
