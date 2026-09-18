// Tests for the receipt service: the pass-owned loop of fetching the
// upstream receipt envelope, verifying it locally, transitioning the
// pass only on a verified receipt, and publishing the privacy-safe
// GitHub check exactly once.
package receipt_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

type fakeReceiptAuthority struct {
	coreapi.Authority
	// mu guards the counters and maps: the concurrency test drives
	// the fake from multiple goroutines.
	mu              sync.Mutex
	receipt         *coreapi.SignedReceiptEnvelope
	receipts        map[string]*coreapi.SignedReceiptEnvelope
	receiptErr      error
	receiptCalls    int
	history         coreapi.SigningKeyHistory
	publishCalls    int
	publishErr      error
	published       []coreapi.GitHubCheckRequest
	checks          map[string]coreapi.GitHubCheckResult
	reconcileStatus string
	reconcileCalls  int
}

func (f *fakeReceiptAuthority) GetReceipt(ctx context.Context, grantID string, opts coreapi.RequestOptions) (coreapi.SignedReceiptEnvelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.receiptCalls++
	if f.receiptErr != nil {
		return coreapi.SignedReceiptEnvelope{}, f.receiptErr
	}
	if env, ok := f.receipts[grantID]; ok && env != nil {
		return *env, nil
	}
	if f.receipt == nil {
		return coreapi.SignedReceiptEnvelope{}, &coreapi.UpstreamError{StatusCode: http.StatusNotFound}
	}
	return *f.receipt, nil
}

func (f *fakeReceiptAuthority) GetSigningKeys(ctx context.Context, opts coreapi.RequestOptions) (coreapi.SigningKeyHistory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.history, nil
}

func (f *fakeReceiptAuthority) PublishGitHubCheck(ctx context.Context, req coreapi.GitHubCheckRequest, opts coreapi.RequestOptions) (coreapi.GitHubCheckResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishCalls++
	f.published = append(f.published, req)
	if f.publishErr != nil {
		return coreapi.GitHubCheckResult{}, f.publishErr
	}
	if f.checks == nil {
		f.checks = map[string]coreapi.GitHubCheckResult{}
	}
	if existing, ok := f.checks[req.IdempotencyKey]; ok {
		return existing, nil
	}
	res := coreapi.GitHubCheckResult{
		CheckRunID:     "chk-" + strings.Repeat("1", 8),
		BindingID:      req.BindingID,
		WorkspaceID:    opts.WorkspaceID,
		HeadSHA:        req.HeadSHA,
		Name:           req.Name,
		Status:         req.Status,
		Conclusion:     req.Conclusion,
		IdempotencyKey: req.IdempotencyKey,
		CreatedAt:      time.Now().UTC().Unix(),
	}
	f.checks[req.IdempotencyKey] = res
	return res, nil
}

func (f *fakeReceiptAuthority) ReconcileOperation(ctx context.Context, idempotencyKey, operationID string, opts coreapi.RequestOptions) (coreapi.OperationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconcileCalls++
	return coreapi.OperationResult{
		OperationID:    operationID,
		IdempotencyKey: idempotencyKey,
		Status:         f.reconcileStatus,
	}, nil
}

type serviceFixture struct {
	store   store.Store
	auth    *fakeReceiptAuthority
	signer  testSigner
	now     time.Time
	service *receipt.Service
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "receipt-key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true, validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	ks, err := trust.LoadSigningKeys(pinPath, fps[signer.id])
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	db, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	auth := &fakeReceiptAuthority{reconcileStatus: "completed"}
	svc, err := receipt.NewService(receipt.Config{
		Store:     db,
		Authority: auth,
		Keys:      ks,
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	f := &serviceFixture{store: db, auth: auth, signer: signer, now: now, service: svc}
	f.seedPass(t, "pass-1")
	return f
}

// validPayload is the receipt payload matching the seeded pass
// binding: mission versions 3 and 4 across the projected events, and
// the completed expansion decision ref.
func validPayload(signerID string, now time.Time) receipt.Payload {
	p := basePayload(testSigner{id: signerID}, now)
	p.MissionVersions = []int64{3, 4}
	p.ExpansionDecisionRefs = []string{"exp-1"}
	return p
}

func (f *serviceFixture) seedPass(t *testing.T, passID string) {
	t.Helper()
	f.seedPassFull(t, passID, "run-1", "exp-1")
}

func (f *serviceFixture) seedPassFull(t *testing.T, passID, runID, expansionID string) {
	t.Helper()
	ctx := context.Background()
	now := f.now
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.PutConnection(ctx, store.ConnectionRecord{
			WorkspaceID: "ws-test", ConnectionID: "conn-1",
			RepositoryBindingRef: "binding-1", InstallationID: 222,
			RepositoryID: 111, RepositoryName: "octo-org/repo",
			PermissionStatus: "ok", VerifiedAt: now, CreatedAt: now,
		}); err != nil {
			return err
		}
		if err := tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID: "ws-test", PassID: passID,
			State:          string(missionpass.PassOutcomePending),
			Reconciliation: string(missionpass.ReconciliationSettled),
			ConnectionID:   "conn-1", IssueNumber: 42,
			RepositoryName: "octo-org/repo",
			MissionRef:     "mission-1", RunID: runID,
			Objective: "Add retries", StoreRevision: 1,
		}, 0); err != nil {
			return err
		}
		events := []struct {
			id, typ, cursor string
			at              time.Time
			safe            missionpass.SafeEvent
		}{
			{"ev-1", missionpass.EventRunSucceeded, "c1", now.Add(-time.Hour), missionpass.SafeEvent{
				EventID: "ev-1", Cursor: "c1", Type: missionpass.EventRunSucceeded,
				OccurredAt: now.Add(-time.Hour), AuthScopeMissionVersion: 3,
				ResourceDigest: "sha256:" + strings.Repeat("d", 64),
				Branch:         "authscope/mission-1", HeadSHA: strings.Repeat("a", 40),
			}},
			{"ev-2", missionpass.EventPullRequestCreated, "c2", now.Add(-50 * time.Minute), missionpass.SafeEvent{
				EventID: "ev-2", Cursor: "c2", Type: missionpass.EventPullRequestCreated,
				OccurredAt: now.Add(-50 * time.Minute), AuthScopeMissionVersion: 4,
				ResourceDigest: "sha256:" + strings.Repeat("e", 64),
				Branch:         "authscope/mission-1", HeadSHA: strings.Repeat("a", 40),
				PullRequestNumber: 7,
			}},
			{"ev-3", missionpass.EventActionChecked, "c3", now.Add(-40 * time.Minute), missionpass.SafeEvent{
				EventID: "ev-3", Cursor: "c3", Type: missionpass.EventActionChecked,
				OccurredAt: now.Add(-40 * time.Minute), AuthScopeMissionVersion: 4,
				ResourceDigest: "sha256:" + strings.Repeat("f", 64),
				CheckKind:      missionpass.CheckKindTest, CheckOutcome: missionpass.CheckOutcomePassed,
			}},
			{"ev-4", missionpass.EventReceiptReady, "c4", now.Add(-time.Minute), missionpass.SafeEvent{
				EventID: "ev-4", Cursor: "c4", Type: missionpass.EventReceiptReady,
				OccurredAt: now.Add(-time.Minute), AuthScopeMissionVersion: 4,
				ResourceDigest: "sha256:" + strings.Repeat("d", 64),
			}},
		}
		for _, e := range events {
			raw, err := json.Marshal(e.safe)
			if err != nil {
				return err
			}
			if _, err := tx.PutEventIfAbsent(ctx, store.MissionEventRecord{
				WorkspaceID: "ws-test", PassID: passID, EventID: e.id,
				EventType: e.typ, Cursor: e.cursor, Payload: string(raw), OccurredAt: e.at,
			}); err != nil {
				return err
			}
		}
		return tx.PutExpansion(ctx, store.ExpansionRecord{
			WorkspaceID: "ws-test", ExpansionID: expansionID, PassID: passID,
			MissionRef: "mission-1", Status: store.ExpansionApproved,
			DeltaJSON: `{"scope":"tests"}`, ExpansionDigest: "sha256:" + strings.Repeat("1", 64),
			CreatedAt: now.Add(-30 * time.Minute), UpdatedAt: now.Add(-30 * time.Minute),
		})
	}); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	// Mark the expansion intent completed with its decision reference.
	ctx = context.Background()
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.PutExpansionIntent(ctx, store.ExpansionIntentRecord{
			WorkspaceID: "ws-test", ExpansionID: expansionID, PassID: passID,
			IdempotencyKey: "idem-" + expansionID, Decision: "approve",
			CanonicalDigest: "sha256:" + strings.Repeat("2", 64),
			State:           store.ExpansionIntentInFlight, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		return tx.CompleteExpansionIntent(ctx, "ws-test", expansionID, expansionID, 4)
	}); err != nil {
		t.Fatalf("seed expansion intent: %v", err)
	}
}

func (f *serviceFixture) signedReceipt(t *testing.T) *coreapi.SignedReceiptEnvelope {
	t.Helper()
	env := signEnvelope(t, f.signer, validPayload(f.signer.id, f.now))
	return &env
}

func (f *serviceFixture) passState(t *testing.T, passID string) string {
	t.Helper()
	rec, err := f.store.GetMissionPass(context.Background(), "ws-test", passID)
	if err != nil {
		t.Fatalf("get pass: %v", err)
	}
	return rec.State
}

func TestServiceVerifyReceiptHappyPath(t *testing.T) {
	f := newServiceFixture(t)
	f.auth.receipt = f.signedReceipt(t)

	view, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if view == nil || view.Verification != store.ReceiptVerified {
		t.Fatalf("view = %+v, want verified", view)
	}
	if got := f.passState(t, "pass-1"); got != string(missionpass.PassCompleted) {
		t.Errorf("pass state = %q, want completed", got)
	}
	if f.auth.receiptCalls != 1 {
		t.Errorf("upstream receipt calls = %d, want 1", f.auth.receiptCalls)
	}

	// A second verification is a no-op: the pass is already terminal.
	view2, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("second VerifyReceipt: %v", err)
	}
	if view2.ReceiptDigest != view.ReceiptDigest {
		t.Errorf("second view digest changed")
	}
}

func TestServiceVerifyReceiptMissingUpstream(t *testing.T) {
	f := newServiceFixture(t)
	f.auth.receiptErr = &coreapi.UpstreamError{StatusCode: http.StatusNotFound}

	view, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if view != nil {
		t.Fatalf("view = %+v, want nil while the receipt is absent", view)
	}
	if got := f.passState(t, "pass-1"); got != string(missionpass.PassOutcomePending) {
		t.Errorf("pass state = %q, want outcome_pending", got)
	}
}

func TestServiceVerifyReceiptInvalidLeavesPending(t *testing.T) {
	f := newServiceFixture(t)
	env := f.signedReceipt(t)
	env.Signature = "bogus"
	f.auth.receipt = env

	_, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1")
	if !errors.Is(err, receipt.ErrReceiptUnverifiable) {
		t.Fatalf("err = %v, want ErrReceiptUnverifiable", err)
	}
	if got := f.passState(t, "pass-1"); got != string(missionpass.PassOutcomePending) {
		t.Errorf("pass state = %q, want outcome_pending", got)
	}

	// The unverifiable verdict latches: the worker must not hammer
	// upstream on every poll.
	if _, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1"); !errors.Is(err, receipt.ErrReceiptUnverifiable) {
		t.Fatalf("second err = %v, want ErrReceiptUnverifiable", err)
	}
	if f.auth.receiptCalls != 1 {
		t.Errorf("receipt calls = %d, want 1 (latched)", f.auth.receiptCalls)
	}
}

func TestServiceVerifyReceiptOutcomeMismatch(t *testing.T) {
	f := newServiceFixture(t)
	p := validPayload(f.signer.id, f.now)
	p.Outcome = receipt.OutcomeFailure
	env := signEnvelope(t, f.signer, p)
	f.auth.receipt = &env

	// The receipt must match the locally projected outcome: the seeded
	// pass projected a successful run, so a failure receipt is
	// unverifiable and the pass stays pending.
	if _, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1"); !errors.Is(err, receipt.ErrReceiptUnverifiable) {
		t.Fatalf("err = %v, want ErrReceiptUnverifiable on outcome mismatch", err)
	}
	if got := f.passState(t, "pass-1"); got != string(missionpass.PassOutcomePending) {
		t.Errorf("pass state = %q, want outcome_pending", got)
	}
}

func TestServicePublishVerifiedCheck(t *testing.T) {
	f := newServiceFixture(t)
	f.auth.receipt = f.signedReceipt(t)
	if _, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("verify: %v", err)
	}

	if err := f.service.PublishVerifiedCheck(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if f.auth.publishCalls != 1 {
		t.Fatalf("publish calls = %d, want 1", f.auth.publishCalls)
	}
	req := f.auth.published[0]
	if req.BindingID != "binding-1" {
		t.Errorf("binding_id = %q, want binding-1", req.BindingID)
	}
	if req.Status != coreapi.CheckStatusCompleted || req.Conclusion != coreapi.CheckConclusionSuccess {
		t.Errorf("status/conclusion = %q/%q", req.Status, req.Conclusion)
	}
	for _, c := range canaries {
		raw, _ := json.Marshal(req)
		if strings.Contains(string(raw), c) {
			t.Errorf("published check leaks canary %q", c)
		}
	}

	// A second publish is a no-op: the intent is already settled.
	if err := f.service.PublishVerifiedCheck(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if f.auth.publishCalls != 1 {
		t.Errorf("publish calls = %d, want 1 (settled)", f.auth.publishCalls)
	}
}

func TestServicePublishBeforeVerifyRefused(t *testing.T) {
	f := newServiceFixture(t)
	if err := f.service.PublishVerifiedCheck(context.Background(), "ws-test", "pass-1"); err == nil {
		t.Fatal("publish before verification accepted")
	}
	if f.auth.publishCalls != 0 {
		t.Errorf("publish calls = %d, want 0", f.auth.publishCalls)
	}
}

func TestServicePublishTimeoutThenRetry(t *testing.T) {
	f := newServiceFixture(t)
	f.auth.receipt = f.signedReceipt(t)
	if _, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	f.auth.publishErr = errTimeout

	if err := f.service.PublishVerifiedCheck(context.Background(), "ws-test", "pass-1"); err == nil {
		t.Fatal("expected timeout error")
	}
	st := f.publicationState(t, "pass-1")
	if st != "in_flight" {
		t.Fatalf("publication state = %q, want in_flight", st)
	}

	// Retry uses the same idempotency key; the fake upstream dedupes and
	// the intent settles without a duplicate check run.
	f.auth.publishErr = nil
	f.auth.reconcileStatus = "in_progress"
	if err := f.service.ReconcilePublication(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if f.auth.publishCalls != 2 {
		t.Errorf("publish calls = %d, want 2 (retry with the same key)", f.auth.publishCalls)
	}
	if st := f.publicationState(t, "pass-1"); st != "settled" {
		t.Errorf("publication state = %q, want settled", st)
	}
	if len(f.auth.checks) != 1 {
		t.Errorf("upstream check runs = %d, want 1", len(f.auth.checks))
	}
}

func TestServiceReconcilePublicationDispute(t *testing.T) {
	f := newServiceFixture(t)
	f.auth.receipt = f.signedReceipt(t)
	if _, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The first publish attempt fails transiently, leaving the intent
	// in flight. Upstream then reports the operation as terminally
	// failed: the reconciler disputes the intent instead of retrying
	// forever. The dispute is recorded, not an error.
	f.auth.publishErr = errTimeout
	if err := f.service.PublishVerifiedCheck(context.Background(), "ws-test", "pass-1"); err == nil {
		t.Fatal("expected timeout error")
	}
	if st := f.publicationState(t, "pass-1"); st != "in_flight" {
		t.Fatalf("publication state = %q, want in_flight", st)
	}
	f.auth.publishErr = nil
	f.auth.reconcileStatus = "failed"
	if err := f.service.ReconcilePublication(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if st := f.publicationState(t, "pass-1"); st != "disputed" {
		t.Errorf("publication state = %q, want disputed", st)
	}
}

func TestServiceRefreshesRotatedKeys(t *testing.T) {
	f := newServiceFixture(t)
	// A successor key rotated from the pinned root signs the receipt.
	// The verifier does not know it yet, so verification triggers a
	// key-history refresh that must chain to the pinned root.
	succ := newTestSigner(t, "receipt-key-2")
	p := validPayload(succ.id, f.now)
	env := signEnvelope(t, succ, p)
	f.auth.receipt = &env
	f.auth.history = coreapi.SigningKeyHistory{
		ServedAt: f.now.Unix(),
		Keys: []coreapi.SigningKeyRecord{
			{
				KeyID:     f.signer.id,
				PublicKey: base64.RawURLEncoding.EncodeToString(f.signer.pub),
				ValidFrom: f.now.Add(-2 * time.Hour).Unix(),
			},
			{
				KeyID:       succ.id,
				PublicKey:   base64.RawURLEncoding.EncodeToString(succ.pub),
				ValidFrom:   f.now.Add(-time.Hour).Unix(),
				RotatedFrom: f.signer.id,
			},
		},
	}

	view, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("VerifyReceipt after rotation: %v", err)
	}
	if view.KeyID != succ.id {
		t.Errorf("key id = %q, want %q", view.KeyID, succ.id)
	}
	if got := f.passState(t, "pass-1"); got != string(missionpass.PassCompleted) {
		t.Errorf("pass state = %q, want completed", got)
	}
}

func TestServiceRefreshRejectsBadChain(t *testing.T) {
	f := newServiceFixture(t)
	evil := newTestSigner(t, "evil-key")
	p := validPayload(evil.id, f.now)
	env := signEnvelope(t, evil, p)
	f.auth.receipt = &env
	// The served history claims a rotation, but it does not chain to
	// the pinned root.
	f.auth.history = coreapi.SigningKeyHistory{
		ServedAt: f.now.Unix(),
		Keys: []coreapi.SigningKeyRecord{
			{
				KeyID:       evil.id,
				PublicKey:   base64.RawURLEncoding.EncodeToString(evil.pub),
				ValidFrom:   f.now.Add(-time.Hour).Unix(),
				RotatedFrom: "unknown-previous",
			},
		},
	}
	if _, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1"); !errors.Is(err, receipt.ErrReceiptUnverifiable) {
		t.Fatalf("err = %v, want ErrReceiptUnverifiable", err)
	}
	if got := f.passState(t, "pass-1"); got != string(missionpass.PassOutcomePending) {
		t.Errorf("pass state = %q, want outcome_pending", got)
	}
}

func TestServiceGetPending(t *testing.T) {
	f := newServiceFixture(t)
	st, err := f.service.Get(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if st.Verification != store.ReceiptStatePending {
		t.Errorf("verification = %q, want pending", st.Verification)
	}
}

func TestServiceGetVerified(t *testing.T) {
	f := newServiceFixture(t)
	f.auth.receipt = f.signedReceipt(t)
	if _, err := f.service.VerifyReceipt(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	st, err := f.service.Get(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if st.Verification != store.ReceiptVerified {
		t.Errorf("verification = %q, want verified", st.Verification)
	}
	if st.View == nil || st.View.Outcome != receipt.OutcomeSuccess {
		t.Errorf("view = %+v", st.View)
	}
	if st.Publication != nil {
		t.Errorf("publication = %+v, want nil before the worker publishes", st.Publication)
	}
	if err := f.service.PublishVerifiedCheck(context.Background(), "ws-test", "pass-1"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	st, err = f.service.Get(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("Get after publish: %v", err)
	}
	if st.Publication == nil || st.Publication.State != "settled" {
		t.Errorf("publication = %+v, want settled", st.Publication)
	}
	// The authenticated view carries no raw envelope and no secrets.
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, c := range canaries {
		if strings.Contains(string(raw), c) {
			t.Errorf("receipt view leaks canary %q", c)
		}
	}
}

func TestServiceGetUnknownPass(t *testing.T) {
	f := newServiceFixture(t)
	if _, err := f.service.Get(context.Background(), "ws-test", "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func (f *serviceFixture) publicationState(t *testing.T, passID string) string {
	t.Helper()
	st, err := f.service.Get(context.Background(), "ws-test", passID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if st.Publication == nil {
		t.Fatal("no publication status")
	}
	return st.Publication.State
}

var errTimeout = errors.New("receipt: upstream timeout")

// TestServiceConcurrentVerifyAndRefresh drives VerifyReceipt for
// several passes from multiple goroutines while every verification
// hits the unknown-key path and refreshes the key history. It exists
// for the race detector: the key store, the verifier, and the phased
// store transactions must be safe under concurrent use.
func TestServiceConcurrentVerifyAndRefresh(t *testing.T) {
	f := newServiceFixture(t)
	passes := []struct{ passID, runID, expansionID string }{
		{"pass-1", "run-1", "exp-1"},
		{"pass-2", "run-2", "exp-2"},
		{"pass-3", "run-3", "exp-3"},
		{"pass-4", "run-4", "exp-4"},
	}
	// pass-1 is seeded by the fixture with run-1/exp-1.
	for _, p := range passes[1:] {
		f.seedPassFull(t, p.passID, p.runID, p.expansionID)
	}
	succ := newTestSigner(t, "receipt-key-2")
	f.auth.receipts = map[string]*coreapi.SignedReceiptEnvelope{}
	for _, p := range passes {
		pl := basePayload(succ, f.now)
		pl.GrantID = p.runID
		pl.MissionVersions = []int64{3, 4}
		pl.ExpansionDecisionRefs = []string{p.expansionID}
		env := signEnvelope(t, succ, pl)
		f.auth.receipts[p.runID] = &env
	}
	f.auth.history = coreapi.SigningKeyHistory{
		ServedAt: f.now.Unix(),
		Keys: []coreapi.SigningKeyRecord{
			{
				KeyID:     f.signer.id,
				PublicKey: base64.RawURLEncoding.EncodeToString(f.signer.pub),
				ValidFrom: f.now.Add(-2 * time.Hour).Unix(),
			},
			{
				KeyID:       succ.id,
				PublicKey:   base64.RawURLEncoding.EncodeToString(succ.pub),
				ValidFrom:   f.now.Add(-time.Hour).Unix(),
				RotatedFrom: f.signer.id,
			},
		},
	}

	errs := make([]error, len(passes))
	var wg sync.WaitGroup
	for i, p := range passes {
		wg.Add(1)
		go func(i int, passID string) {
			defer wg.Done()
			_, errs[i] = f.service.VerifyReceipt(context.Background(), "ws-test", passID)
		}(i, p.passID)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("pass %s: %v", passes[i].passID, err)
		}
	}
	for _, p := range passes {
		if got := f.passState(t, p.passID); got != string(missionpass.PassCompleted) {
			t.Errorf("pass %s state = %q, want completed", p.passID, got)
		}
	}
}
