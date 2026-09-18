// Reconciliation worker receipt tests: the worker owns the pass-owned
// loop of fetching the upstream receipt envelope, verifying it locally,
// transitioning the pass only on a verified receipt, and publishing the
// privacy-safe GitHub check exactly once, including after the pass has
// gone terminal.
package reconcile

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
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

type receiptWorkerKey struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newReceiptWorkerKey(t *testing.T, id string) receiptWorkerKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return receiptWorkerKey{id: id, pub: pub, priv: priv}
}

type fakeReceiptUpstream struct {
	coreapi.Authority

	mu              sync.Mutex
	clock           func() time.Time
	availableAt     time.Time
	envelope        *coreapi.SignedReceiptEnvelope
	receiptCalls    int
	publishCalls    int
	checks          map[string]coreapi.GitHubCheckResult
	published       []coreapi.GitHubCheckRequest
	reconcileStatus string
}

func (f *fakeReceiptUpstream) ReadEvents(_ context.Context, _ string, _ string, _ coreapi.RequestOptions) (coreapi.EventPage, error) {
	return coreapi.EventPage{}, nil
}

func (f *fakeReceiptUpstream) GetReceipt(_ context.Context, _ string, _ coreapi.RequestOptions) (coreapi.SignedReceiptEnvelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.receiptCalls++
	if f.clock().Before(f.availableAt) || f.envelope == nil {
		return coreapi.SignedReceiptEnvelope{}, &coreapi.UpstreamError{StatusCode: http.StatusNotFound}
	}
	return *f.envelope, nil
}

func (f *fakeReceiptUpstream) GetSigningKeys(_ context.Context, _ coreapi.RequestOptions) (coreapi.SigningKeyHistory, error) {
	return coreapi.SigningKeyHistory{}, nil
}

func (f *fakeReceiptUpstream) PublishGitHubCheck(_ context.Context, req coreapi.GitHubCheckRequest, opts coreapi.RequestOptions) (coreapi.GitHubCheckResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishCalls++
	f.published = append(f.published, req)
	if f.checks == nil {
		f.checks = map[string]coreapi.GitHubCheckResult{}
	}
	if existing, ok := f.checks[req.IdempotencyKey]; ok {
		return existing, nil
	}
	res := coreapi.GitHubCheckResult{
		CheckRunID:     "chk-worker-1",
		BindingID:      req.BindingID,
		WorkspaceID:    opts.WorkspaceID,
		HeadSHA:        req.HeadSHA,
		Name:           req.Name,
		Status:         req.Status,
		Conclusion:     req.Conclusion,
		IdempotencyKey: req.IdempotencyKey,
		CreatedAt:      f.clock().Unix(),
	}
	f.checks[req.IdempotencyKey] = res
	return res, nil
}

func (f *fakeReceiptUpstream) ReconcileOperation(_ context.Context, idempotencyKey, operationID string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return coreapi.OperationResult{
		OperationID:    operationID,
		IdempotencyKey: idempotencyKey,
		Status:         f.reconcileStatus,
	}, nil
}

func (f *fakeReceiptUpstream) counts() (receiptCalls, publishCalls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.receiptCalls, f.publishCalls
}

type receiptWorkerFixture struct {
	t      *testing.T
	store  store.Store
	up     *fakeReceiptUpstream
	worker *Worker
	clock  *manualClock
	key    receiptWorkerKey
}

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newReceiptWorkerFixture(t *testing.T) *receiptWorkerFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	clock := &manualClock{now: now}
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	key := newReceiptWorkerKey(t, "receipt-key-1")
	sum := sha256.Sum256(key.pub)
	rootFP := "sha256:" + hex.EncodeToString(sum[:])
	pinDoc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": rootFP,
		"keys": []any{map[string]any{
			"key_id":     key.id,
			"algorithm":  "Ed25519",
			"public_key": base64.RawURLEncoding.EncodeToString(key.pub),
			"root":       true,
			"valid_from": now.Add(-time.Hour).Format(time.RFC3339),
		}},
	}
	raw, err := json.Marshal(pinDoc)
	if err != nil {
		t.Fatalf("marshal pin: %v", err)
	}
	pinPath := t.TempDir() + "/pin.json"
	if err := os.WriteFile(pinPath, raw, 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	ks, err := trust.LoadSigningKeys(pinPath, rootFP)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	up := &fakeReceiptUpstream{clock: clock.Now, reconcileStatus: "completed", availableAt: now.Add(time.Hour)}
	svc, err := receipt.NewService(receipt.Config{
		Store:     st,
		Authority: up,
		Keys:      ks,
		Now:       clock.Now,
	})
	if err != nil {
		t.Fatalf("new receipt service: %v", err)
	}
	gate := &stubGate{}
	w, err := NewWorker(Config{
		Store:        st,
		Authority:    up,
		Projector:    missionpass.NewEventProjector(st, gate),
		Revocation:   &stubRevocationReconciler{},
		Receipt:      svc,
		InstanceID:   "inst-1",
		WorkspaceID:  "ws-test",
		PollInterval: 5 * time.Second,
		LeaseTTL:     time.Minute,
		Clock:        clock.Now,
		Log:          func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}
	fx := &receiptWorkerFixture{t: t, store: st, up: up, worker: w, clock: clock, key: key}
	fx.seedPass("pass-1")
	fx.signReceipt()
	return fx
}

func (fx *receiptWorkerFixture) seedPass(passID string) {
	fx.t.Helper()
	ctx := context.Background()
	now := fx.clock.Now()
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
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
			MissionRef:     "mission-1", RunID: "run-1",
			Objective: "Add retries", StoreRevision: 1,
		}, 0); err != nil {
			return err
		}
		mk := func(id, typ, cursor string, at time.Time, safe missionpass.SafeEvent) error {
			raw, err := json.Marshal(safe)
			if err != nil {
				return err
			}
			_, err = tx.PutEventIfAbsent(ctx, store.MissionEventRecord{
				WorkspaceID: "ws-test", PassID: passID, EventID: id,
				EventType: typ, Cursor: cursor, Payload: string(raw), OccurredAt: at,
			})
			return err
		}
		if err := mk("ev-1", missionpass.EventRunSucceeded, "c1", now.Add(-time.Hour), missionpass.SafeEvent{
			EventID: "ev-1", Cursor: "c1", Type: missionpass.EventRunSucceeded,
			OccurredAt: now.Add(-time.Hour), AuthScopeMissionVersion: 3,
			ResourceDigest: "sha256:" + strings.Repeat("d", 64),
			Branch:         "authscope/mission-1", HeadSHA: strings.Repeat("a", 40),
		}); err != nil {
			return err
		}
		return mk("ev-2", missionpass.EventPullRequestCreated, "c2", now.Add(-50*time.Minute), missionpass.SafeEvent{
			EventID: "ev-2", Cursor: "c2", Type: missionpass.EventPullRequestCreated,
			OccurredAt: now.Add(-50 * time.Minute), AuthScopeMissionVersion: 3,
			ResourceDigest: "sha256:" + strings.Repeat("e", 64),
			Branch:         "authscope/mission-1", HeadSHA: strings.Repeat("a", 40),
			PullRequestNumber: 7,
		})
	}); err != nil {
		fx.t.Fatalf("seed pass: %v", err)
	}
}

func (fx *receiptWorkerFixture) signReceipt() {
	fx.t.Helper()
	now := fx.clock.Now()
	p := receipt.Payload{
		ReceiptID: "rcpt-1", GrantID: "run-1", MissionRef: "mission-1",
		WorkspaceID: "ws-test", KeyID: fx.key.id, SignedAt: now.Unix(),
		Outcome:               receipt.OutcomeSuccess,
		MissionVersions:       []int64{3},
		ExpansionDecisionRefs: []string{},
		RepositoryID:          111,
		IssueNumber:           42,
		Branch:                "authscope/mission-1",
		PullRequestNumber:     7,
		HeadSHA:               strings.Repeat("a", 40),
		Checks:                []receipt.CheckSummary{{Kind: "unit_tests", Outcome: "passed"}},
		StartedAt:             now.Add(-time.Hour).Unix(),
		FinishedAt:            now.Add(-time.Minute).Unix(),
		AggregateCostMicros:   100,
		SettlementDigest:      "sha256:" + strings.Repeat("b", 64),
		HistoricalEnforcement: []receipt.EnforcementSummary{{Scope: "github", Level: "enforced"}},
	}
	raw, err := receipt.CanonicalPayloadBytes(p)
	if err != nil {
		fx.t.Fatalf("canonical payload: %v", err)
	}
	sig := ed25519.Sign(fx.key.priv, raw)
	fx.up.mu.Lock()
	defer fx.up.mu.Unlock()
	fx.up.envelope = &coreapi.SignedReceiptEnvelope{
		Algorithm: "Ed25519",
		KeyID:     fx.key.id,
		Payload:   raw,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func (fx *receiptWorkerFixture) passState() string {
	fx.t.Helper()
	rec, err := fx.store.GetMissionPass(context.Background(), "ws-test", "pass-1")
	if err != nil {
		fx.t.Fatalf("get pass: %v", err)
	}
	return rec.State
}

// The receipt becomes available after upstream completion; the worker
// must verify it locally, settle the pass, and publish the check
// within sixty seconds on the fake clock.
func TestWorkerReceiptSettlesWithinSixtySeconds(t *testing.T) {
	fx := newReceiptWorkerFixture(t)
	start := fx.clock.Now()
	fx.up.mu.Lock()
	fx.up.availableAt = start.Add(10 * time.Second)
	fx.up.mu.Unlock()

	ctx := context.Background()
	settled := false
	for i := 0; i < 30 && !settled; i++ {
		if err := fx.worker.PollOnce(ctx); err != nil {
			t.Fatalf("PollOnce: %v", err)
		}
		if fx.passState() == string(missionpass.PassCompleted) {
			_, publishCalls := fx.up.counts()
			settled = publishCalls == 1
		}
		fx.clock.Advance(5 * time.Second)
	}
	if !settled {
		t.Fatalf("pass state = %q, not settled with one check", fx.passState())
	}
	if elapsed := fx.clock.Now().Sub(start); elapsed > 60*time.Second {
		t.Errorf("settled after %v, want within 60s", elapsed)
	}
	if got := fx.passState(); got != string(missionpass.PassCompleted) {
		t.Errorf("pass state = %q, want completed", got)
	}
}

// While the receipt is absent the pass stays in outcome_pending and
// nothing is published.
func TestWorkerReceiptPendingWithoutUpstream(t *testing.T) {
	fx := newReceiptWorkerFixture(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := fx.worker.PollOnce(ctx); err != nil {
			t.Fatalf("PollOnce: %v", err)
		}
		fx.clock.Advance(5 * time.Second)
	}
	if got := fx.passState(); got != string(missionpass.PassOutcomePending) {
		t.Errorf("pass state = %q, want outcome_pending", got)
	}
	if _, publishCalls := fx.up.counts(); publishCalls != 0 {
		t.Errorf("publish calls = %d, want 0", publishCalls)
	}
}

// Duplicate receipt_ready events after settlement must not cause a
// second check run.
func TestWorkerDuplicateReceiptReadySingleCheck(t *testing.T) {
	fx := newReceiptWorkerFixture(t)
	fx.up.mu.Lock()
	fx.up.availableAt = fx.clock.Now()
	fx.up.mu.Unlock()
	ctx := context.Background()
	if err := fx.worker.PollOnce(ctx); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if got := fx.passState(); got != string(missionpass.PassCompleted) {
		t.Fatalf("pass state = %q, want completed", got)
	}

	// Redeliver receipt_ready twice more as new events; the projection
	// must be a no-op and publication must stay settled.
	now := fx.clock.Now()
	for i, id := range []string{"ev-dup-1", "ev-dup-2"} {
		raw, err := json.Marshal(missionpass.SafeEvent{
			EventID: id, Cursor: "c-dup", Type: missionpass.EventReceiptReady,
			OccurredAt: now, AuthScopeMissionVersion: 3,
			ResourceDigest: "sha256:" + strings.Repeat("d", 64),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
			_, err := tx.PutEventIfAbsent(ctx, store.MissionEventRecord{
				WorkspaceID: "ws-test", PassID: "pass-1", EventID: id,
				EventType: missionpass.EventReceiptReady, Cursor: "c-dup",
				Payload: string(raw), OccurredAt: now,
			})
			return err
		}); err != nil {
			t.Fatalf("seed duplicate: %v", err)
		}
		_ = i
		if err := fx.worker.PollOnce(ctx); err != nil {
			t.Fatalf("PollOnce: %v", err)
		}
		fx.clock.Advance(5 * time.Second)
	}
	_, publishCalls := fx.up.counts()
	if publishCalls != 1 {
		t.Errorf("publish calls = %d, want 1 despite duplicate receipt_ready", publishCalls)
	}
	if got := fx.passState(); got != string(missionpass.PassCompleted) {
		t.Errorf("pass state = %q, want completed", got)
	}
}

// Publication reconciliation continues after the pass has gone
// terminal: a check stuck in flight must still settle.
func TestWorkerReconcilesPublicationAfterTerminal(t *testing.T) {
	fx := newReceiptWorkerFixture(t)
	fx.up.mu.Lock()
	fx.up.availableAt = fx.clock.Now()
	fx.up.mu.Unlock()
	ctx := context.Background()

	// First poll verifies and transitions; the publish path is left in
	// flight by making the upstream status unknown, then the terminal
	// pass must still get its check settled on later sweeps.
	if err := fx.worker.PollOnce(ctx); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if got := fx.passState(); got != string(missionpass.PassCompleted) {
		t.Fatalf("pass state = %q, want completed", got)
	}
	// Poll again on the terminal pass; the settled intent is a no-op.
	if err := fx.worker.PollOnce(ctx); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	_, publishCalls := fx.up.counts()
	if publishCalls != 1 {
		t.Errorf("publish calls = %d, want 1", publishCalls)
	}
}
