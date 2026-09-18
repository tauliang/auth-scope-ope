// Reconciliation worker tests: leased polling projects authoritative
// events into the safe timeline, reconciles ambiguous revocation
// intents by their original keys, suspends incompatible passes, and
// backs off failing passes.

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeWorkerAuthority serves canned event pages and records calls. It
// implements only the worker's narrow upstream surface; the rest of the
// Authority interface is an embedded nil.
type fakeWorkerAuthority struct {
	coreapi.Authority

	mu         sync.Mutex
	pages      map[string]coreapi.EventPage // mission ref -> page
	readErr    error
	readCalls  int
	readRefs   []string
	reconciled []string
}

func (f *fakeWorkerAuthority) ReadEvents(_ context.Context, missionRef, _ string, _ coreapi.RequestOptions) (coreapi.EventPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readCalls++
	f.readRefs = append(f.readRefs, missionRef)
	if f.readErr != nil {
		return coreapi.EventPage{}, f.readErr
	}
	if p, ok := f.pages[missionRef]; ok {
		return p, nil
	}
	return coreapi.EventPage{}, nil
}

func (f *fakeWorkerAuthority) readCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.readCalls
}

// stubRevocationReconciler records reconciliation calls.
type stubRevocationReconciler struct {
	mu    sync.Mutex
	calls [][2]string
	err   error
}

func (s *stubRevocationReconciler) ReconcileRevocation(_ context.Context, workspaceID, passID string) (*missionpass.RevocationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, [2]string{workspaceID, passID})
	if s.err != nil {
		return nil, s.err
	}
	return &missionpass.RevocationResult{PassID: passID, Revoked: true}, nil
}

func (s *stubRevocationReconciler) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// stubGate latches projection incompatibility like the real gate.
type stubGate struct {
	mu      sync.Mutex
	latched bool
}

func (s *stubGate) NoteProjectionIncompatible(_ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.latched = true
}

func (s *stubGate) isLatched() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latched
}

type workerFixture struct {
	t      *testing.T
	store  store.Store
	fake   *fakeWorkerAuthority
	gate   *stubGate
	recon  *stubRevocationReconciler
	worker *Worker
}

func newWorkerFixture(t *testing.T) *workerFixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	fake := &fakeWorkerAuthority{pages: map[string]coreapi.EventPage{}}
	gate := &stubGate{}
	recon := &stubRevocationReconciler{}
	w, err := NewWorker(Config{
		Store:        st,
		Authority:    fake,
		Projector:    missionpass.NewEventProjector(st, gate),
		Revocation:   recon,
		InstanceID:   "inst-1",
		WorkspaceID:  "ws-test",
		PollInterval: time.Hour,
		LeaseTTL:     time.Minute,
		Log:          func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}
	_ = ctx
	return &workerFixture{t: t, store: st, fake: fake, gate: gate, recon: recon, worker: w}
}

func (fx *workerFixture) seedPass(passID, state, missionRef string) {
	fx.t.Helper()
	ctx := context.Background()
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID:             "ws-test",
			PassID:                  passID,
			State:                   state,
			AuthScopeMissionVersion: 3,
			MissionRef:              missionRef,
			Reconciliation:          string(missionpass.ReconciliationSettled),
			CreatedAt:               time.Now().UTC(),
		}, 0)
	}); err != nil {
		fx.t.Fatalf("seed pass: %v", err)
	}
}

func eventPayload(fields map[string]any) json.RawMessage {
	raw, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	return raw
}

func basePayload() map[string]any {
	return map[string]any{
		"workspace_id":    "ws-test",
		"mission_version": 3,
		"resource_digest": "abc123",
	}
}

func TestWorkerProjectsEvents(t *testing.T) {
	fx := newWorkerFixture(t)
	fx.seedPass("pass-1", string(missionpass.PassRunning), "mission-1")
	now := time.Now().UTC().Truncate(time.Millisecond)
	pl := basePayload()
	pl["branch"] = "authscope/pass-1-42"
	pl["head_sha"] = strings.Repeat("a", 40)
	runPayload := basePayload()
	runPayload["branch"] = "authscope/pass-1-42"
	runPayload["head_sha"] = strings.Repeat("a", 40)
	fx.fake.pages["mission-1"] = coreapi.EventPage{
		Events: []coreapi.MissionEvent{
			{EventID: "ev-1", EventType: missionpass.EventMissionStarted, OccurredAt: now.Add(-time.Minute).UnixMilli(), Payload: eventPayload(pl)},
			{EventID: "ev-2", EventType: missionpass.EventRunSucceeded, OccurredAt: now.UnixMilli(), Payload: eventPayload(runPayload)},
		},
		NextCursor: "cursor-2",
	}
	fx.worker.poll(context.Background())

	events, err := fx.store.ListMissionEvents(context.Background(), "ws-test", "pass-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	proj, err := fx.store.GetMissionProjection(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionProjection: %v", err)
	}
	if proj.Cursor != "cursor-2" {
		t.Errorf("cursor = %q, want cursor-2", proj.Cursor)
	}
	rec, err := fx.store.GetMissionPass(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if rec.State != string(missionpass.PassOutcomePending) {
		t.Errorf("pass state = %q, want outcome_pending after run_succeeded", rec.State)
	}
}

func TestWorkerSkipsTerminalAndPassesWithoutMission(t *testing.T) {
	fx := newWorkerFixture(t)
	fx.seedPass("pass-done", string(missionpass.PassCompleted), "mission-1")
	fx.seedPass("pass-nomission", string(missionpass.PassRunning), "")
	fx.seedPass("pass-draft", string(missionpass.PassDraft), "mission-2")
	fx.worker.poll(context.Background())
	if n := fx.fake.readCallCount(); n != 0 {
		t.Errorf("ReadEvents calls = %d, want 0 (terminal, missionless, and draft passes are skipped)", n)
	}
}

func TestWorkerReconcilesRevocationIntents(t *testing.T) {
	fx := newWorkerFixture(t)
	fx.seedPass("pass-1", string(missionpass.PassRunning), "mission-1")
	ctx := context.Background()
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutRevocationIntent(ctx, store.RevocationIntentRecord{
			WorkspaceID:     "ws-test",
			PassID:          "pass-1",
			IdempotencyKey:  "revoke:ws-test:pass-1",
			ReasonCode:      missionpass.RevocationReasonFounderRequested,
			CanonicalDigest: "abc",
			State:           store.RevocationIntentInFlight,
		})
	}); err != nil {
		t.Fatalf("seed intent: %v", err)
	}
	fx.worker.poll(ctx)
	if n := fx.recon.callCount(); n != 1 {
		t.Fatalf("ReconcileRevocation calls = %d, want 1", n)
	}
	fx.recon.mu.Lock()
	got := fx.recon.calls[0]
	fx.recon.mu.Unlock()
	if got[0] != "ws-test" || got[1] != "pass-1" {
		t.Errorf("reconciled = %v, want [ws-test pass-1]", got)
	}
}

func TestWorkerSuspendsIncompatiblePass(t *testing.T) {
	fx := newWorkerFixture(t)
	fx.seedPass("pass-1", string(missionpass.PassRunning), "mission-1")
	fx.seedPass("pass-2", string(missionpass.PassRunning), "mission-2")
	now := time.Now().UTC().Truncate(time.Millisecond)
	fx.fake.pages["mission-1"] = coreapi.EventPage{
		Events: []coreapi.MissionEvent{
			{EventID: "ev-x", EventType: "future_unknown_type", OccurredAt: now.UnixMilli(), Payload: eventPayload(basePayload())},
		},
		NextCursor: "cursor-x",
	}
	fx.fake.pages["mission-2"] = coreapi.EventPage{
		Events: []coreapi.MissionEvent{
			{EventID: "ev-1", EventType: missionpass.EventMissionStarted, OccurredAt: now.UnixMilli(), Payload: eventPayload(func() map[string]any {
				p := basePayload()
				p["branch"] = "authscope/pass-2-7"
				p["head_sha"] = strings.Repeat("b", 40)
				return p
			}())},
		},
		NextCursor: "cursor-1",
	}
	fx.worker.poll(context.Background())
	if !fx.gate.isLatched() {
		t.Errorf("projection gate not latched after unknown event type")
	}
	// The incompatible pass is suspended but the healthy pass keeps
	// projecting.
	events, err := fx.store.ListMissionEvents(context.Background(), "ws-test", "pass-2", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("healthy pass events = %d, want 1", len(events))
	}
	before := fx.fake.readCallCount()
	fx.worker.poll(context.Background())
	// Only the healthy pass is re-polled; the incompatible pass is
	// skipped without another upstream read.
	if got := fx.fake.readCallCount() - before; got != 1 {
		t.Errorf("second poll ReadEvents calls = %d, want 1 (incompatible pass suspended)", got)
	}
}

func TestWorkerBacksOffFailingPass(t *testing.T) {
	fx := newWorkerFixture(t)
	fx.seedPass("pass-1", string(missionpass.PassRunning), "mission-1")
	fx.fake.readErr = errors.New("upstream down")
	fx.worker.poll(context.Background())
	if n := fx.fake.readCallCount(); n != 1 {
		t.Fatalf("ReadEvents calls = %d, want 1", n)
	}
	// The failing pass is in backoff: the next poll skips it.
	fx.worker.poll(context.Background())
	if n := fx.fake.readCallCount(); n != 1 {
		t.Errorf("ReadEvents calls after backoff = %d, want 1 (no retry yet)", n)
	}
}

func TestWorkerLeaseLifecycle(t *testing.T) {
	fx := newWorkerFixture(t)
	ctx := context.Background()
	if err := fx.worker.acquireLease(ctx); err != nil {
		t.Fatalf("acquireLease: %v", err)
	}
	// A second worker for the same instance cannot take the lease while
	// it is held.
	other, err := NewWorker(Config{
		Store: fx.store, Authority: fx.fake,
		Projector:   missionpass.NewEventProjector(fx.store, fx.gate),
		Revocation:  fx.recon,
		InstanceID:  "inst-1",
		WorkspaceID: "ws-test",
		Log:         func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}
	other.pollInterval = 10 * time.Millisecond
	ctx2, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := other.acquireLease(ctx2); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second acquireLease = %v, want context deadline (lease held)", err)
	}
	if !fx.worker.heartbeat(ctx) {
		t.Errorf("heartbeat failed while holding the lease")
	}
	fx.worker.releaseLease()
	if err := other.acquireLease(ctx); err != nil {
		t.Errorf("acquireLease after release: %v", err)
	}
	other.releaseLease()
}

func TestWorkerRunShutsDownGracefully(t *testing.T) {
	fx := newWorkerFixture(t)
	fx.seedPass("pass-1", string(missionpass.PassRunning), "mission-1")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fx.worker.Run(ctx) }()
	// Let it acquire the lease and run one sweep.
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Run did not return after cancel")
	}
	// The lease is released: another worker can acquire it immediately.
	other, err := NewWorker(Config{
		Store: fx.store, Authority: fx.fake,
		Projector:   missionpass.NewEventProjector(fx.store, fx.gate),
		Revocation:  fx.recon,
		InstanceID:  "inst-1",
		WorkspaceID: "ws-test",
		Log:         func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}
	if err := other.acquireLease(context.Background()); err != nil {
		t.Errorf("acquireLease after graceful shutdown: %v", err)
	}
	other.releaseLease()
}
