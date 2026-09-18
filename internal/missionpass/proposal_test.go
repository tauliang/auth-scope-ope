package missionpass

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/github"
	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeMissionAuthority records the upstream call sequence so tests assert
// the exact order: trusted source refresh, workflow-posture refresh,
// ShapeMission, CreateProposal, then persistence. Every fixture value is
// recognizably fake.
type fakeMissionAuthority struct {
	coreapi.Authority
	mu       sync.Mutex
	calls    []string
	binding  coreapi.RepositoryBinding
	issue    coreapi.GitHubIssueSnapshot
	posture  coreapi.WorkflowPosture
	shaped   coreapi.MissionDraft
	shapeErr error
	// shapeEchoRequest makes the fake return the shaped draft with the
	// request's budget and TTL, like AuthScope shaping inside the
	// requested limits. Tests that need a widened shaped result disable
	// it and set the widened values on the fixture directly.
	shapeEchoRequest bool
	proposal         coreapi.Proposal
	proposalErr      error
	failProposalOnce error
	reconcile        coreapi.OperationResult
	reconcileErr     error
	shapeKeys        []string
	proposalKeys     []string
	proposalCalls    int
	reconcileCalls   int
	// gateProposal, when non-nil, blocks the fake's CreateProposal until
	// the channel is closed. Tests use it to force overlapping attempts.
	gateProposal chan struct{}
}

func (f *fakeMissionAuthority) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeMissionAuthority) orderedCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

func (f *fakeMissionAuthority) GetRepositoryBinding(_ context.Context, _ string, _ coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	f.record("GetRepositoryBinding")
	return f.binding, nil
}

func (f *fakeMissionAuthority) ReadGitHubIssue(_ context.Context, _ coreapi.GitHubIssueRequest, _ coreapi.RequestOptions) (coreapi.GitHubIssueSnapshot, error) {
	f.record("ReadGitHubIssue")
	return f.issue, nil
}

func (f *fakeMissionAuthority) InspectWorkflowPosture(_ context.Context, _ coreapi.WorkflowPostureRequest, _ coreapi.RequestOptions) (coreapi.WorkflowPosture, error) {
	f.record("InspectWorkflowPosture")
	return f.posture, nil
}

func (f *fakeMissionAuthority) ShapeMission(_ context.Context, in coreapi.ShapeMissionRequest, opts coreapi.RequestOptions) (coreapi.MissionDraft, error) {
	f.record("ShapeMission")
	f.mu.Lock()
	f.shapeKeys = append(f.shapeKeys, opts.IdempotencyKey)
	echo := f.shapeEchoRequest
	shaped := f.shaped
	f.mu.Unlock()
	if echo {
		shaped.BudgetMicros = in.BudgetMicros
		shaped.TTLSeconds = in.TTLSeconds
	}
	return shaped, f.shapeErr
}

func (f *fakeMissionAuthority) CreateProposal(_ context.Context, _ coreapi.CreateProposalRequest, opts coreapi.RequestOptions) (coreapi.Proposal, error) {
	f.record("CreateProposal")
	if f.gateProposal != nil {
		<-f.gateProposal
	}
	f.mu.Lock()
	f.proposalCalls++
	f.proposalKeys = append(f.proposalKeys, opts.IdempotencyKey)
	err := f.proposalErr
	if f.failProposalOnce != nil {
		err = f.failProposalOnce
		f.failProposalOnce = nil
	}
	f.mu.Unlock()
	if err != nil {
		return coreapi.Proposal{}, err
	}
	return f.proposal, nil
}

func (f *fakeMissionAuthority) ReconcileOperation(_ context.Context, key, _ string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	f.record("ReconcileOperation")
	f.mu.Lock()
	f.reconcileCalls++
	f.mu.Unlock()
	if f.reconcileErr != nil {
		return coreapi.OperationResult{}, f.reconcileErr
	}
	out := f.reconcile
	out.IdempotencyKey = key
	return out, nil
}

var fixtureClock = time.Date(2026, time.September, 17, 22, 0, 0, 0, time.UTC)

func openProposalStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	conn := store.ConnectionRecord{
		WorkspaceID:          "ws-test",
		ConnectionID:         "conn-1",
		RepositoryBindingRef: "binding-1",
		InstallationID:       222,
		RepositoryID:         111,
		RepositoryName:       "octo-org/host",
		PermissionStatus:     "ok",
		VerifiedAt:           fixtureClock,
		CreatedAt:            fixtureClock,
	}
	if err := st.WithTx(context.Background(), func(tx store.Tx) error {
		return tx.PutConnection(context.Background(), conn)
	}); err != nil {
		t.Fatalf("put connection: %v", err)
	}
	return st
}

func newProposalFixture(t *testing.T) (*Service, *fakeMissionAuthority, store.Store) {
	t.Helper()
	st := openProposalStore(t)
	fake := &fakeMissionAuthority{
		binding: coreapi.RepositoryBinding{
			BindingID: "binding-1", WorkspaceID: "ws-test",
			InstallationID: "222", RepositoryID: "111", Repository: "octo-org/host",
		},
		issue: coreapi.GitHubIssueSnapshot{
			WorkspaceID: "ws-test", BindingID: "binding-1", IssueNumber: 42,
			Title: "Add retries", Body: "- [ ] retry with backoff", State: "open",
			BaseRef: "main", BaseSHA: strings.Repeat("a", 40),
			SourceRevision: "rev-1", CanonicalDigest: "sha256:" + strings.Repeat("b", 64),
			SnapshotAt: fixtureClock.Unix(),
		},
		posture: coreapi.WorkflowPosture{
			BindingID: "binding-1", Ref: "main", WorkflowsInspected: 2, Posture: "clean",
		},
		shaped: coreapi.MissionDraft{
			ProposalDigest:   "sha256:" + strings.Repeat("c", 64),
			InvocationDigest: "sha256:" + strings.Repeat("d", 64),
			AgentKitID:       FixedAgentKitID,
			AgentKitVersion:  FixedAgentKitVersion,
			RunnerArguments:  []string{"authscope-agent-run", "--mission", "pass-1"},
			DecisionDigest:   "sha256:" + strings.Repeat("e", 64),
			BudgetMicros:     10_000_000,
			TTLSeconds:       3600,
			CanonicalDraft:   []byte(`{"objective":"Add retries"}`),
			ShapedAt:         fixtureClock.Unix(),
			WorkspaceID:      "ws-test",
		},
		proposal: coreapi.Proposal{
			ProposalID:       "prop-1",
			ProposalDigest:   "sha256:" + strings.Repeat("f", 64),
			InvocationDigest: "sha256:" + strings.Repeat("d", 64),
			AgentKitID:       FixedAgentKitID,
			AgentKitVersion:  FixedAgentKitVersion,
			RunnerArguments:  []string{"authscope-agent-run", "--mission", "pass-1"},
			Status:           "draft",
			WorkspaceID:      "ws-test",
			DecisionDigest:   "sha256:" + strings.Repeat("e", 64),
			CreatedAt:        fixtureClock.Unix(),
		},
	}
	fake.shapeEchoRequest = true
	src, err := github.NewSource(github.SourceConfig{
		Store:     st,
		Authority: fake,
		Clock:     func() time.Time { return fixtureClock },
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	svc, err := NewService(Config{
		Store:           st,
		Authority:       fake,
		Source:          src,
		Clock:           func() time.Time { return fixtureClock },
		UpstreamTimeout: 5 * time.Second,
		NewPassID:       func() (string, error) { return "pass-1", nil },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, fake, st
}

func createInput() CreateProposalInput {
	return CreateProposalInput{
		ConnectionID:           "conn-1",
		IssueNumber:            42,
		ExpiresAt:              fixtureClock.Add(time.Hour),
		MaxAggregateCostMicros: 10_000_000,
	}
}

// requireCallOrder asserts the exact upstream call order: trusted source
// refresh, workflow-posture refresh, ShapeMission, then CreateProposal.
func requireCallOrder(t *testing.T, fake *fakeMissionAuthority) {
	t.Helper()
	want := []string{
		"GetRepositoryBinding", "ReadGitHubIssue",
		"GetRepositoryBinding", "InspectWorkflowPosture",
		"ShapeMission", "CreateProposal",
	}
	var got []string
	for _, c := range fake.orderedCalls() {
		switch c {
		case "GetRepositoryBinding", "ReadGitHubIssue", "InspectWorkflowPosture", "ShapeMission", "CreateProposal", "ReconcileOperation":
			got = append(got, c)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("upstream calls = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("upstream calls = %v, want %v", got, want)
		}
	}
}

func TestCreateProposalCallOrder(t *testing.T) {
	svc, fake, _ := newProposalFixture(t)
	if _, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput()); err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	requireCallOrder(t, fake)
}

func TestCreateProposalPersistsExactUpstreamValues(t *testing.T) {
	svc, fake, st := newProposalFixture(t)
	rec, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	// The record stores AuthScope's returned values byte-for-byte: proposal
	// ID, proposal digest, fixed agent-kit ID/version, the exact runner
	// argument array, and the invocation digest. OPE never computes a
	// substitute authority digest.
	if rec.ProposalID != "prop-1" {
		t.Errorf("ProposalID = %q, want prop-1", rec.ProposalID)
	}
	if rec.ProposalDigest != "sha256:"+strings.Repeat("f", 64) {
		t.Errorf("ProposalDigest = %q, want the exact upstream digest", rec.ProposalDigest)
	}
	if rec.AgentKitID != FixedAgentKitID || rec.AgentKitVersion != FixedAgentKitVersion {
		t.Errorf("kit = %q %q, want the fixed template kit", rec.AgentKitID, rec.AgentKitVersion)
	}
	wantArgs := []string{"authscope-agent-run", "--mission", "pass-1"}
	if len(rec.RunnerArguments) != len(wantArgs) {
		t.Fatalf("RunnerArguments = %v, want %v", rec.RunnerArguments, wantArgs)
	}
	for i := range wantArgs {
		if rec.RunnerArguments[i] != wantArgs[i] {
			t.Fatalf("RunnerArguments = %v, want %v", rec.RunnerArguments, wantArgs)
		}
	}
	if rec.InvocationDigest != "sha256:"+strings.Repeat("d", 64) {
		t.Errorf("InvocationDigest = %q, want the exact upstream digest", rec.InvocationDigest)
	}
	if rec.ApprovedProposalDigest != "" {
		t.Errorf("ApprovedProposalDigest = %q, want empty until Task 7", rec.ApprovedProposalDigest)
	}
	if rec.DraftVersion != 1 {
		t.Errorf("DraftVersion = %d, want 1", rec.DraftVersion)
	}
	if rec.AuthScopeMissionVersion != 0 {
		t.Errorf("AuthScopeMissionVersion = %d, want 0 before approval", rec.AuthScopeMissionVersion)
	}
	if rec.StoreRevision != 1 {
		t.Errorf("StoreRevision = %d, want 1", rec.StoreRevision)
	}
	if rec.State != PassDraft {
		t.Errorf("State = %q, want draft", rec.State)
	}
	if rec.Reconciliation != ReconciliationSettled {
		t.Errorf("Reconciliation = %q, want settled", rec.Reconciliation)
	}
	if rec.SourceRevision != "rev-1" || rec.SourceDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Errorf("source = %q %q, want the pinned snapshot values", rec.SourceRevision, rec.SourceDigest)
	}
	if rec.BaseSHA != strings.Repeat("a", 40) {
		t.Errorf("BaseSHA = %q", rec.BaseSHA)
	}
	if rec.MissionBranch != "authscope/pass-1-42" {
		t.Errorf("MissionBranch = %q, want authscope/pass-1-42", rec.MissionBranch)
	}
	if !rec.Limits.ExpiresAt.Equal(fixtureClock.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v", rec.Limits.ExpiresAt)
	}
	if rec.Limits.MaxAggregateCostMicros != 10_000_000 {
		t.Errorf("MaxAggregateCostMicros = %d", rec.Limits.MaxAggregateCostMicros)
	}
	// The idempotency key is workspace-qualified and stable per pass.
	if len(fake.proposalKeys) != 1 || !strings.Contains(fake.proposalKeys[0], "ws-test") || !strings.Contains(fake.proposalKeys[0], "pass-1") {
		t.Errorf("proposal idempotency keys = %v, want one workspace-qualified key", fake.proposalKeys)
	}
	// The persisted store row round-trips the same record.
	stored, err := st.GetMissionPass(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if stored.ProposalID != "prop-1" || stored.ProposalDigest != rec.ProposalDigest || stored.InvocationDigest != rec.InvocationDigest {
		t.Errorf("stored proposal = %+v, want the exact upstream values", stored)
	}
}

func TestCreateProposalRejectsUpstreamMutations(t *testing.T) {
	cases := map[string]func(*coreapi.Proposal){
		"kit id":      func(p *coreapi.Proposal) { p.AgentKitID = "other-kit" },
		"kit version": func(p *coreapi.Proposal) { p.AgentKitVersion = "9.9.9" },
		"runner args reordered": func(p *coreapi.Proposal) {
			p.RunnerArguments = []string{"--mission", "authscope-agent-run", "pass-1"}
		},
		"runner args changed": func(p *coreapi.Proposal) {
			p.RunnerArguments = []string{"authscope-agent-run", "--mission", "pass-2"}
		},
		"invocation digest swapped": func(p *coreapi.Proposal) {
			p.InvocationDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"proposal digest untagged": func(p *coreapi.Proposal) {
			p.ProposalDigest = strings.Repeat("f", 64)
		},
		"empty proposal id": func(p *coreapi.Proposal) { p.ProposalID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			svc, fake, st := newProposalFixture(t)
			mutate(&fake.proposal)
			_, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
			if err == nil {
				t.Fatal("CreateProposal = nil, want fail-closed error")
			}
			if _, gerr := st.GetMissionPass(context.Background(), "ws-test", "pass-1"); !errors.Is(gerr, store.ErrNotFound) {
				t.Errorf("GetMissionPass = %v, want not found: nothing may persist", gerr)
			}
		})
	}
}

func TestCreateProposalRejectsWidenedShape(t *testing.T) {
	for name, mutate := range map[string]func(*coreapi.MissionDraft){
		"budget widened": func(d *coreapi.MissionDraft) { d.BudgetMicros = 30_000_000 },
		"ttl widened":    func(d *coreapi.MissionDraft) { d.TTLSeconds = 10800 },
		"kit swapped":    func(d *coreapi.MissionDraft) { d.AgentKitID = "other-kit" },
	} {
		t.Run(name, func(t *testing.T) {
			svc, fake, st := newProposalFixture(t)
			fake.shapeEchoRequest = false
			mutate(&fake.shaped)
			if _, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput()); err == nil {
				t.Fatal("CreateProposal = nil, want template violation")
			}
			if _, gerr := st.GetMissionPass(context.Background(), "ws-test", "pass-1"); !errors.Is(gerr, store.ErrNotFound) {
				t.Errorf("GetMissionPass = %v, want not found", gerr)
			}
		})
	}
}

func TestCreateProposalFailsClosedOnSourceProblems(t *testing.T) {
	t.Run("risky posture", func(t *testing.T) {
		svc, fake, _ := newProposalFixture(t)
		fake.posture.Posture = "risky"
		fake.posture.Findings = []coreapi.WorkflowFinding{{Path: ".github/workflows/x.yml", Risk: coreapi.WorkflowRiskSecretAccess}}
		_, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
		if !errors.Is(err, ErrUnsafePosture) {
			t.Errorf("CreateProposal = %v, want ErrUnsafePosture", err)
		}
	})
	t.Run("malformed base SHA", func(t *testing.T) {
		svc, fake, _ := newProposalFixture(t)
		fake.issue.BaseSHA = "not-a-sha"
		_, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
		if err == nil {
			t.Error("CreateProposal = nil, want snapshot validation error")
		}
	})
	t.Run("closed issue", func(t *testing.T) {
		svc, fake, _ := newProposalFixture(t)
		fake.issue.State = "closed"
		_, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
		if err == nil {
			t.Error("CreateProposal = nil, want issue-unavailable error")
		}
	})
}

func TestCreateProposalTimeoutPersistsIntentAndReconciles(t *testing.T) {
	svc, fake, st := newProposalFixture(t)
	fake.proposalErr = context.DeadlineExceeded
	fake.reconcile = coreapi.OperationResult{OperationID: "op-1", Status: "in_flight", WorkspaceID: "ws-test"}
	_, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
	if !errors.Is(err, ErrOperationInFlight) {
		t.Fatalf("CreateProposal = %v, want ErrOperationInFlight", err)
	}
	// Exactly one proposal mutation was attempted; the outcome was
	// reconciled by the same idempotency key, never re-mutated.
	if fake.proposalCalls != 1 {
		t.Errorf("CreateProposal calls = %d, want 1", fake.proposalCalls)
	}
	if fake.reconcileCalls != 1 {
		t.Fatalf("ReconcileOperation calls = %d, want 1", fake.reconcileCalls)
	}
	// The persisted intent is reconciliation-pending with no proposal yet.
	stored, err := st.GetMissionPass(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if stored.Reconciliation != string(ReconciliationPending) {
		t.Errorf("Reconciliation = %q, want pending", stored.Reconciliation)
	}
	if stored.ProposalID != "" || stored.ProposalDigest != "" {
		t.Errorf("intent carries proposal values: %+v", stored)
	}
}

func TestCreateProposalTimeoutReconcileCompletedReplaysSameKey(t *testing.T) {
	svc, fake, st := newProposalFixture(t)
	// The first mutation attempt times out; reconcile reports completed, so
	// the service replays the same mutation with the same idempotency key
	// rather than issuing another proposal mutation.
	fake.failProposalOnce = context.DeadlineExceeded
	fake.reconcile = coreapi.OperationResult{OperationID: "op-1", Status: "completed", WorkspaceID: "ws-test"}
	rec, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	if fake.proposalCalls != 2 {
		t.Errorf("CreateProposal calls = %d, want 2 (one timed-out attempt plus one same-key replay)", fake.proposalCalls)
	}
	if len(fake.proposalKeys) != 2 || fake.proposalKeys[0] != fake.proposalKeys[1] {
		t.Errorf("proposal keys = %v, want the same idempotency key twice", fake.proposalKeys)
	}
	if rec.ProposalID != "prop-1" || rec.Reconciliation != ReconciliationSettled {
		t.Errorf("record = %+v, want the settled replayed proposal", rec)
	}
	stored, err := st.GetMissionPass(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if stored.ProposalID != "prop-1" || stored.Reconciliation != string(ReconciliationSettled) {
		t.Errorf("stored = %+v", stored)
	}
}

func TestCreateProposalValidatesInput(t *testing.T) {
	svc, _, _ := newProposalFixture(t)
	bad := createInput()
	bad.ExpiresAt = fixtureClock.Add(3 * time.Hour)
	if _, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", bad); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expiry past template max: err = %v, want ErrInvalidInput", err)
	}
	bad = createInput()
	bad.MaxAggregateCostMicros = 30_000_000
	if _, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", bad); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("budget past template max: err = %v, want ErrInvalidInput", err)
	}
	bad = createInput()
	bad.ExpiresAt = fixtureClock.Add(-time.Hour)
	if _, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", bad); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expiry in the past: err = %v, want ErrInvalidInput", err)
	}
	bad = createInput()
	bad.ConnectionID = "missing"
	if _, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", bad); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing connection: err = %v, want store.ErrNotFound", err)
	}
}

func TestReviseProposal(t *testing.T) {
	svc, fake, st := newProposalFixture(t)
	created, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	// Only an earlier expiry and a lower aggregate-cost ceiling are
	// accepted. The revision reruns shaping and creates a new upstream
	// proposal with DraftVersion + 1; AuthScopeMissionVersion stays 0.
	fake.proposal.ProposalID = "prop-2"
	fake.proposal.ProposalDigest = "sha256:" + strings.Repeat("9", 64)
	revised, err := svc.ReviseProposal(context.Background(), "ws-test", "founder-1", ReviseProposalInput{
		PassID:                 "pass-1",
		ExpectedStoreRevision:  created.StoreRevision,
		ExpectedDraftVersion:   created.DraftVersion,
		ExpiresAt:              fixtureClock.Add(30 * time.Minute),
		MaxAggregateCostMicros: 5_000_000,
	})
	if err != nil {
		t.Fatalf("ReviseProposal: %v", err)
	}
	if revised.DraftVersion != 2 {
		t.Errorf("DraftVersion = %d, want 2", revised.DraftVersion)
	}
	if revised.StoreRevision != 2 {
		t.Errorf("StoreRevision = %d, want 2", revised.StoreRevision)
	}
	if revised.AuthScopeMissionVersion != 0 {
		t.Errorf("AuthScopeMissionVersion = %d, want 0", revised.AuthScopeMissionVersion)
	}
	if revised.ProposalID != "prop-2" {
		t.Errorf("ProposalID = %q, want the new upstream proposal", revised.ProposalID)
	}
	if revised.ApprovedProposalDigest != "" {
		t.Errorf("ApprovedProposalDigest = %q, want empty", revised.ApprovedProposalDigest)
	}
	if revised.State != PassDraft {
		t.Errorf("State = %q, want draft", revised.State)
	}
	if revised.Limits.MaxAggregateCostMicros != 5_000_000 {
		t.Errorf("budget = %d", revised.Limits.MaxAggregateCostMicros)
	}
	// The revision used a fresh idempotency key: a new upstream proposal.
	if len(fake.proposalKeys) != 2 || fake.proposalKeys[0] == fake.proposalKeys[1] {
		t.Errorf("proposal keys = %v, want two distinct keys", fake.proposalKeys)
	}
	stored, err := st.GetMissionPass(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if stored.DraftVersion != 2 || stored.ProposalID != "prop-2" {
		t.Errorf("stored = %+v", stored)
	}
}

func TestReviseProposalRejectsWidening(t *testing.T) {
	setup := func(t *testing.T) (*Service, ProposalRecord) {
		t.Helper()
		svc, _, _ := newProposalFixture(t)
		rec, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
		if err != nil {
			t.Fatalf("CreateProposal: %v", err)
		}
		return svc, rec
	}
	revise := func(rec ProposalRecord, expiry time.Time, budget int64) ReviseProposalInput {
		return ReviseProposalInput{
			PassID: rec.PassID, ExpectedStoreRevision: rec.StoreRevision,
			ExpectedDraftVersion: rec.DraftVersion, ExpiresAt: expiry,
			MaxAggregateCostMicros: budget,
		}
	}
	t.Run("later expiry", func(t *testing.T) {
		svc, rec := setup(t)
		_, err := svc.ReviseProposal(context.Background(), "ws-test", "founder-1",
			revise(rec, fixtureClock.Add(90*time.Minute), 5_000_000))
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	})
	t.Run("higher budget", func(t *testing.T) {
		svc, rec := setup(t)
		_, err := svc.ReviseProposal(context.Background(), "ws-test", "founder-1",
			revise(rec, fixtureClock.Add(30*time.Minute), 15_000_000))
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	})
	t.Run("no-op", func(t *testing.T) {
		svc, rec := setup(t)
		_, err := svc.ReviseProposal(context.Background(), "ws-test", "founder-1",
			revise(rec, fixtureClock.Add(time.Hour), 10_000_000))
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	})
	t.Run("past template max", func(t *testing.T) {
		svc, rec := setup(t)
		_, err := svc.ReviseProposal(context.Background(), "ws-test", "founder-1",
			revise(rec, fixtureClock.Add(3*time.Hour), 5_000_000))
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v, want ErrInvalidInput", err)
		}
	})
}

func TestReviseProposalCASConflict(t *testing.T) {
	svc, _, _ := newProposalFixture(t)
	rec, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	_, err = svc.ReviseProposal(context.Background(), "ws-test", "founder-1", ReviseProposalInput{
		PassID: rec.PassID, ExpectedStoreRevision: rec.StoreRevision + 1,
		ExpectedDraftVersion: rec.DraftVersion,
		ExpiresAt:            fixtureClock.Add(30 * time.Minute), MaxAggregateCostMicros: 5_000_000,
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("err = %v, want store.ErrConflict", err)
	}
	_, err = svc.ReviseProposal(context.Background(), "ws-test", "founder-1", ReviseProposalInput{
		PassID: rec.PassID, ExpectedStoreRevision: rec.StoreRevision,
		ExpectedDraftVersion: rec.DraftVersion + 1,
		ExpiresAt:            fixtureClock.Add(30 * time.Minute), MaxAggregateCostMicros: 5_000_000,
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("err = %v, want store.ErrConflict", err)
	}
}

func TestReviseProposalRejectsStaleSource(t *testing.T) {
	svc, fake, _ := newProposalFixture(t)
	rec, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	// The issue moved under the pinned source revision: fail closed.
	fake.issue.SourceRevision = "rev-2"
	_, err = svc.ReviseProposal(context.Background(), "ws-test", "founder-1", ReviseProposalInput{
		PassID: rec.PassID, ExpectedStoreRevision: rec.StoreRevision,
		ExpectedDraftVersion: rec.DraftVersion,
		ExpiresAt:            fixtureClock.Add(30 * time.Minute), MaxAggregateCostMicros: 5_000_000,
	})
	if !errors.Is(err, ErrStaleSource) {
		t.Errorf("err = %v, want ErrStaleSource", err)
	}
}

func TestReviseProposalRequiresDraftState(t *testing.T) {
	svc, _, st := newProposalFixture(t)
	rec, _, err := svc.CreateProposal(context.Background(), "ws-test", "founder-1", createInput())
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	// Simulate approval having moved the pass out of draft.
	stored, err := st.GetMissionPass(context.Background(), "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	stored.State = string(PassApproved)
	if err := st.WithTx(context.Background(), func(tx store.Tx) error {
		return tx.PutMissionPass(context.Background(), stored, stored.StoreRevision)
	}); err != nil {
		t.Fatalf("move to approved: %v", err)
	}
	_, err = svc.ReviseProposal(context.Background(), "ws-test", "founder-1", ReviseProposalInput{
		PassID: rec.PassID, ExpectedStoreRevision: rec.StoreRevision + 1,
		ExpectedDraftVersion: rec.DraftVersion,
		ExpiresAt:            fixtureClock.Add(30 * time.Minute), MaxAggregateCostMicros: 5_000_000,
	})
	if !errors.Is(err, ErrNotDraft) {
		t.Errorf("err = %v, want ErrNotDraft", err)
	}
}

func TestReviseProposalUnknownPass(t *testing.T) {
	svc, _, _ := newProposalFixture(t)
	_, err := svc.ReviseProposal(context.Background(), "ws-test", "founder-1", ReviseProposalInput{
		PassID: "missing", ExpectedStoreRevision: 1, ExpectedDraftVersion: 1,
		ExpiresAt: fixtureClock.Add(30 * time.Minute), MaxAggregateCostMicros: 5_000_000,
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want store.ErrNotFound", err)
	}
}

// TestCreateProposalIdempotentRetryResolvesSamePass verifies that a
// retried draft-open with the same idempotency key returns the existing
// pass without issuing any further upstream calls.
func TestCreateProposalIdempotentRetryResolvesSamePass(t *testing.T) {
	svc, fake, _ := newProposalFixture(t)
	ctx := context.Background()
	in := createInput()
	in.IdempotencyKey = "req-1"

	first, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
	if err != nil {
		t.Fatalf("first CreateProposal: %v", err)
	}
	if replayed {
		t.Fatal("first CreateProposal reported replayed")
	}
	callsAfterFirst := len(fake.orderedCalls())
	proposalsAfterFirst := fake.proposalCalls

	second, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
	if err != nil {
		t.Fatalf("second CreateProposal: %v", err)
	}
	if !replayed {
		t.Fatal("second CreateProposal did not report replayed")
	}
	if second.PassID != first.PassID {
		t.Errorf("replay pass = %q, want %q", second.PassID, first.PassID)
	}
	if second.ProposalID != first.ProposalID || second.StoreRevision != first.StoreRevision {
		t.Errorf("replay record = %+v, want %+v", second, first)
	}
	if got := len(fake.orderedCalls()); got != callsAfterFirst {
		t.Errorf("upstream calls after replay = %d, want %d (no new calls)", got, callsAfterFirst)
	}
	if fake.proposalCalls != proposalsAfterFirst {
		t.Errorf("proposal calls after replay = %d, want %d", fake.proposalCalls, proposalsAfterFirst)
	}
}

// TestCreateProposalIdempotentRetryAfterPending returns the pending pass
// instead of opening a duplicate when the first attempt's outcome stayed
// ambiguous.
func TestCreateProposalIdempotentRetryAfterPending(t *testing.T) {
	svc, fake, _ := newProposalFixture(t)
	ctx := context.Background()
	fake.failProposalOnce = context.DeadlineExceeded
	fake.reconcile = coreapi.OperationResult{Status: "unknown"}
	in := createInput()
	in.IdempotencyKey = "req-pending"

	pending, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
	if !errors.Is(err, ErrOperationInFlight) {
		t.Fatalf("first err = %v, want ErrOperationInFlight", err)
	}
	if replayed {
		t.Fatal("first CreateProposal reported replayed")
	}
	if pending.PassID == "" || pending.Reconciliation != ReconciliationPending {
		t.Fatalf("pending record = %+v", pending)
	}

	again, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
	if err != nil {
		t.Fatalf("retry err = %v", err)
	}
	if !replayed {
		t.Fatal("retry did not report replayed")
	}
	if again.PassID != pending.PassID || again.Reconciliation != ReconciliationPending {
		t.Errorf("retry record = %+v, want the pending pass", again)
	}
}

// TestCreateProposalConcurrentSameKeyIssuesOneUpstreamMutation forces two
// draft-open attempts with the same idempotency key to overlap: the
// rival arrives while the owner is blocked inside the upstream proposal
// mutation. The rival must not open a duplicate draft; exactly one
// upstream mutation may happen.
func TestCreateProposalConcurrentSameKeyIssuesOneUpstreamMutation(t *testing.T) {
	svc, fake, st := newProposalFixture(t)
	oldWait := awaitPassRowTimeout
	awaitPassRowTimeout = 100 * time.Millisecond
	t.Cleanup(func() { awaitPassRowTimeout = oldWait })

	gate := make(chan struct{})
	fake.gateProposal = gate
	ctx := context.Background()
	in := createInput()
	in.IdempotencyKey = "req-race"

	type outcome struct {
		rec      ProposalRecord
		replayed bool
		err      error
	}
	ownerDone := make(chan outcome, 1)
	go func() {
		rec, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
		ownerDone <- outcome{rec, replayed, err}
	}()

	// Wait until the owner is blocked inside the upstream mutation.
	deadline := time.Now().Add(5 * time.Second)
	for {
		inside := false
		for _, c := range fake.orderedCalls() {
			if c == "CreateProposal" {
				inside = true
				break
			}
		}
		if inside {
			break
		}
		if time.Now().After(deadline) {
			close(gate)
			t.Fatal("owner never reached the upstream proposal mutation")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The rival arrives with the same key while the owner's pass row is
	// not visible yet. It must fail closed instead of opening a second
	// draft.
	if _, _, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in); !errors.Is(err, ErrDuplicateRequestInFlight) {
		close(gate)
		t.Fatalf("rival err = %v, want ErrDuplicateRequestInFlight", err)
	}

	close(gate)
	owner := <-ownerDone
	if owner.err != nil {
		t.Fatalf("owner err = %v", owner.err)
	}
	if owner.replayed {
		t.Fatal("owner reported replayed")
	}
	if fake.proposalCalls != 1 {
		t.Fatalf("upstream proposal mutations = %d, want exactly 1", fake.proposalCalls)
	}
	if got, err := st.GetMissionPassIDByRequestKey(ctx, "ws-test", "req-race"); err != nil || got != owner.rec.PassID {
		t.Fatalf("key owner = %q, %v; want %q", got, err, owner.rec.PassID)
	}
	// A later retry with the same key replays the owner's pass without
	// another upstream call.
	again, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
	if err != nil {
		t.Fatalf("retry err = %v", err)
	}
	if !replayed || again.PassID != owner.rec.PassID {
		t.Fatalf("retry = %+v replayed=%v, want replay of %q", again, replayed, owner.rec.PassID)
	}
	if fake.proposalCalls != 1 {
		t.Fatalf("upstream proposal mutations after replay = %d, want 1", fake.proposalCalls)
	}
}

// TestCreateProposalInFlightKeyFailsClosed covers the race the old code
// got wrong: a mapping exists but the owner's pass row is not visible
// yet. The second attempt must wait for the owner and then fail closed,
// never delete the mapping and open a duplicate draft.
func TestCreateProposalInFlightKeyFailsClosed(t *testing.T) {
	svc, _, st := newProposalFixture(t)
	oldWait := awaitPassRowTimeout
	awaitPassRowTimeout = 50 * time.Millisecond
	t.Cleanup(func() { awaitPassRowTimeout = oldWait })

	ctx := context.Background()
	// Simulate an owner that claimed the key but has not persisted yet.
	if _, err := st.ClaimMissionPassRequestKey(ctx, "ws-test", "key-inflight", "pass-ghost"); err != nil {
		t.Fatalf("claim key: %v", err)
	}
	in := createInput()
	in.IdempotencyKey = "key-inflight"
	if _, _, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in); !errors.Is(err, ErrDuplicateRequestInFlight) {
		t.Fatalf("err = %v, want ErrDuplicateRequestInFlight", err)
	}
	// The mapping still belongs to the in-flight owner; no draft was
	// opened for anyone else.
	if got, err := st.GetMissionPassIDByRequestKey(ctx, "ws-test", "key-inflight"); err != nil || got != "pass-ghost" {
		t.Fatalf("key owner after fail-closed = %q, %v; want pass-ghost", got, err)
	}
	if _, err := st.GetMissionPass(ctx, "ws-test", "pass-ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ghost pass row err = %v, want not found", err)
	}
}

// TestCreateProposalReclaimsDanglingKey shows the one defensible rule for
// treating a mapping as dangling: the claim is older than the legitimate
// claim-to-persist window and its pass row never appeared, so the owner
// died without releasing it. The retry reclaims the key and proceeds.
func TestCreateProposalReclaimsDanglingKey(t *testing.T) {
	svc, fake, st := newProposalFixture(t)
	oldDangling := requestKeyDanglingAfter
	requestKeyDanglingAfter = 0
	t.Cleanup(func() { requestKeyDanglingAfter = oldDangling })
	oldWait := awaitPassRowTimeout
	awaitPassRowTimeout = 50 * time.Millisecond
	t.Cleanup(func() { awaitPassRowTimeout = oldWait })

	ctx := context.Background()
	if _, err := st.ClaimMissionPassRequestKey(ctx, "ws-test", "key-dangling", "pass-ghost"); err != nil {
		t.Fatalf("claim key: %v", err)
	}
	in := createInput()
	in.IdempotencyKey = "key-dangling"
	rec, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
	if err != nil {
		t.Fatalf("reclaim err = %v", err)
	}
	if replayed {
		t.Fatal("reclaim reported replayed")
	}
	if rec.PassID == "" || rec.PassID == "pass-ghost" {
		t.Fatalf("reclaimed pass = %q, want a fresh pass", rec.PassID)
	}
	if got, err := st.GetMissionPassIDByRequestKey(ctx, "ws-test", "key-dangling"); err != nil || got != rec.PassID {
		t.Fatalf("key owner after reclaim = %q, %v; want %q", got, err, rec.PassID)
	}
	if fake.proposalCalls != 1 {
		t.Fatalf("upstream proposal mutations = %d, want 1", fake.proposalCalls)
	}
}

// TestCreateProposalFailureReleasesKey verifies that an attempt which
// fails before persisting releases its idempotency key, so a corrected
// retry with the same key can claim again instead of failing closed
// forever.
func TestCreateProposalFailureReleasesKey(t *testing.T) {
	svc, fake, st := newProposalFixture(t)
	ctx := context.Background()
	fake.shapeErr = errors.New("shaping exploded")
	in := createInput()
	in.IdempotencyKey = "key-fail"

	if _, _, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in); err == nil {
		t.Fatal("want shaping error, got nil")
	}
	if got, err := st.GetMissionPassIDByRequestKey(ctx, "ws-test", "key-fail"); err != nil || got != "" {
		t.Fatalf("key mapping after failure = %q, %v; want released", got, err)
	}

	fake.shapeErr = nil
	rec, replayed, err := svc.CreateProposal(ctx, "ws-test", "founder-1", in)
	if err != nil {
		t.Fatalf("retry err = %v", err)
	}
	if replayed {
		t.Fatal("retry reported replayed")
	}
	if rec.PassID == "" {
		t.Fatal("retry opened no pass")
	}
	if got, err := st.GetMissionPassIDByRequestKey(ctx, "ws-test", "key-fail"); err != nil || got != rec.PassID {
		t.Fatalf("key owner after retry = %q, %v; want %q", got, err, rec.PassID)
	}
}
