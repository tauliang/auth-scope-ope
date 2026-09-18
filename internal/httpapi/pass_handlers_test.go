package httpapi

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

// testInvocationDigest is the pinned invocation digest for the pass
// fixture's kit and ordered arguments. The CLI launch handoff recomputes
// this digest and rejects any mismatch, so the fixture uses the same
// canonicalization.
func testInvocationDigest() string {
	return authn.InvocationDigestForLaunch("authscope-agent-kit", "1.0.0", []string{"authscope-agent-run", "--mission"})
}

// stubPassAuthority extends the GitHub stub with the mission-proposal
// broker surface. ShapeMission echoes the requested budget and TTL the
// way AuthScope shapes inside the requested limits.
type stubPassAuthority struct {
	*stubGitHubAuthority
	shaped          coreapi.MissionDraft
	proposal        coreapi.Proposal
	createErr       error
	reconcileStatus string
	// Approval stub fields (methods in approval_handlers_test.go).
	mission            coreapi.Mission
	approveErr         error
	failApproveOnce    error
	approveCalls       int
	approveKeys        []string
	prepareLaunchCalls int
	missionsCreated    int
	approvedByKey      map[string]coreapi.Mission
	signedAttestations []identity.SignedDecisionAttestation
	identityRoles      map[string][]string
	identityKeys       map[string]ed25519.PublicKey
	seenNonces         map[string]bool
	expectedSubject    string
	// Revocation stub fields (methods in revoke_handlers_test.go).
	revokeCalls    int
	revokeKeys     []string
	revokedByKey   map[string]coreapi.Revocation
	failRevokeOnce error
}

func (s *stubPassAuthority) ShapeMission(_ context.Context, in coreapi.ShapeMissionRequest, _ coreapi.RequestOptions) (coreapi.MissionDraft, error) {
	shaped := s.shaped
	shaped.BudgetMicros = in.BudgetMicros
	shaped.TTLSeconds = in.TTLSeconds
	return shaped, nil
}

func (s *stubPassAuthority) CreateProposal(_ context.Context, _ coreapi.CreateProposalRequest, opts coreapi.RequestOptions) (coreapi.Proposal, error) {
	if s.createErr != nil {
		return coreapi.Proposal{}, s.createErr
	}
	return s.proposal, nil
}

func (s *stubPassAuthority) ReconcileOperation(_ context.Context, _ string, key string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	return coreapi.OperationResult{OperationID: "op-1", IdempotencyKey: key, Status: s.reconcileStatus}, nil
}

type passFixture struct {
	*authTestFixture
	stub *stubPassAuthority
	csrf string
	deps Dependencies
}

func newPassFixture(t *testing.T) *passFixture {
	t.Helper()
	f := newAuthTestFixture(t)
	f.config.AuthScopeURL = "https://authscope.local"
	invocation := testInvocationDigest()
	gh := &stubGitHubAuthority{
		binding: coreapi.RepositoryBinding{
			BindingID: "binding-1", WorkspaceID: "ws-test", Repository: "octo-org/repo",
			RepositoryID: "111", InstallationID: "222",
		},
		issue: coreapi.GitHubIssueSnapshot{
			WorkspaceID: "ws-test", BindingID: "binding-1", IssueNumber: 42,
			Title: "Add retries", Body: "- [ ] retry with backoff", State: "open",
			BaseRef: "main", BaseSHA: strings.Repeat("a", 40),
			SourceRevision: "rev-1", CanonicalDigest: "sha256:" + strings.Repeat("b", 64),
			SnapshotAt: time.Now().UTC().Unix(),
		},
		posture: coreapi.WorkflowPosture{
			BindingID: "binding-1", Ref: "main", WorkflowsInspected: 2,
			Posture: "clean",
		},
	}
	stub := &stubPassAuthority{
		stubGitHubAuthority: gh,
		shaped: coreapi.MissionDraft{
			ProposalDigest:   "sha256:" + strings.Repeat("c", 64),
			InvocationDigest: invocation,
			AgentKitID:       "authscope-agent-kit",
			AgentKitVersion:  "1.0.0",
			RunnerArguments:  []string{"authscope-agent-run", "--mission"},
			CanonicalDraft:   []byte(`{"objective":"Add retries"}`),
		},
		proposal: coreapi.Proposal{
			ProposalID:       "prop-1",
			ProposalDigest:   "sha256:" + strings.Repeat("f", 64),
			InvocationDigest: invocation,
			AgentKitID:       "authscope-agent-kit",
			AgentKitVersion:  "1.0.0",
			RunnerArguments:  []string{"authscope-agent-run", "--mission"},
		},
		reconcileStatus: "completed",
	}
	signer := identity.NewEphemeralSigner()
	stub.identityRoles = map[string][]string{signer.IdentityDigest(): {coreapi.DecisionAttestorRole}}
	stub.identityKeys = map[string]ed25519.PublicKey{signer.IdentityDigest(): signer.PublicKey()}
	stub.seenNonces = make(map[string]bool)
	stub.expectedSubject = "prop-1"
	stub.mission = coreapi.Mission{
		MissionID: "mission-1", MissionRef: "mission-1", WorkspaceID: "ws-test",
		State: "active", Version: 3,
	}
	attestor := identity.NewDecisionAttestor(signer)
	cliAuth, err := authn.NewCLIAuthorizationService(authn.CLIAuthorizationConfig{
		Store:          f.store,
		Authn:          f.authn,
		Attestor:       attestor,
		BrowserBaseURL: "https://ope.example.com",
	})
	if err != nil {
		t.Fatalf("new CLI authorization service: %v", err)
	}
	revocation, err := missionpass.NewRevocationService(missionpass.RevocationConfig{
		Store:     f.store,
		Authn:     f.authn,
		Authority: stub,
		Attestor:  attestor,
	})
	if err != nil {
		t.Fatalf("new revocation service: %v", err)
	}
	cliRevocation, err := missionpass.NewCLIRevocationService(missionpass.CLIRevocationConfig{
		Store:       f.store,
		Revocation:  revocation,
		WorkspaceID: "ws-test",
		BrowserURL:  "https://ope.example.com",
	})
	if err != nil {
		t.Fatalf("new CLI revocation service: %v", err)
	}
	projector := missionpass.NewEventProjector(f.store, nil)
	deps := Dependencies{
		Config: f.config,
		Contract: coreapi.ContractReport{
			CoreVersion: "ope-v1.0.0", DigestMatch: true,
			OperationsRequired: 36, OperationsPresent: 36,
		},
		Store:         f.store,
		Authn:         f.authn,
		Authority:     stub,
		Attestor:      attestor,
		CLIAuth:       cliAuth,
		Revocation:    revocation,
		CLIRevocation: cliRevocation,
		Projector:     projector,
	}
	f.handler = New(deps)
	csrf := f.enrollOverHTTP(t)
	ctx := context.Background()
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutConnection(ctx, store.ConnectionRecord{
			WorkspaceID:          "ws-test",
			ConnectionID:         "conn-1",
			RepositoryBindingRef: "binding-1",
			InstallationID:       222,
			RepositoryID:         111,
			RepositoryName:       "octo-org/repo",
			PermissionStatus:     "verified",
			VerifiedAt:           time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	return &passFixture{authTestFixture: f, stub: stub, csrf: csrf, deps: deps}
}

// passHeaders builds the exact guard headers for state-changing pass
// requests.
func (f *passFixture) passHeaders(idemKey string, extra map[string]string) map[string]string {
	h := map[string]string{
		"Host":            "ope.example.com",
		"Origin":          "https://ope.example.com",
		"Content-Type":    "application/json",
		"X-CSRF-Token":    f.csrf,
		"Idempotency-Key": idemKey,
	}
	for k, v := range extra {
		if v == "" {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	return h
}

func (f *passFixture) postPass(t *testing.T, path, body, idemKey string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doRaw(t, http.MethodPost, path, body, f.passHeaders(idemKey, extra))
}

func (f *passFixture) putPass(t *testing.T, path, body, idemKey string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doRaw(t, http.MethodPut, path, body, f.passHeaders(idemKey, extra))
}

func (f *passFixture) getPass(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "https://ope.example.com"+path, nil)
	req.Host = "ope.example.com"
	for _, c := range f.jar {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func createDraftBody(expires time.Time, budget int64) string {
	return `{"connection_id":"conn-1","issue_number":42,` +
		`"expires_at":"` + expires.Format(time.RFC3339) + `",` +
		`"max_aggregate_cost_micros":` + strconv.FormatInt(budget, 10) + `}`
}

// createDraft opens a draft through the HTTP API and returns its pass ID.
func (f *passFixture) createDraft(t *testing.T, expires time.Time, budget int64) string {
	t.Helper()
	rec := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, budget), "key-1", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create draft status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	decodeBody(t, rec, &body)
	id, _ := body["pass_id"].(string)
	if id == "" {
		t.Fatalf("create draft returned no pass_id: %s", rec.Body.String())
	}
	return id
}

func TestPassDraftCreate(t *testing.T) {
	f := newPassFixture(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	rec := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, 10_000_000), "key-1", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		PassID                  string   `json:"pass_id"`
		StoreRevision           int64    `json:"store_revision"`
		DraftVersion            int64    `json:"draft_version"`
		ProposalID              string   `json:"proposal_id"`
		ProposalDigest          string   `json:"proposal_digest"`
		InvocationDigest        string   `json:"invocation_digest"`
		AgentKitID              string   `json:"agent_kit_id"`
		AgentKitVersion         string   `json:"agent_kit_version"`
		RunnerArguments         []string `json:"runner_arguments"`
		State                   string   `json:"state"`
		Reconciliation          string   `json:"reconciliation"`
		ConnectionID            string   `json:"connection_id"`
		IssueNumber             int64    `json:"issue_number"`
		RepositoryName          string   `json:"repository_name"`
		Objective               string   `json:"objective"`
		AcceptanceCriteria      []string `json:"acceptance_criteria"`
		MissionBranch           string   `json:"mission_branch"`
		BaseSHA                 string   `json:"base_sha"`
		ApprovedProposalDigest  string   `json:"approved_proposal_digest"`
		AuthScopeMissionVersion int64    `json:"authscope_mission_version"`
	}
	decodeBody(t, rec, &body)
	if body.PassID == "" || body.ProposalID != "prop-1" {
		t.Fatalf("identity = %q %q", body.PassID, body.ProposalID)
	}
	if body.ProposalDigest != "sha256:"+strings.Repeat("f", 64) {
		t.Errorf("proposal_digest = %q", body.ProposalDigest)
	}
	if body.InvocationDigest != testInvocationDigest() {
		t.Errorf("invocation_digest = %q", body.InvocationDigest)
	}
	if body.AgentKitID != "authscope-agent-kit" || body.AgentKitVersion != "1.0.0" {
		t.Errorf("kit = %q %q", body.AgentKitID, body.AgentKitVersion)
	}
	if len(body.RunnerArguments) != 2 || body.RunnerArguments[0] != "authscope-agent-run" {
		t.Errorf("runner_arguments = %v", body.RunnerArguments)
	}
	if body.State != "draft" || body.Reconciliation != "settled" {
		t.Errorf("state = %q reconciliation = %q", body.State, body.Reconciliation)
	}
	if body.ConnectionID != "conn-1" || body.IssueNumber != 42 || body.RepositoryName != "octo-org/repo" {
		t.Errorf("source = %q %d %q", body.ConnectionID, body.IssueNumber, body.RepositoryName)
	}
	if body.Objective != "Add retries" || len(body.AcceptanceCriteria) != 1 {
		t.Errorf("snapshot = %q %v", body.Objective, body.AcceptanceCriteria)
	}
	if !strings.HasPrefix(body.MissionBranch, "authscope/") || !strings.HasSuffix(body.MissionBranch, "-42") {
		t.Errorf("mission_branch = %q", body.MissionBranch)
	}
	if body.BaseSHA != strings.Repeat("a", 40) {
		t.Errorf("base_sha = %q", body.BaseSHA)
	}
	if body.ApprovedProposalDigest != "" || body.AuthScopeMissionVersion != 0 {
		t.Errorf("pre-approval fields = %q %d", body.ApprovedProposalDigest, body.AuthScopeMissionVersion)
	}
	if body.StoreRevision != 1 || body.DraftVersion != 1 {
		t.Errorf("revisions = %d %d", body.StoreRevision, body.DraftVersion)
	}
}

func TestPassDraftCreateGuards(t *testing.T) {
	f := newPassFixture(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	body := createDraftBody(expires, 10_000_000)

	if rec := f.postPass(t, "/api/v1/mission-passes/drafts", body, "", map[string]string{"Idempotency-Key": ""}); rec.Code != http.StatusBadRequest {
		t.Errorf("missing idempotency key status = %d", rec.Code)
	}
	if rec := f.postPass(t, "/api/v1/mission-passes/drafts", body, "k", map[string]string{"Origin": ""}); rec.Code != http.StatusForbidden {
		t.Errorf("missing origin status = %d", rec.Code)
	}
	if rec := f.postPass(t, "/api/v1/mission-passes/drafts", body, "k", map[string]string{"X-CSRF-Token": ""}); rec.Code != http.StatusForbidden {
		t.Errorf("missing csrf status = %d", rec.Code)
	}
	unknown := strings.Replace(body, `"conn-1"`, `"conn-1","bogus_field":1`, 1)
	if rec := f.postPass(t, "/api/v1/mission-passes/drafts", unknown, "k", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field status = %d", rec.Code)
	}
	badExpiry := strings.Replace(body, expires.Format(time.RFC3339), "not-a-time", 1)
	if rec := f.postPass(t, "/api/v1/mission-passes/drafts", badExpiry, "k", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad expiry status = %d", rec.Code)
	}
}

func TestPassGet(t *testing.T) {
	f := newPassFixture(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	id := f.createDraft(t, expires, 10_000_000)

	rec := f.getPass(t, "/api/v1/mission-passes/"+id)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	decodeBody(t, rec, &body)
	if body["pass_id"] != id || body["proposal_id"] != "prop-1" {
		t.Errorf("get = %v", body)
	}

	// Unauthenticated reads fail.
	saved := f.jar
	f.jar = map[string]*http.Cookie{}
	defer func() { f.jar = saved }()
	if rec := f.getPass(t, "/api/v1/mission-passes/"+id); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated status = %d", rec.Code)
	}

	// Unknown passes 404.
	f.jar = saved
	if rec := f.getPass(t, "/api/v1/mission-passes/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown pass status = %d", rec.Code)
	}
}

func TestPassDraftRevise(t *testing.T) {
	f := newPassFixture(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	id := f.createDraft(t, expires, 10_000_000)

	f.stub.proposal.ProposalID = "prop-2"
	f.stub.proposal.ProposalDigest = "sha256:" + strings.Repeat("e", 64)
	narrower := expires.Add(-30 * time.Minute).Format(time.RFC3339)
	putBody := `{"expected_store_revision":1,"expected_draft_version":1,` +
		`"expires_at":"` + narrower + `","max_aggregate_cost_micros":5000000}`
	rec := f.putPass(t, "/api/v1/mission-passes/"+id+"/draft", putBody, "key-2", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		StoreRevision  int64  `json:"store_revision"`
		DraftVersion   int64  `json:"draft_version"`
		ProposalID     string `json:"proposal_id"`
		ProposalDigest string `json:"proposal_digest"`
		Reconciliation string `json:"reconciliation"`
		Limits         struct {
			MaxAggregateCostMicros int64 `json:"max_aggregate_cost_micros"`
		} `json:"limits"`
	}
	decodeBody(t, rec, &body)
	if body.StoreRevision != 2 || body.DraftVersion != 2 {
		t.Errorf("revisions = %d %d", body.StoreRevision, body.DraftVersion)
	}
	if body.ProposalID != "prop-2" || body.ProposalDigest != "sha256:"+strings.Repeat("e", 64) {
		t.Errorf("proposal = %q %q", body.ProposalID, body.ProposalDigest)
	}
	if body.Limits.MaxAggregateCostMicros != 5_000_000 {
		t.Errorf("budget = %d", body.Limits.MaxAggregateCostMicros)
	}
	if body.Reconciliation != "settled" {
		t.Errorf("reconciliation = %q", body.Reconciliation)
	}
}

func TestPassDraftReviseGuards(t *testing.T) {
	f := newPassFixture(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	id := f.createDraft(t, expires, 10_000_000)
	narrower := expires.Add(-30 * time.Minute).Format(time.RFC3339)
	base := func() string {
		return `{"expected_store_revision":1,"expected_draft_version":1,` +
			`"expires_at":"` + narrower + `","max_aggregate_cost_micros":5000000}`
	}

	// Protected field edits fail with 422.
	protected := strings.Replace(base(), `"max_aggregate_cost_micros":5000000`,
		`"max_aggregate_cost_micros":5000000,"objective":"pwned"`, 1)
	if rec := f.putPass(t, "/api/v1/mission-passes/"+id+"/draft", protected, "k", nil); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("protected field status = %d", rec.Code)
	}
	protected = strings.Replace(base(), `"max_aggregate_cost_micros":5000000`,
		`"max_aggregate_cost_micros":5000000,"runner_arguments":["evil"]`, 1)
	if rec := f.putPass(t, "/api/v1/mission-passes/"+id+"/draft", protected, "k", nil); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("protected runner args status = %d", rec.Code)
	}

	// Unknown fields fail with 400.
	unknown := strings.Replace(base(), `"max_aggregate_cost_micros":5000000`,
		`"max_aggregate_cost_micros":5000000,"mystery":1`, 1)
	if rec := f.putPass(t, "/api/v1/mission-passes/"+id+"/draft", unknown, "k", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field status = %d", rec.Code)
	}

	// Stale revisions fail with 409.
	stale := strings.Replace(base(), `"expected_store_revision":1`, `"expected_store_revision":7`, 1)
	if rec := f.putPass(t, "/api/v1/mission-passes/"+id+"/draft", stale, "k", nil); rec.Code != http.StatusConflict {
		t.Errorf("stale revision status = %d", rec.Code)
	}

	// Widening edits fail with 400: the request is well-formed but asks
	// for values outside the allowed narrowing.
	wider := strings.Replace(base(), `"max_aggregate_cost_micros":5000000`, `"max_aggregate_cost_micros":15000000`, 1)
	if rec := f.putPass(t, "/api/v1/mission-passes/"+id+"/draft", wider, "k", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("widened budget status = %d", rec.Code)
	}
	later := strings.Replace(base(), narrower, expires.Add(time.Hour).Format(time.RFC3339), 1)
	if rec := f.putPass(t, "/api/v1/mission-passes/"+id+"/draft", later, "k", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("later expiry status = %d", rec.Code)
	}
}

func TestPassDraftCreateAmbiguousReturns202(t *testing.T) {
	f := newPassFixture(t)
	f.stub.createErr = context.DeadlineExceeded
	f.stub.reconcileStatus = "unknown"
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	rec := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, 10_000_000), "key-1", nil)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		PassID         string `json:"pass_id"`
		Reconciliation string `json:"reconciliation"`
		ProposalID     string `json:"proposal_id"`
	}
	decodeBody(t, rec, &body)
	if body.PassID == "" {
		t.Fatal("202 returned no pass_id")
	}
	if body.Reconciliation != "pending" {
		t.Errorf("reconciliation = %q, want pending", body.Reconciliation)
	}
	if body.ProposalID != "" {
		t.Errorf("proposal_id = %q, want empty while pending", body.ProposalID)
	}
	// Retrying the same request with the same idempotency key resolves
	// to the same pending pass instead of opening a duplicate draft.
	retry := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, 10_000_000), "key-1", nil)
	if retry.Code != http.StatusAccepted {
		t.Fatalf("retry status = %d, body = %s", retry.Code, retry.Body.String())
	}
	var rebody struct {
		PassID         string `json:"pass_id"`
		Reconciliation string `json:"reconciliation"`
	}
	decodeBody(t, retry, &rebody)
	if rebody.PassID != body.PassID {
		t.Errorf("retry pass_id = %q, want %q", rebody.PassID, body.PassID)
	}
	if rebody.Reconciliation != "pending" {
		t.Errorf("retry reconciliation = %q, want pending", rebody.Reconciliation)
	}
}

func TestPassDraftCreateIdempotentRetry(t *testing.T) {
	f := newPassFixture(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	first := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, 10_000_000), "key-dup", nil)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d, body = %s", first.Code, first.Body.String())
	}
	var firstBody struct {
		PassID string `json:"pass_id"`
	}
	decodeBody(t, first, &firstBody)

	// The same idempotency key replays the existing draft: 200, same
	// pass, and no second upstream proposal.
	second := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, 10_000_000), "key-dup", nil)
	if second.Code != http.StatusOK {
		t.Fatalf("retry status = %d, body = %s", second.Code, second.Body.String())
	}
	var secondBody struct {
		PassID     string `json:"pass_id"`
		ProposalID string `json:"proposal_id"`
	}
	decodeBody(t, second, &secondBody)
	if secondBody.PassID != firstBody.PassID {
		t.Errorf("retry pass_id = %q, want %q", secondBody.PassID, firstBody.PassID)
	}
	if secondBody.ProposalID != "prop-1" {
		t.Errorf("retry proposal_id = %q", secondBody.ProposalID)
	}
}
