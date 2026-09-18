package httpapi

// HTTP coverage for the exact one-use expansion decision ceremony:
// list pending expansions, begin a passkey decision, and finish it.
// The upstream is faked independently and verifies the exact binding
// AuthScope would check.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/expansion"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// expansionStubAuthority wraps stubPassAuthority with the expansion
// upstream surface. Attestation verification mirrors AuthScope's exact
// binding checks.
type expansionStubAuthority struct {
	*stubPassAuthority

	mu           sync.Mutex
	expansions   []coreapi.Expansion
	deltas       map[string]json.RawMessage
	decideErr    error
	failDecideOnce error
	decideCalls  int
	decideKeys   []string
	decidedByKey map[string]coreapi.ExpansionResult
	expected     expansion.ExpansionBinding
	tamper       func(*identity.SignedDecisionAttestation)
}

func (s *expansionStubAuthority) ListExpansions(_ context.Context, missionRef string, _ coreapi.RequestOptions) ([]coreapi.Expansion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []coreapi.Expansion
	for _, e := range s.expansions {
		if e.MissionRef == missionRef {
			out = append(out, e)
		}
	}
	return out, nil
}

func (s *expansionStubAuthority) GetExpansion(_ context.Context, expansionID string, _ coreapi.RequestOptions) (json.RawMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, ok := s.deltas[expansionID]
	if !ok {
		return nil, &coreapi.UpstreamError{StatusCode: 404, Message: "expansion not found"}
	}
	return append(json.RawMessage(nil), raw...), nil
}

func (s *expansionStubAuthority) DecideExpansion(_ context.Context, expansionID string, decision coreapi.ExpansionDecision, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.ExpansionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decideCalls++
	s.decideKeys = append(s.decideKeys, opts.IdempotencyKey)
	if s.failDecideOnce != nil {
		err := s.failDecideOnce
		s.failDecideOnce = nil
		if s.decidedByKey == nil {
			s.decidedByKey = map[string]coreapi.ExpansionResult{}
		}
		name := "deny"
		if decision.Approve {
			name = "approve_once"
		}
		s.decidedByKey[opts.IdempotencyKey] = coreapi.ExpansionResult{
			ExpansionID: expansionID, Decision: name, DecidedAt: time.Now().UTC().Unix(),
			MissionVersion: s.expected.ExpectedAuthScopeVersion + 1,
		}
		return coreapi.ExpansionResult{}, err
	}
	if s.decideErr != nil {
		return coreapi.ExpansionResult{}, s.decideErr
	}
	if s.decidedByKey == nil {
		s.decidedByKey = map[string]coreapi.ExpansionResult{}
	}
	if res, ok := s.decidedByKey[opts.IdempotencyKey]; ok {
		return res, nil
	}
	if s.tamper != nil {
		s.tamper(&att)
	}
	if err := s.verifyExpansionAttestation(expansionID, decision, att); err != nil {
		return coreapi.ExpansionResult{}, err
	}
	name := "deny"
	version := s.expected.ExpectedAuthScopeVersion
	if decision.Approve {
		name = "approve_once"
		version = s.expected.ExpectedAuthScopeVersion + 1
	}
	res := coreapi.ExpansionResult{
		ExpansionID: expansionID, Decision: name, DecidedAt: time.Now().UTC().Unix(), MissionVersion: version,
	}
	s.decidedByKey[opts.IdempotencyKey] = res
	return res, nil
}

func (s *expansionStubAuthority) ReconcileOperation(_ context.Context, idempotencyKey, _ string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.decidedByKey[idempotencyKey]; !ok {
		return coreapi.OperationResult{Status: "not_found"}, nil
	}
	return coreapi.OperationResult{Status: "completed"}, nil
}

func (s *expansionStubAuthority) verifyExpansionAttestation(expansionID string, decision coreapi.ExpansionDecision, att identity.SignedDecisionAttestation) error {
	deny := func(format string, args ...any) error {
		return &coreapi.UpstreamError{StatusCode: 403, Message: fmt.Sprintf(format, args...)}
	}
	roles, ok := s.identityRoles[att.IdentityDigest]
	if !ok {
		return deny("unknown signing identity")
	}
	allowed := false
	for _, r := range roles {
		if r == coreapi.DecisionAttestorRole {
			allowed = true
			break
		}
	}
	if !allowed {
		return deny("signing identity lacks decision_attestor role")
	}
	pub, ok := s.identityKeys[att.IdentityDigest]
	if !ok {
		return deny("unknown signing identity key")
	}
	canonical, err := identity.CanonicalClaimsJSON(att.Claims, att.KeyID, att.IdentityDigest)
	if err != nil {
		return deny("invalid claims: %v", err)
	}
	msg := append(append([]byte(identity.AttestationDomain), 0x00), canonical...)
	if !ed25519.Verify(pub, msg, att.Signature) {
		return deny("signature verification failed")
	}
	c := att.Claims
	b := s.expected
	if c.WorkspaceID != b.WorkspaceID || c.Audience != identity.AudienceExpansionDecision ||
		c.Purpose != identity.PurposeExpansionDecision || c.SubjectID != expansionID {
		return deny("binding mismatch")
	}
	sum := sha256.Sum256(expansion.CanonicalExpansionBytes(b))
	if c.DecisionDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return deny("decision digest mismatch")
	}
	want := expansion.Deny
	if decision.Approve {
		want = expansion.ApproveOnce
	}
	if b.Decision != want {
		return deny("decision mismatch")
	}
	if c.AuthenticationMethod != identity.AuthMethodWebAuthnUV {
		return deny("auth method mismatch")
	}
	var zero [32]byte
	if c.Nonce == zero {
		return deny("zero nonce")
	}
	return nil
}

// expansionHTTPFixture wires a real expansion.Service into the HTTP
// handler with a pass sitting in awaiting_expansion.
type expansionHTTPFixture struct {
	*passFixture
	svc    *expansion.Service
	estub  *expansionStubAuthority
	passID string
}

func newExpansionHTTPFixture(t *testing.T) *expansionHTTPFixture {
	t.Helper()
	pf := newPassFixture(t)
	passID := pf.approvedPass(t)

	signer := identity.NewEphemeralSigner()
	digest := signer.IdentityDigest()
	pf.stub.identityRoles[digest] = []string{coreapi.DecisionAttestorRole}
	pf.stub.identityKeys[digest] = signer.PublicKey()

	now := time.Now().UTC()
	requestedExpiry := now.Add(30 * time.Minute).Truncate(time.Second)
	delta := expansion.Delta{
		ExpansionID:               "exp-1",
		MissionRef:                "mission-1",
		MissionVersion:            3,
		BlockedOperation:          "files.write",
		Resource:                  "github:octo-org/repo",
		Repository:                "octo-org/repo",
		Ref:                       "refs/heads/mission-1",
		Path:                      "config/flags.yaml",
		Destination:               "config/flags.yaml",
		NormalizedArgumentsDigest: "sha256:" + strings.Repeat("a", 64),
		Quantity:                  1,
		BudgetMicros:              50_000,
		CurrentAuthority:          "read-only",
		RequestedAuthority:        "write:config/flags.yaml",
		ConsequenceChange:         "agent may write config/flags.yaml once",
		ReasonCode:                "config_update_required",
		Reversibility:             "reversible",
		RequestedExpiry:           requestedExpiry,
		AgentRationale:            "The agent asked to flip the feature flag.",
	}
	delta.ExpansionDigest = expansion.CanonicalExpansionDigest(delta)
	raw, err := json.Marshal(delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}
	estub := &expansionStubAuthority{
		stubPassAuthority: pf.stub,
		expansions: []coreapi.Expansion{{
			ExpansionID: "exp-1", MissionRef: "mission-1", Status: "pending", RequestedAt: now.Unix(),
		}},
		deltas: map[string]json.RawMessage{"exp-1": raw},
		expected: expansion.ExpansionBinding{
			WorkspaceID: "ws-test", PassID: passID, MissionRef: "mission-1",
			ExpectedAuthScopeVersion: 3, ExpansionID: "exp-1",
			ExpansionDigest: delta.ExpansionDigest, Decision: expansion.ApproveOnce,
			EffectiveExpiry: requestedExpiry,
			Purpose:         "expansion_decision", Audience: "authscope:expansion-decision",
		},
	}
	svc, err := expansion.NewService(expansion.Config{
		Store:     pf.store,
		Authn:     pf.authn,
		Authority: estub,
		Attestor:  identity.NewDecisionAttestor(signer),
		Clock:     time.Now,
	})
	if err != nil {
		t.Fatalf("new expansion service: %v", err)
	}
	pf.deps.Expansion = svc
	pf.handler = New(pf.deps)

	// Move the approved pass to awaiting_expansion, as the event
	// projector would after an expansion_requested event.
	ctx := context.Background()
	if err := pf.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, "ws-test", passID)
		if err != nil {
			return err
		}
		rec.State = "awaiting_expansion"
		return tx.PutMissionPass(ctx, rec, rec.StoreRevision)
	}); err != nil {
		t.Fatalf("move pass to awaiting_expansion: %v", err)
	}
	// Sync the pending expansion into the local store.
	if _, err := svc.ListPending(ctx, "ws-test", passID); err != nil {
		t.Fatalf("sync expansions: %v", err)
	}
	return &expansionHTTPFixture{passFixture: pf, svc: svc, estub: estub, passID: passID}
}

func (f *expansionHTTPFixture) expansionBegin(t *testing.T, expansionID, decision string) string {
	t.Helper()
	body := `{"decision":` + strconv.Quote(decision) + `}`
	rec := f.postPass(t, "/api/v1/expansions/"+expansionID+"/decide/begin", body, "idem-exp-begin", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expansion begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		ChallengeID     string `json:"challenge_id"`
		EffectiveExpiry string `json:"effective_expiry"`
	}
	decodeBody(t, rec, &begin)
	if begin.ChallengeID == "" {
		t.Fatalf("expansion begin missing challenge: %s", rec.Body.String())
	}
	return begin.ChallengeID
}

func (f *expansionHTTPFixture) expansionFinish(t *testing.T, expansionID, challengeID string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"challenge_id":"` + challengeID + `","assertion":{"id":"cred-1"}}`
	return f.postPass(t, "/api/v1/expansions/"+expansionID+"/decide/finish", body, "idem-exp-finish", nil)
}

func TestExpansionListPending(t *testing.T) {
	f := newExpansionHTTPFixture(t)
	rec := f.getPass(t, "/api/v1/mission-passes/"+f.passID+"/expansions")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var res struct {
		PassID     string `json:"pass_id"`
		Expansions []struct {
			ExpansionID               string `json:"expansion_id"`
			ExpansionDigest           string `json:"expansion_digest"`
			BlockedOperation          string `json:"blocked_operation"`
			Resource                  string `json:"resource"`
			CurrentAuthority          string `json:"current_authority"`
			RequestedAuthority        string `json:"requested_authority"`
			NormalizedArgumentsDigest string `json:"normalized_arguments_digest"`
			ConsequenceChange         string `json:"consequence_change"`
			ReasonCode                string `json:"reason_code"`
			Reversibility             string `json:"reversibility"`
			Stale                     bool   `json:"stale"`
		} `json:"expansions"`
	}
	decodeBody(t, rec, &res)
	if res.PassID != f.passID {
		t.Errorf("pass_id = %q, want %q", res.PassID, f.passID)
	}
	if len(res.Expansions) != 1 {
		t.Fatalf("expansions = %d, want 1", len(res.Expansions))
	}
	e := res.Expansions[0]
	if e.ExpansionID != "exp-1" || !strings.HasPrefix(e.ExpansionDigest, "sha256:") {
		t.Errorf("expansion identity = %q/%q", e.ExpansionID, e.ExpansionDigest)
	}
	if e.BlockedOperation != "files.write" || e.Resource != "github:octo-org/repo" {
		t.Errorf("blocked op/resource = %q/%q", e.BlockedOperation, e.Resource)
	}
	if e.CurrentAuthority != "read-only" || e.RequestedAuthority != "write:config/flags.yaml" {
		t.Errorf("authority pair = %q/%q", e.CurrentAuthority, e.RequestedAuthority)
	}
	if e.Stale {
		t.Errorf("stale = true, want false")
	}
}

func TestExpansionBeginFinishApproveOnce(t *testing.T) {
	f := newExpansionHTTPFixture(t)
	challengeID := f.expansionBegin(t, "exp-1", "approve_once")
	f.queueAssertion(t, 2, true)
	rec := f.expansionFinish(t, "exp-1", challengeID)
	if rec.Code != http.StatusOK {
		t.Fatalf("finish: status %d body %s", rec.Code, rec.Body.String())
	}
	var res struct {
		ExpansionID          string `json:"expansion_id"`
		Decision             string `json:"decision"`
		DecisionRef          string `json:"decision_ref"`
		AuthScopeMissionVersion int64 `json:"authscope_mission_version"`
		State                string `json:"state"`
	}
	decodeBody(t, rec, &res)
	if res.Decision != "approve_once" {
		t.Errorf("decision = %q, want approve_once", res.Decision)
	}
	if res.AuthScopeMissionVersion != 4 {
		t.Errorf("mission version = %d, want 4", res.AuthScopeMissionVersion)
	}
	if res.State != "running" {
		t.Errorf("state = %q, want running", res.State)
	}
	if f.estub.decideCalls != 1 {
		t.Errorf("upstream decide calls = %d, want 1", f.estub.decideCalls)
	}
}

func TestExpansionBeginInvalidDecision(t *testing.T) {
	f := newExpansionHTTPFixture(t)
	rec := f.postPass(t, "/api/v1/expansions/exp-1/decide/begin", `{"decision":"approve"}`, "idem-exp-bad", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpansionBeginUnknownDecisionValue(t *testing.T) {
	f := newExpansionHTTPFixture(t)
	rec := f.postPass(t, "/api/v1/expansions/exp-1/decide/begin", `{"decision":"maybe"}`, "idem-exp-bad2", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestExpansionFinishAmbiguousReturns202(t *testing.T) {
	f := newExpansionHTTPFixture(t)
	challengeID := f.expansionBegin(t, "exp-1", "approve_once")
	f.queueAssertion(t, 2, true)
	f.estub.failDecideOnce = &coreapi.UpstreamError{StatusCode: 503, Code: "unavailable", Message: "stub: dropped response"}
	rec := f.expansionFinish(t, "exp-1", challengeID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body %s", rec.Code, rec.Body.String())
	}
	var pending struct {
		ExpansionID    string `json:"expansion_id"`
		Reconciliation string `json:"reconciliation"`
	}
	decodeBody(t, rec, &pending)
	if pending.ExpansionID != "exp-1" {
		t.Errorf("expansion_id = %q, want exp-1", pending.ExpansionID)
	}
	if pending.Reconciliation != "pending" {
		t.Errorf("reconciliation = %q, want pending", pending.Reconciliation)
	}
}

func TestExpansionBeginRequiresSession(t *testing.T) {
	f := newExpansionHTTPFixture(t)
	f.withoutSession(t, func() {
		rec := f.postPass(t, "/api/v1/expansions/exp-1/decide/begin", `{"decision":"deny"}`, "idem-exp-nosess", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

func TestExpansionBeginOriginGuard(t *testing.T) {
	f := newExpansionHTTPFixture(t)
	rec := f.postPass(t, "/api/v1/expansions/exp-1/decide/begin", `{"decision":"deny"}`, "idem-exp-origin", map[string]string{"Origin": "https://evil.example.com"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
