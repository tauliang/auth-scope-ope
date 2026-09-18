package httpapi

// Task 7: HTTP coverage for approve/begin, approve/finish, and GET
// reconciliation of an ambiguous approval.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
)

// approvalStubFields extends stubPassAuthority with upstream approval
// verification. The fields live on stubPassAuthority (defined in
// pass_handlers_test.go); the methods are defined here.
func (s *stubPassAuthority) ApproveProposal(_ context.Context, proposalID string, in coreapi.ApproveProposalInput, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Mission, error) {
	s.approveCalls++
	s.approveKeys = append(s.approveKeys, opts.IdempotencyKey)
	if s.approvedByKey == nil {
		s.approvedByKey = make(map[string]coreapi.Mission)
	}
	if m, ok := s.approvedByKey[opts.IdempotencyKey]; ok {
		return m, nil
	}
	if s.failApproveOnce != nil {
		err := s.failApproveOnce
		s.failApproveOnce = nil
		s.missionsCreated++
		s.approvedByKey[opts.IdempotencyKey] = s.mission
		return coreapi.Mission{}, err
	}
	if s.approveErr != nil {
		return coreapi.Mission{}, s.approveErr
	}
	if err := s.verifyApprovalAttestation(att, proposalID, in); err != nil {
		return coreapi.Mission{}, err
	}
	s.missionsCreated++
	s.approvedByKey[opts.IdempotencyKey] = s.mission
	s.signedAttestations = append(s.signedAttestations, att)
	return s.mission, nil
}

func (s *stubPassAuthority) PrepareLaunch(_ context.Context, _ string, _ coreapi.LaunchRequest, _ identity.SignedDecisionAttestation, _ coreapi.RequestOptions) (coreapi.LaunchArtifacts, error) {
	s.prepareLaunchCalls++
	return coreapi.LaunchArtifacts{}, errors.New("stub: PrepareLaunch must not be called during approval")
}

func (s *stubPassAuthority) denyApproval(format string, args ...any) error {
	return &coreapi.UpstreamError{StatusCode: 403, Code: "decision_denied", Message: fmt.Sprintf(format, args...)}
}

func (s *stubPassAuthority) verifyApprovalAttestation(att identity.SignedDecisionAttestation, proposalID string, in coreapi.ApproveProposalInput) error {
	roles := s.identityRoles[att.IdentityDigest]
	allowed := false
	for _, r := range roles {
		if r == coreapi.DecisionAttestorRole {
			allowed = true
			break
		}
	}
	if !allowed {
		return s.denyApproval("signing identity lacks decision_attestor role")
	}
	pub, ok := s.identityKeys[att.IdentityDigest]
	if !ok {
		return s.denyApproval("unknown signing identity")
	}
	canonical, err := identity.CanonicalClaimsJSON(att.Claims, att.KeyID, att.IdentityDigest)
	if err != nil {
		return s.denyApproval("invalid claims: %v", err)
	}
	msg := append(append([]byte(identity.AttestationDomain), 0x00), canonical...)
	if !ed25519.Verify(pub, msg, att.Signature) {
		return s.denyApproval("signature verification failed")
	}
	c := att.Claims
	if c.WorkspaceID != "ws-test" {
		return s.denyApproval("workspace mismatch")
	}
	if c.Audience != identity.AudienceProposalApproval {
		return s.denyApproval("audience mismatch")
	}
	if c.Purpose != identity.PurposePassApproval {
		return s.denyApproval("purpose mismatch")
	}
	if c.SubjectID != proposalID || proposalID != s.expectedSubject {
		return s.denyApproval("subject mismatch")
	}
	for _, d := range []string{c.DecisionDigest, c.InvocationDigest, in.ProposalDigest, in.InvocationDigest} {
		if !approvalDigestPattern.MatchString(d) {
			return s.denyApproval("malformed digest %q", d)
		}
	}
	if in.InvocationDigest != c.InvocationDigest {
		return s.denyApproval("request invocation digest does not match attestation")
	}
	if c.AuthenticationMethod != identity.AuthMethodWebAuthnUV {
		return s.denyApproval("auth method mismatch")
	}
	var zero [32]byte
	if c.Nonce == zero {
		return s.denyApproval("zero nonce")
	}
	nonceKey := base64.RawURLEncoding.EncodeToString(c.Nonce[:])
	if s.seenNonces[nonceKey] {
		return s.denyApproval("replayed nonce")
	}
	now := time.Now()
	if c.IssuedAt.After(now.Add(time.Minute)) {
		return s.denyApproval("issued_at in future")
	}
	if !c.ExpiresAt.After(now) {
		return s.denyApproval("attestation expired")
	}
	s.seenNonces[nonceKey] = true
	return nil
}

var approvalDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// approveTestFixture bundles a pass fixture with helpers for the approval
// HTTP flow.
type approveTestFixture struct {
	*passFixture
	assertIdx int
}

func newApproveTestFixture(t *testing.T) *approveTestFixture {
	t.Helper()
	return &approveTestFixture{passFixture: newPassFixture(t)}
}

// queueAssertion queues one successful decision assertion with an
// advancing sign count.
func (f *approveTestFixture) queueAssertion() {
	f.assertIdx++
	f.stubVerifier().assertOutcomes = append(f.stubVerifier().assertOutcomes, authn.VerifiedAssertion{
		CredentialID: []byte("cred-1"),
		NewSignCount: uint32(f.assertIdx),
		UserVerified: true,
	})
}

func (f *approveTestFixture) stubVerifier() *stubVerifier {
	return f.authTestFixture.stub
}

// createApprovalDraft opens a draft and returns its pass ID.
func (f *approveTestFixture) createApprovalDraft(t *testing.T) string {
	t.Helper()
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	rec := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, 5_000_000), "idem-approve-1", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create draft: status %d body %s", rec.Code, rec.Body.String())
	}
	var created struct {
		PassID string `json:"pass_id"`
	}
	decodeBody(t, rec, &created)
	if created.PassID == "" {
		t.Fatalf("create draft missing pass_id: %s", rec.Body.String())
	}
	return created.PassID
}

type approveBeginResponse struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

func (f *approveTestFixture) approveBegin(t *testing.T, passID string) approveBeginResponse {
	t.Helper()
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/approve/begin", `{}`, "idem-begin-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin approveBeginResponse
	decodeBody(t, rec, &begin)
	if begin.ChallengeID == "" || len(begin.Options) == 0 {
		t.Fatalf("approve begin missing challenge: %s", rec.Body.String())
	}
	return begin
}

func (f *approveTestFixture) approveFinish(t *testing.T, passID, challengeID string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"challenge_id":"` + challengeID + `","assertion":{"id":"cred-1"}}`
	return f.postPass(t, "/api/v1/mission-passes/"+passID+"/approve/finish", body, "idem-finish-1", nil)
}

func TestApproveBeginFinishHappyPath(t *testing.T) {
	f := newApproveTestFixture(t)
	passID := f.createApprovalDraft(t)
	begin := f.approveBegin(t, passID)

	f.queueAssertion()
	rec := f.approveFinish(t, passID, begin.ChallengeID)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve finish: status %d body %s", rec.Code, rec.Body.String())
	}
	var res struct {
		MissionRef              string `json:"mission_ref"`
		MissionHash             string `json:"mission_hash"`
		AuthScopeMissionVersion int64  `json:"authscope_mission_version"`
		ApprovalDecisionRef     string `json:"approval_decision_ref"`
	}
	decodeBody(t, rec, &res)
	if res.MissionRef != "mission-1" {
		t.Errorf("mission_ref = %q, want mission-1", res.MissionRef)
	}
	if !strings.HasPrefix(res.MissionHash, "sha256:") {
		t.Errorf("mission_hash = %q, want sha256:<hex>", res.MissionHash)
	}
	if res.AuthScopeMissionVersion != 3 {
		t.Errorf("authscope_mission_version = %d, want 3", res.AuthScopeMissionVersion)
	}
	if res.ApprovalDecisionRef == "" {
		t.Errorf("approval_decision_ref is empty")
	}
	if f.stub.approveCalls != 1 {
		t.Errorf("ApproveProposal calls = %d, want 1", f.stub.approveCalls)
	}
	if f.stub.prepareLaunchCalls != 0 {
		t.Errorf("PrepareLaunch calls = %d, want 0", f.stub.prepareLaunchCalls)
	}
	if len(f.stub.approveKeys) != 1 || f.stub.approveKeys[0] != "approve:ws-test:"+passID+":1" {
		t.Errorf("idempotency keys = %v", f.stub.approveKeys)
	}

	// The pass is approved and carries the mission, without a run.
	stored, err := f.store.GetMissionPass(context.Background(), "ws-test", passID)
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if stored.State != "approved" || stored.Reconciliation != "settled" {
		t.Errorf("state = %q reconciliation = %q, want approved/settled", stored.State, stored.Reconciliation)
	}
	if stored.MissionRef != "mission-1" || stored.RunID != "" {
		t.Errorf("mission_ref = %q run_id = %q, want mission-1 and empty", stored.MissionRef, stored.RunID)
	}
}

func TestApproveFinishUnknownChallenge(t *testing.T) {
	f := newApproveTestFixture(t)
	passID := f.createApprovalDraft(t)
	f.queueAssertion()
	rec := f.approveFinish(t, passID, "bogus-challenge")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body = %s", rec.Code, rec.Body.String())
	}
	if f.stub.approveCalls != 0 {
		t.Errorf("ApproveProposal calls = %d, want 0", f.stub.approveCalls)
	}
}

func TestApproveFinishChallengeReplay(t *testing.T) {
	f := newApproveTestFixture(t)
	passID := f.createApprovalDraft(t)
	begin := f.approveBegin(t, passID)
	f.queueAssertion()
	if rec := f.approveFinish(t, passID, begin.ChallengeID); rec.Code != http.StatusOK {
		t.Fatalf("first finish: status %d body %s", rec.Code, rec.Body.String())
	}
	f.queueAssertion()
	rec := f.approveFinish(t, passID, begin.ChallengeID)
	if rec.Code != http.StatusConflict && rec.Code != http.StatusNotFound {
		t.Errorf("replay status = %d, want 404 or 409, body = %s", rec.Code, rec.Body.String())
	}
	if f.stub.missionsCreated != 1 {
		t.Errorf("missions created = %d, want 1", f.stub.missionsCreated)
	}
}

func TestApproveFinishStaleProposal(t *testing.T) {
	f := newApproveTestFixture(t)
	passID := f.createApprovalDraft(t)
	begin := f.approveBegin(t, passID)
	// Narrow the limits after begin: the exact proposal moved.
	expires := time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second)
	body := `{"expected_store_revision":1,"expected_draft_version":1,` +
		`"expires_at":"` + expires.Format(time.RFC3339) + `","max_aggregate_cost_micros":4000000}`
	if rec := f.putPass(t, "/api/v1/mission-passes/"+passID+"/draft", body, "idem-revise-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("revise: status %d body %s", rec.Code, rec.Body.String())
	}
	f.queueAssertion()
	rec := f.approveFinish(t, passID, begin.ChallengeID)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	if f.stub.approveCalls != 0 {
		t.Errorf("ApproveProposal calls = %d, want 0 (stale proposal must not reach upstream)", f.stub.approveCalls)
	}
}

func TestApproveTimeoutReconcilesThroughGet(t *testing.T) {
	f := newApproveTestFixture(t)
	passID := f.createApprovalDraft(t)
	begin := f.approveBegin(t, passID)

	f.stub.failApproveOnce = context.DeadlineExceeded
	f.queueAssertion()
	rec := f.approveFinish(t, passID, begin.ChallengeID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("finish: status %d, want 202, body = %s", rec.Code, rec.Body.String())
	}
	var pending struct {
		Reconciliation string `json:"reconciliation"`
		State          string `json:"state"`
	}
	decodeBody(t, rec, &pending)
	if pending.Reconciliation != "pending" || pending.State != "draft" {
		t.Errorf("202 payload = %+v, want draft/pending review", pending)
	}

	// While the outcome is uncertain the operation is still in flight.
	f.stub.reconcileStatus = "in_flight"
	rec = f.getPass(t, "/api/v1/mission-passes/"+passID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status %d body %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"reconciliation":"pending"`) {
		t.Errorf("GET body lacks pending reconciliation: %s", body)
	}

	// The operation completed upstream: the next GET settles it without a
	// second mission.
	f.stub.reconcileStatus = "completed"
	rec = f.getPass(t, "/api/v1/mission-passes/"+passID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get after settle: status %d body %s", rec.Code, rec.Body.String())
	}
	var settled struct {
		State     string `json:"state"`
		MissionRef string `json:"mission_ref"`
	}
	decodeBody(t, rec, &settled)
	if settled.State != "approved" || settled.MissionRef != "mission-1" {
		t.Errorf("settled = %+v, want approved with mission-1", settled)
	}
	if f.stub.missionsCreated != 1 {
		t.Errorf("missions created = %d, want 1 (no duplicate mission)", f.stub.missionsCreated)
	}
}

func TestApproveBeginOnApprovedConflict(t *testing.T) {
	f := newApproveTestFixture(t)
	passID := f.createApprovalDraft(t)
	begin := f.approveBegin(t, passID)
	f.queueAssertion()
	if rec := f.approveFinish(t, passID, begin.ChallengeID); rec.Code != http.StatusOK {
		t.Fatalf("finish: status %d body %s", rec.Code, rec.Body.String())
	}
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/approve/begin", `{}`, "idem-begin-2", nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("begin on approved: status %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
}

func TestApproveAttestationDigestCoversSignedBytes(t *testing.T) {
	f := newApproveTestFixture(t)
	passID := f.createApprovalDraft(t)
	begin := f.approveBegin(t, passID)
	f.queueAssertion()
	if rec := f.approveFinish(t, passID, begin.ChallengeID); rec.Code != http.StatusOK {
		t.Fatalf("finish: status %d body %s", rec.Code, rec.Body.String())
	}
	if len(f.stub.signedAttestations) != 1 {
		t.Fatalf("signed attestations = %d, want 1", len(f.stub.signedAttestations))
	}
	raw, err := json.Marshal(f.stub.signedAttestations[0])
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])
	stored, err := f.store.GetMissionPass(context.Background(), "ws-test", passID)
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if stored.AttestationDigest != want {
		t.Errorf("attestation_digest = %q, want %q", stored.AttestationDigest, want)
	}
}
