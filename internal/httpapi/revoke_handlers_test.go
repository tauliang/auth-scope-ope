package httpapi

// HTTP coverage for revoke/begin, revoke/finish, and the result-only CLI
// revocation handoff: register, browser decision, loopback redirect, and
// result exchange.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
)

// revokeStubFields extends stubPassAuthority with upstream revocation
// verification. The method overrides the promoted nil embedded
// coreapi.Authority method; without it the call would panic.
func (s *stubPassAuthority) RevokeMission(_ context.Context, missionRef string, in coreapi.RevokeRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Revocation, error) {
	s.revokeCalls++
	s.revokeKeys = append(s.revokeKeys, opts.IdempotencyKey)
	if s.revokedByKey == nil {
		s.revokedByKey = make(map[string]coreapi.Revocation)
	}
	// Idempotent dedupe: a replay of the same key returns the original
	// revocation without re-verifying the attestation, exactly like
	// AuthScope.
	if rev, ok := s.revokedByKey[opts.IdempotencyKey]; ok {
		return rev, nil
	}
	if s.failRevokeOnce != nil {
		err := s.failRevokeOnce
		s.failRevokeOnce = nil
		// The call landed upstream and revoked the mission; only the
		// response was lost.
		rev := coreapi.Revocation{
			MissionRef: missionRef, Revoked: true,
			RevokedAt: time.Now().UTC().UnixMilli(), Containment: "acknowledged",
		}
		s.revokedByKey[opts.IdempotencyKey] = rev
		return coreapi.Revocation{}, err
	}
	if err := s.verifyRevocationAttestation(att, missionRef, in); err != nil {
		return coreapi.Revocation{}, err
	}
	rev := coreapi.Revocation{
		MissionRef: missionRef, Revoked: true,
		RevokedAt: time.Now().UTC().UnixMilli(), Containment: "acknowledged",
	}
	s.revokedByKey[opts.IdempotencyKey] = rev
	return rev, nil
}

func (s *stubPassAuthority) verifyRevocationAttestation(att identity.SignedDecisionAttestation, missionRef string, in coreapi.RevokeRequest) error {
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
	if c.Audience != identity.AudienceMissionRevoke {
		return s.denyApproval("audience mismatch: %q", c.Audience)
	}
	if c.Purpose != identity.PurposeMissionRevoke {
		return s.denyApproval("purpose mismatch: %q", c.Purpose)
	}
	if c.SubjectID != missionRef {
		return s.denyApproval("subject mismatch: %q", c.SubjectID)
	}
	if !validRevocationReasons[in.Reason] {
		return s.denyApproval("reason outside the fixed enum: %q", in.Reason)
	}
	nonceKey := base64.RawURLEncoding.EncodeToString(c.Nonce[:])
	if s.seenNonces[nonceKey] {
		return s.denyApproval("replayed nonce")
	}
	s.seenNonces[nonceKey] = true
	return nil
}

// validRevocationReasons mirrors the service's fixed enum for the stub.
var validRevocationReasons = map[string]bool{
	"founder_requested":  true,
	"safety_concern":     true,
	"mission_superseded": true,
}

// revokeTestFixture bundles an approved pass with revocation helpers.
type revokeTestFixture struct {
	*passFixture
	assertIdx int
}

func newRevokeTestFixture(t *testing.T) *revokeTestFixture {
	t.Helper()
	// approvedPass consumes sign count 1, so the revocation assertions
	// start at 2: the credential sign count must strictly advance.
	return &revokeTestFixture{passFixture: newPassFixture(t), assertIdx: 1}
}

// queueRevokeAssertion queues one successful decision assertion with an
// advancing sign count.
func (f *revokeTestFixture) queueRevokeAssertion() {
	f.assertIdx++
	f.authTestFixture.stub.assertOutcomes = append(f.authTestFixture.stub.assertOutcomes, authn.VerifiedAssertion{
		CredentialID: []byte("cred-1"),
		NewSignCount: uint32(f.assertIdx),
		UserVerified: true,
	})
}

func (f *revokeTestFixture) revokeBegin(t *testing.T, passID, reason string) struct {
	ChallengeID string `json:"challenge_id"`
} {
	t.Helper()
	body := `{"reason":` + strconv.Quote(reason) + `}`
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", body, "idem-revoke-begin", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	decodeBody(t, rec, &begin)
	if begin.ChallengeID == "" {
		t.Fatalf("revoke begin missing challenge: %s", rec.Body.String())
	}
	return begin
}

func (f *revokeTestFixture) revokeFinish(t *testing.T, passID, challengeID string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"challenge_id":"` + challengeID + `","assertion":{"id":"cred-1"}}`
	return f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/finish", body, "idem-revoke-finish", nil)
}

func TestRevokeBeginFinishHappyPath(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)

	begin := f.revokeBegin(t, passID, "founder_requested")
	f.queueRevokeAssertion()
	rec := f.revokeFinish(t, passID, begin.ChallengeID)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke finish: status %d body %s", rec.Code, rec.Body.String())
	}
	var res struct {
		PassID      string `json:"pass_id"`
		MissionRef  string `json:"mission_ref"`
		Revoked     bool   `json:"revoked"`
		Containment string `json:"containment"`
		ReasonCode  string `json:"reason_code"`
	}
	decodeBody(t, rec, &res)
	if res.PassID != passID {
		t.Errorf("pass_id = %q, want %q", res.PassID, passID)
	}
	if !res.Revoked {
		t.Errorf("revoked = false, want true")
	}
	if res.Containment != "acknowledged" {
		t.Errorf("containment = %q, want acknowledged", res.Containment)
	}
	if res.ReasonCode != "founder_requested" {
		t.Errorf("reason_code = %q, want founder_requested", res.ReasonCode)
	}
	if f.stub.revokeCalls != 1 {
		t.Errorf("upstream revoke calls = %d, want 1", f.stub.revokeCalls)
	}
	// The pass is revoked; a second begin is a conflict.
	rec = f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", `{"reason":"founder_requested"}`, "idem-revoke-begin-2", nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("second begin status = %d, want 409", rec.Code)
	}
}

func TestRevokeBeginInvalidReason(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", `{"reason":"founder_changed_mind"}`, "idem-revoke-begin-bad", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestRevokeBeginDraftNotRevocable(t *testing.T) {
	f := newRevokeTestFixture(t)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	passID := f.createDraft(t, expires, 5_000_000)
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", `{"reason":"safety_concern"}`, "idem-revoke-begin-draft", nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", rec.Code)
	}
}

func TestRevokeFinishAmbiguousReturns202(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	begin := f.revokeBegin(t, passID, "safety_concern")
	f.queueRevokeAssertion()
	// The upstream revoke lands but the response is lost: a retryable
	// upstream status is ambiguous, never a plain error.
	f.stub.failRevokeOnce = &coreapi.UpstreamError{StatusCode: 503, Code: "unavailable", Message: "stub: dropped response"}
	rec := f.revokeFinish(t, passID, begin.ChallengeID)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body %s", rec.Code, rec.Body.String())
	}
	var pending struct {
		PassID         string `json:"pass_id"`
		Reconciliation string `json:"reconciliation"`
	}
	decodeBody(t, rec, &pending)
	if pending.PassID != passID {
		t.Errorf("pass_id = %q, want %q", pending.PassID, passID)
	}
	if pending.Reconciliation != "pending" {
		t.Errorf("reconciliation = %q, want pending", pending.Reconciliation)
	}
}

func TestRevokeOriginGuard(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", `{"reason":"founder_requested"}`, "idem-revoke-origin", map[string]string{"Origin": "https://evil.example.com"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestRevokeRequiresSession(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	f.withoutSession(t, func() {
		rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", `{"reason":"founder_requested"}`, "idem-revoke-nosess", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})
}

// cliRevocationHarness registers one CLI revocation request and returns
// the registration response plus the PKCE verifier.
type cliRevocationHarness struct {
	requestID string
	state     string
	verifier  string
	redirect  string
	digest    string
}

func (f *revokeTestFixture) registerCLIRevocation(t *testing.T, passID string) *cliRevocationHarness {
	t.Helper()
	verifier, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	state, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	redirect := "http://127.0.0.1:54321/callback"
	rec := f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/revocations", map[string]string{
		"Host":         "ope.example.com",
		"Content-Type": "application/json",
	}, map[string]any{
		"pass_id":               passID,
		"redirect_uri":          redirect,
		"state":                 state,
		"code_challenge":        authn.CodeChallengeS256(verifier),
		"code_challenge_method": "S256",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status %d body %s", rec.Code, rec.Body.String())
	}
	var reg struct {
		RequestID        string `json:"request_id"`
		BrowserURL       string `json:"browser_url"`
		RevocationDigest string `json:"revocation_digest"`
	}
	decodeBody(t, rec, &reg)
	if reg.RequestID == "" || reg.BrowserURL == "" || reg.RevocationDigest == "" {
		t.Fatalf("register missing fields: %s", rec.Body.String())
	}
	if !strings.Contains(reg.BrowserURL, "/mission/"+passID+"?cli_revocation="+reg.RequestID) {
		t.Errorf("browser_url = %q, want mission path with cli_revocation", reg.BrowserURL)
	}
	return &cliRevocationHarness{
		requestID: reg.RequestID,
		state:     state,
		verifier:  verifier,
		redirect:  redirect,
		digest:    reg.RevocationDigest,
	}
}

func TestCLIRevocationLoopbackFlow(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	h := f.registerCLIRevocation(t, passID)

	// Browser decision: the normal revoke begin, with the founder
	// picking the reason.
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", `{"reason":"mission_superseded"}`, "idem-cli-revoke-begin", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	decodeBody(t, rec, &begin)
	if begin.ChallengeID == "" {
		t.Fatalf("begin missing challenge: %s", rec.Body.String())
	}

	// Browser decision: the normal finish carries the CLI request ID,
	// so it 302s to the exact loopback callback instead of returning
	// JSON.
	f.queueRevokeAssertion()
	rec = f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/finish",
		`{"challenge_id":"`+begin.ChallengeID+`","assertion":{"id":"cred-1"},"cli_revocation_id":"`+h.requestID+`"}`, "idem-cli-revoke-finish", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("CLI finish: status %d body %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, h.redirect+"?code=") {
		t.Fatalf("location = %q, want loopback callback with code", location)
	}
	if !strings.Contains(location, "state="+h.state) {
		t.Errorf("location = %q, want original state", location)
	}
	code := strings.SplitN(strings.TrimPrefix(location, h.redirect+"?code="), "&", 2)[0]
	if code == "" {
		t.Fatalf("no code in redirect: %q", location)
	}

	// Exchange: one-use code plus verifier returns only the result
	// reference and the containment.
	rec = f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/revocations/token", map[string]string{
		"Host":         "ope.example.com",
		"Content-Type": "application/json",
	}, map[string]any{
		"code":          code,
		"code_verifier": h.verifier,
		"redirect_uri":  h.redirect,
		"state":         h.state,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("exchange: status %d body %s", rec.Code, rec.Body.String())
	}
	var exchanged struct {
		ResultRef   string `json:"result_ref"`
		Containment string `json:"containment"`
	}
	decodeBody(t, rec, &exchanged)
	if exchanged.ResultRef == "" {
		t.Errorf("missing result_ref: %s", rec.Body.String())
	}
	if exchanged.Containment != "acknowledged" {
		t.Errorf("containment = %q, want acknowledged", exchanged.Containment)
	}
	// An identical retry recovers the original result: the exchange is
	// idempotent so a lost response does not lose the revocation.
	rec = f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/revocations/token", map[string]string{
		"Host":         "ope.example.com",
		"Content-Type": "application/json",
	}, map[string]any{
		"code":          code,
		"code_verifier": h.verifier,
		"redirect_uri":  h.redirect,
		"state":         h.state,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("replay exchange: status %d, want 200", rec.Code)
	}
	var replayed struct {
		ResultRef   string `json:"result_ref"`
		Containment string `json:"containment"`
	}
	decodeBody(t, rec, &replayed)
	if replayed.ResultRef != exchanged.ResultRef {
		t.Errorf("replay result_ref = %q, want %q", replayed.ResultRef, exchanged.ResultRef)
	}
	// A wrong verifier is rejected without distinguishing the cause.
	rec = f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/revocations/token", map[string]string{
		"Host":         "ope.example.com",
		"Content-Type": "application/json",
	}, map[string]any{
		"code":          code,
		"code_verifier": "wrong-verifier",
		"redirect_uri":  h.redirect,
		"state":         h.state,
	})
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong verifier status = %d, want 401", rec.Code)
	}
}

func TestCLIRevocationFinishRejectsUnknownRequest(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	// The normal begin still works, but the finish fails before any
	// revocation runs when the CLI request is unknown.
	rec := f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/begin", `{"reason":"founder_requested"}`, "idem-unknown-begin", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	decodeBody(t, rec, &begin)
	f.queueRevokeAssertion()
	rec = f.postPass(t, "/api/v1/mission-passes/"+passID+"/revoke/finish",
		`{"challenge_id":"`+begin.ChallengeID+`","assertion":{"id":"cred-1"},"cli_revocation_id":"clr-unknown"}`, "idem-unknown-finish", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown finish: status %d, want 404", rec.Code)
	}
	// The revocation did not run: the pass is still approved.
	stored, err := f.store.GetMissionPass(context.Background(), "ws-test", passID)
	if err != nil {
		t.Fatalf("get pass: %v", err)
	}
	if stored.State != "approved" {
		t.Errorf("pass state = %q, want approved", stored.State)
	}
}
