package httpapi

// Task 8: one-use browser PKCE handoff for CLI launch authorization.
// These tests run the full route path through the real HTTP handlers,
// including the browser approval begin/finish and the loopback redirect.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
)

type cliBrowserHarness struct {
	authzID   string
	start     CLIAuthorizationStart
	verifier  string
	state     string
	passID    string
	challenge string
}

// queueAssertion queues one successful decision assertion with the given
// sign count and user-verification flag.
func (f *passFixture) queueAssertion(t *testing.T, signCount uint32, userVerified bool) {
	t.Helper()
	f.authTestFixture.stub.assertOutcomes = append(f.authTestFixture.stub.assertOutcomes, authn.VerifiedAssertion{
		CredentialID: []byte("cred-1"),
		NewSignCount: signCount,
		UserVerified: userVerified,
	})
}

// approvedPass creates a draft and runs the full approval flow, returning
// an approved pass ID for the CLI handoff tests.
func (f *passFixture) approvedPass(t *testing.T) string {
	t.Helper()
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	rec := f.postPass(t, "/api/v1/mission-passes/drafts", createDraftBody(expires, 5_000_000), "idem-cli-1", nil)
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
	rec = f.postPass(t, "/api/v1/mission-passes/"+created.PassID+"/approve/begin", `{}`, "idem-cli-begin-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		ChallengeID string `json:"challenge_id"`
	}
	decodeBody(t, rec, &begin)
	if begin.ChallengeID == "" {
		t.Fatalf("approve begin missing challenge: %s", rec.Body.String())
	}
	f.queueAssertion(t, 1, true)
	rec = f.postPass(t, "/api/v1/mission-passes/"+created.PassID+"/approve/finish",
		`{"challenge_id":"`+begin.ChallengeID+`","assertion":{"id":"cred-1"}}`, "idem-cli-finish-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve finish: status %d body %s", rec.Code, rec.Body.String())
	}
	return created.PassID
}

func (f *passFixture) newCLIAuthHarness(t *testing.T) *cliBrowserHarness {
	t.Helper()
	passID := f.approvedPass(t)
	verifier, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	state, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	h := &cliBrowserHarness{verifier: verifier, state: state, passID: passID}
	rec := f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/authorizations",
		map[string]string{"Content-Type": "application/json"},
		map[string]any{
			"pass_id":               passID,
			"redirect_uri":          "http://127.0.0.1:54321/callback",
			"state":                 state,
			"code_challenge":        authn.CodeChallengeS256(verifier),
			"code_challenge_method": "S256",
			"ephemeral_public_key":  ephemeralPublicKey(t),
		})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var start CLIAuthorizationStart
	decodeBody(t, rec, &start)
	if start.AuthorizationID == "" || start.BrowserURL == "" {
		t.Fatalf("bad start: %+v", start)
	}
	// Task 8: the create response returns the exact approved proposal
	// digest, agent-kit ID/version, ordered arguments, and invocation
	// digest. The CLI recomputes the pinned invocation digest and must
	// agree with the authoritative stored digest.
	if start.ProposalDigest != "sha256:"+strings.Repeat("f", 64) {
		t.Errorf("proposal_digest = %q", start.ProposalDigest)
	}
	if start.AgentKitID != "authscope-agent-kit" || start.AgentKitVersion != "1.0.0" {
		t.Errorf("kit = %q %q", start.AgentKitID, start.AgentKitVersion)
	}
	if len(start.RunnerArguments) != 2 || start.RunnerArguments[0] != "authscope-agent-run" {
		t.Errorf("runner_arguments = %v", start.RunnerArguments)
	}
	wantInvocation := authn.InvocationDigestForLaunch(start.AgentKitID, start.AgentKitVersion, start.RunnerArguments)
	if start.InvocationDigest != wantInvocation {
		t.Errorf("invocation_digest = %q, recomputed %q", start.InvocationDigest, wantInvocation)
	}
	h.authzID = start.AuthorizationID
	h.start = start
	return h
}

// doJSONRaw posts a JSON body (or a raw string) with explicit headers,
// without the session guard headers.
func (f *passFixture) doJSONRaw(t *testing.T, method, path string, headers map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var raw string
	if s, ok := body.(string); ok {
		raw = s
	} else {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		raw = string(b)
	}
	return f.doRaw(t, method, path, raw, headers)
}

// withoutSession runs fn with the fixture's cookie jar cleared, so the
// request carries no founder session.
func (f *passFixture) withoutSession(t *testing.T, fn func()) {
	t.Helper()
	saved := f.jar
	f.jar = map[string]*http.Cookie{}
	defer func() { f.jar = saved }()
	fn()
}

// browserApproveCLI runs the founder browser decision for the CLI
// authorization: begin, assert with user verification, finish.
func (f *passFixture) browserApproveCLI(t *testing.T, h *cliBrowserHarness) string {
	t.Helper()
	rec := f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/begin", "", "idem-cli-approve-begin", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("begin status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		ChallengeID      string   `json:"challenge_id"`
		PassID           string   `json:"pass_id"`
		ProposalDigest   string   `json:"proposal_digest"`
		InvocationDigest string   `json:"invocation_digest"`
		AgentKitID       string   `json:"agent_kit_id"`
		AgentKitVersion  string   `json:"agent_kit_version"`
		RunnerArguments  []string `json:"runner_arguments"`
	}
	decodeBody(t, rec, &begin)
	if begin.ChallengeID == "" {
		t.Fatalf("begin missing challenge: %s", rec.Body.String())
	}
	if begin.PassID != h.passID || begin.ProposalDigest != h.start.ProposalDigest ||
		begin.InvocationDigest != h.start.InvocationDigest {
		t.Fatalf("begin binding mismatch: %+v", begin)
	}
	h.challenge = begin.ChallengeID
	f.queueAssertion(t, 3, true)
	rec = f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/finish",
		`{"challenge_id":"`+begin.ChallengeID+`","assertion":{}}`, "idem-cli-approve-finish", nil)
	// Task 8: finish answers a real 302 redirect to the exact loopback
	// callback; the UI shows only "Return to the CLI" afterwards.
	if rec.Code != http.StatusFound {
		t.Fatalf("finish status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return rec.Header().Get("Location")
}

func TestCLIAuthorizationEndToEnd(t *testing.T) {
	f := newPassFixture(t)
	h := f.newCLIAuthHarness(t)
	redirect := f.browserApproveCLI(t, h)
	// The finish step redirects the code and the original state to the
	// exact loopback callback the CLI registered.
	if !strings.HasPrefix(redirect, "http://127.0.0.1:54321/callback?code=") {
		t.Fatalf("redirect = %q", redirect)
	}
	rest := strings.TrimPrefix(redirect, "http://127.0.0.1:54321/callback?code=")
	code := rest
	if i := strings.Index(rest, "&"); i >= 0 {
		code = rest[:i]
	}
	if !strings.Contains(redirect, "state="+h.state) {
		t.Fatalf("redirect missing original state: %q", redirect)
	}
	if code == "" {
		t.Fatalf("redirect missing code: %q", redirect)
	}
	// The code is one-use: a second browser decision on the same
	// authorization fails closed.
	rec := f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/begin", "", "idem-cli-second-begin", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("second begin status = %d, want 409", rec.Code)
	}
}

func TestCLIAuthorizationCreateRejections(t *testing.T) {
	f := newPassFixture(t)
	passID := f.approvedPass(t)
	newBody := func() map[string]any {
		verifier, err := authn.NewPKCEVerifier()
		if err != nil {
			t.Fatalf("verifier: %v", err)
		}
		state, err := authn.NewPKCEVerifier()
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		return map[string]any{
			"pass_id":               passID,
			"redirect_uri":          "http://127.0.0.1:54321/callback",
			"state":                 state,
			"code_challenge":        authn.CodeChallengeS256(verifier),
			"code_challenge_method": "S256",
			"ephemeral_public_key":  ephemeralPublicKey(t),
		}
	}
	cases := []struct {
		name       string
		mutate     func(map[string]any)
		wantStatus int
	}{
		{"localhost redirect", func(b map[string]any) { b["redirect_uri"] = "http://localhost:54321/callback" }, http.StatusBadRequest},
		{"non-loopback redirect", func(b map[string]any) { b["redirect_uri"] = "http://10.0.0.1:54321/callback" }, http.StatusBadRequest},
		{"https redirect", func(b map[string]any) { b["redirect_uri"] = "https://127.0.0.1:54321/callback" }, http.StatusBadRequest},
		{"wrong path", func(b map[string]any) { b["redirect_uri"] = "http://127.0.0.1:54321/x" }, http.StatusBadRequest},
		{"plain pkce", func(b map[string]any) { b["code_challenge_method"] = "plain" }, http.StatusBadRequest},
		{"short challenge", func(b map[string]any) { b["code_challenge"] = "short" }, http.StatusBadRequest},
		{"short ephemeral key", func(b map[string]any) { b["ephemeral_public_key"] = "short" }, http.StatusBadRequest},
		{"unknown pass", func(b map[string]any) { b["pass_id"] = "pass-nope" }, http.StatusNotFound},
		{"malformed json", nil, http.StatusBadRequest},
		{"empty body", func(b map[string]any) {
			for k := range b {
				delete(b, k)
			}
		}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec *httptest.ResponseRecorder
			if tc.mutate == nil {
				rec = f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/authorizations",
					map[string]string{"Content-Type": "application/json"}, "not json")
			} else {
				body := newBody()
				tc.mutate(body)
				rec = f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/authorizations",
					map[string]string{"Content-Type": "application/json"}, body)
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestCLIAuthorizationBeginRejections(t *testing.T) {
	f := newPassFixture(t)
	h := f.newCLIAuthHarness(t)
	// No session: 401.
	var rec *httptest.ResponseRecorder
	f.withoutSession(t, func() {
		rec = f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/begin", "", "idem-nosess-1", nil)
	})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated begin status = %d, want 401", rec.Code)
	}
	// Wrong origin: 403.
	rec = f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/begin", "", "idem-origin-1",
		map[string]string{"Origin": "https://evil.example.com"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bad origin begin status = %d, want 403", rec.Code)
	}
	// Unknown authorization: 404.
	rec = f.postPass(t, "/api/v1/cli/authorizations/authz-nope/approve/begin", "", "idem-unknown-1", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown begin status = %d, want 404", rec.Code)
	}
	// Missing idempotency key: 400.
	rec = f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/begin", "", "ignored",
		map[string]string{"Idempotency-Key": ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing idempotency key begin status = %d, want 400", rec.Code)
	}
	// Bad content type on finish: 415.
	rec = f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/finish", "", "idem-ct-1",
		map[string]string{"Content-Type": "text/plain"})
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("finish content-type status = %d, want 415", rec.Code)
	}
}

func TestCLIAuthorizationFinishWrongChallenge(t *testing.T) {
	f := newPassFixture(t)
	h := f.newCLIAuthHarness(t)
	rec := f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/begin", "", "idem-cli-wrong-begin", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("begin status = %d", rec.Code)
	}
	f.queueAssertion(t, 3, true)
	// Finishing with a different challenge id fails closed: the ceremony
	// is not found.
	rec = f.postPass(t, "/api/v1/cli/authorizations/"+h.authzID+"/approve/finish",
		`{"challenge_id":"dec-nope","assertion":{}}`, "idem-cli-wrong-finish", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("wrong challenge finish status = %d, want 404", rec.Code)
	}
}

func TestCLIAuthorizationRateLimited(t *testing.T) {
	f := newPassFixture(t)
	// The limiter is shared per server; hammer create to trigger it.
	var last int
	for i := 0; i < 40; i++ {
		verifier, _ := authn.NewPKCEVerifier()
		state, _ := authn.NewPKCEVerifier()
		rec := f.doJSONRaw(t, http.MethodPost, "/api/v1/cli/authorizations",
			map[string]string{"Content-Type": "application/json"},
			map[string]any{
				"pass_id":               "pass-nope-" + string(rune('a'+i%26)),
				"redirect_uri":          "http://127.0.0.1:54321/callback",
				"state":                 state,
				"code_challenge":        authn.CodeChallengeS256(verifier),
				"code_challenge_method": "S256",
				"ephemeral_public_key":  ephemeralPublicKey(t),
			})
		last = rec.Code
		if last == http.StatusTooManyRequests {
			break
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after hammering create, last status = %d", last)
	}
}

// ephemeralPublicKey returns a valid base64url 32-byte X25519 public key
// for request fixtures.
func ephemeralPublicKey(t *testing.T) string {
	t.Helper()
	return "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
}
