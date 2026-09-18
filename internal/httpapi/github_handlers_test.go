package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/github"
)

// stubGitHubAuthority implements the AuthScope broker surface for the
// GitHub HTTP tests. All fixtures are recognizably fake; no credential
// material appears here.
type stubGitHubAuthority struct {
	coreapi.Authority
	beginHandoff  coreapi.GitHubBindingHandoff
	binding       coreapi.RepositoryBinding
	issue         coreapi.GitHubIssueSnapshot
	posture       coreapi.WorkflowPosture
	finishCalls   int
	lastFinishKey string
}

func (s *stubGitHubAuthority) BeginGitHubBinding(_ context.Context, in coreapi.GitHubBindingBeginRequest, opts coreapi.RequestOptions) (coreapi.GitHubBindingHandoff, error) {
	if in.Repository == "" || opts.IdempotencyKey == "" {
		return coreapi.GitHubBindingHandoff{}, &coreapi.UpstreamError{StatusCode: 400, Message: "bad request"}
	}
	return s.beginHandoff, nil
}

func (s *stubGitHubAuthority) ReconcileOperation(_ context.Context, _, _ string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	return coreapi.OperationResult{Status: "unknown"}, nil
}

func (s *stubGitHubAuthority) FinishGitHubBinding(_ context.Context, in coreapi.GitHubBindingFinishRequest, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	s.finishCalls++
	s.lastFinishKey = opts.IdempotencyKey
	if in.HandoffID == "" || in.BindingCode == "" {
		return coreapi.RepositoryBinding{}, &coreapi.UpstreamError{StatusCode: 400, Message: "bad request"}
	}
	return s.binding, nil
}

func (s *stubGitHubAuthority) GetRepositoryBinding(_ context.Context, _ string, _ coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return s.binding, nil
}

func (s *stubGitHubAuthority) ReadGitHubIssue(_ context.Context, _ coreapi.GitHubIssueRequest, _ coreapi.RequestOptions) (coreapi.GitHubIssueSnapshot, error) {
	return s.issue, nil
}

func (s *stubGitHubAuthority) InspectWorkflowPosture(_ context.Context, _ coreapi.WorkflowPostureRequest, _ coreapi.RequestOptions) (coreapi.WorkflowPosture, error) {
	return s.posture, nil
}

type githubFixture struct {
	*authTestFixture
	stub *stubGitHubAuthority
	csrf string
}

func newGitHubFixture(t *testing.T) *githubFixture {
	t.Helper()
	f := newAuthTestFixture(t)
	f.config.AuthScopeURL = "https://authscope.local"
	stub := &stubGitHubAuthority{
		beginHandoff: coreapi.GitHubBindingHandoff{
			HandoffID:       "upstream-handoff-1",
			BindingCode:     "recognizably-fake-binding-code",
			InstallationURL: "https://authscope.local/install/github?handoff_id=upstream-handoff-1",
			ExpiresAt:       time.Now().UTC().Add(10 * time.Minute).Unix(),
		},
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
	deps := Dependencies{
		Config: f.config,
		Contract: coreapi.ContractReport{
			CoreVersion: "ope-v1.0.0", DigestMatch: true,
			OperationsRequired: 36, OperationsPresent: 36,
		},
		Store:     f.store,
		Authn:     f.authn,
		Authority: stub,
	}
	f.handler = New(deps)
	csrf := f.enrollOverHTTP(t)
	return &githubFixture{authTestFixture: f, stub: stub, csrf: csrf}
}

// postGitHub sends an authenticated JSON POST with the guards' exact
// headers plus CSRF and idempotency key.
func (f *githubFixture) postGitHub(t *testing.T, path, body, idemKey string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h := map[string]string{
		"Host":            "ope.example.com",
		"Origin":          "https://ope.example.com",
		"Content-Type":    "application/json",
		"X-CSRF-Token":    f.csrf,
		"Idempotency-Key": idemKey,
	}
	for k, v := range headers {
		if v == "" {
			delete(h, k)
		} else {
			h[k] = v
		}
	}
	return f.doRaw(t, http.MethodPost, path, body, h)
}

// getGitHub sends an authenticated GET with the exact Host.
func (f *githubFixture) getGitHub(t *testing.T, path string, authed bool) *httptest.ResponseRecorder {
	t.Helper()
	if !authed {
		saved := f.jar
		f.jar = map[string]*http.Cookie{}
		defer func() { f.jar = saved }()
	}
	req := httptest.NewRequest(http.MethodGet, "https://ope.example.com"+path, nil)
	req.Host = "ope.example.com"
	for _, c := range f.jar {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func TestGitHubBeginGuards(t *testing.T) {
	f := newGitHubFixture(t)
	body := `{"repository":"octo-org/repo"}`
	cases := []struct {
		name    string
		headers map[string]string
		body    string
		want    int
	}{
		{"wrong host", map[string]string{"Host": "evil.example.com"}, body, http.StatusForbidden},
		{"wrong origin", map[string]string{"Origin": "https://evil.example.com"}, body, http.StatusForbidden},
		{"wrong content type", map[string]string{"Content-Type": "text/plain"}, body, http.StatusUnsupportedMediaType},
		{"missing csrf", map[string]string{"X-CSRF-Token": ""}, body, http.StatusForbidden},
		{"missing idempotency key", map[string]string{"Idempotency-Key": ""}, body, http.StatusBadRequest},
		{"bad json", nil, `{not json`, http.StatusBadRequest},
		{"unknown field", nil, `{"repository":"octo-org/repo","token":"ghp_fake"}`, http.StatusBadRequest},
		{"invalid repo", nil, `{"repository":"not a repo"}`, http.StatusBadRequest},
		{"empty body", nil, ``, http.StatusBadRequest},
	}
	for _, tc := range cases {
		rec := f.postGitHub(t, "/api/v1/connections/github/begin", tc.body, "idem-guard", tc.headers)
		if rec.Code != tc.want {
			t.Fatalf("%s: status = %d, want %d, body %s", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
	// Unauthenticated (no session cookie) is rejected.
	saved := f.jar
	f.jar = map[string]*http.Cookie{}
	rec := f.postGitHub(t, "/api/v1/connections/github/begin", body, "idem-guard-2", nil)
	f.jar = saved
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated begin: status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestGitHubBeginFinishFlow(t *testing.T) {
	f := newGitHubFixture(t)
	rec := f.postGitHub(t, "/api/v1/connections/github/begin", `{"repository":"octo-org/repo"}`, "idem-flow-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		HandoffID       string `json:"handoff_id"`
		InstallationURL string `json:"installation_url"`
		ExpiresAt       string `json:"expires_at"`
	}
	decodeBody(t, rec, &begin)
	if begin.HandoffID == "" || begin.InstallationURL == "" || begin.ExpiresAt == "" {
		t.Fatalf("begin missing fields: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "recognizably-fake-binding-code") {
		t.Fatal("begin response leaks binding code")
	}
	u, err := url.Parse(begin.InstallationURL)
	if err != nil {
		t.Fatalf("parse installation URL: %v", err)
	}
	if u.Scheme+"://"+u.Host != "https://authscope.local" {
		t.Fatalf("installation URL origin = %s", u.Scheme+"://"+u.Host)
	}
	state := u.Query().Get("state")
	if state == "" || u.Query().Get("handoff_id") != begin.HandoffID {
		t.Fatalf("installation URL missing handoff/state: %s", begin.InstallationURL)
	}

	// The AuthScope redirect: exactly three query fields, no session
	// needed, fixed same-origin redirect, nothing reflected.
	cbPath := "/api/v1/connections/github/callback?handoff_id=" + url.QueryEscape(begin.HandoffID) +
		"&code=" + url.QueryEscape("one-use-code-1") + "&state=" + url.QueryEscape(state)
	cbRec := f.getGitHub(t, cbPath, false)
	if cbRec.Code != http.StatusSeeOther {
		t.Fatalf("callback: status %d body %s", cbRec.Code, cbRec.Body.String())
	}
	if loc := cbRec.Header().Get("Location"); loc != githubCompletionPath {
		t.Fatalf("callback redirect = %q", loc)
	}
	if strings.Contains(cbRec.Body.String(), "one-use-code-1") || strings.Contains(cbRec.Body.String(), state) {
		t.Fatal("callback response reflects query material")
	}

	// Finish with the original session.
	finRec := f.postGitHub(t, "/api/v1/connections/github/"+begin.HandoffID+"/finish", `{}`, "idem-flow-2", nil)
	if finRec.Code != http.StatusOK {
		t.Fatalf("finish: status %d body %s", finRec.Code, finRec.Body.String())
	}
	var conn GitHubConnectionView
	decodeBody(t, finRec, &conn)
	if conn.ConnectionID != "binding-1" || conn.WorkspaceID != "ws-test" {
		t.Fatalf("connection = %+v", conn)
	}
	if conn.InstallationID != 222 || conn.RepositoryID != 111 || conn.RepositoryName != "octo-org/repo" {
		t.Fatalf("connection identity wrong: %+v", conn)
	}
	if conn.PermissionStatus != "ok" || conn.VerifiedAt == "" {
		t.Fatalf("connection status wrong: %+v", conn)
	}
	if f.stub.finishCalls != 1 {
		t.Fatalf("finishCalls = %d", f.stub.finishCalls)
	}

	// Retried finish with the same idempotency key replays without a
	// second upstream mutation.
	finRec2 := f.postGitHub(t, "/api/v1/connections/github/"+begin.HandoffID+"/finish", `{}`, "idem-flow-2", nil)
	if finRec2.Code != http.StatusOK {
		t.Fatalf("replayed finish: status %d body %s", finRec2.Code, finRec2.Body.String())
	}
	if f.stub.finishCalls != 1 {
		t.Fatalf("replayed finish reached upstream: %d", f.stub.finishCalls)
	}
}

func TestGitHubCallbackRejects(t *testing.T) {
	f := newGitHubFixture(t)
	rec := f.postGitHub(t, "/api/v1/connections/github/begin", `{"repository":"octo-org/repo"}`, "idem-cb-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: status %d", rec.Code)
	}
	var begin struct {
		HandoffID       string `json:"handoff_id"`
		InstallationURL string `json:"installation_url"`
	}
	decodeBody(t, rec, &begin)
	u, _ := url.Parse(begin.InstallationURL)
	state := u.Query().Get("state")
	base := "/api/v1/connections/github/callback?handoff_id=" + url.QueryEscape(begin.HandoffID) +
		"&code=" + url.QueryEscape("c") + "&state=" + url.QueryEscape(state)

	cases := []struct {
		name string
		path string
		want int
	}{
		{"extra field", base + "&evil=1", http.StatusBadRequest},
		{"missing code", "/api/v1/connections/github/callback?handoff_id=" + url.QueryEscape(begin.HandoffID) + "&state=" + url.QueryEscape(state), http.StatusBadRequest},
		{"unknown handoff", "/api/v1/connections/github/callback?handoff_id=nope&code=c&state=" + url.QueryEscape(state), http.StatusNotFound},
		{"wrong state", base[:len(base)-4] + "0000", http.StatusBadRequest},
	}
	for _, tc := range cases {
		r := f.getGitHub(t, tc.path, false)
		if r.Code != tc.want {
			t.Fatalf("%s: status = %d, want %d, body %s", tc.name, r.Code, tc.want, r.Body.String())
		}
		if strings.Contains(r.Body.String(), "one-use") || strings.Contains(r.Body.String(), state) {
			t.Fatalf("%s: problem body reflects callback material", tc.name)
		}
	}

	// Wrong Host on the callback is rejected.
	req := httptest.NewRequest(http.MethodGet, "https://ope.example.com"+base, nil)
	req.Host = "evil.example.com"
	rec2 := httptest.NewRecorder()
	f.handler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("callback wrong host: status = %d", rec2.Code)
	}
}

func TestGitHubIssueFlow(t *testing.T) {
	f := newGitHubFixture(t)
	// Connect first.
	rec := f.postGitHub(t, "/api/v1/connections/github/begin", `{"repository":"octo-org/repo"}`, "idem-issue-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: status %d", rec.Code)
	}
	var begin struct {
		HandoffID       string `json:"handoff_id"`
		InstallationURL string `json:"installation_url"`
	}
	decodeBody(t, rec, &begin)
	u, _ := url.Parse(begin.InstallationURL)
	cb := "/api/v1/connections/github/callback?handoff_id=" + url.QueryEscape(begin.HandoffID) +
		"&code=" + url.QueryEscape("code-issue") + "&state=" + url.QueryEscape(u.Query().Get("state"))
	if r := f.getGitHub(t, cb, false); r.Code != http.StatusSeeOther {
		t.Fatalf("callback: status %d", r.Code)
	}
	fin := f.postGitHub(t, "/api/v1/connections/github/"+begin.HandoffID+"/finish", `{}`, "idem-issue-2", nil)
	if fin.Code != http.StatusOK {
		t.Fatalf("finish: status %d body %s", fin.Code, fin.Body.String())
	}

	issueRec := f.getGitHub(t, "/api/v1/connections/github/binding-1/issues/42", true)
	if issueRec.Code != http.StatusOK {
		t.Fatalf("issue: status %d body %s", issueRec.Code, issueRec.Body.String())
	}
	var issue GitHubIssueResponse
	decodeBody(t, issueRec, &issue)
	if issue.Snapshot.IssueNumber != 42 || issue.Snapshot.Objective != "Add retries" {
		t.Fatalf("snapshot = %+v", issue.Snapshot)
	}
	if issue.Snapshot.SourceDigest != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("source digest = %q", issue.Snapshot.SourceDigest)
	}
	if len(issue.Snapshot.AcceptanceCriteria) != 1 || issue.Snapshot.AcceptanceCriteria[0] != "retry with backoff" {
		t.Fatalf("criteria = %v", issue.Snapshot.AcceptanceCriteria)
	}
	if issue.Posture.Outcome != "clean" || issue.Posture.HeadSHA != strings.Repeat("a", 40) {
		t.Fatalf("posture = %+v", issue.Posture)
	}
	if issue.Posture.CheckedAt == "" || issue.Posture.ExpiresAt == "" {
		t.Fatalf("posture window missing: %+v", issue.Posture)
	}

	// Unknown connection and bad issue numbers fail closed.
	if r := f.getGitHub(t, "/api/v1/connections/github/nope/issues/42", true); r.Code != http.StatusNotFound {
		t.Fatalf("unknown connection: status = %d", r.Code)
	}
	if r := f.getGitHub(t, "/api/v1/connections/github/binding-1/issues/0", true); r.Code != http.StatusBadRequest {
		t.Fatalf("bad issue number: status = %d", r.Code)
	}
	if r := f.getGitHub(t, "/api/v1/connections/github/binding-1/issues/42", false); r.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated issue read: status = %d", r.Code)
	}
}

func TestGitHubIssueClosedFails(t *testing.T) {
	f := newGitHubFixture(t)
	f.stub.issue.State = "closed"
	rec := f.postGitHub(t, "/api/v1/connections/github/begin", `{"repository":"octo-org/repo"}`, "idem-closed-1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin: status %d", rec.Code)
	}
	var begin struct {
		HandoffID       string `json:"handoff_id"`
		InstallationURL string `json:"installation_url"`
	}
	decodeBody(t, rec, &begin)
	u, _ := url.Parse(begin.InstallationURL)
	cb := "/api/v1/connections/github/callback?handoff_id=" + url.QueryEscape(begin.HandoffID) +
		"&code=" + url.QueryEscape("code-closed") + "&state=" + url.QueryEscape(u.Query().Get("state"))
	if r := f.getGitHub(t, cb, false); r.Code != http.StatusSeeOther {
		t.Fatalf("callback: status %d", r.Code)
	}
	fin := f.postGitHub(t, "/api/v1/connections/github/"+begin.HandoffID+"/finish", `{}`, "idem-closed-2", nil)
	if fin.Code != http.StatusOK {
		t.Fatalf("finish: status %d", fin.Code)
	}
	if r := f.getGitHub(t, "/api/v1/connections/github/binding-1/issues/42", true); r.Code != http.StatusNotFound {
		t.Fatalf("closed issue: status = %d body %s", r.Code, r.Body.String())
	}
}

func TestGitHubRoutesAbsentWithoutAuthority(t *testing.T) {
	// The pre-auth surface keeps working when the GitHub surface is not
	// wired; the routes simply do not exist.
	rec := httptest.NewRecorder()
	New(testDeps()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/connections/github/begin", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestAuthScopeOriginDerivation(t *testing.T) {
	// Origin normalization lives in the github package; the HTTP layer
	// only requires the services to fail closed on a bad origin.
	for in, want := range map[string]string{
		"https://authscope.example.com":      "https://authscope.example.com",
		"https://authscope.example.com/base": "",
		"HTTPS://AuthScope.Example.COM":      "https://authscope.example.com",
		"http://localhost:8080/x":            "",
		"":                                   "",
		"not a url":                          "",
	} {
		got, err := github.NormalizeAuthScopeOrigin(in)
		if want == "" {
			if err == nil {
				t.Fatalf("NormalizeAuthScopeOrigin(%q) = %q, want error", in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeAuthScopeOrigin(%q) error: %v", in, err)
		}
		if got != want {
			t.Fatalf("NormalizeAuthScopeOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}
