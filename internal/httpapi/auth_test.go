package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

// stubVerifier is a scripted authn.Verifier for HTTP tests.
type stubVerifier struct {
	regOutcomes    []authn.RegisteredCredential
	regErrs        []error
	assertOutcomes []authn.VerifiedAssertion
	assertErrs     []error
	regCalls       int
	assertCalls    int
}

func (s *stubVerifier) BeginRegistration(_ context.Context, _ authn.CeremonyUser, _, _ string, _ [][]byte) ([]byte, []byte, error) {
	idx := s.regCalls
	s.regCalls++
	return []byte(`{"publicKey":{"challenge":"reg"}}`), []byte(fmt.Sprintf(`{"idx":%d}`, idx)), nil
}

func (s *stubVerifier) FinishRegistration(_ context.Context, _ authn.CeremonyUser, sessionJSON, _ []byte) (authn.RegisteredCredential, error) {
	var v struct {
		Idx int `json:"idx"`
	}
	if err := json.Unmarshal(sessionJSON, &v); err != nil {
		return authn.RegisteredCredential{}, err
	}
	if v.Idx < len(s.regErrs) && s.regErrs[v.Idx] != nil {
		return authn.RegisteredCredential{}, s.regErrs[v.Idx]
	}
	return s.regOutcomes[v.Idx], nil
}

func (s *stubVerifier) BeginAssertion(_ context.Context, _ authn.CeremonyUser, _, _ string, _ [][]byte) ([]byte, []byte, error) {
	idx := s.assertCalls
	s.assertCalls++
	return []byte(`{"publicKey":{"challenge":"assert"}}`), []byte(fmt.Sprintf(`{"idx":%d}`, idx)), nil
}

func (s *stubVerifier) FinishAssertion(_ context.Context, _ authn.CeremonyUser, _ []authn.StoredCredential, sessionJSON, _ []byte) (authn.VerifiedAssertion, error) {
	var v struct {
		Idx int `json:"idx"`
	}
	if err := json.Unmarshal(sessionJSON, &v); err != nil {
		return authn.VerifiedAssertion{}, err
	}
	if v.Idx < len(s.assertErrs) && s.assertErrs[v.Idx] != nil {
		return authn.VerifiedAssertion{}, s.assertErrs[v.Idx]
	}
	return s.assertOutcomes[v.Idx], nil
}

type authTestFixture struct {
	handler http.Handler
	stub    *stubVerifier
	authn   *authn.Service
	store   store.Store
	config  config.Config
	jar     map[string]*http.Cookie
}

func newAuthTestFixture(t *testing.T) *authTestFixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	cfg := config.Config{
		Mode:        "development",
		Hostname:    "ope.example.com",
		Origin:      "https://ope.example.com",
		RPID:        "ope.example.com",
		WorkspaceID: "ws-test",
		InstanceID:  "inst-http-1",
	}
	inst := store.InstanceRecord{
		InstanceID:        cfg.InstanceID,
		WorkspaceID:       cfg.WorkspaceID,
		Hostname:          cfg.Hostname,
		Origin:            cfg.Origin,
		RPID:              cfg.RPID,
		SessionCookieName: store.DeriveSessionCookieName(cfg.InstanceID),
		CreatedAt:         time.Now().UTC(),
	}
	if err := db.WithTx(ctx, func(tx store.Tx) error {
		return tx.BindInstance(ctx, inst)
	}); err != nil {
		t.Fatalf("bind instance: %v", err)
	}
	stub := &stubVerifier{}
	svc, err := authn.NewService(ctx, db, stub)
	if err != nil {
		t.Fatalf("new authn service: %v", err)
	}
	deps := Dependencies{
		Config: cfg,
		Contract: coreapi.ContractReport{
			CoreVersion:        "ope-v1.0.0",
			DigestMatch:        true,
			OperationsRequired: 36,
			OperationsPresent:  36,
		},
		Store: db,
		Authn: svc,
	}
	return &authTestFixture{
		handler: New(deps),
		stub:    stub,
		authn:   svc,
		store:   db,
		config:  cfg,
		jar:     map[string]*http.Cookie{},
	}
}

// do sends a JSON POST with the exact Host/Origin/Content-Type the guards
// require, carrying the fixture cookie jar forward.
func (f *authTestFixture) do(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doRaw(t, http.MethodPost, path, body, map[string]string{
		"Host":         "ope.example.com",
		"Origin":       "https://ope.example.com",
		"Content-Type": "application/json",
	})
}

func (f *authTestFixture) doRaw(t *testing.T, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "https://ope.example.com"+path, reader)
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	for _, c := range f.jar {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(f.jar, c.Name)
		} else {
			f.jar[c.Name] = c
		}
	}
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, rec.Body.String())
	}
}

func (f *authTestFixture) issueBootstrapCode(t *testing.T) string {
	t.Helper()
	code, err := f.authn.EnsureBootstrapCode(context.Background())
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	if code == "" {
		t.Fatal("expected a bootstrap code")
	}
	return code
}

func (f *authTestFixture) enrollOverHTTP(t *testing.T) (csrfToken string) {
	t.Helper()
	f.stub.regOutcomes = append(f.stub.regOutcomes,
		authn.RegisteredCredential{ID: []byte("cred-1"), PublicKey: []byte("pk-1"), UserVerified: true},
	)
	code := f.issueBootstrapCode(t)
	rec := f.do(t, "/api/v1/bootstrap/begin", `{"code":"`+code+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap begin: status %d body %s", rec.Code, rec.Body.String())
	}
	rec = f.do(t, "/api/v1/auth/register/begin", `{"display_name":"Shengquan"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("register begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var regBegin struct {
		CeremonyID string          `json:"ceremony_id"`
		Options    json.RawMessage `json:"options"`
	}
	decodeBody(t, rec, &regBegin)
	if regBegin.CeremonyID == "" || len(regBegin.Options) == 0 {
		t.Fatalf("register begin missing fields: %s", rec.Body.String())
	}
	rec = f.do(t, "/api/v1/auth/register/finish",
		`{"ceremony_id":"`+regBegin.CeremonyID+`","response":{"id":"cred-1"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("register finish: status %d body %s", rec.Code, rec.Body.String())
	}
	rec = f.do(t, "/api/v1/bootstrap/recovery/begin", `{"method":"offline_key"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var recovery struct {
		Method      string `json:"method"`
		RecoveryKey string `json:"recovery_key"`
	}
	decodeBody(t, rec, &recovery)
	if recovery.RecoveryKey == "" {
		t.Fatalf("missing recovery key: %s", rec.Body.String())
	}
	rec = f.do(t, "/api/v1/bootstrap/complete", `{"recovery_confirmation":"`+recovery.RecoveryKey+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap complete: status %d body %s", rec.Code, rec.Body.String())
	}
	var done struct {
		CSRFToken string `json:"csrf_token"`
	}
	decodeBody(t, rec, &done)
	if done.CSRFToken == "" {
		t.Fatalf("missing CSRF token: %s", rec.Body.String())
	}
	return done.CSRFToken
}

func TestAuthBootstrapGuards(t *testing.T) {
	f := newAuthTestFixture(t)
	code := f.issueBootstrapCode(t)
	body := `{"code":"` + code + `"}`

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"wrong host", map[string]string{"Host": "evil.example.com", "Origin": "https://ope.example.com", "Content-Type": "application/json"}, http.StatusForbidden},
		{"wrong origin", map[string]string{"Host": "ope.example.com", "Origin": "https://evil.example.com", "Content-Type": "application/json"}, http.StatusForbidden},
		{"missing origin", map[string]string{"Host": "ope.example.com", "Content-Type": "application/json"}, http.StatusForbidden},
		{"wrong content type", map[string]string{"Host": "ope.example.com", "Origin": "https://ope.example.com", "Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		{"content type with charset", map[string]string{"Host": "ope.example.com", "Origin": "https://ope.example.com", "Content-Type": "application/json; charset=utf-8"}, http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.doRaw(t, http.MethodPost, "/api/v1/bootstrap/begin", body, tc.headers)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.want, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Fatalf("content type = %q", ct)
			}
		})
	}
}

func TestAuthBootstrapWrongCode(t *testing.T) {
	f := newAuthTestFixture(t)
	rec := f.do(t, "/api/v1/bootstrap/begin", `{"code":"wrong"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var problem map[string]any
	decodeBody(t, rec, &problem)
	if problem["title"] != "invalid bootstrap code" {
		t.Fatalf("problem = %v", problem)
	}
	// The problem response must not reflect secrets or ceremony material.
	if strings.Contains(rec.Body.String(), "wrong") {
		t.Fatalf("problem reflects the submitted code: %s", rec.Body.String())
	}
}

func TestAuthBootstrapRequiresCeremonyCookie(t *testing.T) {
	f := newAuthTestFixture(t)
	rec := f.do(t, "/api/v1/auth/register/begin", `{}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthFullBootstrapFlow(t *testing.T) {
	f := newAuthTestFixture(t)
	csrfToken := f.enrollOverHTTP(t)
	if csrfToken == "" {
		t.Fatal("missing CSRF token")
	}

	// The session cookie is set with strict attributes under the exact
	// bound name; the bootstrap cookie is cleared.
	sessionCookie, ok := f.jar[f.authn.SessionCookieName()]
	if !ok {
		t.Fatalf("session cookie %q not set; jar = %v", f.authn.SessionCookieName(), f.jar)
	}
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("weak session cookie attributes: %+v", sessionCookie)
	}
	if sessionCookie.Path != "/" {
		t.Fatalf("session cookie path = %q", sessionCookie.Path)
	}
	if _, ok := f.jar[f.authn.BootstrapCookieName()]; ok {
		t.Fatal("bootstrap cookie should be cleared after completion")
	}

	// First paint now reports the enrolled founder and the live session.
	req := httptest.NewRequest(http.MethodGet, "https://ope.example.com/api/v1/bootstrap", nil)
	for _, c := range f.jar {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d", rec.Code)
	}
	var status BootstrapResponse
	decodeBody(t, rec, &status)
	if !status.Enrolled || status.EnrollmentState != "authenticated" {
		t.Fatalf("status = %+v", status)
	}
	if status.Workspace == nil || status.Workspace.WorkspaceID != "ws-test" {
		t.Fatalf("workspace = %+v", status.Workspace)
	}
}

func TestAuthBootstrapRejectsSessionReuse(t *testing.T) {
	f := newAuthTestFixture(t)
	f.enrollOverHTTP(t)
	code := ""
	rec := f.do(t, "/api/v1/bootstrap/begin", `{"code":"`+code+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	var problem map[string]any
	decodeBody(t, rec, &problem)
	if problem["title"] != "already authenticated" {
		t.Fatalf("problem = %v", problem)
	}
}

func TestAuthLoginFlow(t *testing.T) {
	f := newAuthTestFixture(t)

	// Login before enrollment is a 404, not a ceremony.
	rec := f.do(t, "/api/v1/auth/login/begin", `{}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	f.enrollOverHTTP(t)
	// Drop the enrollment session: login must mint its own.
	delete(f.jar, f.authn.SessionCookieName())

	f.stub.assertOutcomes = append(f.stub.assertOutcomes, authn.VerifiedAssertion{
		CredentialID: []byte("cred-1"), NewSignCount: 1, UserVerified: true,
	})
	rec = f.do(t, "/api/v1/auth/login/begin", `{}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login begin: status %d body %s", rec.Code, rec.Body.String())
	}
	var begin struct {
		CeremonyID string          `json:"ceremony_id"`
		Options    json.RawMessage `json:"options"`
	}
	decodeBody(t, rec, &begin)
	rec = f.do(t, "/api/v1/auth/login/finish",
		`{"ceremony_id":"`+begin.CeremonyID+`","response":{"id":"cred-1"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login finish: status %d body %s", rec.Code, rec.Body.String())
	}
	var done struct {
		CSRFToken string `json:"csrf_token"`
	}
	decodeBody(t, rec, &done)
	if done.CSRFToken == "" {
		t.Fatal("missing CSRF token")
	}
	if _, ok := f.jar[f.authn.SessionCookieName()]; !ok {
		t.Fatal("login did not set a session cookie")
	}

	// A failed assertion is a 400 problem without credential contents.
	f.stub.assertOutcomes = append(f.stub.assertOutcomes, authn.VerifiedAssertion{})
	f.stub.assertErrs = append(f.stub.assertErrs, nil, errors.New("bad signature"))
	rec = f.do(t, "/api/v1/auth/login/begin", `{}`)
	decodeBody(t, rec, &begin)
	rec = f.do(t, "/api/v1/auth/login/finish",
		`{"ceremony_id":"`+begin.CeremonyID+`","response":{"id":"cred-1"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "bad signature") {
		t.Fatalf("problem leaks verifier detail: %s", rec.Body.String())
	}
}

func TestAuthBodyTooLarge(t *testing.T) {
	f := newAuthTestFixture(t)
	big := `{"code":"` + strings.Repeat("a", (1<<20)+1) + `"}`
	rec := f.do(t, "/api/v1/bootstrap/begin", big)
	if rec.Code == http.StatusOK {
		t.Fatal("oversized body was accepted")
	}
}

func TestAuthUnknownFieldsRejected(t *testing.T) {
	f := newAuthTestFixture(t)
	code := f.issueBootstrapCode(t)
	rec := f.do(t, "/api/v1/bootstrap/begin", `{"code":"`+code+`","extra":1}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestAuthTrailingJSONRejected(t *testing.T) {
	f := newAuthTestFixture(t)
	code := f.issueBootstrapCode(t)
	bodies := []string{
		`{"code":"` + code + `"}{"code":"` + code + `"}`,
		`{"code":"` + code + `"}]`,
		`{"code":"` + code + `"} trailing`,
	}
	for _, body := range bodies {
		rec := f.do(t, "/api/v1/bootstrap/begin", body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestAuthenticateRequestWrongCookieName(t *testing.T) {
	f := newAuthTestFixture(t)
	f.enrollOverHTTP(t)
	token := f.jar[f.authn.SessionCookieName()].Value

	req := httptest.NewRequest(http.MethodPost, "https://ope.example.com/api/v1/auth/login/begin", nil)
	req.AddCookie(&http.Cookie{Name: "authscope-ope-session", Value: token})
	if _, _, err := authenticateRequest(Dependencies{Authn: f.authn}, req); !errors.Is(err, authn.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for wrong cookie name, got %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "https://ope.example.com/api/v1/auth/login/begin", nil)
	req.AddCookie(&http.Cookie{Name: f.authn.SessionCookieName(), Value: token})
	if _, _, err := authenticateRequest(Dependencies{Authn: f.authn}, req); err != nil {
		t.Fatalf("expected success for exact cookie name, got %v", err)
	}
}

func TestVerifyRequestCSRF(t *testing.T) {
	f := newAuthTestFixture(t)
	csrfToken := f.enrollOverHTTP(t)
	token := f.jar[f.authn.SessionCookieName()].Value
	_, rec, err := f.authn.AuthenticateSessionToken(context.Background(), token)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/begin", nil)
	req.Header.Set(csrfHeaderName, csrfToken)
	if err := verifyRequestCSRF(req, rec); err != nil {
		t.Fatalf("valid CSRF rejected: %v", err)
	}
	req.Header.Set(csrfHeaderName, "wrong")
	if err := verifyRequestCSRF(req, rec); !errors.Is(err, authn.ErrCSRFMismatch) {
		t.Fatalf("expected ErrCSRFMismatch, got %v", err)
	}
}

func TestAuthSecurityHeaders(t *testing.T) {
	f := newAuthTestFixture(t)
	rec := f.do(t, "/api/v1/auth/login/begin", `{}`)
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Fatalf("CSP = %q", got)
	}
	if got := rec.Header().Get("Permissions-Policy"); !strings.Contains(got, "camera=()") {
		t.Fatalf("Permissions-Policy = %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
}

func TestBootstrapEndpointEnrollmentStates(t *testing.T) {
	f := newAuthTestFixture(t)
	get := func() BootstrapResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "https://ope.example.com/api/v1/bootstrap", nil)
		for _, c := range f.jar {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		var status BootstrapResponse
		decodeBody(t, rec, &status)
		return status
	}
	if got := get(); got.Enrolled || got.EnrollmentState != "needs_bootstrap" {
		t.Fatalf("before enrollment: %+v", got)
	}
	f.enrollOverHTTP(t)
	if got := get(); !got.Enrolled || got.EnrollmentState != "authenticated" {
		t.Fatalf("after enrollment with session: %+v", got)
	}
	delete(f.jar, f.authn.SessionCookieName())
	if got := get(); !got.Enrolled || got.EnrollmentState != "locked" {
		t.Fatalf("after enrollment without session: %+v", got)
	}
}
