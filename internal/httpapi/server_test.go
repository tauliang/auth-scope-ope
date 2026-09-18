package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tauliang/authscope-ope/internal/coreapi"
)

func testDeps() Dependencies {
	return Dependencies{
		Contract: coreapi.ContractReport{
			CoreVersion:        "ope-v1.0.0",
			DigestMatch:        true,
			OperationsRequired: 36,
			OperationsPresent:  36,
		},
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testDeps()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("body = %v", body)
	}
}

func TestReadyzReady(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testDeps()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestReadyzNotReady(t *testing.T) {
	deps := testDeps()
	deps.Contract.DigestMatch = false
	deps.Contract.Problems = []string{"vendored OpenAPI digest mismatch"}
	rec := httptest.NewRecorder()
	New(deps).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "not_ready" {
		t.Fatalf("body = %v", body)
	}
}

func TestBootstrapShape(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testDeps()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body BootstrapResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Enrolled {
		t.Fatal("expected enrolled=false before Task 3")
	}
	if body.Workspace != nil {
		t.Fatal("expected no workspace binding before Task 2")
	}
	if body.Compatibility.Status != "ready" {
		t.Fatalf("compatibility = %+v", body.Compatibility)
	}
	if len(body.AuthorityLabels) == 0 {
		t.Fatal("expected authority labels")
	}
}

func TestBootstrapRejectsPost(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testDeps()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	New(testDeps()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestCLIRoutesRegisteredOnlyWithService(t *testing.T) {
	// Without the CLI authorization service the routes do not exist.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/authorizations", nil)
	req.Header.Set("Content-Type", "application/json")
	New(testDeps()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("create without service status = %d, want 404", rec.Code)
	}
	// With the service wired, create is reachable without a session: a
	// malformed body fails validation (400), not routing (404).
	f := newPassFixture(t)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/cli/authorizations", nil)
	req.Header.Set("Content-Type", "application/json")
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with service status = %d, want 400", rec.Code)
	}
}
