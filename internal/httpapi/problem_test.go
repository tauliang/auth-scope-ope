package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

func TestWriteProblemShape(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, http.StatusTeapot, "teapot", "Teapot.")
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type = %q", ct)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Type != "about:blank" || p.Title != "teapot" || p.Status != http.StatusTeapot || p.Detail != "Teapot." {
		t.Fatalf("problem = %+v", p)
	}
}

func TestUpstreamHTTPStatusMapping(t *testing.T) {
	cases := []struct {
		upstream int
		local    int
	}{
		{401, 401}, {403, 403}, {404, 404}, {409, 409},
		{412, 412}, {429, 429}, {400, 503}, {500, 503}, {503, 503},
	}
	for _, tc := range cases {
		err := &coreapi.UpstreamError{StatusCode: tc.upstream, Code: "test", Message: "m"}
		if got := UpstreamHTTPStatus(err); got != tc.local {
			t.Fatalf("upstream %d -> %d, want %d", tc.upstream, got, tc.local)
		}
	}
	if got := UpstreamHTTPStatus(coreapi.ErrGateNotHealthy); got != http.StatusServiceUnavailable {
		t.Fatalf("gate not healthy -> %d, want 503", got)
	}
	if got := UpstreamHTTPStatus(coreapi.ErrResponseTooLarge); got != http.StatusServiceUnavailable {
		t.Fatalf("response too large -> %d, want 503", got)
	}
	// Unknown errors fail closed to 503, never to a retryable allow path.
	if got := UpstreamHTTPStatus(errors.New("boom")); got != http.StatusServiceUnavailable {
		t.Fatalf("unknown -> %d, want 503", got)
	}
}

func TestWriteUpstreamErrorNeverLeaks(t *testing.T) {
	secret := "secret-token-xyz-123"
	err := &coreapi.UpstreamError{
		StatusCode: 403,
		Code:       "attestor_not_authorized",
		Message:    "denied for " + secret,
		RequestID:  "req-1",
	}
	rec := httptest.NewRecorder()
	WriteUpstreamError(rec, err)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("problem body leaks upstream message: %s", rec.Body.String())
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Title != "upstream denied the request" {
		t.Fatalf("title = %q", p.Title)
	}
}

// stubAuthorityForGate implements just enough of coreapi.Authority for
// gate verification tests.
type stubAuthorityForGate struct {
	coreapi.Authority
	workspace string
	digest    string
	roles     []string
}

func (s stubAuthorityForGate) Discover(context.Context) (coreapi.Discovery, error) {
	lock := coreapi.LockedContract()
	manifest := coreapi.RequiredManifest()
	seen := map[string]bool{}
	var caps []string
	for _, op := range manifest.RequiredOperations {
		if !seen[op.Capability] {
			seen[op.Capability] = true
			caps = append(caps, op.Capability)
		}
	}
	return coreapi.Discovery{Version: lock.CoreVersion, OpenAPISHA256: lock.OpenAPISHA256, Capabilities: caps}, nil
}

func (s stubAuthorityForGate) VerifyWorkspaceIdentity(_ context.Context, workspace string) (coreapi.WorkspaceIdentity, error) {
	return coreapi.WorkspaceIdentity{
		IdentityID:     "wid-1",
		IdentityDigest: s.digest,
		WorkspaceID:    s.workspace,
		Roles:          s.roles,
	}, nil
}

func openGateTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rec := store.InstanceRecord{
		InstanceID:        "inst-httpapi-1",
		WorkspaceID:       "ws-test",
		Hostname:          "localhost",
		Origin:            "http://localhost:8080",
		RPID:              "localhost",
		SessionCookieName: store.DeriveSessionCookieName("inst-httpapi-1"),
		CreatedAt:         time.Now().UTC(),
	}
	if err := st.WithTx(context.Background(), func(tx store.Tx) error {
		return tx.BindInstance(context.Background(), rec)
	}); err != nil {
		t.Fatalf("bind instance: %v", err)
	}
	return st
}

func healthyGate(t *testing.T) *coreapi.Gate {
	t.Helper()
	auth := stubAuthorityForGate{
		workspace: "ws-test",
		digest:    "sha256:" + strings.Repeat("a", 64),
		roles:     []string{coreapi.DecisionAttestorRole},
	}
	gate := coreapi.NewGate(auth, openGateTestStore(t))
	if err := gate.Verify(context.Background()); err != nil {
		t.Fatalf("gate verify: %v", err)
	}
	return gate
}

func TestReadyzWithGate(t *testing.T) {
	contract := coreapi.ContractReport{
		CoreVersion:        "ope-v1.0.0",
		DigestMatch:        true,
		OperationsRequired: 36,
		OperationsPresent:  36,
	}

	t.Run("healthy gate is ready", func(t *testing.T) {
		deps := Dependencies{Contract: contract, Gate: healthyGate(t)}
		rec := httptest.NewRecorder()
		New(deps).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("never-verified gate is not ready", func(t *testing.T) {
		auth := stubAuthorityForGate{workspace: "ws-test"}
		gate := coreapi.NewGate(auth, openGateTestStore(t))
		deps := Dependencies{Contract: contract, Gate: gate}
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
	})

	t.Run("nil gate keeps contract-only behavior", func(t *testing.T) {
		deps := Dependencies{Contract: contract}
		rec := httptest.NewRecorder()
		New(deps).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	})
}

func TestRequireVerifiedGateMiddleware(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("nil gate fails closed", func(t *testing.T) {
		rec := httptest.NewRecorder()
		RequireVerifiedGate(nil)(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("stale gate rejected after registration", func(t *testing.T) {
		auth := stubAuthorityForGate{workspace: "ws-test"}
		gate := coreapi.NewGate(auth, openGateTestStore(t))
		h := RequireVerifiedGate(gate)(inner)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("content type = %q", ct)
		}
	})

	t.Run("healthy gate passes through", func(t *testing.T) {
		rec := httptest.NewRecorder()
		RequireVerifiedGate(healthyGate(t))(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
	})
}
