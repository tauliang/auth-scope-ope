package httpapi

// Token exchange endpoint tests: the strict unauthenticated
// POST /api/v1/cli/token exchanges one code plus verifier for the sealed
// envelope, rate-limits per IP, and maps exchange errors to problems.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/launch"
)

// stubExchanger is a fake launch service for the token route.
type stubExchanger struct {
	result launch.ExchangeResult
	err    error
	calls  int
}

func (s *stubExchanger) ExchangeAndPrepare(_ context.Context, req launch.ExchangeRequest) (launch.ExchangeResult, error) {
	s.calls++
	if req.Code == "" || req.Verifier == "" {
		return launch.ExchangeResult{}, launch.ErrInvalidExchange
	}
	return s.result, s.err
}

func newTokenServer(stub *stubExchanger) http.Handler {
	return New(Dependencies{Launch: stub})
}

func postToken(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/token", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:45531"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCLITokenSuccess(t *testing.T) {
	sealed := []byte("sealed-envelope-bytes")
	stub := &stubExchanger{result: launch.ExchangeResult{
		RunID:          "run-1",
		MissionRef:     "mission-01",
		SealedEnvelope: sealed,
	}}
	h := newTokenServer(stub)
	rec := postToken(t, h, `{"code":"abc","verifier":"def"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var resp cliTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RunID != "run-1" || resp.MissionRef != "mission-01" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	raw, err := base64.RawURLEncoding.DecodeString(resp.SealedEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(sealed) {
		t.Fatal("sealed envelope mismatch")
	}
	if stub.calls != 1 {
		t.Fatalf("exchange calls = %d, want 1", stub.calls)
	}
}

func TestCLITokenRejectsUnknownFields(t *testing.T) {
	stub := &stubExchanger{}
	h := newTokenServer(stub)
	rec := postToken(t, h, `{"code":"abc","verifier":"def","command":"rm -rf /"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if stub.calls != 0 {
		t.Fatal("exchange must not run on a rejected body")
	}
}

func TestCLITokenRejectsNonJSON(t *testing.T) {
	stub := &stubExchanger{}
	h := newTokenServer(stub)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/token", strings.NewReader(`{"code":"abc"}`))
	req.RemoteAddr = "127.0.0.1:45531"
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
}

func TestCLITokenRejectsWrongMethod(t *testing.T) {
	stub := &stubExchanger{}
	h := newTokenServer(stub)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/cli/token", nil)
	req.RemoteAddr = "127.0.0.1:45531"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestCLITokenMapsErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
	}{
		{"not found", launch.ErrExchangeNotFound, http.StatusNotFound},
		{"invalid", launch.ErrInvalidExchange, http.StatusBadRequest},
		{"stale", launch.ErrExchangeStale, http.StatusGone},
		{"attestation missing", launch.ErrAttestationMissing, http.StatusGone},
		{"conflict", launch.ErrExchangeConflict, http.StatusConflict},
		{"binding changed", launch.ErrBindingChanged, http.StatusConflict},
		{"ambiguous", launch.ErrAmbiguousExchange, http.StatusServiceUnavailable},
		{"denied", &coreapi.UpstreamError{StatusCode: 403, Code: "denied"}, http.StatusForbidden},
		{"upstream failed", &coreapi.UpstreamError{StatusCode: 500, Code: "boom"}, http.StatusBadGateway},
		{"unknown", context.DeadlineExceeded, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubExchanger{err: tc.err}
			h := newTokenServer(stub)
			rec := postToken(t, h, `{"code":"abc","verifier":"def"}`)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d, body %s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestCLITokenRateLimited(t *testing.T) {
	stub := &stubExchanger{result: launch.ExchangeResult{RunID: "r", SealedEnvelope: []byte("x")}}
	h := newTokenServer(stub)
	var last *httptest.ResponseRecorder
	for i := 0; i < cliTokenRateLimit+2; i++ {
		last = postToken(t, h, `{"code":"abc","verifier":"def"}`)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", last.Code)
	}
}

func TestCLITokenRouteAbsentWithoutLaunchService(t *testing.T) {
	h := New(Dependencies{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cli/token", strings.NewReader(`{}`))
	req.RemoteAddr = "127.0.0.1:45531"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}
