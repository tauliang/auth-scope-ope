package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Without the embedweb tag the UI is unavailable: the root answers 503
// instead of serving assets.
func TestSpaUnavailableWithoutEmbed(t *testing.T) {
	h := New(testDeps())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// API paths keep their exact semantics under the UI wrapper: unknown
// API paths 404 and never fall back to the UI.
func TestSpaDoesNotShadowAPI(t *testing.T) {
	h := New(testDeps())
	for _, path := range []string{"/api/v1/nope", "/api/v1/cli/token"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusServiceUnavailable {
			t.Fatalf("GET %s reached the UI handler", path)
		}
	}
}

// Non-GET requests to UI paths fall through to the API mux (404), so
// the UI never answers non-GET methods.
func TestSpaGetOnly(t *testing.T) {
	h := New(testDeps())
	req := httptest.NewRequest(http.MethodPost, "/settings", nil)
	req.RemoteAddr = "127.0.0.1:1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestIsUIPath(t *testing.T) {
	ui := []string{"/", "/settings", "/missions/123", "/assets/app.js"}
	for _, p := range ui {
		if !isUIPath(p) {
			t.Errorf("isUIPath(%q) = false, want true", p)
		}
	}
	api := []string{"/api/v1/bootstrap", "/api/", "/healthz", "/readyz"}
	for _, p := range api {
		if isUIPath(p) {
			t.Errorf("isUIPath(%q) = true, want false", p)
		}
	}
}
