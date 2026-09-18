package cli

// The CLI side of the result-only loopback PKCE revocation handoff.
// Tests use real loopback listeners (the sandbox permits loopback) and
// a fake OPE server; no secret may reach disk.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
)

type fakeRevokeServer struct {
	t *testing.T

	mu          sync.Mutex
	redirectURI string
	state       string
	challenge   string
	code        string
	exchanges   int
}

func (f *fakeRevokeServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/cli/revocations" && r.Method == http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			if body["pass_id"] != "pass-1" {
				http.Error(w, "bad pass", http.StatusBadRequest)
				return
			}
			if body["code_challenge_method"] != "S256" {
				http.Error(w, "bad method", http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			f.redirectURI, _ = body["redirect_uri"].(string)
			f.state, _ = body["state"].(string)
			f.challenge, _ = body["code_challenge"].(string)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"request_id":        "req-1",
				"browser_url":       "https://ope.example.com/mission/pass-1?cli_revocation=req-1",
				"revocation_digest": "sha256:" + strings.Repeat("e", 64),
			})
		case r.URL.Path == "/api/v1/cli/revocations/token" && r.Method == http.MethodPost:
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			f.exchanges++
			if body["code"] != f.code || body["state"] != f.state || body["redirect_uri"] != f.redirectURI {
				http.Error(w, "bad exchange", http.StatusUnauthorized)
				return
			}
			verifier, _ := body["code_verifier"].(string)
			if authn.CodeChallengeS256(verifier) != f.challenge {
				http.Error(w, "bad verifier", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"result_ref":  "revres-1",
				"containment": "acknowledged",
			})
		default:
			http.NotFound(w, r)
		}
	})
}

func newFakeRevokeServer(t *testing.T) (*httptest.Server, *fakeRevokeServer) {
	t.Helper()
	fake := &fakeRevokeServer{t: t}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	return srv, fake
}

// driveRevokeCallback simulates the browser finishing the revocation:
// it delivers code+state to the loopback redirect URI the CLI
// registered.
func driveRevokeCallback(t *testing.T, fake *fakeRevokeServer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fake.mu.Lock()
		redirectURI := fake.redirectURI
		fake.mu.Unlock()
		if redirectURI != "" || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fake.mu.Lock()
	redirectURI, state := fake.redirectURI, fake.state
	fake.mu.Unlock()
	if redirectURI == "" {
		t.Fatal("CLI never posted the register request")
	}
	if state == "" {
		t.Fatal("register request missing state")
	}
	code := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	fake.mu.Lock()
	fake.code = code
	fake.mu.Unlock()
	resp, err := http.Get(redirectURI + "?code=" + code + "&state=" + state)
	if err != nil {
		t.Fatalf("browser callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("browser callback status = %d", resp.StatusCode)
	}
}

func TestRevokeMissionEndToEnd(t *testing.T) {
	srv, fake := newFakeRevokeServer(t)
	var opened string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		// The "browser" acts once the CLI has registered its loopback URI.
		deadline := time.Now().Add(5 * time.Second)
		for {
			fake.mu.Lock()
			uri := fake.redirectURI
			fake.mu.Unlock()
			if uri != "" || !time.Now().Before(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		driveRevokeCallback(t, fake)
	}()
	var out strings.Builder
	outcome, err := RevokeMission(ctx, srv.URL, "pass-1", RevokeOptions{
		OpenBrowser: func(url string) error { opened = url; return nil },
		Output:      &out,
	})
	if err != nil {
		t.Fatalf("RevokeMission: %v", err)
	}
	if outcome == nil {
		t.Fatal("nil outcome")
	}
	if outcome.ResultRef != "revres-1" {
		t.Errorf("result_ref = %q, want revres-1", outcome.ResultRef)
	}
	if outcome.Containment != "acknowledged" {
		t.Errorf("containment = %q, want acknowledged", outcome.Containment)
	}
	if opened != "https://ope.example.com/mission/pass-1?cli_revocation=req-1" {
		t.Errorf("opened = %q", opened)
	}
	if !strings.Contains(out.String(), "https://ope.example.com/mission/pass-1?cli_revocation=req-1") {
		t.Errorf("output missing browser URL: %q", out.String())
	}
	fake.mu.Lock()
	exchanges := fake.exchanges
	fake.mu.Unlock()
	if exchanges != 1 {
		t.Errorf("exchanges = %d, want 1", exchanges)
	}
}

func TestRevokeMissionRequiresPass(t *testing.T) {
	_, err := RevokeMission(context.Background(), "http://127.0.0.1:1", "", RevokeOptions{})
	if err == nil {
		t.Fatal("expected error for missing pass id")
	}
}

func TestRevocationRequestDestroyZeroesSecrets(t *testing.T) {
	req := &RevocationRequest{
		RequestID: "req-1",
		state:     []byte{1, 2, 3},
		verifier:  []byte{4, 5, 6},
		Code:      "code-1",
	}
	req.Destroy()
	for _, b := range req.state {
		if b != 0 {
			t.Error("state not zeroed")
		}
	}
	for _, b := range req.verifier {
		if b != 0 {
			t.Error("verifier not zeroed")
		}
	}
	if req.Code != "" {
		t.Error("code not cleared")
	}
}
