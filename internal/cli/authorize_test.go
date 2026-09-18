package cli

// Task 8: the CLI side of the one-use browser PKCE handoff. Tests use
// real loopback listeners (the sandbox permits loopback) and a fake OPE
// server; no secret may reach disk.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
)

// testListener binds a real loopback listener on an ephemeral port.
func testListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func callbackURL(t *testing.T, ln net.Listener, code, state string) string {
	t.Helper()
	port := ln.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("http://127.0.0.1:%d/callback?code=%s&state=%s", port, code, state)
}

func TestReceiveAuthorizationCodeHappyPath(t *testing.T) {
	ln := testListener(t)
	const state = "test-state-value"
	const code = "test-code-value"
	done := make(chan string, 1)
	go func() {
		got, err := ReceiveAuthorizationCode(context.Background(), ln, state)
		if err != nil {
			t.Errorf("ReceiveAuthorizationCode: %v", err)
			return
		}
		done <- got
	}()
	time.Sleep(50 * time.Millisecond)
	resp, err := http.Get(callbackURL(t, ln, code, state))
	if err != nil {
		t.Fatalf("callback GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status = %d, body = %s", resp.StatusCode, body)
	}
	select {
	case got := <-done:
		if got != code {
			t.Fatalf("code = %q, want %q", got, code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the code")
	}
}

func TestReceiveAuthorizationCodeRejects(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		query string
	}{
		{"wrong state", "/callback", "code=abc&state=wrong"},
		{"missing code", "/callback", "state=s"},
		{"missing state", "/callback", "code=abc"},
		{"wrong path", "/other", "code=abc&state=s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln := testListener(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			errCh := make(chan error, 1)
			go func() {
				_, err := ReceiveAuthorizationCode(ctx, ln, "s")
				errCh <- err
			}()
			time.Sleep(50 * time.Millisecond)
			port := ln.Addr().(*net.TCPAddr).Port
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d%s?%s", port, tc.path, tc.query))
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				t.Fatalf("rejected callback answered %d", resp.StatusCode)
			}
			// A rejected callback must not consume the single attempt:
			// the real one still succeeds afterwards.
			resp2, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=good&state=s", port))
			if err != nil {
				t.Fatalf("retry GET: %v", err)
			}
			resp2.Body.Close()
			if resp2.StatusCode != http.StatusOK {
				t.Fatalf("retry status = %d, want 200", resp2.StatusCode)
			}
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("ReceiveAuthorizationCode: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out")
			}
		})
	}
}

func TestReceiveAuthorizationCodeDuplicateRejected(t *testing.T) {
	ln := testListener(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = ReceiveAuthorizationCode(context.Background(), ln, "s")
	}()
	time.Sleep(50 * time.Millisecond)
	port := ln.Addr().(*net.TCPAddr).Port
	first, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=one&state=s", port))
	if err != nil {
		t.Fatalf("first GET: %v", err)
	}
	// The confirmation body must arrive intact even though the server
	// shuts down as soon as the code is signalled.
	body, err := io.ReadAll(first.Body)
	first.Body.Close()
	if err != nil {
		t.Fatalf("first body: %v", err)
	}
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d", first.StatusCode)
	}
	if string(body) != "Return to the CLI.\n" {
		t.Fatalf("first body = %q", body)
	}
	<-done
	// The listener is closed after the single callback; a duplicate has
	// nowhere to go.
	if _, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=two&state=s", port)); err == nil {
		t.Fatal("expected the closed listener to refuse a duplicate callback")
	}
}

func TestReceiveAuthorizationCodeConcurrentCallbacks(t *testing.T) {
	ln := testListener(t)
	done := make(chan string, 1)
	go func() {
		code, err := ReceiveAuthorizationCode(context.Background(), ln, "s")
		if err == nil {
			done <- code
		}
	}()
	time.Sleep(50 * time.Millisecond)
	port := ln.Addr().(*net.TCPAddr).Port
	var wg sync.WaitGroup
	statuses := make([]int, 8)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=code-%d&state=s", port, i))
			if err != nil {
				return
			}
			resp.Body.Close()
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, s := range statuses {
		if s == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("exactly one callback must succeed, got %d", ok)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the code")
	}
}

func TestReceiveAuthorizationCodeRejectsNonLoopbackPeer(t *testing.T) {
	if !rejectsNonLoopbackPeer("192.168.1.5:1234") {
		t.Fatal("non-loopback peer was not rejected")
	}
	if !rejectsNonLoopbackPeer("[::1]:1234") {
		t.Fatal("ipv6 peer was not rejected by the strict 127.0.0.1 check")
	}
	if rejectsNonLoopbackPeer("127.0.0.1:1234") {
		t.Fatal("loopback peer was rejected")
	}
}

// fakeOPEServer captures the create request and answers with a start
// payload whose invocation digest the CLI recomputes.
type fakeOPEServer struct {
	t           *testing.T
	mu          sync.Mutex
	redirectURI string
	createBody  map[string]any
	kitID       string
	kitVersion  string
	args        []string
	digest      string
}

func (f *fakeOPEServer) setCreate(body map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createBody = body
	f.redirectURI, _ = body["redirect_uri"].(string)
}

func (f *fakeOPEServer) createSnapshot() (redirectURI string, body map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.redirectURI, f.createBody
}

func (f *fakeOPEServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/authorizations" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		f.setCreate(body)
		digest := f.digest
		if digest == "" {
			digest = authn.InvocationDigestForLaunch(f.kitID, f.kitVersion, f.args)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_id":  "authz-1",
			"browser_url":       "https://ope.example.com/?cli_authorization=authz-1",
			"proposal_digest":   "sha256:" + strings.Repeat("f", 64),
			"agent_kit_id":      f.kitID,
			"agent_kit_version": f.kitVersion,
			"runner_arguments":  f.args,
			"invocation_digest": digest,
		})
	})
}

func newFakeOPEServer(t *testing.T) (*httptest.Server, *fakeOPEServer) {
	t.Helper()
	fake := &fakeOPEServer{
		t:          t,
		kitID:      "authscope-agent-kit",
		kitVersion: "1.0.0",
		args:       []string{"authscope-agent-run", "--mission"},
	}
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	return srv, fake
}

// driveBrowserCallback simulates the browser finishing the handoff: it
// delivers code+state to the loopback redirect URI the CLI registered.
func driveBrowserCallback(t *testing.T, fake *fakeOPEServer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		redirectURI, _ := fake.createSnapshot()
		if redirectURI != "" || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	redirectURI, createBody := fake.createSnapshot()
	if redirectURI == "" {
		t.Fatal("CLI never posted the create request")
	}
	state, _ := createBody["state"].(string)
	if state == "" {
		t.Fatal("create request missing state")
	}
	resp, err := http.Get(redirectURI + "?code=" + base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + "&state=" + state)
	if err != nil {
		t.Fatalf("browser callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("browser callback status = %d", resp.StatusCode)
	}
}

func TestAuthorizeLaunchEndToEnd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	srv, fake := newFakeOPEServer(t)
	var opened string
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		// The "browser" acts once the CLI has registered its loopback URI.
		deadline := time.Now().Add(5 * time.Second)
		for {
			redirectURI, _ := fake.createSnapshot()
			if redirectURI != "" || !time.Now().Before(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		redirectURI, _ := fake.createSnapshot()
		if redirectURI != "" {
			driveBrowserCallback(t, fake)
		}
	}()
	bundle, err := AuthorizeLaunch(ctx, srv.URL, "pass-1", Options{
		OpenBrowser: func(url string) error { opened = url; return nil },
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	defer bundle.Destroy()
	if opened != "https://ope.example.com/?cli_authorization=authz-1" {
		t.Fatalf("browser URL = %q", opened)
	}
	if bundle.Code == "" {
		t.Fatal("missing authorization code")
	}
	if bundle.ProposalDigest != "sha256:"+strings.Repeat("f", 64) {
		t.Fatalf("proposal digest = %q", bundle.ProposalDigest)
	}
	// The CLI retains the expected invocation values only in memory.
	if bundle.AgentKitID != "authscope-agent-kit" || bundle.AgentKitVersion != "1.0.0" {
		t.Fatalf("kit = %q %q", bundle.AgentKitID, bundle.AgentKitVersion)
	}
	if len(bundle.RunnerArguments) != 2 || bundle.RunnerArguments[0] != "authscope-agent-run" {
		t.Fatalf("args = %v", bundle.RunnerArguments)
	}
	if bundle.InvocationDigest != authn.InvocationDigestForLaunch(bundle.AgentKitID, bundle.AgentKitVersion, bundle.RunnerArguments) {
		t.Fatal("retained invocation digest does not match the pinned recompute")
	}
	if len(bundle.state) != 32 || len(bundle.verifier) != 32 {
		t.Fatal("state/verifier are not 256-bit")
	}
	var zeroKey [32]byte
	if bundle.ephemeralPrivateKey == zeroKey {
		t.Fatal("missing ephemeral private key")
	}
	// The create request carried the S256 challenge, the state, and the
	// ephemeral public key, and no command or argument fields.
	redirectURI, createBody := fake.createSnapshot()
	for _, field := range []string{"pass_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "ephemeral_public_key"} {
		if _, ok := createBody[field]; !ok {
			t.Fatalf("create request missing %q", field)
		}
	}
	if createBody["code_challenge_method"] != "S256" {
		t.Fatalf("challenge method = %v", createBody["code_challenge_method"])
	}
	for _, forbidden := range []string{"command", "arguments", "runner_arguments", "agent_kit_id"} {
		if _, ok := createBody[forbidden]; ok {
			t.Fatalf("create request must not carry %q", forbidden)
		}
	}
	if !strings.HasPrefix(redirectURI, "http://127.0.0.1:") || !strings.HasSuffix(redirectURI, "/callback") {
		t.Fatalf("redirect URI = %q", redirectURI)
	}
	// No CLI secret may reach disk: the CLI wrote nothing under HOME.
	var files []string
	_ = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if len(files) != 0 {
		t.Fatalf("CLI wrote files to disk: %v", files)
	}
}

func TestAuthorizeLaunchRejectsInvocationMismatch(t *testing.T) {
	srv, fake := newFakeOPEServer(t)
	fake.digest = "sha256:" + strings.Repeat("0", 64) // tampered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := AuthorizeLaunch(ctx, srv.URL, "pass-1", Options{})
	if err == nil || !strings.Contains(err.Error(), "invocation digest") {
		t.Fatalf("AuthorizeLaunch err = %v, want invocation digest mismatch", err)
	}
}

func TestLaunchAuthorizationDestroyZeroesSecrets(t *testing.T) {
	b := &LaunchAuthorization{
		Code:                "secret-code",
		state:               []byte("0123456789abcdef0123456789abcdef"),
		verifier:            []byte("0123456789abcdef0123456789abcdef"),
		ephemeralPrivateKey: [32]byte{1, 2, 3},
	}
	b.Destroy()
	if b.Code != "" {
		t.Fatal("code not zeroed")
	}
	for i, v := range b.state {
		if v != 0 {
			t.Fatalf("state byte %d not zeroed", i)
		}
	}
	for i, v := range b.verifier {
		if v != 0 {
			t.Fatalf("verifier byte %d not zeroed", i)
		}
	}
	var zeroKey [32]byte
	if b.ephemeralPrivateKey != zeroKey {
		t.Fatal("ephemeral private key not zeroed")
	}
}
