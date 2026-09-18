// Package cli is the operator-facing CLI. AuthorizeLaunch runs the
// one-use browser PKCE handoff that authorizes a single launch of an
// approved pass: it opens a pending CLI authorization, prints the browser
// URL for the founder, and waits on a loopback callback for the
// authorization code. Secrets (state, verifier, code, ephemeral private
// key) stay in memory only; Destroy zeroes them.
package cli

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/tauliang/authscope-ope/internal/authn"
)

// defaultCallbackTimeout bounds the whole browser handoff.
const defaultCallbackTimeout = 5 * time.Minute

// Options configures one AuthorizeLaunch call.
type Options struct {
	// HTTPClient performs the create request; defaults to http.DefaultClient.
	HTTPClient *http.Client
	// OpenBrowser, when set, is called with the browser URL. The URL is
	// always printed too, so the handoff never requires xdg-open.
	OpenBrowser func(url string) error
	// Output receives the printed browser URL; defaults to os.Stdout.
	Output io.Writer
	// CallbackTimeout bounds the wait for the loopback callback.
	CallbackTimeout time.Duration
}

// LaunchAuthorization is the retained handoff material for the Task 9
// exchange. Code, verifier, state, and the ephemeral private key live in
// memory only; Destroy zeroes them.
type LaunchAuthorization struct {
	AuthorizationID  string
	PassID           string
	ProposalDigest   string
	AgentKitID       string
	AgentKitVersion  string
	RunnerArguments  []string
	InvocationDigest string
	Code             string

	state               []byte
	verifier            []byte
	ephemeralPrivateKey [32]byte
}

// Destroy zeroes the in-memory secrets. It is idempotent.
func (b *LaunchAuthorization) Destroy() {
	if b == nil {
		return
	}
	for i := range b.state {
		b.state[i] = 0
	}
	for i := range b.verifier {
		b.verifier[i] = 0
	}
	for i := range b.ephemeralPrivateKey {
		b.ephemeralPrivateKey[i] = 0
	}
	b.state = nil
	b.verifier = nil
	b.Code = ""
}

// createRequest is the wire form of the authorization request.
type createRequest struct {
	PassID              string `json:"pass_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	EphemeralPublicKey  string `json:"ephemeral_public_key"`
}

// createResponse is the wire form of the pending authorization.
type createResponse struct {
	AuthorizationID  string   `json:"authorization_id"`
	BrowserURL       string   `json:"browser_url"`
	ProposalDigest   string   `json:"proposal_digest"`
	AgentKitID       string   `json:"agent_kit_id"`
	AgentKitVersion  string   `json:"agent_kit_version"`
	RunnerArguments  []string `json:"runner_arguments"`
	InvocationDigest string   `json:"invocation_digest"`
}

// AuthorizeLaunch runs the browser PKCE handoff for one launch of an
// approved pass and returns the retained authorization bundle for the
// Task 9 exchange. On any error the bundle is destroyed before returning.
func AuthorizeLaunch(ctx context.Context, apiBase, passID string, opts Options) (bundle *LaunchAuthorization, err error) {
	if passID == "" {
		return nil, fmt.Errorf("cli: pass id is required")
	}
	apiBase = strings.TrimSuffix(apiBase, "/")
	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}
	timeout := opts.CallbackTimeout
	if timeout <= 0 {
		timeout = defaultCallbackTimeout
	}

	stateRaw, verifierRaw, priv, err := newHandoffSecrets()
	if err != nil {
		return nil, err
	}
	// The bundle takes ownership of the secrets immediately, so every
	// failure below destroys them through one path. The raw locals are
	// cleared after the copy; the slice headers alias the bundle and are
	// dropped.
	bundle = &LaunchAuthorization{PassID: passID}
	bundle.state = stateRaw
	bundle.verifier = verifierRaw
	bundle.ephemeralPrivateKey = priv
	stateRaw, verifierRaw = nil, nil
	for i := range priv {
		priv[i] = 0
	}
	// Named returns: any non-nil err below destroys the bundle before it
	// is returned.
	defer func() {
		if err != nil {
			bundle.Destroy()
			bundle = nil
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("cli: bind loopback listener: %w", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	start, err := postCreate(ctx, client, apiBase, passID, redirectURI, bundle.state, bundle.verifier, bundle.ephemeralPrivateKey)
	if err != nil {
		return nil, err
	}
	// The CLI canonicalizes kit ID/version and ordered arguments with the
	// pinned digest algorithm and rejects any mismatch with the
	// authoritative stored digest.
	if want := authn.InvocationDigestForLaunch(start.AgentKitID, start.AgentKitVersion, start.RunnerArguments); subtle.ConstantTimeCompare([]byte(want), []byte(start.InvocationDigest)) != 1 {
		return nil, fmt.Errorf("cli: invocation digest mismatch: server %q, recomputed %q", start.InvocationDigest, want)
	}

	bundle.AuthorizationID = start.AuthorizationID
	bundle.ProposalDigest = start.ProposalDigest
	bundle.AgentKitID = start.AgentKitID
	bundle.AgentKitVersion = start.AgentKitVersion
	bundle.RunnerArguments = append([]string{}, start.RunnerArguments...)
	bundle.InvocationDigest = start.InvocationDigest

	fmt.Fprintf(out, "Open this URL in your browser to authorize the launch:\n%s\n", start.BrowserURL)
	if opts.OpenBrowser != nil {
		// Best effort: the printed URL is the real handoff path.
		_ = opts.OpenBrowser(start.BrowserURL)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	expectedState := base64.RawURLEncoding.EncodeToString(bundle.state)
	code, err := ReceiveAuthorizationCode(ctx, ln, expectedState)
	if err != nil {
		return nil, err
	}
	if code == "" {
		return nil, fmt.Errorf("cli: empty authorization code")
	}
	bundle.Code = code
	return bundle, nil
}

// newHandoffSecrets generates the 256-bit state, PKCE verifier, and
// ephemeral X25519 keypair for one handoff.
func newHandoffSecrets() (state, verifier []byte, priv [32]byte, err error) {
	stateStr, err := authn.NewPKCEVerifier()
	if err != nil {
		return nil, nil, priv, err
	}
	verifierStr, err := authn.NewPKCEVerifier()
	if err != nil {
		return nil, nil, priv, err
	}
	state, err = base64.RawURLEncoding.DecodeString(stateStr)
	if err != nil {
		return nil, nil, priv, err
	}
	verifier, err = base64.RawURLEncoding.DecodeString(verifierStr)
	if err != nil {
		return nil, nil, priv, err
	}
	priv, _, err = authn.EphemeralX25519Keypair()
	if err != nil {
		return nil, nil, priv, err
	}
	return state, verifier, priv, nil
}

// postCreate opens the pending authorization on the OPE server.
func postCreate(ctx context.Context, client *http.Client, apiBase, passID, redirectURI string, state, verifier []byte, priv [32]byte) (*createResponse, error) {
	pub, err := x25519Public(priv)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(createRequest{
		PassID:              passID,
		RedirectURI:         redirectURI,
		State:               base64.RawURLEncoding.EncodeToString(state),
		CodeChallenge:       authn.CodeChallengeS256(base64.RawURLEncoding.EncodeToString(verifier)),
		CodeChallengeMethod: "S256",
		EphemeralPublicKey:  base64.RawURLEncoding.EncodeToString(pub[:]),
	})
	if err != nil {
		return nil, fmt.Errorf("cli: encode create request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/v1/cli/authorizations", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cli: build create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cli: create authorization: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("cli: create authorization: status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var start createResponse
	if err := json.Unmarshal(raw, &start); err != nil {
		return nil, fmt.Errorf("cli: decode create response: %w", err)
	}
	if start.AuthorizationID == "" || start.BrowserURL == "" {
		return nil, fmt.Errorf("cli: create authorization: incomplete response")
	}
	return &start, nil
}

// rejectsNonLoopbackPeer reports whether a RemoteAddr must be refused: only
// 127.0.0.1 is accepted, never other IPv4, IPv6, or unparsable peers.
func rejectsNonLoopbackPeer(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return true
	}
	return host != "127.0.0.1"
}

// ReceiveAuthorizationCode serves exactly one loopback callback and returns
// the authorization code. It requires a loopback peer, the exact expected
// state, and a nonempty code; duplicate or concurrent callbacks after the
// first success are refused. The listener is closed on return.
func ReceiveAuthorizationCode(ctx context.Context, ln net.Listener, expectedState string) (string, error) {
	var once atomic.Bool
	codeCh := make(chan string, 1)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" {
				http.NotFound(w, r)
				return
			}
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if rejectsNonLoopbackPeer(r.RemoteAddr) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			// The OPE web UI follows the server's 302 here with fetch, so
			// reflect its Origin: the response carries no secrets, only the
			// "Return to the CLI" confirmation.
			if origin := r.Header.Get("Origin"); origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			q := r.URL.Query()
			code := q.Get("code")
			state := q.Get("state")
			if code == "" || subtle.ConstantTimeCompare([]byte(state), []byte(expectedState)) != 1 {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if !once.CompareAndSwap(false, true) {
				http.Error(w, "already consumed", http.StatusGone)
				return
			}
			// Write and flush the confirmation before signalling the code:
			// the receiver closes the server on the signal, which would
			// otherwise race the in-flight response and truncate it.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(w, "Return to the CLI.\n")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			codeCh <- code
		}),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case code := <-codeCh:
		// Graceful shutdown, not Close: the confirmation response was
		// flushed before the code was signalled, and Close can tear the
		// connection down before the client reads the body. Shutdown
		// still closes the listener at once, so a duplicate callback
		// after the single success has nowhere to go.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(shutdownCtx)
		cancel()
		<-serveErr
		return code, nil
	case err := <-serveErr:
		return "", fmt.Errorf("cli: callback listener: %w", err)
	case <-ctx.Done():
		_ = srv.Close()
		<-serveErr
		return "", fmt.Errorf("cli: waiting for the browser callback: %w", ctx.Err())
	}
}

// x25519Public derives the public key for a private key.
func x25519Public(priv [32]byte) ([32]byte, error) {
	var zero, pub [32]byte
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return zero, fmt.Errorf("cli: x25519: %w", err)
	}
	copy(pub[:], p)
	return pub, nil
}
