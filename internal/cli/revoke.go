// Package cli: the result-only loopback PKCE revocation handoff.
//
// RevokeMission runs the founder's browser revocation decision for one
// pass: it registers the request, prints the browser URL, waits on the
// loopback callback for the one-use result code, and exchanges the code
// plus verifier for only the opaque result reference and the fixed
// containment state. The founder picks the revocation reason in the
// browser. No session or credential is ever issued. Secrets (state,
// verifier, code) stay in memory only; Destroy zeroes them.
package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
)

// RevokeOptions configures one RevokeMission call.
type RevokeOptions struct {
	// HTTPClient performs the register and exchange requests; defaults
	// to http.DefaultClient.
	HTTPClient *http.Client
	// OpenBrowser, when set, is called with the browser URL. The URL is
	// always printed too, so the handoff never requires xdg-open.
	OpenBrowser func(url string) error
	// Output receives the printed browser URL and result; defaults to
	// os.Stdout.
	Output io.Writer
	// CallbackTimeout bounds the wait for the loopback callback.
	CallbackTimeout time.Duration
}

// RevocationRequest is the retained handoff material for the result
// exchange. Code, verifier, and state live in memory only; Destroy
// zeroes them.
type RevocationRequest struct {
	RequestID string
	PassID    string
	Code      string

	state    []byte
	verifier []byte
}

// Destroy zeroes the in-memory secrets. It is idempotent.
func (r *RevocationRequest) Destroy() {
	if r == nil {
		return
	}
	for i := range r.state {
		r.state[i] = 0
	}
	for i := range r.verifier {
		r.verifier[i] = 0
	}
	r.state = nil
	r.verifier = nil
	r.Code = ""
}

// RevocationOutcome is the CLI's whole result: the opaque result
// reference plus the fixed containment state.
type RevocationOutcome struct {
	ResultRef   string
	Containment string
}

// revokeRegisterRequest is the wire form of the registration.
type revokeRegisterRequest struct {
	PassID              string `json:"pass_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// revokeRegisterResponse is the wire form of the registered request.
type revokeRegisterResponse struct {
	RequestID        string `json:"request_id"`
	BrowserURL       string `json:"browser_url"`
	RevocationDigest string `json:"revocation_digest"`
}

// revokeExchangeResponse is the wire form of the exchanged result.
type revokeExchangeResponse struct {
	ResultRef   string `json:"result_ref"`
	Containment string `json:"containment"`
}

// RevokeMission runs the browser revocation handoff for one pass and
// returns the opaque result reference plus the fixed containment state.
// The founder picks the revocation reason in the browser. The request
// bundle is always destroyed before RevokeMission returns, so no handoff
// secret survives a completed or failed call.
func RevokeMission(ctx context.Context, apiBase, passID string, opts RevokeOptions) (outcome *RevocationOutcome, err error) {
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

	stateStr, verifierStr, err := newRevocationSecrets()
	if err != nil {
		return nil, err
	}
	state, err := base64.RawURLEncoding.DecodeString(stateStr)
	if err != nil {
		return nil, fmt.Errorf("cli: decode state: %w", err)
	}
	verifier, err := base64.RawURLEncoding.DecodeString(verifierStr)
	if err != nil {
		return nil, fmt.Errorf("cli: decode verifier: %w", err)
	}
	req := &RevocationRequest{PassID: passID}
	req.state = state
	req.verifier = verifier
	// Named returns: the request is destroyed on every path, so no
	// handoff secret survives this call.
	defer req.Destroy()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("cli: bind loopback listener: %w", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	reg, err := postRevocationRegister(ctx, client, apiBase, passID, redirectURI, stateStr, verifierStr)
	if err != nil {
		return nil, err
	}
	req.RequestID = reg.RequestID

	fmt.Fprintf(out, "Open this URL in your browser to revoke the mission:\n%s\n", reg.BrowserURL)
	if opts.OpenBrowser != nil {
		// Best effort: the printed URL is the real handoff path.
		_ = opts.OpenBrowser(reg.BrowserURL)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	code, err := ReceiveAuthorizationCode(ctx, ln, stateStr)
	if err != nil {
		return nil, err
	}
	if code == "" {
		return nil, fmt.Errorf("cli: empty result code")
	}
	req.Code = code

	outcome, err = exchangeRevocationResult(ctx, client, apiBase, code, verifierStr, redirectURI, stateStr)
	if err != nil {
		return nil, err
	}
	// The revocation outcome is a result, not a secret: report it. The
	// deferred Destroy zeroes the handoff material on every path.
	fmt.Fprintf(out, "Revocation result %s: containment %s.\n", outcome.ResultRef, outcome.Containment)
	return outcome, nil
}

// newRevocationSecrets generates the 256-bit state and PKCE verifier
// for one revocation handoff, in the base64url form the wire carries.
func newRevocationSecrets() (state, verifier string, err error) {
	state, err = authn.NewPKCEVerifier()
	if err != nil {
		return "", "", fmt.Errorf("cli: new state: %w", err)
	}
	verifier, err = authn.NewPKCEVerifier()
	if err != nil {
		return "", "", fmt.Errorf("cli: new verifier: %w", err)
	}
	return state, verifier, nil
}

// postRevocationRegister registers the revocation request.
func postRevocationRegister(ctx context.Context, client *http.Client, apiBase, passID, redirectURI, state, verifier string) (*revokeRegisterResponse, error) {
	body, err := json.Marshal(revokeRegisterRequest{
		PassID:              passID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       authn.CodeChallengeS256(verifier),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		return nil, fmt.Errorf("cli: encode revocation request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/v1/cli/revocations", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cli: build revocation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cli: register revocation: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("cli: register revocation: %s", tokenErrorDetail(resp.StatusCode, raw))
	}
	var reg revokeRegisterResponse
	if err := json.Unmarshal(raw, &reg); err != nil {
		return nil, fmt.Errorf("cli: decode revocation registration: %w", err)
	}
	if reg.RequestID == "" || reg.BrowserURL == "" {
		return nil, fmt.Errorf("cli: register revocation: incomplete response")
	}
	return &reg, nil
}

// exchangeRevocationResult exchanges the one-use result code plus
// verifier for the opaque result reference and containment.
func exchangeRevocationResult(ctx context.Context, client *http.Client, apiBase, code, verifier, redirectURI, state string) (*RevocationOutcome, error) {
	body, err := json.Marshal(map[string]string{
		"code":           code,
		"code_verifier":  verifier,
		"redirect_uri":   redirectURI,
		"state":          state,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: encode revocation exchange: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/v1/cli/revocations/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cli: build revocation exchange: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cli: exchange revocation result: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cli: exchange revocation result: %s", tokenErrorDetail(resp.StatusCode, raw))
	}
	var exchanged revokeExchangeResponse
	if err := json.Unmarshal(raw, &exchanged); err != nil {
		return nil, fmt.Errorf("cli: decode revocation result: %w", err)
	}
	if exchanged.ResultRef == "" || exchanged.Containment == "" {
		return nil, fmt.Errorf("cli: exchange revocation result: incomplete response")
	}
	return &RevocationOutcome{
		ResultRef:   exchanged.ResultRef,
		Containment: exchanged.Containment,
	}, nil
}
