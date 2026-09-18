// Package cli: token exchange and envelope opening for the governed run.
//
// After AuthorizeLaunch returns the in-memory authorization bundle,
// ExchangeLaunch posts the code plus verifier to POST /api/v1/cli/token
// and returns the sealed signed envelope. OpenSealedEnvelope opens the
// envelope with the bundle's ephemeral private key, verifies the pinned
// signing keys, the audience, expiry, nonce, isolation, and every value
// retained from the authorization, and returns the payload plus the
// signed envelope bytes for runner FD delivery. Secrets stay in memory
// only.
package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/launch"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// tokenResponse is the wire form of the exchange result.
type tokenResponse struct {
	RunID          string `json:"run_id"`
	MissionRef     string `json:"mission_ref"`
	SealedEnvelope string `json:"sealed_envelope"`
}

// problemBody is the RFC 9457 error the server renders.
type problemBody struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// TokenExchange is the prepared governed run returned by the token
// endpoint. SealedEnvelope is the opaque sealed signed envelope; it is
// never persisted.
type TokenExchange struct {
	RunID          string
	MissionRef     string
	SealedEnvelope []byte
}

// Verifier returns the bundle's PKCE verifier in base64url.
func (b *LaunchAuthorization) Verifier() string {
	if b == nil || len(b.verifier) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b.verifier)
}

// EphemeralPrivateKey returns a copy of the bundle's ephemeral X25519
// private key.
func (b *LaunchAuthorization) EphemeralPrivateKey() [32]byte {
	var priv [32]byte
	if b != nil {
		priv = b.ephemeralPrivateKey
	}
	return priv
}

// ExchangeLaunch exchanges the bundle's code plus verifier for the
// sealed signed envelope of the prepared governed run. The HTTP client
// defaults to http.DefaultClient. On any error the bundle is left
// untouched; the caller still owns Destroy.
func ExchangeLaunch(ctx context.Context, apiBase string, bundle *LaunchAuthorization, client *http.Client) (*TokenExchange, error) {
	if bundle == nil {
		return nil, fmt.Errorf("cli: launch authorization is required")
	}
	if bundle.Code == "" {
		return nil, fmt.Errorf("cli: authorization code is missing")
	}
	verifier := bundle.Verifier()
	if verifier == "" {
		return nil, fmt.Errorf("cli: PKCE verifier is missing")
	}
	if client == nil {
		client = http.DefaultClient
	}
	apiBase = strings.TrimSuffix(apiBase, "/")
	body, err := json.Marshal(map[string]string{
		"code":     bundle.Code,
		"verifier": verifier,
	})
	if err != nil {
		return nil, fmt.Errorf("cli: encode token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/v1/cli/token", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cli: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cli: token exchange: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cli: token exchange: %s", tokenErrorDetail(resp.StatusCode, raw))
	}
	var tok tokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, fmt.Errorf("cli: decode token response: %w", err)
	}
	if tok.RunID == "" || tok.SealedEnvelope == "" {
		return nil, fmt.Errorf("cli: token exchange: incomplete response")
	}
	sealed, err := base64.RawURLEncoding.DecodeString(tok.SealedEnvelope)
	if err != nil || len(sealed) == 0 {
		return nil, fmt.Errorf("cli: token exchange: bad sealed envelope")
	}
	return &TokenExchange{
		RunID:          tok.RunID,
		MissionRef:     tok.MissionRef,
		SealedEnvelope: sealed,
	}, nil
}

// tokenErrorDetail renders a user-safe exchange failure from the status
// and the server's problem body.
func tokenErrorDetail(status int, raw []byte) string {
	var p problemBody
	if err := json.Unmarshal(raw, &p); err == nil && p.Title != "" {
		if p.Detail != "" {
			return fmt.Sprintf("status %d: %s: %s", status, p.Title, p.Detail)
		}
		return fmt.Sprintf("status %d: %s", status, p.Title)
	}
	if s := strings.TrimSpace(string(raw)); s != "" {
		return fmt.Sprintf("status %d: %s", status, s)
	}
	return fmt.Sprintf("status %d", status)
}

// OpenSealedEnvelope opens the sealed envelope with the bundle's
// ephemeral private key and verifies it against the pinned signing keys
// and every value retained from the authorization. runnerExecutable must
// be the validated absolute runner path: the envelope must name exactly
// the binary about to start. It returns the verified payload and the
// signed envelope bytes for runner FD delivery.
func (b *LaunchAuthorization) OpenSealedEnvelope(sealed []byte, keys *trust.KeyStore, runnerExecutable string) (*launch.LaunchPayload, []byte, error) {
	if b == nil {
		return nil, nil, fmt.Errorf("cli: launch authorization is required")
	}
	if keys == nil {
		return nil, nil, fmt.Errorf("cli: signing-key trust store is required")
	}
	if runnerExecutable == "" {
		return nil, nil, fmt.Errorf("cli: runner executable is required")
	}
	expected := launch.ExpectedBinding{
		ProposalDigest:   b.ProposalDigest,
		InvocationDigest: b.InvocationDigest,
		AgentKitID:       b.AgentKitID,
		AgentKitVersion:  b.AgentKitVersion,
		RunnerExecutable: runnerExecutable,
		RunnerArguments:  append([]string{}, b.RunnerArguments...),
	}
	return launch.OpenEnvelope(sealed, b.ephemeralPrivateKey, keys, expected, launch.NewNonceCache(), time.Now())
}
