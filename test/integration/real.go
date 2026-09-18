package integration

// Shared harness for the real-integration suite (Task 16, release proof).
//
// Every test in this package drives the pinned real AuthScope service,
// the enforcing gateway, the supported authscope-agent-run runtime, the
// fixed coding-agent kit, and a disposable GitHub installation and
// repository. Nothing here substitutes a fake: when OPE_REAL_INTEGRATION
// is not "1", or when any real prerequisite is absent, the test skips
// and names exactly what is missing. The preflight script
// (scripts/run-real-integration.sh --preflight) checks the same
// prerequisite set and fails closed before any test runs.
//
// The suite is operator-driven for the human ceremonies (passkey
// approval, browser CLI authorization, the GitHub installation click
// through). The operator performs those once against the real backend
// and records the resulting artifact identifiers in a manifest JSON
// file named by OPE_REAL_MANIFEST. The Go tests then verify the
// security properties of those artifacts (invocation-digest equality
// through every stage, local receipt verification, minimal check
// contents) and run the fully automatable denial, timing, concurrency,
// and isolation matrices themselves.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/identity"
)

// realPrereq names one real prerequisite with the environment variable
// that provides it. The preflight script checks this same set; keep the
// two in sync.
type realPrereq struct {
	env  string
	what string
}

var realPrereqs = []realPrereq{
	{"AUTH_SCOPE_URL", "pinned real AuthScope service base URL (https)"},
	{"OPE_GATEWAY_URL", "enforcing AuthScope gateway base URL"},
	{"OPE_RUNTIME_BIN", "supported authscope-agent-run executable"},
	{"OPE_AGENT_KIT", "fixed coding-agent kit as id@version"},
	{"OPE_GITHUB_REPO", "disposable private GitHub repository as owner/name"},
	{"OPE_GITHUB_INSTALLATION_ID", "AuthScope-hosted GitHub installation id"},
	{"OPE_SIGNING_KEYS_DIGEST", "expected signing-key-history digest"},
	{"OPE_AUTHSCOPE_VERSION", "pinned immutable AuthScope release version"},
	{"OPE_WORKSPACE_ID", "bound AuthScope workspace id"},
	{"OPE_HOSTNAME", "public hostname of the OPE instance under test"},
	{"OPE_ORIGIN", "exact browser origin of the OPE instance under test"},
	{"OPE_WORKLOAD_SIGNER_REF", "non-exportable workload signer reference"},
	{"OPE_URL", "base URL of the OPE release build under test"},
	{"OPE_REAL_MANIFEST", "JSON manifest of operator-recorded artifacts"},
}

// realEnv carries the resolved real-integration environment.
type realEnv struct {
	AuthScopeURL         string
	GatewayURL           string
	RuntimeBin           string
	AgentKit             string
	GitHubRepo           string
	GitHubInstallationID string
	SigningKeysDigest    string
	AuthScopeVersion     string
	WorkspaceID          string
	Hostname             string
	Origin               string
	WorkloadSignerRef    string
	OPEURL               string
	ManifestPath         string
	values               map[string]string
}

// loadReal skips the test unless the full real environment is present.
// Every skip names the missing prerequisite so the operator knows
// exactly what to provision; nothing is faked or defaulted.
func loadReal(t *testing.T) realEnv {
	t.Helper()
	if os.Getenv("OPE_REAL_INTEGRATION") != "1" {
		t.Skip("real integration suite disabled: set OPE_REAL_INTEGRATION=1 with the real prerequisites to run")
	}
	var missing []string
	values := map[string]string{}
	for _, p := range realPrereqs {
		v := strings.TrimSpace(os.Getenv(p.env))
		if v == "" {
			missing = append(missing, fmt.Sprintf("%s (%s)", p.env, p.what))
			continue
		}
		values[p.env] = v
	}
	if len(missing) > 0 {
		t.Skipf("real integration prerequisites absent:\n  - %s", strings.Join(missing, "\n  - "))
	}
	return realEnv{
		AuthScopeURL:         values["AUTH_SCOPE_URL"],
		GatewayURL:           values["OPE_GATEWAY_URL"],
		RuntimeBin:           values["OPE_RUNTIME_BIN"],
		AgentKit:             values["OPE_AGENT_KIT"],
		GitHubRepo:           values["OPE_GITHUB_REPO"],
		GitHubInstallationID: values["OPE_GITHUB_INSTALLATION_ID"],
		SigningKeysDigest:    values["OPE_SIGNING_KEYS_DIGEST"],
		AuthScopeVersion:     values["OPE_AUTHSCOPE_VERSION"],
		WorkspaceID:          values["OPE_WORKSPACE_ID"],
		Hostname:             values["OPE_HOSTNAME"],
		Origin:               values["OPE_ORIGIN"],
		WorkloadSignerRef:    values["OPE_WORKLOAD_SIGNER_REF"],
		OPEURL:               values["OPE_URL"],
		ManifestPath:         values["OPE_REAL_MANIFEST"],
		values:               values,
	}
}

// realManifest is the operator-recorded artifact set for one completed
// real journey. The human ceremonies (passkey approval, browser CLI
// authorization, GitHub installation click-through) are performed once
// and recorded here; the tests verify their security properties.
type realManifest struct {
	MissionRef       string   `json:"mission_ref"`
	ProposalID       string   `json:"proposal_id"`
	ProposalDigest   string   `json:"proposal_digest"`
	InvocationDigest string   `json:"invocation_digest"`
	AgentKit         string   `json:"agent_kit"`
	RunnerArgv       []string `json:"runner_argv"`
	GrantID          string   `json:"grant_id"`
	RunID            string   `json:"run_id"`
	Branch           string   `json:"branch"`
	PRNumber         int64    `json:"pr_number"`
	ReceiptID        string   `json:"receipt_id"`
	HandoffID        string   `json:"handoff_id"`
	ConnectionID     string   `json:"connection_id"`
	IssueNumber      int64    `json:"issue_number"`
	RepositoryID     int64    `json:"repository_id"`
}

func loadManifest(t *testing.T, e realEnv) realManifest {
	t.Helper()
	raw, err := os.ReadFile(e.ManifestPath)
	if err != nil {
		t.Fatalf("cannot read OPE_REAL_MANIFEST %q: %v", e.ManifestPath, err)
	}
	var m realManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("invalid OPE_REAL_MANIFEST %q: %v", e.ManifestPath, err)
	}
	if m.MissionRef == "" || m.InvocationDigest == "" || m.ProposalDigest == "" {
		t.Fatalf("OPE_REAL_MANIFEST %q is missing mission_ref, proposal_digest, or invocation_digest", e.ManifestPath)
	}
	return m
}

// invocationDigestOf binds the fixed agent-kit id/version and the exact
// proposal runner-argument array into one digest. The same computation
// must reproduce the digest at every stage: proposal, CLI create,
// passkey decision, token exchange, and sealed launch envelope.
func invocationDigestOf(agentKit string, argv []string) string {
	h := sha256.New()
	h.Write([]byte("ope-invocation-v1\x00"))
	h.Write([]byte(agentKit))
	h.Write([]byte("\x00"))
	for _, a := range argv {
		h.Write([]byte(a))
		h.Write([]byte("\x00"))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// realHTTP is an HTTP client bound to one OPE origin with a cookie jar,
// used for the same-origin authenticated calls in the suite.
type realHTTP struct {
	client *http.Client
	origin string
}

func newRealHTTP(t *testing.T, origin string) *realHTTP {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cannot build cookie jar: %v", err)
	}
	return &realHTTP{
		client: &http.Client{Jar: jar, Timeout: 30 * time.Second},
		origin: strings.TrimRight(origin, "/"),
	}
}

func (h *realHTTP) do(t *testing.T, method, path string, body any, headers map[string]string) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("cannot marshal request body: %v", err)
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.origin+path, rdr)
	if err != nil {
		t.Fatalf("cannot build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", h.origin)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		t.Fatalf("cannot read response body: %v", err)
	}
	return resp.StatusCode, out
}

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("response is not JSON: %v\nbody: %s", err, truncate(raw, 2000))
	}
	return m
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

// recordedRequest is one request observed by the tee proxy.
type recordedRequest struct {
	Method string
	Path   string
	Query  string
	Body   []byte
}

// teeProxy is a reverse proxy placed in front of the OPE instance under
// test. It records every request so the suite can prove properties of
// the OPE request stream, such as "no GitHub OAuth code or token ever
// reaches OPE".
type teeProxy struct {
	server   *http.Server
	url      string
	mu       sync.Mutex
	requests []recordedRequest
}

func newTeeProxy(t *testing.T, target string) *teeProxy {
	t.Helper()
	tgt, err := url.Parse(target)
	if err != nil {
		t.Fatalf("invalid proxy target %q: %v", target, err)
	}
	p := &teeProxy{}
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = tgt.Scheme
			r.URL.Host = tgt.Host
			r.Host = tgt.Host
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(r.Body, 8<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		p.mu.Lock()
		p.requests = append(p.requests, recordedRequest{
			Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: body,
		})
		p.mu.Unlock()
		proxy.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: handler}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen for tee proxy: %v", err)
	}
	p.server = srv
	p.url = "http://" + ln.Addr().String()
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return p
}

func (p *teeProxy) recorded() []recordedRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]recordedRequest, len(p.requests))
	copy(out, p.requests)
	return out
}

// githubOAuthMaterial matches GitHub OAuth codes and tokens in captured
// traffic. OPE must never see these: the GitHub installation handoff is
// AuthScope-hosted, and only the one-use AuthScope binding code reaches
// OPE's finish endpoint.
var githubOAuthMaterial = regexp.MustCompile(`(?i)(github[^"']{0,40}(oauth|access_token|refresh_token)|"code"\s*:\s*"[A-Za-z0-9_\-]{8,}"|access_token\s*=\s*[A-Za-z0-9_\-]{8,}|gho_[A-Za-z0-9_]{20,}|ghu_[A-Za-z0-9_]{20,})`)

// assertNoGitHubOAuthMaterial fails the test when any captured OPE
// request carries GitHub OAuth code or token material.
func assertNoGitHubOAuthMaterial(t *testing.T, reqs []recordedRequest) {
	t.Helper()
	for _, r := range reqs {
		hay := r.Method + " " + r.Path + "?" + r.Query + "\n" + string(r.Body)
		if m := githubOAuthMaterial.FindString(hay); m != "" {
			t.Fatalf("GitHub OAuth material reached OPE in %s %s: matched %q", r.Method, r.Path, truncateStr(m, 80))
		}
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// mintAttestationForTest mints a well-formed decision attestation with a
// throwaway signer for the denial matrix. These attestations must be
// rejected by the real backend: the throwaway identity was never
// registered and carries no decision_attestor role.
func mintAttestationForTest(t *testing.T, mutate func(*identity.DecisionClaims)) identity.SignedDecisionAttestation {
	t.Helper()
	signer := identity.NewEphemeralSigner()
	attestor := identity.NewDecisionAttestor(signer)
	var nonce [32]byte
	copy(nonce[:], "test-nonce-0000000000000000000000")
	claims := identity.DecisionClaims{
		WorkspaceID:               "ws-real-test",
		FounderID:                 "founder-test",
		Audience:                  identity.AudienceProposalApproval,
		Purpose:                   identity.PurposePassApproval,
		SubjectID:                 "proposal-test",
		DecisionDigest:            "sha256:" + strings.Repeat("a", 64),
		InvocationDigest:          "sha256:" + strings.Repeat("b", 64),
		AuthenticationMethod:      identity.AuthMethodWebAuthnUV,
		AuthenticationProofDigest: "sha256:" + strings.Repeat("c", 64),
		Nonce:                     nonce,
		IssuedAt:                  time.Now().UTC().Add(-time.Minute),
		ExpiresAt:                 time.Now().UTC().Add(10 * time.Minute),
	}
	if mutate != nil {
		mutate(&claims)
	}
	att, err := attestor.Attest(context.Background(), claims)
	if err != nil {
		t.Fatalf("cannot mint test attestation: %v", err)
	}
	return att
}

// attestationJSON renders a signed attestation as the JSON the OPE
// finish endpoints accept.
func attestationJSON(att identity.SignedDecisionAttestation) map[string]any {
	return map[string]any{
		"algorithm":       att.Algorithm,
		"key_id":          att.KeyID,
		"identity_digest": att.IdentityDigest,
		"claims": map[string]any{
			"workspace_id":                att.Claims.WorkspaceID,
			"founder_id":                  att.Claims.FounderID,
			"audience":                    att.Claims.Audience,
			"purpose":                     att.Claims.Purpose,
			"subject_id":                  att.Claims.SubjectID,
			"decision_digest":             att.Claims.DecisionDigest,
			"invocation_digest":           att.Claims.InvocationDigest,
			"authentication_method":       att.Claims.AuthenticationMethod,
			"authentication_proof_digest": att.Claims.AuthenticationProofDigest,
			"nonce":                       hex.EncodeToString(att.Claims.Nonce[:]),
			"issued_at":                   att.Claims.IssuedAt.UTC().Format(time.RFC3339),
			"expires_at":                  att.Claims.ExpiresAt.UTC().Format(time.RFC3339),
		},
		"signature": hex.EncodeToString(att.Signature),
	}
}
