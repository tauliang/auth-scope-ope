package coreapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeAuthScope is a test-only AuthScope mission-authority. It verifies
// workload-transport signatures, asserts request shape, verifies decision
// attestations with one-time-consumption semantics, and serves fixtures.
type fakeAuthScope struct {
	t         *testing.T
	signer    *identity.EphemeralSigner
	keys      map[string]ed25519.PublicKey
	roles     map[string][]string
	workspace string

	mu             sync.Mutex
	requests       []recordedRequest
	consumedNonces map[string]bool

	slow      map[string]time.Duration
	oversized map[string]bool
	badEnum   map[string]bool
	problem   map[string]int
}

type recordedRequest struct {
	method string
	path   string
	query  string
	header http.Header
	body   []byte
}

func newFakeAuthScope(t *testing.T) *fakeAuthScope {
	t.Helper()
	signer := identity.NewEphemeralSigner()
	return &fakeAuthScope{
		t:              t,
		signer:         signer,
		keys:           map[string]ed25519.PublicKey{signer.KeyID(): signer.PublicKey()},
		roles:          map[string][]string{signer.KeyID(): {DecisionAttestorRole}},
		workspace:      "ws-test",
		consumedNonces: map[string]bool{},
		slow:           map[string]time.Duration{},
		oversized:      map[string]bool{},
		badEnum:        map[string]bool{},
		problem:        map[string]int{},
	}
}

func (f *fakeAuthScope) client() *Client {
	f.t.Helper()
	srv := httptest.NewServer(f)
	f.t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, nil, f.signer, "development")
	if err != nil {
		f.t.Fatalf("NewClient: %v", err)
	}
	return c
}

func (f *fakeAuthScope) fixture(name string) []byte {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func (f *fakeAuthScope) lastRequest() recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		f.t.Fatal("no requests recorded")
	}
	return f.requests[len(f.requests)-1]
}

// verifyTransport checks the workload-signer transport authentication and
// derives the caller identity from it, never from a client header.
func (f *fakeAuthScope) verifyTransport(w http.ResponseWriter, r *http.Request, body []byte) bool {
	keyID := r.Header.Get("X-AuthScope-Workload-KeyID")
	ts := r.Header.Get("X-AuthScope-Workload-Timestamp")
	sigB64 := r.Header.Get("X-AuthScope-Workload-Signature")
	pub, ok := f.keys[keyID]
	if !ok || keyID == "" || ts == "" || sigB64 == "" {
		writeFakeProblem(w, http.StatusUnauthorized, "authentication_required", "unknown workload identity")
		return false
	}
	secs, err := parseInt(ts)
	if err != nil || abs64(time.Now().Unix()-secs) > 300 {
		writeFakeProblem(w, http.StatusUnauthorized, "authentication_required", "stale workload timestamp")
		return false
	}
	sum := sha256.Sum256(body)
	path := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		writeFakeProblem(w, http.StatusUnauthorized, "authentication_required", "malformed workload signature")
		return false
	}
	if !ed25519.Verify(pub, workloadAuthPayload(ts, r.Method, path, hex.EncodeToString(sum[:])), sig) {
		writeFakeProblem(w, http.StatusUnauthorized, "authentication_required", "bad workload signature")
		return false
	}
	return true
}

func writeFakeProblem(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code": code, "message": message, "request_id": "fake-req-1", "retryable": false,
	})
}

func (f *fakeAuthScope) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if !f.verifyTransport(w, r, body) {
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{
		method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery,
		header: r.Header.Clone(), body: body,
	})
	f.mu.Unlock()

	if r.Header.Get("Content-Type") != "application/json" {
		writeFakeProblem(w, http.StatusBadRequest, "invalid_request", "content type must be application/json")
		return
	}

	path := r.URL.EscapedPath()
	if d, ok := f.slow[path]; ok {
		time.Sleep(d)
	}
	if f.oversized[path] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseBytes+16))
		return
	}
	if status, ok := f.problem[path]; ok {
		writeFakeProblem(w, status, "denied_for_test", "denied by fake AuthScope")
		return
	}
	if f.badEnum[path] {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"binding_id":"binding-1","ref":"main","workflows_inspected":1,"findings":[],"posture":"mysterious"}`))
		return
	}

	switch {
	case path == "/.well-known/mission-authority" && r.Method == http.MethodGet:
		f.serveDiscovery(w)
	case path == "/v1/identities/workload/verify" && r.Method == http.MethodPost:
		f.serveVerifyIdentity(w, r)
	case path == "/v1/integrations/github/bindings/begin" && r.Method == http.MethodPost:
		f.serveFixture(w, "github_handoff.json", http.StatusCreated)
	case path == "/v1/integrations/github/bindings/finish" && r.Method == http.MethodPost:
		f.serveFixture(w, "repository_binding.json", http.StatusOK)
	case path == "/v1/missions" && r.Method == http.MethodGet:
		f.serveFixture(w, "active_missions.json", http.StatusOK)
	case strings.HasPrefix(path, "/v1/workspaces/") && strings.HasSuffix(path, "/contain") && r.Method == http.MethodPost:
		f.serveContain(w, r, body)
	case path == "/v1/integrations/github/workflow-posture" && r.Method == http.MethodPost:
		f.serveFixture(w, "workflow_posture.json", http.StatusOK)
	case path == "/.well-known/auth-scope-signing-keys" && r.Method == http.MethodGet:
		f.serveFixture(w, "signing_keys.json", http.StatusOK)
	case path == "/v1/events" && r.Method == http.MethodGet:
		f.serveFixture(w, "event_page.json", http.StatusOK)
	case strings.HasSuffix(path, "/receipt") && r.Method == http.MethodGet:
		f.serveFixture(w, "receipt.json", http.StatusOK)
	default:
		writeFakeProblem(w, http.StatusNotFound, "not_found", "no fake handler for "+path)
	}
}

func (f *fakeAuthScope) serveFixture(w http.ResponseWriter, name string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(f.fixture(name))
}

func (f *fakeAuthScope) serveDiscovery(w http.ResponseWriter) {
	lock := LockedContract()
	manifest := RequiredManifest()
	seen := map[string]bool{}
	var caps []string
	for _, op := range manifest.RequiredOperations {
		if !seen[op.Capability] {
			seen[op.Capability] = true
			caps = append(caps, op.Capability)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":        lock.CoreVersion,
		"openapi_sha256": lock.OpenAPISHA256,
		"capabilities":   caps,
	})
}

func (f *fakeAuthScope) serveVerifyIdentity(w http.ResponseWriter, r *http.Request) {
	keyID := r.Header.Get("X-AuthScope-Workload-KeyID")
	digest := "sha256:" + hex.EncodeToString(sha256Sum([]byte(keyID)))
	if keyID == f.signer.KeyID() {
		digest = f.signer.IdentityDigest()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"identity_id":      "wid-1",
		"identity_digest":  digest,
		"workspace_id":     f.workspace,
		"roles":            f.roles[keyID],
		"registry_version": 3,
	})
}

func (f *fakeAuthScope) serveContain(w http.ResponseWriter, r *http.Request, body []byte) {
	var parsed struct {
		Attestation map[string]any `json:"attestation"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Attestation == nil {
		writeFakeProblem(w, http.StatusBadRequest, "invalid_attestation", "missing attestation")
		return
	}
	if err := f.verifyEnvelope(parsed.Attestation); err != nil {
		writeFakeProblem(w, http.StatusForbidden, "invalid_attestation", err.Error())
		return
	}
	f.serveFixture(w, "containment.json", http.StatusOK)
}

// wireClaimsJSON mirrors the attestation wire claims for verification.
type wireClaimsJSON struct {
	WorkspaceID string `json:"workspace_id"`
	Founder     string `json:"founder"`
	Audience    string `json:"audience"`
	Purpose     string `json:"purpose"`
	Subject     struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"subject"`
	DecisionDigest            string `json:"decision_digest"`
	InvocationDigest          string `json:"invocation_digest"`
	AuthenticationMethod      string `json:"authentication_method"`
	AuthenticationProofDigest string `json:"authentication_proof_digest"`
	IssuedAt                  int64  `json:"issued_at"`
	ExpiresAt                 int64  `json:"expires_at"`
	Nonce                     string `json:"nonce"`
}

// verifyEnvelope is the fake AuthScope decision-attestation verifier. It
// checks the signature against the canonical claims, enforces workspace,
// audience, purpose, digest, nonce, freshness, and one-time consumption,
// and requires the decision_attestor role on the signer registration.
func (f *fakeAuthScope) verifyEnvelope(env map[string]any) error {
	alg, _ := env["algorithm"].(string)
	keyID, _ := env["key_id"].(string)
	identityDigest, _ := env["identity_digest"].(string)
	sigB64, _ := env["signature"].(string)
	if alg != identity.AlgorithmTag {
		return errors.New("unsupported algorithm")
	}
	roles := f.roles[keyID]
	authorized := false
	for _, r := range roles {
		if r == DecisionAttestorRole {
			authorized = true
		}
	}
	if !authorized {
		return errors.New("attestor_not_authorized")
	}
	pub, ok := f.keys[keyID]
	if !ok {
		return errors.New("unknown_signer")
	}
	claimsRaw, err := json.Marshal(env["claims"])
	if err != nil {
		return errors.New("malformed")
	}
	var wc wireClaimsJSON
	if err := json.Unmarshal(claimsRaw, &wc); err != nil {
		return errors.New("malformed")
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(wc.Nonce)
	if err != nil || len(nonceBytes) != 32 {
		return errors.New("malformed")
	}
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	claims := identity.DecisionClaims{
		WorkspaceID:               wc.WorkspaceID,
		FounderID:                 wc.Founder,
		Audience:                  wc.Audience,
		Purpose:                   wc.Purpose,
		SubjectID:                 wc.Subject.ID,
		DecisionDigest:            wc.DecisionDigest,
		InvocationDigest:          wc.InvocationDigest,
		AuthenticationMethod:      wc.AuthenticationMethod,
		AuthenticationProofDigest: wc.AuthenticationProofDigest,
		Nonce:                     nonce,
		IssuedAt:                  time.Unix(wc.IssuedAt, 0).UTC(),
		ExpiresAt:                 time.Unix(wc.ExpiresAt, 0).UTC(),
	}
	canonical, err := identity.CanonicalClaimsJSON(claims, keyID, identityDigest)
	if err != nil {
		return errors.New("decision_binding_mismatch: " + err.Error())
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("malformed")
	}
	domainMsg := append([]byte(identity.AttestationDomain), 0x00)
	domainMsg = append(domainMsg, canonical...)
	if !ed25519.Verify(pub, domainMsg, sig) {
		return errors.New("bad_signature")
	}
	if claims.WorkspaceID != f.workspace {
		return errors.New("workspace_mismatch")
	}
	now := time.Now().Unix()
	if now >= claims.ExpiresAt.Unix() {
		return errors.New("expired")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.consumedNonces[wc.Nonce] {
		return errors.New("attestation_replayed")
	}
	f.consumedNonces[wc.Nonce] = true
	return nil
}

func parseInt(s string) (int64, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func testRequestOptions() RequestOptions {
	return RequestOptions{
		WorkspaceID:    "ws-test",
		ActorID:        "founder-1",
		TraceID:        "trace-1",
		RequestID:      "req-1",
		IdempotencyKey: "idem-1",
		MissionVersion: 7,
	}
}

func validTestAttestation(t *testing.T, f *fakeAuthScope, purpose string) map[string]any {
	t.Helper()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	claims := identity.DecisionClaims{
		WorkspaceID:               "ws-test",
		FounderID:                 "founder-1",
		Audience:                  identity.AudienceWorkspaceContain,
		Purpose:                   purpose,
		SubjectID:                 "ws-test",
		DecisionDigest:            "sha256:" + strings.Repeat("d", 64),
		AuthenticationMethod:      identity.AuthMethodOfflineRecovery,
		AuthenticationProofDigest: "sha256:" + strings.Repeat("e", 64),
		Nonce:                     nonce,
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(5 * time.Minute),
	}
	if purpose == identity.PurposePassApproval {
		claims.Audience = identity.AudienceProposalApproval
		claims.AuthenticationMethod = identity.AuthMethodWebAuthnUV
		claims.InvocationDigest = "sha256:" + strings.Repeat("f", 64)
		claims.SubjectID = "proposal-1"
	}
	attestor := identity.NewDecisionAttestor(f.signer)
	att, err := attestor.Attest(context.Background(), claims)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	env, err := identity.WireEnvelope(att)
	if err != nil {
		t.Fatalf("WireEnvelope: %v", err)
	}
	return env
}

func mutateEnvelope(env map[string]any, path string, value any) map[string]any {
	raw, _ := json.Marshal(env)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	target := out
	if strings.HasPrefix(path, "claims.") {
		target = out["claims"].(map[string]any)
		path = strings.TrimPrefix(path, "claims.")
	}
	if strings.Contains(path, ".") {
		parts := strings.SplitN(path, ".", 2)
		target = target[parts[0]].(map[string]any)
		path = parts[1]
	}
	target[path] = value
	return out
}

func TestClientGitHubBindingHandoff(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	opts := testRequestOptions()

	handoff, err := c.BeginGitHubBinding(context.Background(), GitHubBindingBeginRequest{Repository: "octo/repo"}, opts)
	if err != nil {
		t.Fatalf("BeginGitHubBinding: %v", err)
	}
	if handoff.HandoffID != "handoff-1" || handoff.BindingCode == "" {
		t.Fatalf("handoff = %+v", handoff)
	}

	req := f.lastRequest()
	if req.method != http.MethodPost {
		t.Fatalf("method = %s", req.method)
	}
	if req.path != "/v1/integrations/github/bindings/begin" {
		t.Fatalf("path = %s", req.path)
	}
	if string(req.body) != `{"repository":"octo/repo"}` {
		t.Fatalf("body = %s", req.body)
	}
	assertRequestHeaders(t, req, opts)

	binding, err := c.FinishGitHubBinding(context.Background(), GitHubBindingFinishRequest{
		HandoffID:   handoff.HandoffID,
		BindingCode: handoff.BindingCode,
	}, opts)
	if err != nil {
		t.Fatalf("FinishGitHubBinding: %v", err)
	}
	if binding.Repository != "octo/repo" || binding.WorkspaceID != "ws-test" {
		t.Fatalf("binding = %+v", binding)
	}
	req = f.lastRequest()
	if req.path != "/v1/integrations/github/bindings/finish" {
		t.Fatalf("path = %s", req.path)
	}
	var finishBody map[string]any
	if err := json.Unmarshal(req.body, &finishBody); err != nil {
		t.Fatal(err)
	}
	if finishBody["handoff_id"] != "handoff-1" || finishBody["binding_code"] != handoff.BindingCode {
		t.Fatalf("finish body = %s", req.body)
	}
}

func assertRequestHeaders(t *testing.T, req recordedRequest, opts RequestOptions) {
	t.Helper()
	if got := req.header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := req.header.Get("X-AuthScope-Workspace"); got != opts.WorkspaceID {
		t.Fatalf("X-AuthScope-Workspace = %q", got)
	}
	if got := req.header.Get("X-Request-ID"); got != opts.RequestID {
		t.Fatalf("X-Request-ID = %q", got)
	}
	if got := req.header.Get("Idempotency-Key"); got != opts.IdempotencyKey {
		t.Fatalf("Idempotency-Key = %q", got)
	}
	if got := req.header.Get("X-AuthScope-Actor"); got != opts.ActorID {
		t.Fatalf("X-AuthScope-Actor = %q", got)
	}
	if got := req.header.Get("X-Trace-ID"); got != opts.TraceID {
		t.Fatalf("X-Trace-ID = %q", got)
	}
	if got := req.header.Get("X-AuthScope-Mission-Version"); got != "7" {
		t.Fatalf("X-AuthScope-Mission-Version = %q", got)
	}
	// The authenticated transport must carry the workload identity: key
	// ID, timestamp, and signature, with no bearer token anywhere.
	if got := req.header.Get("X-AuthScope-Workload-KeyID"); got == "" {
		t.Fatal("missing workload key ID")
	}
	if req.header.Get("X-AuthScope-Workload-Signature") == "" {
		t.Fatal("missing workload signature")
	}
	if req.header.Get("Authorization") != "" {
		t.Fatal("transport must not use bearer tokens")
	}
}

func TestClientListActiveMissions(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	missions, err := c.ListActiveMissions(context.Background(), testRequestOptions())
	if err != nil {
		t.Fatalf("ListActiveMissions: %v", err)
	}
	if len(missions) != 2 || missions[0].MissionRef != "mission-1" {
		t.Fatalf("missions = %+v", missions)
	}
	req := f.lastRequest()
	if req.method != http.MethodGet || req.path != "/v1/missions" {
		t.Fatalf("request = %s %s", req.method, req.path)
	}
}

func TestClientContainWorkspace(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	env := validTestAttestation(t, f, identity.PurposeOfflineRecoveryContain)
	att := attestationFromEnvelope(t, env)

	got, err := c.ContainWorkspace(context.Background(), WorkspaceContainmentRequest{
		Founder:        "founder-1",
		IdempotencyKey: "idem-contain-1",
	}, att, testRequestOptions())
	if err != nil {
		t.Fatalf("ContainWorkspace: %v", err)
	}
	if !got.Contained || got.Generation != 3 {
		t.Fatalf("containment = %+v", got)
	}
	req := f.lastRequest()
	if req.path != "/v1/workspaces/ws-test/contain" {
		t.Fatalf("path = %s", req.path)
	}
	var body map[string]any
	if err := json.Unmarshal(req.body, &body); err != nil {
		t.Fatal(err)
	}
	if body["founder"] != "founder-1" || body["idempotency_key"] != "idem-contain-1" {
		t.Fatalf("body = %s", req.body)
	}
	if _, ok := body["attestation"].(map[string]any); !ok {
		t.Fatalf("body missing attestation: %s", req.body)
	}
}

// attestationFromEnvelope rebuilds a SignedDecisionAttestation from a wire
// envelope for client calls that need a mutated or replayed attestation.
func attestationFromEnvelope(t *testing.T, env map[string]any) identity.SignedDecisionAttestation {
	t.Helper()
	raw, _ := json.Marshal(env["claims"])
	var wc wireClaimsJSON
	if err := json.Unmarshal(raw, &wc); err != nil {
		t.Fatal(err)
	}
	nonceBytes, _ := base64.RawURLEncoding.DecodeString(wc.Nonce)
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	sig, _ := base64.RawURLEncoding.DecodeString(env["signature"].(string))
	keyID, _ := env["key_id"].(string)
	digest, _ := env["identity_digest"].(string)
	return identity.SignedDecisionAttestation{
		Algorithm:      identity.AlgorithmTag,
		KeyID:          keyID,
		IdentityDigest: digest,
		Claims: identity.DecisionClaims{
			WorkspaceID:               wc.WorkspaceID,
			FounderID:                 wc.Founder,
			Audience:                  wc.Audience,
			Purpose:                   wc.Purpose,
			SubjectID:                 wc.Subject.ID,
			DecisionDigest:            wc.DecisionDigest,
			InvocationDigest:          wc.InvocationDigest,
			AuthenticationMethod:      wc.AuthenticationMethod,
			AuthenticationProofDigest: wc.AuthenticationProofDigest,
			Nonce:                     nonce,
			IssuedAt:                  time.Unix(wc.IssuedAt, 0).UTC(),
			ExpiresAt:                 time.Unix(wc.ExpiresAt, 0).UTC(),
		},
		Signature: sig,
	}
}

func TestClientAttestationVerification(t *testing.T) {
	newEnv := func(t *testing.T) (*fakeAuthScope, map[string]any) {
		f := newFakeAuthScope(t)
		return f, validTestAttestation(t, f, identity.PurposePassApproval)
	}

	t.Run("valid accepted", func(t *testing.T) {
		f, env := newEnv(t)
		if err := f.verifyEnvelope(env); err != nil {
			t.Fatalf("valid attestation denied: %v", err)
		}
	})

	mutations := []struct {
		name  string
		field string
		value any
	}{
		{"workspace", "claims.workspace_id", "ws-evil"},
		{"audience", "claims.audience", identity.AudienceMissionRevoke},
		{"purpose", "claims.purpose", identity.PurposeMissionRevoke},
		{"subject", "claims.subject.id", "proposal-evil"},
		{"decision digest", "claims.decision_digest", "sha256:" + strings.Repeat("0", 64)},
		{"invocation digest", "claims.invocation_digest", "sha256:" + strings.Repeat("1", 64)},
		{"auth method", "claims.authentication_method", identity.AuthMethodOfflineRecovery},
		{"proof digest", "claims.authentication_proof_digest", "sha256:" + strings.Repeat("2", 64)},
		{"nonce", "claims.nonce", base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))},
		{"issued at", "claims.issued_at", float64(time.Now().Add(time.Hour).Unix())},
		{"expires at", "claims.expires_at", float64(time.Now().Add(-time.Minute).Unix())},
		{"key id", "key_id", "someone-else"},
	}
	for _, m := range mutations {
		t.Run("mutated "+m.name+" denied", func(t *testing.T) {
			f, env := newEnv(t)
			if err := f.verifyEnvelope(mutateEnvelope(env, m.field, m.value)); err == nil {
				t.Fatalf("mutated %s was accepted", m.name)
			}
		})
	}

	t.Run("mutated signature denied", func(t *testing.T) {
		f, env := newEnv(t)
		sigB64 := env["signature"].(string)
		raw, err := base64.RawURLEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatal(err)
		}
		// Flip a bit in the decoded bytes so the mutation is real.
		raw[len(raw)-1] ^= 0x01
		bad := mutateEnvelope(env, "signature", base64.RawURLEncoding.EncodeToString(raw))
		if err := f.verifyEnvelope(bad); err == nil {
			t.Fatal("mutated signature was accepted")
		}
	})

	t.Run("identity without decision_attestor denied", func(t *testing.T) {
		f := newFakeAuthScope(t)
		other := identity.NewEphemeralSigner()
		f.keys[other.KeyID()] = other.PublicKey()
		f.roles[other.KeyID()] = []string{"reader"}
		var nonce [32]byte
		_, _ = rand.Read(nonce[:])
		now := time.Now().UTC().Truncate(time.Second)
		att, err := identity.NewDecisionAttestor(other).Attest(context.Background(), identity.DecisionClaims{
			WorkspaceID:               "ws-test",
			FounderID:                 "founder-1",
			Audience:                  identity.AudienceProposalApproval,
			Purpose:                   identity.PurposePassApproval,
			SubjectID:                 "proposal-1",
			DecisionDigest:            "sha256:" + strings.Repeat("d", 64),
			InvocationDigest:          "sha256:" + strings.Repeat("f", 64),
			AuthenticationMethod:      identity.AuthMethodWebAuthnUV,
			AuthenticationProofDigest: "sha256:" + strings.Repeat("e", 64),
			Nonce:                     nonce,
			IssuedAt:                  now,
			ExpiresAt:                 now.Add(5 * time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		env, err := identity.WireEnvelope(att)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.verifyEnvelope(env); err == nil {
			t.Fatal("identity without decision_attestor was accepted")
		}
	})

	t.Run("replay denied", func(t *testing.T) {
		f, env := newEnv(t)
		if err := f.verifyEnvelope(env); err != nil {
			t.Fatalf("first consumption denied: %v", err)
		}
		if err := f.verifyEnvelope(env); err == nil {
			t.Fatal("replayed attestation was accepted")
		}
	})

	t.Run("tampered attestation denied end to end", func(t *testing.T) {
		f := newFakeAuthScope(t)
		c := f.client()
		env := validTestAttestation(t, f, identity.PurposeOfflineRecoveryContain)
		bad := mutateEnvelope(env, "claims.workspace_id", "ws-evil")
		att := attestationFromEnvelope(t, bad)
		_, err := c.ContainWorkspace(context.Background(), WorkspaceContainmentRequest{
			Founder:        "founder-1",
			IdempotencyKey: "idem-tamper-1",
		}, att, testRequestOptions())
		var upErr *UpstreamError
		if !errors.As(err, &upErr) {
			t.Fatalf("error = %v, want UpstreamError", err)
		}
		if upErr.LocalStatus() != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", upErr.LocalStatus())
		}
	})
}

func TestClientTimeout(t *testing.T) {
	f := newFakeAuthScope(t)
	f.slow["/v1/missions"] = 300 * time.Millisecond
	c := f.client()
	opts := testRequestOptions()
	opts.Timeout = 50 * time.Millisecond
	_, err := c.ListActiveMissions(context.Background(), opts)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context.DeadlineExceeded", err)
	}
}

func TestClientResponseTooLarge(t *testing.T) {
	f := newFakeAuthScope(t)
	f.oversized["/v1/missions"] = true
	c := f.client()
	_, err := c.ListActiveMissions(context.Background(), testRequestOptions())
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("error = %v, want ErrResponseTooLarge", err)
	}
}

func TestClientUnknownEnumFails(t *testing.T) {
	f := newFakeAuthScope(t)
	f.badEnum["/v1/integrations/github/workflow-posture"] = true
	c := f.client()
	_, err := c.InspectWorkflowPosture(context.Background(), WorkflowPostureRequest{
		BindingID: "binding-1",
		Ref:       "main",
	}, testRequestOptions())
	if err == nil || !strings.Contains(err.Error(), "unknown workflow posture") {
		t.Fatalf("error = %v, want unknown enum failure", err)
	}
}

func TestClientProblemMapping(t *testing.T) {
	cases := []struct {
		upstream int
		local    int
	}{
		{401, 401}, {403, 403}, {404, 404}, {409, 409},
		{412, 412}, {429, 429}, {400, 503}, {500, 503}, {503, 503},
	}
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(http.StatusText(tc.upstream), " ", "_"), func(t *testing.T) {
			f := newFakeAuthScope(t)
			f.problem["/v1/missions"] = tc.upstream
			c := f.client()
			_, err := c.ListActiveMissions(context.Background(), testRequestOptions())
			var upErr *UpstreamError
			if !errors.As(err, &upErr) {
				t.Fatalf("error = %v, want UpstreamError", err)
			}
			if upErr.LocalStatus() != tc.local {
				t.Fatalf("upstream %d mapped to %d, want %d", tc.upstream, upErr.LocalStatus(), tc.local)
			}
			if upErr.StatusCode != tc.upstream {
				t.Fatalf("status code = %d", upErr.StatusCode)
			}
		})
	}
}

func TestClientRejectsInsecureBaseURL(t *testing.T) {
	signer := identity.NewEphemeralSigner()
	if _, err := NewClient("http://authscope.local", nil, signer, "release"); !errors.Is(err, ErrInsecureBaseURL) {
		t.Fatalf("error = %v, want ErrInsecureBaseURL", err)
	}
	if _, err := NewClient("http://127.0.0.1:9", nil, signer, "development"); err != nil {
		t.Fatalf("development http must be allowed: %v", err)
	}
	if _, err := NewClient("https://authscope.example.com", nil, signer, "release"); err != nil {
		t.Fatalf("release https must be allowed: %v", err)
	}
	if _, err := NewClient("https://authscope.example.com", nil, nil, "release"); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("error = %v, want ErrNoSigner", err)
	}
}

func TestClientRequiresWorkspace(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	_, err := c.ListActiveMissions(context.Background(), RequestOptions{})
	if !errors.Is(err, ErrMissingWorkspace) {
		t.Fatalf("error = %v, want ErrMissingWorkspace", err)
	}
}

func TestClientGeneratesRequestID(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	opts := testRequestOptions()
	opts.RequestID = ""
	if _, err := c.ListActiveMissions(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if got := f.lastRequest().header.Get("X-Request-ID"); got == "" {
		t.Fatal("request ID was not generated")
	}
}

func TestClientRedactsSecrets(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer super-secret-token")
	h.Set("Cookie", "session=abc")
	h.Set("X-AuthScope-Workload-Signature", "sig-secret")
	h.Set("X-Request-ID", "req-1")
	redacted := redactHeaders(h)
	if got := redacted.Get("Authorization"); got != "[redacted]" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := redacted.Get("Cookie"); got != "[redacted]" {
		t.Fatalf("Cookie = %q", got)
	}
	if got := redacted.Get("X-AuthScope-Workload-Signature"); got != "[redacted]" {
		t.Fatalf("workload signature = %q", got)
	}
	if got := redacted.Get("X-Request-ID"); got != "req-1" {
		t.Fatalf("X-Request-ID = %q", got)
	}
	// The original must be untouched.
	if h.Get("Authorization") != "Bearer super-secret-token" {
		t.Fatal("redactHeaders mutated the original")
	}
}

func TestClientErrorsNeverCarrySecrets(t *testing.T) {
	f := newFakeAuthScope(t)
	f.problem["/v1/workspaces/ws-test/contain"] = http.StatusForbidden
	c := f.client()
	env := validTestAttestation(t, f, identity.PurposeOfflineRecoveryContain)
	att := attestationFromEnvelope(t, env)
	_, err := c.ContainWorkspace(context.Background(), WorkspaceContainmentRequest{
		Founder:        "founder-1",
		IdempotencyKey: "idem-1",
	}, att, testRequestOptions())
	if err == nil {
		t.Fatal("expected an error")
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(att.Signature)
	if strings.Contains(err.Error(), sigB64) {
		t.Fatal("error contains the attestation signature")
	}
	workloadSig := f.lastRequest().header.Get("X-AuthScope-Workload-Signature")
	if workloadSig == "" {
		t.Fatal("test setup: no workload signature recorded")
	}
	if strings.Contains(err.Error(), workloadSig) {
		t.Fatal("error contains the workload signature")
	}
}

func TestClientDecodesTypedResponses(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	opts := testRequestOptions()

	posture, err := c.InspectWorkflowPosture(context.Background(), WorkflowPostureRequest{
		BindingID: "binding-1", Ref: "main",
	}, opts)
	if err != nil {
		t.Fatalf("InspectWorkflowPosture: %v", err)
	}
	if posture.Posture != WorkflowPostureRisky || len(posture.Findings) != 1 {
		t.Fatalf("posture = %+v", posture)
	}
	if posture.Findings[0].Risk != WorkflowRiskSecretAccess {
		t.Fatalf("risk = %q", posture.Findings[0].Risk)
	}

	keys, err := c.GetSigningKeys(context.Background(), opts)
	if err != nil {
		t.Fatalf("GetSigningKeys: %v", err)
	}
	if len(keys.Keys) != 1 || keys.Keys[0].KeyID != "ask-1" {
		t.Fatalf("keys = %+v", keys)
	}

	page, err := c.ReadEvents(context.Background(), "mission-1", "", opts)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(page.Events) != 1 || page.NextCursor != "cursor-1" {
		t.Fatalf("page = %+v", page)
	}
	req := f.lastRequest()
	if req.path != "/v1/events" || !strings.Contains(req.query, "mission_ref=mission-1") {
		t.Fatalf("request = %s %s?%s", req.method, req.path, req.query)
	}

	receipt, err := c.GetReceipt(context.Background(), "grant-1", opts)
	if err != nil {
		t.Fatalf("GetReceipt: %v", err)
	}
	if receipt.Algorithm != "Ed25519" || receipt.KeyID != "ask-1" {
		t.Fatalf("receipt envelope = %+v", receipt)
	}
	var payload struct {
		ReceiptID        string `json:"receipt_id"`
		SettlementDigest string `json:"settlement_digest"`
	}
	if err := json.Unmarshal(receipt.Payload, &payload); err != nil {
		t.Fatalf("decode receipt payload: %v", err)
	}
	if payload.ReceiptID != "receipt-1" {
		t.Fatalf("receipt payload = %+v", payload)
	}
	if payload.SettlementDigest == "" {
		t.Fatalf("receipt payload is missing the settlement digest: %+v", payload)
	}
	if req := f.lastRequest(); req.path != "/v1/executions/grant-1/receipt" {
		t.Fatalf("path = %s", req.path)
	}
}

// openTestStoreForGate opens a throwaway store with a bound instance for
// gate tests.
func openTestStoreForGate(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	rec := store.InstanceRecord{
		InstanceID:        "inst-gate-1",
		WorkspaceID:       "ws-test",
		Hostname:          "localhost",
		Origin:            "http://localhost:8080",
		RPID:              "localhost",
		SessionCookieName: store.DeriveSessionCookieName("inst-gate-1"),
		CreatedAt:         time.Now().UTC(),
	}
	if err := st.WithTx(context.Background(), func(tx store.Tx) error {
		return tx.BindInstance(context.Background(), rec)
	}); err != nil {
		t.Fatalf("bind instance: %v", err)
	}
	return st
}

func TestGateVerifySuccess(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	st := openTestStoreForGate(t)
	gate := NewGate(c, st)
	if gate.Healthy() {
		t.Fatal("gate must not be healthy before verification")
	}
	if err := gate.Verify(context.Background()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !gate.Healthy() {
		t.Fatal("gate must be healthy after verification")
	}
	if gate.IdentityDigest() != f.signer.IdentityDigest() {
		t.Fatalf("digest = %q", gate.IdentityDigest())
	}
	inst, err := st.GetInstance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inst.WorkloadIdentityDigest != f.signer.IdentityDigest() {
		t.Fatalf("stored digest = %q", inst.WorkloadIdentityDigest)
	}
}

func TestGateRejectsMissingAttestorRole(t *testing.T) {
	f := newFakeAuthScope(t)
	f.roles[f.signer.KeyID()] = []string{"reader"}
	c := f.client()
	gate := NewGate(c, openTestStoreForGate(t))
	if err := gate.Verify(context.Background()); !errors.Is(err, ErrMissingAttestorRole) {
		t.Fatalf("error = %v, want ErrMissingAttestorRole", err)
	}
	if gate.Healthy() {
		t.Fatal("gate must not be healthy")
	}
}

func TestGateRejectsWorkspaceMismatch(t *testing.T) {
	f := newFakeAuthScope(t)
	f.workspace = "ws-other"
	c := f.client()
	gate := NewGate(c, openTestStoreForGate(t))
	if err := gate.Verify(context.Background()); !errors.Is(err, ErrWorkspaceMismatch) {
		t.Fatalf("error = %v, want ErrWorkspaceMismatch", err)
	}
}

func TestGateRejectsIncompatibleCore(t *testing.T) {
	f := newFakeAuthScope(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "bogus", "openapi_sha256": "bogus", "capabilities": []string{},
		})
	}))
	t.Cleanup(srv.Close)
	// Bypass transport auth: the handler does not check it. NewClient still
	// signs, which is harmless here.
	c, err := NewClient(srv.URL, nil, f.signer, "development")
	if err != nil {
		t.Fatal(err)
	}
	gate := NewGate(c, openTestStoreForGate(t))
	if err := gate.Verify(context.Background()); !errors.Is(err, ErrIncompatibleCore) {
		t.Fatalf("error = %v, want ErrIncompatibleCore", err)
	}
}

func TestGateIdentityMismatchIsFatal(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	st := openTestStoreForGate(t)
	other := "sha256:" + strings.Repeat("9", 64)
	if err := st.WithTx(context.Background(), func(tx store.Tx) error {
		return tx.AttachWorkloadIdentity(context.Background(), "", other)
	}); err != nil {
		t.Fatalf("pre-attach: %v", err)
	}
	gate := NewGate(c, st)
	if err := gate.Verify(context.Background()); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("error = %v, want ErrIdentityMismatch", err)
	}
}

func TestGateDecaysToStale(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	gate := NewGate(c, openTestStoreForGate(t))
	now := time.Now()
	gate.clock = func() time.Time { return now }
	if err := gate.Verify(context.Background()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !gate.Healthy() {
		t.Fatal("gate must be healthy")
	}
	now = now.Add(31 * time.Second)
	if gate.Healthy() {
		t.Fatal("gate must be stale after thirty seconds")
	}
}

func TestGatedAuthorityRejectsMutationsWhenStale(t *testing.T) {
	f := newFakeAuthScope(t)
	c := f.client()
	gate := NewGate(c, openTestStoreForGate(t))
	gated := NewGatedAuthority(c, gate)

	// Reads pass through even while the gate is unhealthy.
	if _, err := gated.ListActiveMissions(context.Background(), testRequestOptions()); err != nil {
		t.Fatalf("read while stale: %v", err)
	}
	// Mutations are rejected.
	mutations := []func() error{
		func() error {
			_, err := gated.BeginGitHubBinding(context.Background(), GitHubBindingBeginRequest{Repository: "o/r"}, testRequestOptions())
			return err
		},
		func() error {
			_, err := gated.ShapeMission(context.Background(), ShapeMissionRequest{Title: "t"}, testRequestOptions())
			return err
		},
		func() error {
			_, err := gated.CreateProposal(context.Background(), CreateProposalRequest{Title: "t"}, testRequestOptions())
			return err
		},
		func() error {
			env := validTestAttestation(t, f, identity.PurposeOfflineRecoveryContain)
			_, err := gated.ContainWorkspace(context.Background(), WorkspaceContainmentRequest{}, attestationFromEnvelope(t, env), testRequestOptions())
			return err
		},
	}
	for i, m := range mutations {
		if err := m(); !errors.Is(err, ErrGateNotHealthy) {
			t.Fatalf("mutation %d: error = %v, want ErrGateNotHealthy", i, err)
		}
	}

	// A healthy gate lets mutations through to the fake.
	if err := gate.Verify(context.Background()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, err := gated.BeginGitHubBinding(context.Background(), GitHubBindingBeginRequest{Repository: "octo/repo"}, testRequestOptions()); err != nil {
		t.Fatalf("mutation while healthy: %v", err)
	}
}
