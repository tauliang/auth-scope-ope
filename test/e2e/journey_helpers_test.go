package e2e

// Shared fixtures for the end-to-end journeys. Every journey drives the
// real coreapi.Client against the fake AuthScope and the fake gateway, so
// the contract is proven on the wire, not in mocks.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
)

// journeyFixture wires a fake AuthScope, a fake gateway, and a real
// coreapi.Client with a fresh workload signer.
type journeyFixture struct {
	t         *testing.T
	fake      *FakeAuthScope
	gateway   *FakeGateway
	server    *httptest.Server
	gwServer  *httptest.Server
	client    *coreapi.Client
	signer    *identity.EphemeralSigner
	attestor  *identity.DecisionAttestor
	workspace string
	now       time.Time
}

func newJourneyFixture(t *testing.T, mutate func(*FakeOptions)) *journeyFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	signer := identity.NewEphemeralSigner()
	opts := FakeOptions{
		WorkspaceID:       "ws-e2e-1",
		WorkloadKeyID:     signer.KeyID(),
		WorkloadPublicKey: signer.PublicKey(),
		Now:               func() time.Time { return now },
	}
	if mutate != nil {
		mutate(&opts)
	}
	fake := NewFakeAuthScope(opts)
	server := httptest.NewServer(fake.Handler())
	t.Cleanup(server.Close)
	gateway := NewFakeGateway(fake)
	gwServer := httptest.NewServer(gateway.Handler())
	t.Cleanup(gwServer.Close)
	client, err := coreapi.NewClient(server.URL, nil, signer, "development")
	if err != nil {
		t.Fatalf("cannot build client: %v", err)
	}
	return &journeyFixture{
		t: t, fake: fake, gateway: gateway,
		server: server, gwServer: gwServer,
		client: client, signer: signer,
		attestor:  identity.NewDecisionAttestor(signer),
		workspace: opts.WorkspaceID,
		now:       now,
	}
}

// registrationBody builds the pinned registration request body: the
// workload public key, requested roles, and the Ed25519 proof signature
// over the canonical proof document.
func (f *journeyFixture) registrationBody(workspaceID string, roles []string) map[string]any {
	f.t.Helper()
	pub := base64.StdEncoding.EncodeToString(f.signer.PublicKey())
	doc := canonicalProofDocument(workspaceID, pub, roles)
	sig, err := f.signer.Sign(context.Background(), doc)
	if err != nil {
		f.t.Fatalf("cannot sign registration proof: %v", err)
	}
	return map[string]any{
		"workspace_id":    workspaceID,
		"public_key":      pub,
		"roles":           roles,
		"proof_signature": base64.StdEncoding.EncodeToString(sig),
	}
}

// opts returns request options scoped to the fixture workspace.
func (f *journeyFixture) opts() coreapi.RequestOptions {
	return coreapi.RequestOptions{WorkspaceID: f.workspace}
}

// idemOpts returns request options with an idempotency key.
func (f *journeyFixture) idemOpts(key string) coreapi.RequestOptions {
	o := f.opts()
	o.IdempotencyKey = key
	return o
}

// signAttestation signs a decision attestation for the given purpose with
// fresh nonce and validity window.
func (f *journeyFixture) signAttestation(purpose, audience, subjectID, decisionDigest, invocationDigest string) identity.SignedDecisionAttestation {
	f.t.Helper()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		f.t.Fatalf("cannot generate nonce: %v", err)
	}
	proofSum := sha256.Sum256([]byte("proof\x00" + purpose + "\x00" + subjectID))
	method := identity.AuthMethodWebAuthnUV
	if purpose == identity.PurposeOfflineRecoveryContain {
		method = identity.AuthMethodOfflineRecovery
	}
	return f.signAttestationClaims(identity.DecisionClaims{
		WorkspaceID:               f.workspace,
		FounderID:                 "founder-e2e",
		Audience:                  audience,
		Purpose:                   purpose,
		SubjectID:                 subjectID,
		DecisionDigest:            decisionDigest,
		InvocationDigest:          invocationDigest,
		AuthenticationMethod:      method,
		AuthenticationProofDigest: "sha256:" + hex.EncodeToString(proofSum[:]),
		Nonce:                     nonce,
		IssuedAt:                  f.now,
		ExpiresAt:                 f.now.Add(5 * time.Minute),
	})
}

// signAttestationClaims signs exactly the claims given, for attack tests
// that need malformed or hostile claim values.
func (f *journeyFixture) signAttestationClaims(c identity.DecisionClaims) identity.SignedDecisionAttestation {
	f.t.Helper()
	att, err := f.attestor.Attest(context.Background(), c)
	if err != nil {
		f.t.Fatalf("cannot sign attestation: %v", err)
	}
	return att
}

// tamperSignature returns a copy of the attestation with a corrupted
// signature.
func tamperSignature(att identity.SignedDecisionAttestation) identity.SignedDecisionAttestation {
	out := att
	out.Signature = append([]byte{}, att.Signature...)
	out.Signature[0] ^= 0xff
	return out
}

// doRawWithHeaders signs the request at signTime and then applies header
// overrides (an empty value deletes the header), for transport attack tests.
func (f *journeyFixture) doRawWithHeaders(method, path string, body any, signTime time.Time, extra map[string]string) (int, []byte) {
	f.t.Helper()
	var rawBody []byte
	if body != nil {
		var err error
		rawBody, err = json.Marshal(body)
		if err != nil {
			f.t.Fatalf("cannot marshal body: %v", err)
		}
	}
	req, err := http.NewRequest(method, f.server.URL+path, bytes.NewReader(rawBody))
	if err != nil {
		f.t.Fatalf("cannot build request: %v", err)
	}
	sum := sha256.Sum256(rawBody)
	ts := strconv.FormatInt(signTime.Unix(), 10)
	payload := []byte(strings.Join([]string{
		workloadAuthDomain, ts, method, path, hex.EncodeToString(sum[:]),
	}, "\n"))
	sig, err := f.signer.Sign(context.Background(), payload)
	if err != nil {
		f.t.Fatalf("cannot sign transport payload: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AuthScope-Workload-KeyID", f.signer.KeyID())
	req.Header.Set("X-AuthScope-Workload-Timestamp", ts)
	req.Header.Set("X-AuthScope-Workload-Signature", b64url(sig))
	req.Header.Set("X-AuthScope-Workspace", f.workspace)
	for k, v := range extra {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatalf("cannot read response: %v", err)
	}
	return resp.StatusCode, raw
}

// upstreamErr extracts the *coreapi.UpstreamError from a client call error.
func upstreamErr(t *testing.T, err error) *coreapi.UpstreamError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an upstream error, got nil")
	}
	ue, ok := err.(*coreapi.UpstreamError)
	if !ok {
		t.Fatalf("error is %T, want *coreapi.UpstreamError: %v", err, err)
	}
	return ue
}

// requireUpstreamCode asserts the exact upstream denial code and status.
func requireUpstreamCode(t *testing.T, err error, status int, code string) {
	t.Helper()
	ue := upstreamErr(t, err)
	if ue.StatusCode != status || ue.Code != code {
		t.Fatalf("upstream error = %d %q, want %d %q (message: %s)", ue.StatusCode, ue.Code, status, code, ue.Message)
	}
}

// doRaw performs a transport-authenticated raw request against the fake,
// for operations without a typed client method.
func (f *journeyFixture) doRaw(method, path string, body any, extraHeaders map[string]string) (int, []byte) {
	f.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			f.t.Fatalf("cannot marshal body: %v", err)
		}
	}
	sum := sha256.Sum256(raw)
	ts := strconv.FormatInt(f.now.Unix(), 10)
	payload := []byte(strings.Join([]string{
		workloadAuthDomain, ts, method, path, hex.EncodeToString(sum[:]),
	}, "\n"))
	sig, err := f.signer.Sign(context.Background(), payload)
	if err != nil {
		f.t.Fatalf("cannot sign transport payload: %v", err)
	}
	var reader io.Reader
	if len(raw) > 0 {
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, f.server.URL+path, reader)
	if err != nil {
		f.t.Fatalf("cannot build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AuthScope-Workload-KeyID", f.signer.KeyID())
	req.Header.Set("X-AuthScope-Workload-Timestamp", ts)
	req.Header.Set("X-AuthScope-Workload-Signature", b64url(sig))
	req.Header.Set("X-AuthScope-Workspace", f.workspace)
	req.Header.Set("X-Request-ID", fmt.Sprintf("req-%d", f.now.UnixNano()))
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatalf("cannot read response: %v", err)
	}
	return resp.StatusCode, out
}

// doRawGateway performs a transport-authenticated raw request against the
// fake gateway.
func (f *journeyFixture) doRawGateway(path string, body any) (int, []byte) {
	f.t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		f.t.Fatalf("cannot marshal body: %v", err)
	}
	sum := sha256.Sum256(raw)
	ts := strconv.FormatInt(f.now.Unix(), 10)
	payload := []byte(strings.Join([]string{
		workloadAuthDomain, ts, "POST", path, hex.EncodeToString(sum[:]),
	}, "\n"))
	sig, err := f.signer.Sign(context.Background(), payload)
	if err != nil {
		f.t.Fatalf("cannot sign transport payload: %v", err)
	}
	req, err := http.NewRequest("POST", f.gwServer.URL+path, bytes.NewReader(raw))
	if err != nil {
		f.t.Fatalf("cannot build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AuthScope-Workload-KeyID", f.signer.KeyID())
	req.Header.Set("X-AuthScope-Workload-Timestamp", ts)
	req.Header.Set("X-AuthScope-Workload-Signature", b64url(sig))
	req.Header.Set("X-AuthScope-Workspace", f.workspace)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		f.t.Fatalf("cannot read response: %v", err)
	}
	return resp.StatusCode, out
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// jsonRaw parses a JSON document or fails the test.
func jsonRaw(doc string) json.RawMessage {
	return json.RawMessage(doc)
}

// mustUnmarshal decodes JSON or fails the test.
func mustUnmarshal(t *testing.T, raw []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("cannot decode JSON: %v: %s", err, raw)
	}
}

// mustContainCode asserts a problem response carries the exact code.
func mustContainCode(t *testing.T, raw []byte, code string) {
	t.Helper()
	var prob struct {
		Code string `json:"code"`
	}
	mustUnmarshal(t, raw, &prob)
	if prob.Code != code {
		t.Fatalf("problem code = %q, want %q: %s", prob.Code, code, raw)
	}
}
