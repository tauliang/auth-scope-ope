// Package e2e holds contract-faithful fakes of the pinned AuthScope
// release and its enforcing gateway, plus the end-to-end journeys that
// prove the OPE contract against them.
//
// The fakes validate against contracts/authscope-v1.yaml and the pinned
// capability manifest: every operation the fake exposes must appear in the
// manifest (see TestFakeOperationsArePinned), and every response is
// marshaled from the exact DTO types coreapi.Client strict-decodes, so a
// field absent from the pinned contract fails the journey tests instead
// of slipping through.
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/launch"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/receipt"
)

// workloadAuthDomain mirrors the transport-authentication domain
// coreapi signs (internal/coreapi/client.go). The fake verifies it; the
// domain string is part of the pinned transport contract.
const workloadAuthDomain = "authscope-ope/workload-auth/v1"

// fakeTimestampSkew bounds transport timestamp freshness.
const fakeTimestampSkew = 5 * time.Minute

// fakeMaxBody caps request bodies the fake will read.
const fakeMaxBody = 8 << 20

// FakeOptions configures a FakeAuthScope instance.
type FakeOptions struct {
	// WorkspaceID is the single workspace this fake serves. The workload
	// identity is bound to it; any other workspace is foreign.
	WorkspaceID string
	// WorkloadKeyID and WorkloadPublicKey are the registered workload
	// signer the fake verifies transport signatures and decision
	// attestations against.
	WorkloadKeyID     string
	WorkloadPublicKey ed25519.PublicKey
	// Now supplies the fake clock. Defaults to time.Now.
	Now func() time.Time
	// ExtraEventTypes injects unknown event types into event pages so the
	// unknown-event incompatibility path can be tested. The fake refuses
	// to serve a page carrying them (409 incompatible_events): an
	// unknown authenticated event type never reaches a projection.
	ExtraEventTypes []string
	// IncompatibleCore makes discovery report a core version outside the
	// pinned release so the incompatible-AuthScope journey can be tested.
	IncompatibleCore bool
}

func (o FakeOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// FakeOperation is one operation the fake exposes, named by the pinned
// manifest's method plus normalized path template.
type FakeOperation struct {
	Method string
	Path   string
}

// fakeHandoff is one in-flight GitHub binding handoff. The binding code is
// one-use and opaque; it is consumed atomically on finish.
type fakeHandoff struct {
	handoffID   string
	repository  string
	bindingCode string
	expiresAt   time.Time
	consumed    bool
}

// fakeBinding is one repository binding. The workspace owns at most one.
type fakeBinding struct {
	binding coreapi.RepositoryBinding
}

// fakeProposal is one upstream mission proposal.
type fakeProposal struct {
	proposal     coreapi.Proposal
	approved     bool
	decisionHash string
}

// fakeMission is one upstream mission.
type fakeMission struct {
	mission          coreapi.Mission
	proposalID       string
	invocationDigest string
	branch           string
	launchPrepared   bool
	runID            string
	grantID          string
	revoked          bool
	completed        bool
}

// fakeExpansion is one upstream expansion request with its exact delta.
type fakeExpansion struct {
	expansionID    string
	missionRef     string
	status         string // open | approved | denied
	requestedAt    int64
	delta          json.RawMessage
	decisionDigest string
	missionVersion int64
}

// fakeGrant is one execution grant backing a prepared run.
type fakeGrant struct {
	grantID        string
	missionRef     string
	budgetMicros   int64
	remainingMicro int64
	consumed       bool
	settled        bool
	outcome        string
}

// fakeLease is one execution lease.
type fakeLease struct {
	leaseID    string
	missionRef string
	expiresAt  int64
}

// fakeCheck is one published check run, bound to immutable repository id
// and head SHA.
type fakeCheck struct {
	check coreapi.GitHubCheckResult
}

// fakeOperationRecord is the settled result of one idempotent business
// mutation, keyed by the workspace-qualified idempotency key.
type fakeOperationRecord struct {
	operationID    string
	idempotencyKey string
	operation      string
	status         string
	bodySHA        [32]byte
	responseStatus int
	responseBody   []byte
}

// FakeAuthScope is a contract-faithful fake of the pinned AuthScope
// release. It derives the caller workspace from the authenticated
// transport, requires the registered decision_attestor role, and
// independently verifies every decision attestation.
type FakeAuthScope struct {
	opts FakeOptions

	mu             sync.Mutex
	signingKey     ed25519.PrivateKey
	signingPub     ed25519.PublicKey
	signingKeyID   string
	identityDigest string
	roles          []string
	registryVer    int64

	handoffs       map[string]*fakeHandoff
	bindings       map[string]*fakeBinding
	proposals      map[string]*fakeProposal
	missions       map[string]*fakeMission
	expansions     map[string]*fakeExpansion
	openExpansion  map[string]string
	events         map[string][]coreapi.MissionEvent
	eventSeq       int64
	ops            map[string]*fakeOperationRecord
	nonces         map[string]bool
	grants         map[string]*fakeGrant
	leases         map[string]*fakeLease
	checks         map[string]*fakeCheck
	checkByIdent   map[string]string
	receipts       map[string]*coreapi.SignedReceiptEnvelope
	contained      bool
	containmentGen int64
	seq            int64

	operations []FakeOperation
}

// NewFakeAuthScope builds a fake bound to a single workspace and one
// registered workload signer.
func NewFakeAuthScope(opts FakeOptions) *FakeAuthScope {
	if opts.WorkspaceID == "" {
		panic("e2e: FakeAuthScope requires a workspace ID")
	}
	if len(opts.WorkloadPublicKey) != ed25519.PublicKeySize {
		panic("e2e: FakeAuthScope requires a workload public key")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("e2e: cannot generate fake signing key: " + err.Error())
	}
	sum := sha256.Sum256(opts.WorkloadPublicKey)
	f := &FakeAuthScope{
		opts:           opts,
		signingKey:     priv,
		signingPub:     pub,
		signingKeyID:   "fake-authscope-signing-1",
		identityDigest: "sha256:" + hex.EncodeToString(sum[:]),
		roles:          []string{coreapi.DecisionAttestorRole},
		registryVer:    1,
		handoffs:       map[string]*fakeHandoff{},
		bindings:       map[string]*fakeBinding{},
		proposals:      map[string]*fakeProposal{},
		missions:       map[string]*fakeMission{},
		expansions:     map[string]*fakeExpansion{},
		openExpansion:  map[string]string{},
		events:         map[string][]coreapi.MissionEvent{},
		ops:            map[string]*fakeOperationRecord{},
		nonces:         map[string]bool{},
		grants:         map[string]*fakeGrant{},
		leases:         map[string]*fakeLease{},
		checks:         map[string]*fakeCheck{},
		checkByIdent:   map[string]string{},
		receipts:       map[string]*coreapi.SignedReceiptEnvelope{},
	}
	return f
}

// fakeRandomID mints an unpredictable identifier with the given prefix.
func fakeRandomID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("e2e: cannot generate id: " + err.Error())
	}
	return prefix + hex.EncodeToString(b[:])
}

// writeJSON writes a JSON response with no-store caching.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem writes an upstream-style problem body. The client decodes
// code, message, request_id, and retryable; nothing else is trusted.
func writeProblem(w http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(w, status, map[string]any{
		"code":       code,
		"message":    message,
		"request_id": requestID,
		"retryable":  false,
	})
}

// notFoundInWorkspace is the uniform 404 body. It never reveals whether
// another workspace owns the identifier.
func notFoundInWorkspace(w http.ResponseWriter, kind, requestID string) {
	writeProblem(w, http.StatusNotFound, kind+"_not_found",
		kind+" not found in this workspace", requestID)
}

// ctxKey carries the raw request body past the auth middleware.
type ctxKey struct{}

// rawBody returns the request body the auth middleware already read.
func rawBody(r *http.Request) []byte {
	if b, ok := r.Context().Value(ctxKey{}).([]byte); ok {
		return b
	}
	return nil
}

// transportAuthPayload rebuilds the exact payload coreapi signs.
func transportAuthPayload(timestamp, method, path, bodyDigestHex string) []byte {
	return []byte(strings.Join([]string{
		workloadAuthDomain, timestamp, method, path, bodyDigestHex,
	}, "\n"))
}

// authenticate verifies the workload transport signature and derives the
// workspace from the registered identity, never from a caller header. It
// returns false after writing the error response.
func (f *FakeAuthScope) authenticate(w http.ResponseWriter, r *http.Request, body []byte) bool {
	keyID := r.Header.Get("X-AuthScope-Workload-KeyID")
	tsRaw := r.Header.Get("X-AuthScope-Workload-Timestamp")
	sigRaw := r.Header.Get("X-AuthScope-Workload-Signature")
	requestID := r.Header.Get("X-Request-ID")
	if keyID == "" || tsRaw == "" || sigRaw == "" {
		writeProblem(w, http.StatusUnauthorized, "missing_workload_auth",
			"workload transport authentication is required", requestID)
		return false
	}
	if keyID != f.opts.WorkloadKeyID {
		writeProblem(w, http.StatusUnauthorized, "unknown_workload_key",
			"workload key is not registered", requestID)
		return false
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "invalid_workload_timestamp",
			"workload timestamp is not an integer", requestID)
		return false
	}
	now := f.opts.now()
	if ts < now.Add(-fakeTimestampSkew).Unix() || ts > now.Add(fakeTimestampSkew).Unix() {
		writeProblem(w, http.StatusUnauthorized, "stale_workload_timestamp",
			"workload timestamp is outside the freshness window", requestID)
		return false
	}
	sum := sha256.Sum256(body)
	path := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}
	payload := transportAuthPayload(tsRaw, r.Method, path, hex.EncodeToString(sum[:]))
	sig, err := base64.RawURLEncoding.DecodeString(sigRaw)
	if err != nil || len(sig) != ed25519.SignatureSize {
		writeProblem(w, http.StatusUnauthorized, "invalid_workload_signature",
			"workload signature is malformed", requestID)
		return false
	}
	if !ed25519.Verify(f.opts.WorkloadPublicKey, payload, sig) {
		writeProblem(w, http.StatusUnauthorized, "invalid_workload_signature",
			"workload signature verification failed", requestID)
		return false
	}
	// The workspace comes from the registered identity bound to the
	// verified key. A caller-supplied workspace header can never select
	// or override it; a mismatch fails closed.
	if got := r.Header.Get("X-AuthScope-Workspace"); got != f.opts.WorkspaceID {
		writeProblem(w, http.StatusUnauthorized, "workspace_mismatch",
			"workload identity is not bound to the requested workspace", requestID)
		return false
	}
	return true
}

// attestationClaimsWire is the contract DecisionAttestationClaims object,
// in the exact field order the identity package canonicalizes.
type attestationClaimsWire struct {
	Version        int    `json:"version"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id"`
	IdentityDigest string `json:"identity_digest"`
	WorkspaceID    string `json:"workspace_id"`
	Founder        string `json:"founder"`
	Audience       string `json:"audience"`
	Purpose        string `json:"purpose"`
	Subject        struct {
		Kind string `json:"kind"`
		ID   string `json:"id"`
	} `json:"subject"`
	DecisionDigest            string `json:"decision_digest"`
	InvocationDigest          string `json:"invocation_digest"`
	AuthenticationMethod      string `json:"authentication_method"`
	AuthenticationProofDigest string `json:"authentication_proof_digest"`
	AuthenticatedAt           int64  `json:"authenticated_at"`
	IssuedAt                  int64  `json:"issued_at"`
	ExpiresAt                 int64  `json:"expires_at"`
	Nonce                     string `json:"nonce"`
}

// attestationEnvelopeWire is the contract SignedDecisionAttestation object.
type attestationEnvelopeWire struct {
	Algorithm      string                `json:"algorithm"`
	KeyID          string                `json:"key_id"`
	IdentityDigest string                `json:"identity_digest"`
	Claims         attestationClaimsWire `json:"claims"`
	Signature      string                `json:"signature"`
}

// verifiedAttestation is the outcome of independent attestation
// verification.
type verifiedAttestation struct {
	claims attestationClaimsWire
}

// verifyAttestation independently verifies a decision attestation: the
// signature against the registered workload key, the workspace binding,
// the audience, the decision and invocation digests, the nonce freshness,
// and the one-use replay state. The nonce is consumed atomically; a
// second presentation is rejected.
func (f *FakeAuthScope) verifyAttestation(body map[string]json.RawMessage, requestID string) (verifiedAttestation, *fakeRejection) {
	raw, ok := body["attestation"]
	if !ok {
		return verifiedAttestation{}, &fakeRejection{http.StatusBadRequest, "missing_attestation", "decision attestation is required"}
	}
	var env attestationEnvelopeWire
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return verifiedAttestation{}, &fakeRejection{http.StatusBadRequest, "malformed_attestation", "decision attestation does not parse"}
	}
	if env.Algorithm != identity.AlgorithmTag {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "unsupported_attestation_algorithm", "attestation algorithm is not accepted"}
	}
	if env.KeyID != f.opts.WorkloadKeyID {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "unregistered_attestation_key", "attestation key is not registered"}
	}
	if env.IdentityDigest != f.identityDigest {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "attestation_identity_mismatch", "attestation identity does not match the registered workload"}
	}
	if env.Claims.Version != 1 || env.Claims.Algorithm != identity.AlgorithmTag ||
		env.Claims.KeyID != env.KeyID || env.Claims.IdentityDigest != env.IdentityDigest {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "attestation_claims_mismatch", "attestation claims do not match the envelope identity"}
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(env.Claims.Nonce)
	if err != nil || len(nonceBytes) != 32 {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "invalid_attestation_nonce", "attestation nonce is malformed"}
	}
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	dc := identity.DecisionClaims{
		WorkspaceID:               env.Claims.WorkspaceID,
		FounderID:                 env.Claims.Founder,
		Audience:                  env.Claims.Audience,
		Purpose:                   env.Claims.Purpose,
		SubjectID:                 env.Claims.Subject.ID,
		DecisionDigest:            env.Claims.DecisionDigest,
		InvocationDigest:          env.Claims.InvocationDigest,
		AuthenticationMethod:      env.Claims.AuthenticationMethod,
		AuthenticationProofDigest: env.Claims.AuthenticationProofDigest,
		Nonce:                     nonce,
		IssuedAt:                  time.Unix(env.Claims.IssuedAt, 0).UTC(),
		ExpiresAt:                 time.Unix(env.Claims.ExpiresAt, 0).UTC(),
	}
	canonical, err := identity.CanonicalClaimsJSON(dc, env.KeyID, env.IdentityDigest)
	if err != nil {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "invalid_attestation_claims", "attestation claims fail validation"}
	}
	// The fake enforces expiry itself: the signer-side validation only
	// bounds the TTL, so an already-expired attestation must fail here.
	now := f.opts.now()
	if !now.Before(dc.ExpiresAt) {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "attestation_expired", "decision attestation has expired"}
	}
	if dc.IssuedAt.Before(now.Add(-15 * time.Minute)) {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "attestation_stale", "decision attestation is not fresh"}
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "malformed_attestation_signature", "attestation signature is malformed"}
	}
	msg := append([]byte(identity.AttestationDomain), 0x00)
	msg = append(msg, canonical...)
	if !ed25519.Verify(f.opts.WorkloadPublicKey, msg, sig) {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "attestation_signature_invalid", "attestation signature verification failed"}
	}
	if env.Claims.WorkspaceID != f.opts.WorkspaceID {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "attestation_workspace_mismatch", "attestation workspace does not match this workspace"}
	}
	nonceKey := env.Claims.Purpose + "\x00" + env.Claims.Nonce
	f.mu.Lock()
	seen := f.nonces[nonceKey]
	if !seen {
		f.nonces[nonceKey] = true
	}
	f.mu.Unlock()
	if seen {
		return verifiedAttestation{}, &fakeRejection{http.StatusForbidden, "attestation_replayed", "decision attestation was already consumed"}
	}
	_ = requestID
	return verifiedAttestation{claims: env.Claims}, nil
}

// fakeRejection is a verified-attestation failure with an HTTP status.
type fakeRejection struct {
	status  int
	code    string
	message string
}

// requireBinding checks the attestation's audience, purpose, subject, and
// bound digests for one route.
func requireBinding(att verifiedAttestation, audience, purpose, subjectKind, subjectID, decisionDigest, invocationDigest string) *fakeRejection {
	c := att.claims
	if c.Audience != audience {
		return &fakeRejection{http.StatusForbidden, "attestation_audience_mismatch", "attestation audience is not bound to this decision"}
	}
	if c.Purpose != purpose {
		return &fakeRejection{http.StatusForbidden, "attestation_purpose_mismatch", "attestation purpose is not bound to this decision"}
	}
	if c.Subject.Kind != subjectKind || c.Subject.ID != subjectID {
		return &fakeRejection{http.StatusForbidden, "attestation_subject_mismatch", "attestation subject is not bound to this decision"}
	}
	if decisionDigest != "" && c.DecisionDigest != decisionDigest {
		return &fakeRejection{http.StatusForbidden, "attestation_decision_mismatch", "attestation decision digest does not match the approved decision"}
	}
	if invocationDigest != "" && c.InvocationDigest != invocationDigest {
		return &fakeRejection{http.StatusForbidden, "attestation_invocation_mismatch", "attestation invocation digest does not match the approved invocation"}
	}
	return nil
}

// decodeBody strict-decodes the request body into v.
func decodeBody(body []byte, v any, requestID string, w http.ResponseWriter) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "request body does not match the contract schema", requestID)
		return false
	}
	return true
}

// digestHex returns "sha256:"+hex(sha256(b)).
func digestHex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// idempotencyKey resolves the workspace-qualified idempotency key for a
// mutation from the Idempotency-Key header, falling back to the body's
// idempotency_key field.
func (f *FakeAuthScope) idempotencyKey(r *http.Request, body map[string]json.RawMessage) string {
	if k := r.Header.Get("Idempotency-Key"); k != "" {
		return f.opts.WorkspaceID + "\x00" + k
	}
	if raw, ok := body["idempotency_key"]; ok {
		var k string
		if err := json.Unmarshal(raw, &k); err == nil && k != "" {
			return f.opts.WorkspaceID + "\x00" + k
		}
	}
	return ""
}

// idempotencyLookup checks the idempotency registry without recording.
// It returns the stored response when the key was seen with the canonical
// body, or a conflict when the key was reused with different content.
func (f *FakeAuthScope) idempotencyLookup(key string, body []byte) (replay []byte, replayStatus int, conflict bool, opMismatch bool) {
	if key == "" {
		return nil, 0, false, false
	}
	sum := sha256.Sum256(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.ops[key]
	if !ok {
		return nil, 0, false, false
	}
	if rec.bodySHA != sum {
		return nil, 0, true, false
	}
	return rec.responseBody, rec.responseStatus, false, false
}

// idempotencyCheckOp verifies the recorded operation name matches.
func (f *FakeAuthScope) idempotencyCheckOp(key, opName string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.ops[key]
	return !ok || rec.operation == opName
}

// idempotencyStore records the settled result of a business mutation.
func (f *FakeAuthScope) idempotencyStore(key, opName string, body []byte, status int, v any) []byte {
	sum := sha256.Sum256(body)
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	f.mu.Lock()
	f.ops[key] = &fakeOperationRecord{
		operationID:    fakeRandomID("op_"),
		idempotencyKey: strings.TrimPrefix(key, f.opts.WorkspaceID+"\x00"),
		operation:      opName,
		status:         "completed",
		bodySHA:        sum,
		responseStatus: status,
		responseBody:   raw,
	}
	f.mu.Unlock()
	return raw
}

// writeReplay writes a stored idempotent response.
func writeReplay(w http.ResponseWriter, status int, resp []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(resp)
}

// idempotentVerified enforces idempotency for mutations that also verify a
// one-use decision attestation. The registry is consulted before the
// attestation is verified: a replayed body returns the stored result, a
// changed body is rejected, and only a fresh mutation verifies and consumes
// the attestation.
func (f *FakeAuthScope) idempotentVerified(w http.ResponseWriter, r *http.Request, opName string, key string, body []byte, verify func() *fakeRejection, run func() (int, any)) bool {
	requestID := r.Header.Get("X-Request-ID")
	if key != "" {
		if !f.idempotencyCheckOp(key, opName) {
			writeProblem(w, http.StatusConflict, "idempotency_key_reused",
				"idempotency key was used for a different operation", requestID)
			return true
		}
		if replay, status, conflict, _ := f.idempotencyLookup(key, body); conflict {
			writeProblem(w, http.StatusConflict, "idempotency_key_reused",
				"idempotency key reused with different content", requestID)
			return true
		} else if replay != nil {
			writeReplay(w, status, replay)
			return true
		}
	}
	if rej := verify(); rej != nil {
		writeProblem(w, rej.status, rej.code, rej.message, requestID)
		return true
	}
	status, v := run()
	if key == "" {
		writeJSON(w, status, v)
		return true
	}
	raw := f.idempotencyStore(key, opName, body, status, v)
	if raw == nil {
		writeProblem(w, http.StatusInternalServerError, "fake_encoding_error", "fake cannot encode response", requestID)
		return true
	}
	writeReplay(w, status, raw)
	return true
}

// idempotent runs run() for a business mutation, enforcing idempotency:
// replaying the same key with the canonical body returns the original
// result; reusing the key with changed content returns 409. It returns
// true when the response was written (replay or conflict).
func (f *FakeAuthScope) idempotent(w http.ResponseWriter, r *http.Request, opName string, key string, body []byte, run func() (int, any)) bool {
	if key == "" {
		status, v := run()
		writeJSON(w, status, v)
		return true
	}
	if !f.idempotencyCheckOp(key, opName) {
		writeProblem(w, http.StatusConflict, "idempotency_key_reused",
			"idempotency key was used for a different operation", r.Header.Get("X-Request-ID"))
		return true
	}
	if replay, status, conflict, _ := f.idempotencyLookup(key, body); conflict {
		writeProblem(w, http.StatusConflict, "idempotency_key_reused",
			"idempotency key reused with different content", r.Header.Get("X-Request-ID"))
		return true
	} else if replay != nil {
		writeReplay(w, status, replay)
		return true
	}
	status, v := run()
	raw := f.idempotencyStore(key, opName, body, status, v)
	if raw == nil {
		writeProblem(w, http.StatusInternalServerError, "fake_encoding_error", "fake cannot encode response", r.Header.Get("X-Request-ID"))
		return true
	}
	writeReplay(w, status, raw)
	return true
}

// missionVersionRejection enforces optimistic concurrency when the client
// sends X-AuthScope-Mission-Version.
func (f *FakeAuthScope) missionVersionRejection(r *http.Request, m *fakeMission) *fakeRejection {
	raw := r.Header.Get("X-AuthScope-Mission-Version")
	if raw == "" {
		return nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v != m.mission.Version {
		return &fakeRejection{status: http.StatusConflict, code: "version_conflict",
			message: "mission version does not match the current version"}
	}
	return nil
}

// emitEvent appends one authoritative event to a mission's log.
func (f *FakeAuthScope) emitEvent(missionRef, eventType string, payload any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appendEventLocked(missionRef, eventType, payload)
}

// appendEventLocked appends an event; the caller holds f.mu.
func (f *FakeAuthScope) appendEventLocked(missionRef, eventType string, payload any) {
	f.eventSeq++
	raw, _ := json.Marshal(payload)
	f.events[missionRef] = append(f.events[missionRef], coreapi.MissionEvent{
		EventID:    fmt.Sprintf("evt_%06d", f.eventSeq),
		EventType:  eventType,
		OccurredAt: f.opts.now().Unix(),
		Payload:    raw,
	})
}

// knownEventTypes is the allowlist the fake may emit. It mirrors the
// authoritative set the OPE projector accepts; anything else is an
// incompatible projection.
var knownEventTypes = map[string]bool{
	"mission_started":      true,
	"action_checked":       true,
	"expansion_requested":  true,
	"pull_request_created": true,
	"run_succeeded":        true,
	"run_failed":           true,
	"mission_expired":      true,
	"mission_revoked":      true,
	"receipt_ready":        true,
}

// Handler builds the fake's HTTP handler. Every operation is registered
// with its pinned manifest method and path template.
func (f *FakeAuthScope) Handler() http.Handler {
	mux := http.NewServeMux()
	reg := func(method, path string, h http.HandlerFunc) {
		f.operations = append(f.operations, FakeOperation{Method: method, Path: path})
		mux.HandleFunc(method+" "+path, h)
	}

	reg("GET", "/.well-known/mission-authority", f.handleDiscovery)
	reg("GET", "/.well-known/auth-scope-signing-keys", f.handleSigningKeys)
	reg("POST", "/v1/identities/workload/verify", f.authed(f.handleVerifyIdentity))
	reg("POST", "/v1/identities/workload/register", f.authed(f.handleRegisterIdentity))
	reg("POST", "/v1/decision-attestations/verify", f.authed(f.handleVerifyAttestation))
	reg("POST", "/v1/mission-proposals/shape", f.authed(f.handleShapeMission))
	reg("POST", "/v1/mission-proposals", f.authed(f.handleCreateProposal))
	reg("POST", "/v1/mission-proposals/{proposal_id}/approve", f.authed(f.handleApproveProposal))
	reg("GET", "/v1/missions", f.authed(f.handleListActiveMissions))
	reg("GET", "/v1/missions/{mission_ref}/introspect", f.authed(f.handleIntrospectMission))
	reg("POST", "/v1/missions/{mission_ref}/complete", f.authed(f.handleCompleteMission))
	reg("POST", "/v1/missions/{mission_ref}/revoke", f.authed(f.handleRevokeMission))
	reg("POST", "/v1/missions/{mission_ref}/leases", f.authed(f.handleCreateLease))
	reg("POST", "/v1/missions/{mission_ref}/launch/prepare", f.authed(f.handlePrepareLaunch))
	reg("POST", "/v1/missions/{mission_ref}/expansion-requests", f.authed(f.handleRequestExpansion))
	reg("POST", "/v1/leases/{lease_id}/refresh", f.authed(f.handleRefreshLease))
	reg("GET", "/v1/expansion-requests", f.authed(f.handleListExpansions))
	reg("POST", "/v1/expansion-requests/{expansion_id}/approve", f.authed(f.handleDecideExpansion()))
	reg("POST", "/v1/executions/settle", f.authed(f.handleSettleExecution))
	reg("POST", "/v1/executions/reconcile", f.authed(f.handleReconcileExecution))
	reg("POST", "/v1/executions/{grant_id}/consume", f.authed(f.handleConsumeExecution))
	reg("GET", "/v1/executions/{grant_id}/receipt", f.authed(f.handleGetReceipt))
	reg("GET", "/v1/events", f.authed(f.handleReadEvents))
	reg("GET", "/v1/events/stream", f.authed(f.handleReadEvents))
	reg("GET", "/v1/operations/{idempotency_key}", f.authed(f.handleReconcileOperation))
	reg("GET", "/v1/agent-kits", f.authed(f.handleListAgentKits))
	reg("GET", "/v1/runtime-policies", f.authed(f.handleListRuntimePolicies))
	reg("POST", "/v1/runtime-policies/compile", f.authed(f.handleCompileRuntimePolicy))
	reg("POST", "/v1/integrations/github/bindings/begin", f.authed(f.handleBeginBinding))
	reg("POST", "/v1/integrations/github/bindings/finish", f.authed(f.handleFinishBinding))
	reg("GET", "/v1/integrations/github/bindings/{binding_id}", f.authed(f.handleGetBinding))
	reg("POST", "/v1/integrations/github/issues/snapshot", f.authed(f.handleReadIssue))
	reg("POST", "/v1/integrations/github/workflow-posture", f.authed(f.handleWorkflowPosture))
	reg("POST", "/v1/integrations/github/check-runs", f.authed(f.handlePublishCheck))
	reg("POST", "/v1/workspaces/{workspace_id}/contain", f.authed(f.handleContainWorkspace))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body once for transport authentication, then stash it
		// for handlers.
		body, err := io.ReadAll(io.LimitReader(r.Body, fakeMaxBody+1))
		_ = r.Body.Close()
		if err != nil || int64(len(body)) > fakeMaxBody {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "cannot read request body", r.Header.Get("X-Request-ID"))
			return
		}
		// The two well-known endpoints are unauthenticated per the pinned
		// manifest; everything else requires workload transport auth.
		unauth := (r.Method == http.MethodGet && r.URL.EscapedPath() == "/.well-known/mission-authority") ||
			(r.Method == http.MethodGet && r.URL.EscapedPath() == "/.well-known/auth-scope-signing-keys")
		if !unauth && !f.authenticate(w, r, body) {
			return
		}
		r = r.WithContext(contextWithBody(r, body))
		mux.ServeHTTP(w, r)
	})
}

// contextWithBody stashes the raw body in the request context.
func contextWithBody(r *http.Request, body []byte) context.Context {
	return context.WithValue(r.Context(), ctxKey{}, body)
}

// Operations returns the operations this fake exposes, for the
// pin-subset test.
func (f *FakeAuthScope) Operations() []FakeOperation {
	out := make([]FakeOperation, len(f.operations))
	copy(out, f.operations)
	return out
}

// authed adapts a handler that needs the raw body.
func (f *FakeAuthScope) authed(h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(w, r)
	}
}

// handleDiscovery serves the unauthenticated mission-authority document.
// The capabilities list carries every pinned manifest capability name so
// the live compatibility gate can verify the fake like a real release.
func (f *FakeAuthScope) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	version := "ope-v1.0.0"
	if f.opts.IncompatibleCore {
		version = "incompatible-0.0.0"
	}
	caps := make([]string, 0, 36)
	for _, op := range coreapi.RequiredManifest().RequiredOperations {
		caps = append(caps, op.Capability)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":        version,
		"openapi_sha256": "9516e098c5ee9196b6bc73f3633123d173d4249fbc0a5063843924d53b43af76",
		"capabilities":   caps,
	})
}

// handleSigningKeys serves the authenticated signing-key history so OPE
// can verify receipts locally against the fake root.
func (f *FakeAuthScope) handleSigningKeys(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, coreapi.SigningKeyHistory{
		Keys: []coreapi.SigningKeyRecord{{
			KeyID:      f.signingKeyID,
			PublicKey:  base64.RawURLEncoding.EncodeToString(f.signingPub),
			ValidFrom:  f.opts.now().Add(-time.Hour).Unix(),
			ValidUntil: 0,
		}},
		ServedAt: f.opts.now().Unix(),
	})
}

// handleVerifyIdentity returns the workload identity derived from the
// authenticated transport. The identity never comes from a client header.
func (f *FakeAuthScope) handleVerifyIdentity(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, coreapi.WorkspaceIdentity{
		IdentityID:      "ident_" + f.opts.WorkspaceID,
		IdentityDigest:  f.identityDigest,
		WorkspaceID:     f.opts.WorkspaceID,
		Roles:           append([]string{}, f.roles...),
		RegistryVersion: f.registryVer,
	})
}

// registerIdentityRequest is the pinned RegisterWorkloadIdentityRequest
// shape: workspace_id, public_key (padded base64 of the raw 32-byte
// Ed25519 key), roles, and proof_signature (padded base64 Ed25519
// signature over the canonical JSON proof document
// {workspace_id, public_key, roles}).
type registerIdentityRequest struct {
	WorkspaceID    string   `json:"workspace_id"`
	PublicKey      string   `json:"public_key"`
	Roles          []string `json:"roles"`
	ProofSignature string   `json:"proof_signature"`
}

// canonicalProofDocument returns the canonical JSON proof document the
// proof signature covers. Keys are sorted; this is the fake's canonical
// form and tests must build it identically.
func canonicalProofDocument(workspaceID, publicKey string, roles []string) []byte {
	var sb strings.Builder
	sb.WriteString(`{"public_key":`)
	b, _ := json.Marshal(publicKey)
	sb.Write(b)
	sb.WriteString(`,"roles":`)
	b, _ = json.Marshal(roles)
	sb.Write(b)
	sb.WriteString(`,"workspace_id":`)
	b, _ = json.Marshal(workspaceID)
	sb.Write(b)
	sb.WriteString(`}`)
	return []byte(sb.String())
}

// handleRegisterIdentity registers the workspace workload identity
// idempotently. Registration for any other workspace is rejected: the
// fake serves exactly one workspace.
func (f *FakeAuthScope) handleRegisterIdentity(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	var in registerIdentityRequest
	if !decodeBody(rawBody(r), &in, requestID, w) {
		return
	}
	if in.WorkspaceID != f.opts.WorkspaceID {
		writeProblem(w, http.StatusForbidden, "workspace_mismatch",
			"registration is not permitted for this workspace", requestID)
		return
	}
	if in.PublicKey != base64.StdEncoding.EncodeToString(f.opts.WorkloadPublicKey) {
		writeProblem(w, http.StatusForbidden, "identity_mismatch",
			"registration public key does not match the authenticated workload", requestID)
		return
	}
	proofSig, err := base64.StdEncoding.DecodeString(in.ProofSignature)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "proof_signature is not valid base64", requestID)
		return
	}
	doc := canonicalProofDocument(in.WorkspaceID, in.PublicKey, in.Roles)
	if !ed25519.Verify(f.opts.WorkloadPublicKey, doc, proofSig) {
		writeProblem(w, http.StatusForbidden, "invalid_proof",
			"registration proof signature does not verify", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	f.idempotent(w, r, "register_workload_identity", key, rawBody(r), func() (int, any) {
		f.mu.Lock()
		f.registryVer++
		ver := f.registryVer
		f.mu.Unlock()
		return http.StatusOK, coreapi.WorkspaceIdentity{
			IdentityID:      "ident_" + f.opts.WorkspaceID,
			IdentityDigest:  f.identityDigest,
			WorkspaceID:     f.opts.WorkspaceID,
			Roles:           append([]string{}, f.roles...),
			RegistryVersion: ver,
		}
	})
}

// handleVerifyAttestation independently verifies one decision attestation
// without applying it.
func (f *FakeAuthScope) handleVerifyAttestation(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	var body map[string]json.RawMessage
	if !decodeBody(rawBody(r), &body, requestID, w) {
		return
	}
	if _, rej := f.verifyAttestation(body, requestID); rej != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason": rej.code})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true})
}

// handleShapeMission dry-runs mission shaping without creating anything.
func (f *FakeAuthScope) handleShapeMission(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	var in coreapi.ShapeMissionRequest
	if !decodeBody(rawBody(r), &in, requestID, w) {
		return
	}
	if in.Title == "" || in.Objective == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "title and objective are required", requestID)
		return
	}
	invocation := digestHex([]byte("invocation\x00" + in.Title + "\x00" + in.Objective))
	writeJSON(w, http.StatusOK, coreapi.MissionDraft{
		ProposalDigest:   digestHex([]byte("proposal\x00" + in.Title + "\x00" + in.Objective)),
		InvocationDigest: invocation,
		AgentKitID:       "ope-coder-v1",
		AgentKitVersion:  "1.0.0",
		RunnerArguments:  []string{"run", "--mission"},
		DecisionDigest:   digestHex([]byte("decision\x00" + in.Title)),
		BudgetMicros:     in.BudgetMicros,
		TTLSeconds:       in.TTLSeconds,
		CanonicalDraft:   json.RawMessage(`{"template":"github-issue-pr-v1"}`),
		ShapedAt:         f.opts.now().Unix(),
		WorkspaceID:      f.opts.WorkspaceID,
	})
}

// handleCreateProposal creates one upstream proposal per issue.
func (f *FakeAuthScope) handleCreateProposal(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	var in coreapi.CreateProposalRequest
	if !decodeBody(rawBody(r), &in, requestID, w) {
		return
	}
	if in.Title == "" || in.InvocationDigest == "" || in.IdempotencyKey == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request",
			"title, invocation_digest, and idempotency_key are required", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	if key == "" {
		key = f.opts.WorkspaceID + "\x00" + in.IdempotencyKey
	}
	f.idempotent(w, r, "create_proposal", key, rawBody(r), func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		// The fake models the journey's second-proposal denial: one
		// proposal per workspace. A second creation with a fresh key is a
		// 409 with no state change.
		if len(f.proposals) > 0 {
			return http.StatusConflict, map[string]any{
				"code": "proposal_exists", "message": "a proposal already exists in this workspace",
				"request_id": requestID, "retryable": false,
			}
		}
		proposalID := fakeRandomID("prop_")
		proposal := coreapi.Proposal{
			ProposalID:       proposalID,
			ProposalDigest:   digestHex(rawBody(r)),
			InvocationDigest: in.InvocationDigest,
			AgentKitID:       "ope-coder-v1",
			AgentKitVersion:  "1.0.0",
			RunnerArguments:  []string{"run", "--mission"},
			Status:           "pending",
			WorkspaceID:      f.opts.WorkspaceID,
			DecisionDigest:   digestHex([]byte("decision\x00" + proposalID)),
			CreatedAt:        f.opts.now().Unix(),
		}
		f.proposals[proposalID] = &fakeProposal{proposal: proposal}
		return http.StatusOK, proposal
	})
}

// handleApproveProposal approves one proposal with a signed decision
// attestation bound to the exact proposal and invocation digests.
func (f *FakeAuthScope) handleApproveProposal(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	proposalID := r.PathValue("proposal_id")
	var body map[string]json.RawMessage
	raw := rawBody(r)
	if !decodeBody(raw, &body, requestID, w) {
		return
	}
	var pd, id string
	_ = json.Unmarshal(body["proposal_digest"], &pd)
	_ = json.Unmarshal(body["invocation_digest"], &id)
	if pd == "" || id == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "proposal_digest and invocation_digest are required", requestID)
		return
	}
	f.mu.Lock()
	p, ok := f.proposals[proposalID]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "proposal", requestID)
		return
	}
	key := f.idempotencyKey(r, body)
	// Idempotency is checked before the one-use attestation is verified, so
	// a replayed approval returns the original mission rather than failing
	// on the consumed nonce.
	f.idempotentVerified(w, r, "approve_proposal", key, raw,
		func() *fakeRejection {
			att, rej := f.verifyAttestation(body, requestID)
			if rej != nil {
				return rej
			}
			if rej := requireBinding(att, identity.AudienceProposalApproval, identity.PurposePassApproval,
				"mission_proposal", proposalID, pd, id); rej != nil {
				return rej
			}
			if pd != p.proposal.ProposalDigest || id != p.proposal.InvocationDigest {
				return &fakeRejection{status: http.StatusForbidden, code: "proposal_digest_mismatch",
					message: "digests do not match the proposal under review"}
			}
			return nil
		},
		func() (int, any) {
			if raw := r.Header.Get("X-AuthScope-Mission-Version"); raw != "" {
				if v, err := strconv.ParseInt(raw, 10, 64); err != nil || v != 0 {
					return http.StatusConflict, map[string]any{
						"code": "version_conflict", "message": "mission version does not match the current version",
						"request_id": requestID, "retryable": false,
					}
				}
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if p.approved {
				return http.StatusConflict, map[string]any{
					"code": "proposal_already_approved", "message": "proposal was already approved",
					"request_id": requestID, "retryable": false,
				}
			}
			p.approved = true
			p.proposal.Status = "approved"
			missionRef := "msn_" + strings.TrimPrefix(proposalID, "prop_")
			mission := &fakeMission{
				mission: coreapi.Mission{
					MissionID:   "mission_" + strings.TrimPrefix(proposalID, "prop_"),
					MissionRef:  missionRef,
					WorkspaceID: f.opts.WorkspaceID,
					State:       "active",
					Version:     1,
				},
				proposalID:       proposalID,
				invocationDigest: p.proposal.InvocationDigest,
				branch:           "mission/" + missionRef,
			}
			f.missions[missionRef] = mission
			f.appendEventLocked(missionRef, missionpass.EventMissionStarted, map[string]any{"state": "active"})
			return http.StatusOK, mission.mission
		})
}

// handleListActiveMissions is the authoritative workspace-scoped listing.
func (f *FakeAuthScope) handleListActiveMissions(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	missions := make([]coreapi.ActiveMission, 0)
	for _, m := range f.missions {
		if m.mission.State == "active" && !m.revoked {
			missions = append(missions, coreapi.ActiveMission{
				MissionRef:  m.mission.MissionRef,
				State:       m.mission.State,
				WorkspaceID: f.opts.WorkspaceID,
			})
		}
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"missions": missions})
}

// lookupMission returns the mission or writes a uniform 404.
func (f *FakeAuthScope) lookupMission(w http.ResponseWriter, r *http.Request) *fakeMission {
	requestID := r.Header.Get("X-Request-ID")
	ref := r.PathValue("mission_ref")
	f.mu.Lock()
	m, ok := f.missions[ref]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "mission", requestID)
		return nil
	}
	return m
}

// handleIntrospectMission reads mission status and version.
func (f *FakeAuthScope) handleIntrospectMission(w http.ResponseWriter, r *http.Request) {
	m := f.lookupMission(w, r)
	if m == nil {
		return
	}
	f.mu.Lock()
	status := coreapi.MissionStatus{
		MissionRef:  m.mission.MissionRef,
		State:       m.mission.State,
		Version:     m.mission.Version,
		WorkspaceID: f.opts.WorkspaceID,
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, status)
}

// handleCompleteMission marks a mission complete upstream.
func (f *FakeAuthScope) handleCompleteMission(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	m := f.lookupMission(w, r)
	if m == nil {
		return
	}
	raw := rawBody(r)
	key := f.idempotencyKey(r, nil)
	f.idempotent(w, r, "complete_mission", key, raw, func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if m.revoked {
			return http.StatusConflict, map[string]any{
				"code": "mission_revoked", "message": "mission is revoked",
				"request_id": requestID, "retryable": false,
			}
		}
		m.mission.State = "completed"
		m.completed = true
		m.mission.Version++
		return http.StatusOK, m.mission
	})
}

// handleRevokeMission revokes a mission with a signed decision
// attestation. Revocation takes effect at the enforcing gateway
// immediately because the gateway reads this same state.
func (f *FakeAuthScope) handleRevokeMission(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	m := f.lookupMission(w, r)
	if m == nil {
		return
	}
	raw := rawBody(r)
	var body map[string]json.RawMessage
	if !decodeBody(raw, &body, requestID, w) {
		return
	}
	key := f.idempotencyKey(r, body)
	f.idempotentVerified(w, r, "revoke_mission", key, raw,
		func() *fakeRejection {
			att, rej := f.verifyAttestation(body, requestID)
			if rej != nil {
				return rej
			}
			if rej := requireBinding(att, identity.AudienceMissionRevoke, identity.PurposeMissionRevoke,
				"mission", m.mission.MissionRef, "", ""); rej != nil {
				return rej
			}
			return f.missionVersionRejection(r, m)
		},
		func() (int, any) {
			f.mu.Lock()
			m.revoked = true
			m.mission.State = "revoked"
			m.mission.Version++
			f.mu.Unlock()
			f.emitEvent(m.mission.MissionRef, missionpass.EventMissionRevoked, map[string]any{"state": "revoked"})
			return http.StatusOK, coreapi.Revocation{
				MissionRef:  m.mission.MissionRef,
				Revoked:     true,
				RevokedAt:   f.opts.now().Unix(),
				WorkspaceID: f.opts.WorkspaceID,
				Containment: "acknowledged",
			}
		})
}

// sealEnvelopeForCLI seals a real launch.LaunchPayload to the CLI's X25519
// ephemeral public key using the production envelope construction, so a
// fake-issued envelope opens with the real launch.OpenEnvelope.
func (f *FakeAuthScope) sealEnvelopeForCLI(cliPubRaw []byte, p launch.LaunchPayload) ([]byte, error) {
	var cliPub [32]byte
	if len(cliPubRaw) != 32 {
		return nil, fmt.Errorf("e2e: CLI ephemeral key is %d bytes, want 32", len(cliPubRaw))
	}
	copy(cliPub[:], cliPubRaw)
	return launch.SealEnvelope(p, f.signingKey, f.signingKeyID, cliPub)
}

// handlePrepareLaunch prepares exactly one governed run per mission.
func (f *FakeAuthScope) handlePrepareLaunch(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	m := f.lookupMission(w, r)
	if m == nil {
		return
	}
	raw := rawBody(r)
	var body map[string]json.RawMessage
	if !decodeBody(raw, &body, requestID, w) {
		return
	}
	var in struct {
		IdempotencyKey     string `json:"idempotency_key"`
		KitID              string `json:"kit_id"`
		EphemeralPublicKey string `json:"ephemeral_public_key"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&in); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "launch request does not parse", requestID)
		return
	}
	if in.KitID == "" || in.EphemeralPublicKey == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "kit_id and ephemeral_public_key are required", requestID)
		return
	}
	cliPub, err := decodeFlexibleBase64(in.EphemeralPublicKey)
	if err != nil || len(cliPub) != 32 {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "ephemeral_public_key must be a 32-byte X25519 key", requestID)
		return
	}
	key := f.idempotencyKey(r, body)
	if key == "" && in.IdempotencyKey != "" {
		key = f.opts.WorkspaceID + "\x00" + in.IdempotencyKey
	}
	// Idempotency is checked before the one-use attestation is verified, so
	// a replayed launch request returns the original artifacts.
	f.idempotentVerified(w, r, "prepare_launch", key, raw,
		func() *fakeRejection {
			att, rej := f.verifyAttestation(body, requestID)
			if rej != nil {
				return rej
			}
			f.mu.Lock()
			invocationDigest := m.invocationDigest
			f.mu.Unlock()
			if rej := requireBinding(att, identity.AudiencePrepareLaunch, identity.PurposeCLILaunchAuthorization,
				"launch", m.mission.MissionRef, "", invocationDigest); rej != nil {
				return rej
			}
			return f.missionVersionRejection(r, m)
		},
		func() (int, any) {
			f.mu.Lock()
			if m.launchPrepared {
				f.mu.Unlock()
				return http.StatusConflict, map[string]any{
					"code": "launch_exists", "message": "a governed run is already prepared for this mission",
					"request_id": requestID, "retryable": false,
				}
			}
			if m.revoked {
				f.mu.Unlock()
				return http.StatusConflict, map[string]any{
					"code": "mission_revoked", "message": "mission is revoked",
					"request_id": requestID, "retryable": false,
				}
			}
			runID := fakeRandomID("run_")
			grantID := fakeRandomID("grant_")
			leaseID := fakeRandomID("lease_")
			runnerArgs := []string{"run", "--mission"}
			var payloadNonce [32]byte
			if _, err := rand.Read(payloadNonce[:]); err != nil {
				f.mu.Unlock()
				return http.StatusInternalServerError, map[string]any{
					"code": "fake_encoding_error", "message": "fake cannot mint envelope nonce",
					"request_id": requestID, "retryable": false,
				}
			}
			now := f.opts.now()
			prop, ok := f.proposals[m.proposalID]
			if !ok {
				f.mu.Unlock()
				return http.StatusInternalServerError, map[string]any{
					"code": "fake_encoding_error", "message": "fake cannot find launch proposal",
					"request_id": requestID, "retryable": false,
				}
			}
			envelope, err := f.sealEnvelopeForCLI(cliPub, launch.LaunchPayload{
				Audience:         launch.EnvelopeAudience,
				RunID:            runID,
				MissionRef:       m.mission.MissionRef,
				MissionVersion:   m.mission.Version + 1,
				ProposalDigest:   prop.proposal.ProposalDigest,
				InvocationDigest: authn.InvocationDigestForLaunch(in.KitID, "1.0.0", runnerArgs),
				RuntimePolicyID:  "rp_" + m.mission.MissionRef,
				LeaseID:          leaseID,
				AgentKitID:       in.KitID,
				AgentKitVersion:  "1.0.0",
				RunnerExecutable: "ope-runner",
				RunnerArguments:  runnerArgs,
				IsolationProfile: launch.IsolationEnforced,
				Nonce:            base64.RawURLEncoding.EncodeToString(payloadNonce[:]),
				IssuedAt:         now.Unix(),
				ExpiresAt:        now.Add(time.Hour).Unix(),
			})
			if err != nil {
				f.mu.Unlock()
				return http.StatusInternalServerError, map[string]any{
					"code": "fake_encoding_error", "message": "fake cannot seal envelope",
					"request_id": requestID, "retryable": false,
				}
			}
			m.launchPrepared = true
			m.runID = runID
			m.grantID = grantID
			m.mission.Version++
			f.leases[leaseID] = &fakeLease{leaseID: leaseID, missionRef: m.mission.MissionRef, expiresAt: f.opts.now().Add(time.Hour).Unix()}
			f.grants[grantID] = &fakeGrant{grantID: grantID, missionRef: m.mission.MissionRef, budgetMicros: 1_000_000, remainingMicro: 1_000_000}
			artifacts := coreapi.LaunchArtifacts{
				RunID:                   runID,
				MissionRef:              m.mission.MissionRef,
				AuthScopeMissionVersion: m.mission.Version,
				RuntimePolicyID:         "rp_" + m.mission.MissionRef,
				LeaseID:                 leaseID,
				AgentKitID:              in.KitID,
				AgentKitVersion:         "1.0.0",
				InvocationDigest:        m.invocationDigest,
				RunnerExecutable:        "ope-runner",
				RunnerArguments:         []string{"run", "--mission"},
				IsolationProfile:        launch.IsolationEnforced,
				EnvelopeKeyID:           f.signingKeyID,
				SealedSignedEnvelope:    envelope,
				ExpiresAt:               f.opts.now().Add(time.Hour).Unix(),
			}
			f.mu.Unlock()
			return http.StatusOK, artifacts
		})
}

// newX25519Keypair generates an X25519 keypair using the standard
// library ECDH support.
func newX25519Keypair() (priv, pub []byte, err error) {
	curve := ecdh.X25519()
	k, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// decodeFlexibleBase64 decodes base64 std, URL, padded or unpadded.
func decodeFlexibleBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("e2e: not base64")
}

// createLeaseRequest is the fake-local wire shape for lease creation.
type createLeaseRequest struct {
	TTLSeconds     int64  `json:"ttl_seconds"`
	IdempotencyKey string `json:"idempotency_key"`
}

// leaseWire is the fake-local wire shape for a lease.
type leaseWire struct {
	LeaseID    string `json:"lease_id"`
	MissionRef string `json:"mission_ref"`
	ExpiresAt  int64  `json:"expires_at"`
}

// handleCreateLease reserves an execution lease for a mission.
func (f *FakeAuthScope) handleCreateLease(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	m := f.lookupMission(w, r)
	if m == nil {
		return
	}
	raw := rawBody(r)
	var in createLeaseRequest
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	if in.TTLSeconds <= 0 {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "ttl_seconds must be positive", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	if key == "" && in.IdempotencyKey != "" {
		key = f.opts.WorkspaceID + "\x00" + in.IdempotencyKey
	}
	f.idempotent(w, r, "create_mission_lease", key, raw, func() (int, any) {
		leaseID := fakeRandomID("lease_")
		f.mu.Lock()
		f.leases[leaseID] = &fakeLease{leaseID: leaseID, missionRef: m.mission.MissionRef, expiresAt: f.opts.now().Add(time.Duration(in.TTLSeconds) * time.Second).Unix()}
		l := f.leases[leaseID]
		f.mu.Unlock()
		return http.StatusOK, leaseWire{LeaseID: l.leaseID, MissionRef: l.missionRef, ExpiresAt: l.expiresAt}
	})
}

// handleRefreshLease refreshes a lease before expiry.
func (f *FakeAuthScope) handleRefreshLease(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	leaseID := r.PathValue("lease_id")
	raw := rawBody(r)
	var in createLeaseRequest
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	key := f.idempotencyKey(r, nil)
	f.idempotent(w, r, "refresh_lease", key, raw, func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		l, ok := f.leases[leaseID]
		if !ok {
			return http.StatusNotFound, map[string]any{
				"code": "lease_not_found", "message": "lease not found in this workspace",
				"request_id": requestID, "retryable": false,
			}
		}
		if in.TTLSeconds > 0 {
			l.expiresAt = f.opts.now().Add(time.Duration(in.TTLSeconds) * time.Second).Unix()
		}
		return http.StatusOK, leaseWire{LeaseID: l.leaseID, MissionRef: l.missionRef, ExpiresAt: l.expiresAt}
	})
}

// requestExpansionBody is the fake-local wire shape for an expansion
// request. The delta is the exact bounded authority delta the founder
// decides on.
type requestExpansionBody struct {
	Title          string          `json:"title"`
	Delta          json.RawMessage `json:"delta"`
	IdempotencyKey string          `json:"idempotency_key"`
}

// expansionWire is the fake-local wire shape for an expansion request.
type expansionWire struct {
	ExpansionID    string          `json:"expansion_id"`
	MissionRef     string          `json:"mission_ref"`
	Status         string          `json:"status"`
	RequestedAt    int64           `json:"requested_at"`
	Delta          json.RawMessage `json:"delta"`
	DecisionDigest string          `json:"decision_digest"`
}

// handleRequestExpansion creates one exact bounded expansion request per
// mission. At most one open expansion is allowed by the v1 template.
func (f *FakeAuthScope) handleRequestExpansion(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	m := f.lookupMission(w, r)
	if m == nil {
		return
	}
	raw := rawBody(r)
	var in requestExpansionBody
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	if len(in.Delta) == 0 {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "delta is required", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	if key == "" && in.IdempotencyKey != "" {
		key = f.opts.WorkspaceID + "\x00" + in.IdempotencyKey
	}
	f.idempotent(w, r, "request_expansion", key, raw, func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if _, open := f.openExpansion[m.mission.MissionRef]; open {
			return http.StatusConflict, map[string]any{
				"code": "expansion_open", "message": "an expansion request is already open for this mission",
				"request_id": requestID, "retryable": false,
			}
		}
		expansionID := fakeRandomID("exp_")
		rec := &fakeExpansion{
			expansionID:    expansionID,
			missionRef:     m.mission.MissionRef,
			status:         "open",
			requestedAt:    f.opts.now().Unix(),
			delta:          in.Delta,
			decisionDigest: digestHex(canonicalExpansionDelta(in.Delta)),
		}
		f.expansions[expansionID] = rec
		f.openExpansion[m.mission.MissionRef] = expansionID
		return http.StatusOK, expansionWire{
			ExpansionID:    expansionID,
			MissionRef:     m.mission.MissionRef,
			Status:         "open",
			RequestedAt:    rec.requestedAt,
			Delta:          in.Delta,
			DecisionDigest: rec.decisionDigest,
		}
	})
}

// canonicalExpansionDelta canonicalizes the exact delta bytes the
// decision digest covers.
func canonicalExpansionDelta(delta json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(delta, &v); err != nil {
		return delta
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return delta
	}
	return raw
}

// lookupExpansion returns the expansion or writes a uniform 404.
func (f *FakeAuthScope) lookupExpansion(w http.ResponseWriter, r *http.Request) *fakeExpansion {
	requestID := r.Header.Get("X-Request-ID")
	id := r.PathValue("expansion_id")
	f.mu.Lock()
	e, ok := f.expansions[id]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "expansion", requestID)
		return nil
	}
	return e
}

// handleListExpansions lists expansions for one mission.
func (f *FakeAuthScope) handleListExpansions(w http.ResponseWriter, r *http.Request) {
	missionRef := r.URL.Query().Get("mission_ref")
	f.mu.Lock()
	items := make([]coreapi.Expansion, 0)
	for _, e := range f.expansions {
		if missionRef != "" && e.missionRef != missionRef {
			continue
		}
		items = append(items, coreapi.Expansion{
			ExpansionID: e.expansionID,
			MissionRef:  e.missionRef,
			Status:      e.status,
			RequestedAt: e.requestedAt,
		})
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": ""})
}

// handleDecideExpansion approves one expansion with an action-bound
// signed decision attestation over the exact delta. Denial is not part of
// the pinned OPE surface, so the fake exposes approve only.
func (f *FakeAuthScope) handleDecideExpansion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		e := f.lookupExpansion(w, r)
		if e == nil {
			return
		}
		raw := rawBody(r)
		var body map[string]json.RawMessage
		if !decodeBody(raw, &body, requestID, w) {
			return
		}
		var decision string
		_ = json.Unmarshal(body["decision"], &decision)
		if decision != "approve" {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "decision does not match the endpoint verb", requestID)
			return
		}
		f.mu.Lock()
		decisionDigest := e.decisionDigest
		missionRef := e.missionRef
		status := e.status
		f.mu.Unlock()
		if status != "open" {
			writeProblem(w, http.StatusConflict, "expansion_not_open", "expansion request is not open", requestID)
			return
		}
		key := f.idempotencyKey(r, body)
		// Idempotency is checked before the one-use attestation is verified, so
		// a replayed decision returns the original result.
		f.idempotentVerified(w, r, "decide_expansion", key, raw,
			func() *fakeRejection {
				att, rej := f.verifyAttestation(body, requestID)
				if rej != nil {
					return rej
				}
				return requireBinding(att, identity.AudienceExpansionDecision, identity.PurposeExpansionDecision,
					"expansion_request", e.expansionID, decisionDigest, "")
			},
			func() (int, any) {
				f.mu.Lock()
				defer f.mu.Unlock()
				if e.status != "open" {
					return http.StatusConflict, map[string]any{
						"code": "expansion_not_open", "message": "expansion request is not open",
						"request_id": requestID, "retryable": false,
					}
				}
				e.status = "approved"
				delete(f.openExpansion, missionRef)
				if m, ok := f.missions[missionRef]; ok {
					m.mission.Version++
					e.missionVersion = m.mission.Version
				}
				return http.StatusOK, coreapi.ExpansionResult{
					ExpansionID:    e.expansionID,
					Decision:       "approve",
					DecidedAt:      f.opts.now().Unix(),
					MissionVersion: e.missionVersion,
				}
			})
	}
}

// consumeExecutionBody is the fake-local wire shape for consuming from a
// grant.
type consumeExecutionBody struct {
	AmountMicros   int64  `json:"amount_micros"`
	IdempotencyKey string `json:"idempotency_key"`
}

// grantWire is the fake-local wire shape for an execution grant.
type grantWire struct {
	GrantID         string `json:"grant_id"`
	MissionRef      string `json:"mission_ref"`
	BudgetMicros    int64  `json:"budget_micros"`
	RemainingMicros int64  `json:"remaining_micros"`
	Consumed        bool   `json:"consumed"`
	Settled         bool   `json:"settled"`
	Outcome         string `json:"outcome"`
}

// lookupGrant returns the grant or writes a uniform 404.
func (f *FakeAuthScope) lookupGrant(w http.ResponseWriter, r *http.Request) *fakeGrant {
	requestID := r.Header.Get("X-Request-ID")
	id := r.PathValue("grant_id")
	f.mu.Lock()
	g, ok := f.grants[id]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "execution_grant", requestID)
		return nil
	}
	return g
}

// handleConsumeExecution consumes from an execution grant idempotently.
func (f *FakeAuthScope) handleConsumeExecution(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	g := f.lookupGrant(w, r)
	if g == nil {
		return
	}
	raw := rawBody(r)
	var in consumeExecutionBody
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	if in.AmountMicros < 0 {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "amount_micros must not be negative", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	if key == "" && in.IdempotencyKey != "" {
		key = f.opts.WorkspaceID + "\x00" + in.IdempotencyKey
	}
	f.idempotent(w, r, "consume_execution", key, raw, func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if g.settled {
			return http.StatusConflict, map[string]any{
				"code": "grant_settled", "message": "execution grant is settled",
				"request_id": requestID, "retryable": false,
			}
		}
		if in.AmountMicros > g.remainingMicro {
			return http.StatusConflict, map[string]any{
				"code": "insufficient_grant", "message": "execution grant is exhausted",
				"request_id": requestID, "retryable": false,
			}
		}
		g.remainingMicro -= in.AmountMicros
		g.consumed = true
		return http.StatusOK, grantWire{
			GrantID: g.grantID, MissionRef: g.missionRef, BudgetMicros: g.budgetMicros,
			RemainingMicros: g.remainingMicro, Consumed: g.consumed, Settled: g.settled, Outcome: g.outcome,
		}
	})
}

// settleExecutionBody is the fake-local wire shape for settling.
type settleExecutionBody struct {
	GrantID        string `json:"grant_id"`
	Outcome        string `json:"outcome"`
	IdempotencyKey string `json:"idempotency_key"`
}

// handleSettleExecution settles execution after the run.
func (f *FakeAuthScope) handleSettleExecution(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in settleExecutionBody
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	if in.Outcome != "success" && in.Outcome != "failure" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "outcome must be success or failure", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	if key == "" && in.IdempotencyKey != "" {
		key = f.opts.WorkspaceID + "\x00" + in.IdempotencyKey
	}
	f.idempotent(w, r, "settle_execution", key, raw, func() (int, any) {
		f.mu.Lock()
		g, ok := f.grants[in.GrantID]
		if !ok {
			f.mu.Unlock()
			return http.StatusNotFound, map[string]any{
				"code": "execution_grant_not_found", "message": "execution grant not found in this workspace",
				"request_id": requestID, "retryable": false,
			}
		}
		g.settled = true
		g.outcome = in.Outcome
		missionRef := g.missionRef
		f.mu.Unlock()
		eventType := missionpass.EventRunSucceeded
		if in.Outcome != "success" {
			eventType = missionpass.EventRunFailed
		}
		f.emitEvent(missionRef, eventType, map[string]any{"outcome": in.Outcome})
		return http.StatusOK, grantWire{
			GrantID: g.grantID, MissionRef: g.missionRef, BudgetMicros: g.budgetMicros,
			RemainingMicros: g.remainingMicro, Consumed: g.consumed, Settled: g.settled, Outcome: g.outcome,
		}
	})
}

// handleReconcileExecution resolves an uncertain execution outcome.
func (f *FakeAuthScope) handleReconcileExecution(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in struct {
		GrantID string `json:"grant_id"`
	}
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	f.mu.Lock()
	g, ok := f.grants[in.GrantID]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "execution_grant", requestID)
		return
	}
	f.mu.Lock()
	wire := grantWire{
		GrantID: g.grantID, MissionRef: g.missionRef, BudgetMicros: g.budgetMicros,
		RemainingMicros: g.remainingMicro, Consumed: g.consumed, Settled: g.settled, Outcome: g.outcome,
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, wire)
}

// handleGetReceipt serves the signed execution receipt envelope for a
// grant. OPE verifies the signature locally; the fake never vouches for
// its own receipt beyond the signature.
func (f *FakeAuthScope) handleGetReceipt(w http.ResponseWriter, r *http.Request) {
	g := f.lookupGrant(w, r)
	if g == nil {
		return
	}
	f.mu.Lock()
	env, ok := f.receipts[g.grantID]
	if !ok {
		env = f.signReceiptLocked(g)
		f.receipts[g.grantID] = env
	}
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, env)
}

// signReceiptLocked builds and signs the receipt payload in the exact
// shape internal/receipt verifies: a receipt.Payload rendered to
// canonical bytes. A fake-issued receipt therefore passes the real
// local verifier, which the receipt tests assert. Callers hold f.mu.
func (f *FakeAuthScope) signReceiptLocked(g *fakeGrant) *coreapi.SignedReceiptEnvelope {
	now := f.opts.now().Unix()
	settlement := sha256.Sum256([]byte("receipt-settlement:" + g.grantID))
	p := receipt.Payload{
		ReceiptID:           "receipt_" + g.grantID,
		GrantID:             g.grantID,
		MissionRef:          g.missionRef,
		WorkspaceID:         f.opts.WorkspaceID,
		Outcome:             g.outcome,
		KeyID:               f.signingKeyID,
		SignedAt:            now,
		StartedAt:           now - 120,
		FinishedAt:          now - 60,
		BudgetMicros:        g.budgetMicros,
		AggregateCostMicros: g.budgetMicros - g.remainingMicro,
		SettlementDigest:    "sha256:" + hex.EncodeToString(settlement[:]),
		MissionVersions:     []int64{1},
	}
	raw, err := receipt.CanonicalPayloadBytes(p)
	if err != nil {
		panic(fmt.Sprintf("e2e: canonical receipt payload: %v", err))
	}
	sig := ed25519.Sign(f.signingKey, raw)
	return &coreapi.SignedReceiptEnvelope{
		Algorithm: identity.AlgorithmTag,
		KeyID:     f.signingKeyID,
		Payload:   raw,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

// handleReadEvents serves one authenticated, cursor-resumable event page.
// Unknown event types are incompatible: the fake refuses to serve a page
// carrying them so they can never reach a projection.
func (f *FakeAuthScope) handleReadEvents(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	missionRef := r.URL.Query().Get("mission_ref")
	cursor := r.URL.Query().Get("cursor")
	if missionRef == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "mission_ref is required", requestID)
		return
	}
	f.mu.Lock()
	_, known := f.missions[missionRef]
	events := append([]coreapi.MissionEvent{}, f.events[missionRef]...)
	f.mu.Unlock()
	if !known {
		notFoundInWorkspace(w, "mission", requestID)
		return
	}
	if len(f.opts.ExtraEventTypes) > 0 {
		writeProblem(w, http.StatusConflict, "incompatible_events",
			"event page carries unknown event types and cannot be projected", requestID)
		return
	}
	start := 0
	if cursor != "" {
		for i, e := range events {
			if e.EventID == cursor {
				start = i + 1
				break
			}
		}
	}
	page := events[start:]
	for _, e := range page {
		if !knownEventTypes[e.EventType] {
			writeProblem(w, http.StatusConflict, "incompatible_events",
				"event page carries unknown event types and cannot be projected", requestID)
			return
		}
	}
	nextCursor := ""
	if len(page) > 0 {
		nextCursor = page[len(page)-1].EventID
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": page, "next_cursor": nextCursor})
}

// handleReconcileOperation looks up the settled result of an ambiguous
// mutation by workspace-qualified idempotency key.
func (f *FakeAuthScope) handleReconcileOperation(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	key := r.PathValue("idempotency_key")
	full := f.opts.WorkspaceID + "\x00" + key
	f.mu.Lock()
	rec, ok := f.ops[full]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "operation", requestID)
		return
	}
	writeJSON(w, http.StatusOK, coreapi.OperationResult{
		OperationID:    rec.operationID,
		IdempotencyKey: rec.idempotencyKey,
		Status:         rec.status,
		WorkspaceID:    f.opts.WorkspaceID,
	})
}

// handleListAgentKits lists the supported coding-agent kits.
func (f *FakeAuthScope) handleListAgentKits(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"kits": []coreapi.AgentKit{{
		KitID:               "ope-coder-v1",
		Name:                "OPE Coder",
		Version:             "1.0.0",
		RuntimeRequirements: []string{"isolated-worktree", "gateway-egress"},
	}}})
}

// handleListRuntimePolicies lists runtime policy snapshots.
func (f *FakeAuthScope) handleListRuntimePolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": []map[string]any{{
		"snapshot_id": "rp_snapshot_1",
		"version":     1,
	}}})
}

// compileRuntimePolicyBody is the fake-local wire shape for compiling a
// runtime policy.
type compileRuntimePolicyBody struct {
	MissionRef string `json:"mission_ref"`
}

// handleCompileRuntimePolicy compiles the effective governed runtime
// policy for a mission.
func (f *FakeAuthScope) handleCompileRuntimePolicy(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in compileRuntimePolicyBody
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	f.mu.Lock()
	_, ok := f.missions[in.MissionRef]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "mission", requestID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"manifest_id":       "rpm_" + in.MissionRef,
		"mission_ref":       in.MissionRef,
		"isolation_profile": "isolated-worktree",
		"egress":            "gateway-only",
	})
}

// handleBeginBinding starts the AuthScope-hosted GitHub App installation
// handoff. The workspace owns at most one repository binding: a second
// begin is denied with the exact upstream denial.
func (f *FakeAuthScope) handleBeginBinding(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in coreapi.GitHubBindingBeginRequest
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	if in.Repository == "" || !strings.Contains(in.Repository, "/") {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "repository must be owner/name", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	f.idempotent(w, r, "begin_github_binding", key, raw, func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(f.bindings) > 0 {
			return http.StatusConflict, map[string]any{
				"code": "binding_exists", "message": "workspace already has a repository binding",
				"request_id": requestID, "retryable": false,
			}
		}
		handoffID := fakeRandomID("handoff_")
		code := fakeRandomID("code_")
		f.handoffs[handoffID] = &fakeHandoff{
			handoffID:   handoffID,
			repository:  in.Repository,
			bindingCode: code,
			expiresAt:   f.opts.now().Add(10 * time.Minute),
		}
		return http.StatusOK, coreapi.GitHubBindingHandoff{
			HandoffID:       handoffID,
			InstallationURL: "https://authscope.test/apps/ope/installations/new",
			BindingCode:     code,
			ExpiresAt:       f.opts.now().Add(10 * time.Minute).Unix(),
		}
	})
}

// handleFinishBinding exchanges the one-use opaque binding code for a
// repository binding. The handoff state is consumed atomically: replaying
// the code is rejected.
func (f *FakeAuthScope) handleFinishBinding(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in coreapi.GitHubBindingFinishRequest
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	if in.HandoffID == "" || in.BindingCode == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "handoff_id and binding_code are required", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	f.idempotent(w, r, "finish_github_binding", key, raw, func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		h, ok := f.handoffs[in.HandoffID]
		if !ok || h.consumed {
			return http.StatusForbidden, map[string]any{
				"code": "handoff_consumed", "message": "binding handoff is unknown or already consumed",
				"request_id": requestID, "retryable": false,
			}
		}
		if subtleCompare(h.bindingCode, in.BindingCode) != 1 || f.opts.now().After(h.expiresAt) {
			return http.StatusForbidden, map[string]any{
				"code": "invalid_binding_code", "message": "binding code is invalid or expired",
				"request_id": requestID, "retryable": false,
			}
		}
		h.consumed = true
		bindingID := fakeRandomID("bnd_")
		binding := coreapi.RepositoryBinding{
			BindingID:      bindingID,
			WorkspaceID:    f.opts.WorkspaceID,
			InstallationID: "inst_" + hexEncode8(h.handoffID),
			RepositoryID:   "123456",
			Repository:     h.repository,
			CreatedAt:      f.opts.now().Unix(),
		}
		f.bindings[bindingID] = &fakeBinding{binding: binding}
		return http.StatusOK, binding
	})
}

// hexEncode8 returns 8 hex chars of sha256(s).
func hexEncode8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// subtleCompare is a constant-time string comparison.
func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}

// lookupBinding returns the binding or writes a uniform 404.
func (f *FakeAuthScope) lookupBinding(w http.ResponseWriter, r *http.Request, bindingID string) *fakeBinding {
	requestID := r.Header.Get("X-Request-ID")
	f.mu.Lock()
	b, ok := f.bindings[bindingID]
	f.mu.Unlock()
	if !ok {
		notFoundInWorkspace(w, "repository_binding", requestID)
		return nil
	}
	return b
}

// handleGetBinding reads one repository binding.
func (f *FakeAuthScope) handleGetBinding(w http.ResponseWriter, r *http.Request) {
	b := f.lookupBinding(w, r, r.PathValue("binding_id"))
	if b == nil {
		return
	}
	writeJSON(w, http.StatusOK, b.binding)
}

// fakeIssueNumbers is the brokered issue catalog per binding.
var fakeIssueNumbers = []int64{1, 2, 3}

// handleReadIssue returns the typed, server-brokered issue snapshot. The
// fake brokers exactly the catalog above; anything else is a uniform 404.
func (f *FakeAuthScope) handleReadIssue(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in coreapi.GitHubIssueRequest
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	b := f.lookupBinding(w, r, in.BindingID)
	if b == nil {
		return
	}
	known := false
	for _, n := range fakeIssueNumbers {
		if n == in.IssueNumber {
			known = true
		}
	}
	if !known {
		notFoundInWorkspace(w, "issue", requestID)
		return
	}
	writeJSON(w, http.StatusOK, coreapi.GitHubIssueSnapshot{
		BindingID:       in.BindingID,
		WorkspaceID:     f.opts.WorkspaceID,
		IssueNumber:     in.IssueNumber,
		Title:           fmt.Sprintf("Fake issue %d", in.IssueNumber),
		Body:            "Brokered issue body for the e2e journey.",
		State:           "open",
		BaseRef:         "main",
		BaseSHA:         "abc123def456abc123def456abc123def456abc1",
		SourceRevision:  "abc123def456abc123def456abc123def456abc1",
		CanonicalDigest: digestHex([]byte("issue\x00" + in.BindingID + "\x00" + strconv.FormatInt(in.IssueNumber, 10))),
		SnapshotAt:      f.opts.now().Unix(),
	})
}

// handleWorkflowPosture inspects workflow posture at a ref.
func (f *FakeAuthScope) handleWorkflowPosture(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in coreapi.WorkflowPostureRequest
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	b := f.lookupBinding(w, r, in.BindingID)
	if b == nil {
		return
	}
	if in.Ref == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "ref is required", requestID)
		return
	}
	posture := coreapi.WorkflowPosture{
		BindingID:          in.BindingID,
		Ref:                in.Ref,
		WorkflowsInspected: 2,
		Findings:           []coreapi.WorkflowFinding{},
		Posture:            coreapi.WorkflowPostureClean,
	}
	if in.Ref == "risky-ref" {
		posture.Findings = []coreapi.WorkflowFinding{{Path: ".github/workflows/ci.yml", Risk: coreapi.WorkflowRiskSecretAccess}}
		posture.Posture = coreapi.WorkflowPostureRisky
	}
	writeJSON(w, http.StatusOK, posture)
}

// handlePublishCheck publishes an idempotent check run bound to the
// immutable repository id and head SHA.
func (f *FakeAuthScope) handlePublishCheck(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	raw := rawBody(r)
	var in coreapi.GitHubCheckRequest
	if !decodeBody(raw, &in, requestID, w) {
		return
	}
	b := f.lookupBinding(w, r, in.BindingID)
	if b == nil {
		return
	}
	if in.HeadSHA == "" || in.Name == "" || in.IdempotencyKey == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request",
			"head_sha, name, and idempotency_key are required", requestID)
		return
	}
	key := f.idempotencyKey(r, nil)
	if key == "" {
		key = f.opts.WorkspaceID + "\x00" + in.IdempotencyKey
	}
	f.idempotent(w, r, "publish_github_check", key, raw, func() (int, any) {
		f.mu.Lock()
		defer f.mu.Unlock()
		ident := in.BindingID + "\x00" + in.HeadSHA + "\x00" + in.Name
		if id, ok := f.checkByIdent[ident]; ok {
			return http.StatusOK, f.checks[id].check
		}
		checkID := fakeRandomID("chk_")
		check := coreapi.GitHubCheckResult{
			CheckRunID:     checkID,
			BindingID:      in.BindingID,
			WorkspaceID:    f.opts.WorkspaceID,
			HeadSHA:        in.HeadSHA,
			Name:           in.Name,
			Status:         in.Status,
			Conclusion:     in.Conclusion,
			IdempotencyKey: in.IdempotencyKey,
			CreatedAt:      f.opts.now().Unix(),
		}
		f.checks[checkID] = &fakeCheck{check: check}
		f.checkByIdent[ident] = checkID
		return http.StatusOK, check
	})
}

// handleContainWorkspace atomically contains the workspace with a signed
// offline-recovery containment attestation.
func (f *FakeAuthScope) handleContainWorkspace(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	if r.PathValue("workspace_id") != f.opts.WorkspaceID {
		notFoundInWorkspace(w, "workspace", requestID)
		return
	}
	raw := rawBody(r)
	var body map[string]json.RawMessage
	if !decodeBody(raw, &body, requestID, w) {
		return
	}
	var founder string
	_ = json.Unmarshal(body["founder"], &founder)
	if founder == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "founder is required", requestID)
		return
	}
	key := f.idempotencyKey(r, body)
	f.idempotentVerified(w, r, "contain_workspace", key, raw,
		func() *fakeRejection {
			att, rej := f.verifyAttestation(body, requestID)
			if rej != nil {
				return rej
			}
			return requireBinding(att, identity.AudienceWorkspaceContain, identity.PurposeOfflineRecoveryContain,
				"workspace", f.opts.WorkspaceID, "", "")
		},
		func() (int, any) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.contained = true
			f.containmentGen++
			return http.StatusOK, coreapi.WorkspaceContainment{
				WorkspaceID:       f.opts.WorkspaceID,
				Contained:         true,
				Generation:        f.containmentGen,
				AttestationDigest: digestHex(raw),
				ContainedAt:       f.opts.now().Unix(),
			}
		})
}

// Revoked reports whether the mission is revoked. The fake gateway reads
// this so revocation takes effect at enforcement immediately.
func (f *FakeAuthScope) Revoked(missionRef string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.missions[missionRef]
	return ok && m.revoked
}

// Contained reports whether the workspace is contained.
func (f *FakeAuthScope) Contained() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.contained
}

// MissionBranch returns the isolated branch of a prepared mission.
func (f *FakeAuthScope) MissionBranch(missionRef string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.missions[missionRef]
	if !ok {
		return "", false
	}
	return m.branch, true
}

// GrantForMission returns the prepared execution grant of a mission.
func (f *FakeAuthScope) GrantForMission(missionRef string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.missions[missionRef]
	if !ok || m.grantID == "" {
		return "", false
	}
	return m.grantID, true
}

// LeaseForMission returns the prepared lease of a mission.
func (f *FakeAuthScope) LeaseForMission(missionRef string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.leases {
		if l.missionRef == missionRef {
			return l.leaseID, true
		}
	}
	return "", false
}

// SigningPublicKey exposes the fake's Ed25519 signing public key so tests
// can verify receipts and sealed envelopes independently.
func (f *FakeAuthScope) SigningPublicKey() ed25519.PublicKey {
	return f.signingPub
}

// SigningKeyID returns the fake's signing key identifier.
func (f *FakeAuthScope) SigningKeyID() string {
	return f.signingKeyID
}
