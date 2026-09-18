// Tests for the exact one-use expansion decision service. AuthScope is
// faked independently: it serves canonical expansion deltas, verifies
// every decision attestation field by field, and rejects tampered,
// replayed, and stale decisions exactly like the real upstream would. A
// tampered or replayed attestation is denied (403); the delta is never
// widened and never re-decided.
package expansion

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

var fixtureClock = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

const (
	fixtureWorkspace      = "ws-test"
	fixtureFounder        = "founder-1"
	fixturePass           = "pass-1"
	fixtureMission        = "mission-1"
	fixtureExpansion      = "exp-1"
	fixtureMissionVersion = int64(3)
)

// stubDecisionVerifier performs no real WebAuthn cryptography: it
// accepts any well-formed assertion payload, exactly like the stub used
// by the authn package's own decision tests. The sign count increments
// on every assertion so retries do not trip clone detection.
type stubDecisionVerifier struct {
	assertErr error
}

func (stubDecisionVerifier) BeginRegistration(_ context.Context, _ authn.CeremonyUser, _, _ string, _ [][]byte) ([]byte, []byte, error) {
	return nil, nil, errors.New("stub: registration unused")
}

func (stubDecisionVerifier) FinishRegistration(_ context.Context, _ authn.CeremonyUser, _ []byte, _ []byte) (authn.RegisteredCredential, error) {
	return authn.RegisteredCredential{}, errors.New("stub: registration unused")
}

func (s stubDecisionVerifier) BeginAssertion(_ context.Context, _ authn.CeremonyUser, _, _ string, _ [][]byte) ([]byte, []byte, error) {
	return []byte(`{"publicKey":{"challenge":"decision"}}`), []byte(`{"kind":"decision"}`), nil
}

func (s stubDecisionVerifier) FinishAssertion(_ context.Context, _ authn.CeremonyUser, _ []authn.StoredCredential, _ []byte, _ []byte) (authn.VerifiedAssertion, error) {
	if s.assertErr != nil {
		return authn.VerifiedAssertion{}, s.assertErr
	}
	// Sign count 0 skips the store update: the test exercises the
	// expansion decision logic, not WebAuthn clone detection.
	return authn.VerifiedAssertion{
		CredentialID: []byte("cred-1"),
		NewSignCount: 0,
		UserVerified: true,
	}, nil
}

// fakeExpansionAuthority serves canonical expansion deltas and verifies
// decision attestations independently, like AuthScope. It records every
// upstream call so tests can assert exact one-use semantics.
type fakeExpansionAuthority struct {
	coreapi.Authority

	mu             sync.Mutex
	expansions     []coreapi.Expansion
	deltas         map[string]json.RawMessage
	listErr        error
	getErr         error
	decideErr      error
	failDecideOnce error
	decideCalls    int
	decideKeys     []string
	decidedByKey   map[string]coreapi.ExpansionResult
	attestations   []identity.SignedDecisionAttestation
	identityKeys   map[string]ed25519.PublicKey
	seenNonces     map[string]bool
	expected       ExpansionBinding
	tamper         func(*identity.SignedDecisionAttestation)
	reconcileState string
	reconcileErr   error
	reconcileCalls int
}

func (f *fakeExpansionAuthority) ListExpansions(_ context.Context, missionRef string, _ coreapi.RequestOptions) ([]coreapi.Expansion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []coreapi.Expansion
	for _, e := range f.expansions {
		if e.MissionRef == missionRef {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeExpansionAuthority) GetExpansion(_ context.Context, expansionID string, _ coreapi.RequestOptions) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	raw, ok := f.deltas[expansionID]
	if !ok {
		return nil, &coreapi.UpstreamError{StatusCode: 404, Message: "expansion not found"}
	}
	// Merge the authoritative decision status into the delta, as the
	// real upstream does for a decided expansion.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	status := "pending"
	decidedVersion := int64(0)
	for _, res := range f.decidedByKey {
		if res.ExpansionID == expansionID {
			if res.Decision == "approve_once" {
				status = "approved"
			} else {
				status = "denied"
			}
			decidedVersion = res.MissionVersion
			break
		}
	}
	obj["status"] = json.RawMessage(`"` + status + `"`)
	if decidedVersion > 0 {
		obj["decided_mission_version"] = json.RawMessage(fmt.Sprintf("%d", decidedVersion))
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (f *fakeExpansionAuthority) DecideExpansion(_ context.Context, expansionID string, decision coreapi.ExpansionDecision, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.ExpansionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decideCalls++
	f.decideKeys = append(f.decideKeys, opts.IdempotencyKey)
	if f.decideErr != nil {
		return coreapi.ExpansionResult{}, f.decideErr
	}
	if f.tamper != nil {
		f.tamper(&att)
	}
	if err := f.verifyDecisionAttestation(expansionID, decision, att); err != nil {
		return coreapi.ExpansionResult{}, err
	}
	f.attestations = append(f.attestations, att)
	if f.failDecideOnce != nil {
		err := f.failDecideOnce
		f.failDecideOnce = nil
		// The mutation landed upstream before the response was lost:
		// the reconciliation path must find it completed by the
		// original idempotency key.
		f.recordDecisionLocked(expansionID, decision, opts.IdempotencyKey)
		return coreapi.ExpansionResult{}, err
	}
	return f.recordDecisionLocked(expansionID, decision, opts.IdempotencyKey), nil
}

// recordDecisionLocked applies the verified decision to the fake
// upstream state and returns the recorded result. It is shared by the
// success path and the lost-response path so an ambiguous mutation is
// still reconcilable by idempotency key.
func (f *fakeExpansionAuthority) recordDecisionLocked(expansionID string, decision coreapi.ExpansionDecision, idempotencyKey string) coreapi.ExpansionResult {
	if f.decidedByKey == nil {
		f.decidedByKey = map[string]coreapi.ExpansionResult{}
	}
	if res, ok := f.decidedByKey[idempotencyKey]; ok {
		return res
	}
	decisionName := "deny"
	if decision.Approve {
		decisionName = "approve_once"
	}
	missionVersion := f.expected.ExpectedAuthScopeVersion
	if decision.Approve {
		missionVersion = f.expected.ExpectedAuthScopeVersion + 1
	}
	res := coreapi.ExpansionResult{
		ExpansionID:    expansionID,
		Decision:       decisionName,
		DecidedAt:      time.Now().UTC().Unix(),
		MissionVersion: missionVersion,
	}
	f.decidedByKey[idempotencyKey] = res
	return res
}

func (f *fakeExpansionAuthority) ReconcileOperation(_ context.Context, idempotencyKey, _ string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconcileCalls++
	if f.reconcileErr != nil {
		return coreapi.OperationResult{}, f.reconcileErr
	}
	if _, ok := f.decidedByKey[idempotencyKey]; !ok {
		return coreapi.OperationResult{Status: "not_found"}, nil
	}
	return coreapi.OperationResult{Status: f.reconcileState}, nil
}

func (f *fakeExpansionAuthority) deny(format string, args ...any) error {
	return &coreapi.UpstreamError{StatusCode: 403, Message: fmt.Sprintf(format, args...)}
}

// verifyDecisionAttestation independently verifies the signed decision
// attestation against the exact expected binding, like AuthScope. Any
// mismatch is a hard denial; the delta is never widened.
func (f *fakeExpansionAuthority) verifyDecisionAttestation(expansionID string, decision coreapi.ExpansionDecision, att identity.SignedDecisionAttestation) error {
	pub, ok := f.identityKeys[att.IdentityDigest]
	if !ok {
		return f.deny("unknown signing identity")
	}
	canonical, err := identity.CanonicalClaimsJSON(att.Claims, att.KeyID, att.IdentityDigest)
	if err != nil {
		return f.deny("invalid claims: %v", err)
	}
	msg := append(append([]byte(identity.AttestationDomain), 0x00), canonical...)
	if !ed25519.Verify(pub, msg, att.Signature) {
		return f.deny("signature verification failed")
	}
	c := att.Claims
	b := f.expected
	if c.WorkspaceID != b.WorkspaceID {
		return f.deny("workspace mismatch")
	}
	if c.Audience != identity.AudienceExpansionDecision {
		return f.deny("audience mismatch")
	}
	if c.Purpose != identity.PurposeExpansionDecision {
		return f.deny("purpose mismatch")
	}
	if c.SubjectID != expansionID {
		return f.deny("subject mismatch")
	}
	sum := sha256.Sum256(CanonicalExpansionBytes(b))
	if c.DecisionDigest != "sha256:"+hex.EncodeToString(sum[:]) {
		return f.deny("decision digest mismatch")
	}
	detail, err := strictDecodeDetail(f.deltas[expansionID])
	if err != nil {
		return f.deny("delta undecodable: %v", err)
	}
	if c.InvocationDigest != detail.Delta.NormalizedArgumentsDigest {
		return f.deny("invocation digest mismatch")
	}
	wantDecision := Deny
	if decision.Approve {
		wantDecision = ApproveOnce
	}
	if b.Decision != wantDecision {
		return f.deny("decision mismatch: bound %q, decided %q", b.Decision, wantDecision)
	}
	if c.AuthenticationMethod != identity.AuthMethodWebAuthnUV {
		return f.deny("auth method mismatch")
	}
	var zero [32]byte
	if c.Nonce == zero {
		return f.deny("zero nonce")
	}
	nonceKey := base64.RawURLEncoding.EncodeToString(c.Nonce[:])
	if f.seenNonces[nonceKey] {
		return f.deny("replayed nonce")
	}
	f.seenNonces[nonceKey] = true
	if !strings.HasPrefix(c.AuthenticationProofDigest, "sha256:") || len(c.AuthenticationProofDigest) != len("sha256:")+64 {
		return f.deny("malformed authentication proof digest")
	}
	now := time.Now()
	if c.IssuedAt.After(now.Add(time.Minute)) {
		return f.deny("issued_at in future")
	}
	if !c.ExpiresAt.After(now) {
		return f.deny("attestation expired")
	}
	return nil
}

func (f *fakeExpansionAuthority) upstreamDeniedCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.decideCalls
}

type expansionFixture struct {
	svc           *Service
	fake          *fakeExpansionAuthority
	st            store.Store
	principal     authn.Principal
	delta         Delta
	missionExpiry time.Time
	clock         *time.Time
}

func openExpansionStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return st
}

// fixtureDelta builds the canonical expansion delta under review: one
// blocked write the agent cannot perform with its current authority.
func fixtureDelta() Delta {
	return Delta{
		ExpansionID:               fixtureExpansion,
		MissionRef:                fixtureMission,
		MissionVersion:            fixtureMissionVersion,
		BlockedOperation:          "files.write",
		Resource:                  "github:octo-org/host",
		Repository:                "octo-org/host",
		Ref:                       "refs/heads/mission-1",
		Path:                      "config/flags.yaml",
		Destination:               "config/flags.yaml",
		NormalizedArgumentsDigest: "sha256:" + strings.Repeat("a", 64),
		Quantity:                  1,
		BudgetMicros:              50_000,
		CurrentAuthority:          "read-only",
		RequestedAuthority:        "write:config/flags.yaml",
		ConsequenceChange:         "agent may write config/flags.yaml once",
		ReasonCode:                "config_update_required",
		Reversibility:             "reversible",
		RequestedExpiry:           fixtureClock.Add(2 * time.Hour),
		AgentRationale:            "The agent asked to flip the feature flag.",
	}
}

func newExpansionFixture(t *testing.T, mutate func(fx *expansionFixture)) *expansionFixture {
	t.Helper()
	ctx := context.Background()
	st := openExpansionStore(t)

	inst := store.InstanceRecord{
		InstanceID: "inst-expansion-1", WorkspaceID: fixtureWorkspace,
		Hostname: "ope.example.com", Origin: "https://ope.example.com",
		RPID: "ope.example.com", SessionCookieName: store.DeriveSessionCookieName("inst-expansion-1"),
		CreatedAt: fixtureClock,
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error { return tx.BindInstance(ctx, inst) }); err != nil {
		t.Fatalf("BindInstance: %v", err)
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateFounder(ctx, store.FounderRecord{
			WorkspaceID: fixtureWorkspace, FounderID: fixtureFounder,
			DisplayName: "Founder", CreatedAt: fixtureClock,
		}); err != nil {
			return err
		}
		return tx.PutWebAuthnCredential(ctx, store.WebAuthnCredentialRecord{
			WorkspaceID:  fixtureWorkspace,
			CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred-1")),
			FounderID:    fixtureFounder,
			PublicKey:    []byte("pk-1"),
			SignCount:    0,
			CreatedAt:    fixtureClock,
		})
	}); err != nil {
		t.Fatalf("seed founder: %v", err)
	}

	authnSvc, err := authn.NewService(ctx, st, stubDecisionVerifier{})
	if err != nil {
		t.Fatalf("authn.NewService: %v", err)
	}

	missionExpiry := fixtureClock.Add(24 * time.Hour)
	pass := store.MissionPassRecord{
		WorkspaceID:             fixtureWorkspace,
		PassID:                  fixturePass,
		StoreRevision:           1,
		DraftVersion:            2,
		AuthScopeMissionVersion: fixtureMissionVersion,
		MissionRef:              fixtureMission,
		ExpiresAt:               missionExpiry,
		State:                   string(missionpass.PassAwaitingExpansion),
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error { return tx.PutMissionPass(ctx, pass, 0) }); err != nil {
		t.Fatalf("seed pass: %v", err)
	}

	delta := fixtureDelta()
	delta.ExpansionDigest = CanonicalExpansionDigest(delta)
	deltaJSON, err := json.Marshal(delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}

	signer := identity.NewEphemeralSigner()
	pub := signer.PublicKey()
	identityDigest := "sha256:" + hex.EncodeToString(mustSHA256(pub))

	fake := &fakeExpansionAuthority{
		expansions: []coreapi.Expansion{{
			ExpansionID: fixtureExpansion,
			MissionRef:  fixtureMission,
			Status:      "pending",
			RequestedAt: fixtureClock.Unix(),
		}},
		deltas:        map[string]json.RawMessage{fixtureExpansion: deltaJSON},
		identityKeys:  map[string]ed25519.PublicKey{identityDigest: pub},
		seenNonces:    map[string]bool{},
		expected: ExpansionBinding{
			WorkspaceID:              fixtureWorkspace,
			PassID:                   fixturePass,
			MissionRef:               fixtureMission,
			ExpectedAuthScopeVersion: fixtureMissionVersion,
			ExpansionID:              fixtureExpansion,
			ExpansionDigest:          delta.ExpansionDigest,
			Decision:                 ApproveOnce,
			EffectiveExpiry:          delta.RequestedExpiry,
			Purpose:                  identity.PurposeExpansionDecision,
			Audience:                 identity.AudienceExpansionDecision,
		},
	}

	clock := fixtureClock
	svc, err := NewService(Config{
		Store:           st,
		Authn:           authnSvc,
		Authority:       fake,
		Attestor:        identity.NewDecisionAttestor(signer),
		Clock:           func() time.Time { return clock },
		UpstreamTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	fx := &expansionFixture{
		svc:           svc,
		fake:          fake,
		st:            st,
		principal:     authn.Principal{WorkspaceID: fixtureWorkspace, FounderID: fixtureFounder, SessionID: "sess-1", AuthTime: fixtureClock},
		delta:         delta,
		missionExpiry: missionExpiry,
		clock:         &clock,
	}
	// Sync the pending expansion into the local store, as the
	// ListPending flow does before BeginDecision.
	if _, err := svc.ListPending(context.Background(), fixtureWorkspace, fixturePass); err != nil {
		t.Fatalf("sync expansions: %v", err)
	}
	if mutate != nil {
		mutate(fx)
	}
	return fx
}

func mustSHA256(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func mustLoadPass(t *testing.T, st store.Store, passID string) store.MissionPassRecord {
	t.Helper()
	var rec store.MissionPassRecord
	if err := st.WithTx(context.Background(), func(tx store.Tx) error {
		var err error
		rec, err = tx.GetMissionPass(context.Background(), fixtureWorkspace, passID)
		return err
	}); err != nil {
		t.Fatalf("load pass: %v", err)
	}
	return rec
}

func beginFinish(t *testing.T, fx *expansionFixture, decision Decision) *DecisionResult {
	t.Helper()
	ctx := context.Background()
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, decision)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	res, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err != nil {
		t.Fatalf("FinishDecision: %v", err)
	}
	return res
}

func isUpstreamDenied(err error) bool {
	var ue *coreapi.UpstreamError
	return errors.As(err, &ue) && ue.StatusCode == 403
}

func TestNewServiceValidatesConfig(t *testing.T) {
	ctx := context.Background()
	st := openExpansionStore(t)
	inst := store.InstanceRecord{
		InstanceID: "inst-expansion-validate", WorkspaceID: fixtureWorkspace,
		Hostname: "ope.example.com", Origin: "https://ope.example.com",
		RPID: "ope.example.com", SessionCookieName: store.DeriveSessionCookieName("inst-expansion-validate"),
		CreatedAt: fixtureClock,
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error { return tx.BindInstance(ctx, inst) }); err != nil {
		t.Fatalf("BindInstance: %v", err)
	}
	authnSvc, err := authn.NewService(ctx, st, stubDecisionVerifier{})
	if err != nil {
		t.Fatalf("authn.NewService: %v", err)
	}
	signer := identity.NewEphemeralSigner()
	base := Config{
		Store:     st,
		Authn:     authnSvc,
		Authority: &fakeExpansionAuthority{},
		Attestor:  identity.NewDecisionAttestor(signer),
		Clock:     time.Now,
	}
	for _, tt := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"store", func(c *Config) { c.Store = nil }},
		{"authn", func(c *Config) { c.Authn = nil }},
		{"authority", func(c *Config) { c.Authority = nil }},
		{"attestor", func(c *Config) { c.Attestor = nil }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if _, err := NewService(cfg); err == nil {
				t.Errorf("NewService with nil %s = nil, want error", tt.name)
			}
		})
	}
}

func TestDecisionRejectsUnknownValues(t *testing.T) {
	for _, raw := range []string{`"approve"`, `"maybe"`, `"APPROVE_ONCE"`, `""`, `1`, `null`} {
		var d Decision
		if err := json.Unmarshal([]byte(raw), &d); err == nil {
			t.Errorf("decision %s decoded, want rejection", raw)
		}
	}
	for _, raw := range []string{`"approve_once"`, `"deny"`} {
		var d Decision
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Errorf("decision %s rejected: %v", raw, err)
		}
	}
}

func TestExpansionDigestCoversCanonicalDeltaOnly(t *testing.T) {
	delta := fixtureDelta()
	first := CanonicalExpansionDigest(delta)
	delta.AgentRationale = "A completely different agent-authored story."
	if got := CanonicalExpansionDigest(delta); got != first {
		t.Errorf("digest changed when only agent rationale changed: agent-authored text must never affect the binding")
	}
	delta.BlockedOperation = "files.delete"
	if got := CanonicalExpansionDigest(delta); got == first {
		t.Errorf("digest unchanged after blocked operation changed")
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Errorf("digest %q is not sha256:<hex>", first)
	}
}

func TestListPendingSyncsCanonicalDelta(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	pending, err := fx.svc.ListPending(context.Background(), fixtureWorkspace, fixturePass)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending = %d, want 1", len(pending))
	}
	got := pending[0].Delta
	if got.ExpansionID != fixtureExpansion {
		t.Errorf("expansion id = %q, want %q", got.ExpansionID, fixtureExpansion)
	}
	if got.ExpansionDigest != fx.delta.ExpansionDigest {
		t.Errorf("digest mismatch: stored delta does not carry the canonical digest")
	}
	if got.ExpansionDigest != CanonicalExpansionDigest(got) {
		t.Errorf("stored digest does not verify against the canonical delta")
	}
	// Every canonical field the browser must display is present.
	if got.BlockedOperation != "files.write" || got.Resource != "github:octo-org/host" {
		t.Errorf("blocked operation/resource = %q/%q, want files.write/github:octo-org/host", got.BlockedOperation, got.Resource)
	}
	if got.Repository != "octo-org/host" || got.Ref != "refs/heads/mission-1" || got.Path != "config/flags.yaml" || got.Destination != "config/flags.yaml" {
		t.Errorf("immutable resource identifiers incomplete: %+v", got)
	}
	if got.NormalizedArgumentsDigest != "sha256:"+strings.Repeat("a", 64) {
		t.Errorf("normalized arguments digest = %q", got.NormalizedArgumentsDigest)
	}
	if got.CurrentAuthority != "read-only" || got.RequestedAuthority != "write:config/flags.yaml" {
		t.Errorf("authority pair = %q/%q", got.CurrentAuthority, got.RequestedAuthority)
	}
	if got.ConsequenceChange == "" || got.ReasonCode != "config_update_required" || got.Reversibility != "reversible" {
		t.Errorf("consequence/reason/reversibility incomplete: %+v", got)
	}
	if !got.RequestedExpiry.Equal(fx.delta.RequestedExpiry) {
		t.Errorf("requested expiry = %v, want %v", got.RequestedExpiry, fx.delta.RequestedExpiry)
	}
	if pending[0].Stale {
		t.Errorf("pending marked stale while mission version matches")
	}
}

func TestListPendingRejectsDigestMismatch(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		// Widen the delta while keeping the original digest: the exact
		// delta AuthScope signed no longer matches what we would show.
		var m map[string]any
		raw := fx.fake.deltas[fixtureExpansion]
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal delta: %v", err)
		}
		m["blocked_operation"] = "admin.console"
		m["requested_authority"] = "admin"
		tampered, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal tampered delta: %v", err)
		}
		fx.fake.deltas[fixtureExpansion] = tampered
	})
	if _, err := fx.svc.ListPending(context.Background(), fixtureWorkspace, fixturePass); err == nil {
		t.Errorf("ListPending accepted a delta whose digest does not cover its fields")
	}
}

func TestListPendingRejectsUnknownFields(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		var m map[string]any
		raw := fx.fake.deltas[fixtureExpansion]
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal delta: %v", err)
		}
		m["surprise_field"] = "surprise"
		extended, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal extended delta: %v", err)
		}
		fx.fake.deltas[fixtureExpansion] = extended
	})
	if _, err := fx.svc.ListPending(context.Background(), fixtureWorkspace, fixturePass); err == nil {
		t.Errorf("ListPending accepted a delta with unknown fields; unknown fields must be rejected, not retained")
	}
}

func TestListPendingRejectsSecondSimultaneousPending(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		fx.fake.expansions = append(fx.fake.expansions, coreapi.Expansion{
			ExpansionID: "exp-2",
			MissionRef:  fixtureMission,
			Status:      "pending",
			RequestedAt: fixtureClock.Unix(),
		})
		delta2 := fixtureDelta()
		delta2.ExpansionID = "exp-2"
		delta2.ExpansionDigest = CanonicalExpansionDigest(delta2)
		raw, err := json.Marshal(delta2)
		if err != nil {
			t.Fatalf("marshal delta2: %v", err)
		}
		fx.fake.deltas["exp-2"] = raw
	})
	_, err := fx.svc.ListPending(context.Background(), fixtureWorkspace, fixturePass)
	if !errors.Is(err, ErrExpansionConflict) {
		t.Errorf("ListPending with two pending expansions = %v, want ErrExpansionConflict", err)
	}
}

func TestListPendingEmptyWhenNonePending(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		fx.fake.expansions = nil
	})
	pending, err := fx.svc.ListPending(context.Background(), fixtureWorkspace, fixturePass)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %d, want 0", len(pending))
	}
}

func TestListPendingWrongWorkspaceSeesNothing(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	pending, err := fx.svc.ListPending(context.Background(), "ws-other", fixturePass)
	if err != nil {
		t.Fatalf("ListPending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %d for foreign workspace, want 0", len(pending))
	}
}

func TestApproveOnceBindsExactFields(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	ctx := context.Background()
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	if begin.ChallengeID == "" || len(begin.OptionsJSON) == 0 {
		t.Errorf("begin returned empty challenge or options")
	}
	if begin.ExpansionID != fixtureExpansion || begin.Decision != ApproveOnce {
		t.Errorf("begin = %+v, want exp-1/approve_once", begin)
	}
	// Requested expiry (2h) is inside the mission expiry (24h), so the
	// effective expiry is the requested one.
	if !begin.EffectiveExpiry.Equal(fx.delta.RequestedExpiry) {
		t.Errorf("effective expiry = %v, want requested %v", begin.EffectiveExpiry, fx.delta.RequestedExpiry)
	}
	res, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err != nil {
		t.Fatalf("FinishDecision: %v", err)
	}
	if res.Decision != ApproveOnce {
		t.Errorf("decision = %q, want approve_once", res.Decision)
	}
	if !strings.HasPrefix(res.DecisionRef, "expansion-decision:") {
		t.Errorf("decision ref = %q, want expansion-decision: prefix", res.DecisionRef)
	}
	if res.AuthScopeMissionVersion != fixtureMissionVersion+1 {
		t.Errorf("mission version = %d, want %d", res.AuthScopeMissionVersion, fixtureMissionVersion+1)
	}
	if fx.fake.upstreamDeniedCalls() != 1 {
		t.Errorf("upstream decide calls = %d, want exactly 1", fx.fake.upstreamDeniedCalls())
	}
	// The fake independently verified the exact binding; double-check the
	// attested claims here too.
	fx.fake.mu.Lock()
	att := fx.fake.attestations[0]
	fx.fake.mu.Unlock()
	if att.Claims.Purpose != identity.PurposeExpansionDecision {
		t.Errorf("purpose = %q, want expansion_decision", att.Claims.Purpose)
	}
	if att.Claims.Audience != identity.AudienceExpansionDecision {
		t.Errorf("audience = %q, want authscope:expansion-decision", att.Claims.Audience)
	}
}

func TestApproveOnceSettlesPass(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	res := beginFinish(t, fx, ApproveOnce)
	stored := mustLoadPass(t, fx.st, fixturePass)
	if stored.State != string(missionpass.PassRunning) {
		t.Errorf("state = %q, want running after approval", stored.State)
	}
	if stored.AuthScopeMissionVersion != fixtureMissionVersion+1 {
		t.Errorf("mission version = %d, want %d", stored.AuthScopeMissionVersion, fixtureMissionVersion+1)
	}
	if stored.StoreRevision != 2 {
		t.Errorf("store revision = %d, want 2 (exactly one increment)", stored.StoreRevision)
	}
	if stored.DraftVersion != 2 {
		t.Errorf("draft version = %d, want 2 (unchanged)", stored.DraftVersion)
	}
	if res.State != string(missionpass.PassRunning) {
		t.Errorf("result state = %q, want running", res.State)
	}
}

func TestApproveOnceClampsEffectiveExpiryToMission(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		// Requested expiry beyond the mission expiry: the effective
		// expiry must be the mission expiry, and AuthScope must see
		// that exact bound.
		fx.delta.RequestedExpiry = fixtureClock.Add(72 * time.Hour)
		fx.delta.ExpansionDigest = CanonicalExpansionDigest(fx.delta)
		raw, err := json.Marshal(fx.delta)
		if err != nil {
			t.Fatalf("marshal delta: %v", err)
		}
		fx.fake.deltas[fixtureExpansion] = raw
		fx.fake.expected.ExpansionDigest = fx.delta.ExpansionDigest
		fx.fake.expected.EffectiveExpiry = fx.missionExpiry
	})
	ctx := context.Background()
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	if !begin.EffectiveExpiry.Equal(fx.missionExpiry) {
		t.Errorf("effective expiry = %v, want mission expiry %v", begin.EffectiveExpiry, fx.missionExpiry)
	}
	if _, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); err != nil {
		t.Errorf("FinishDecision with clamped expiry: %v", err)
	}
}

func TestDenyLeavesAuthorityByteIdentical(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		fx.fake.expected.Decision = Deny
		// Denial carries no grant: the effective expiry is zero.
		fx.fake.expected.EffectiveExpiry = time.Time{}
	})
	before := mustLoadPass(t, fx.st, fixturePass)
	res := beginFinish(t, fx, Deny)
	if res.Decision != Deny {
		t.Errorf("decision = %q, want deny", res.Decision)
	}
	stored := mustLoadPass(t, fx.st, fixturePass)
	if stored.State != before.State || stored.AuthScopeMissionVersion != before.AuthScopeMissionVersion ||
		stored.StoreRevision != before.StoreRevision || stored.MissionRef != before.MissionRef {
		t.Errorf("denial changed the pass: before=%+v after=%+v", before, stored)
	}
	if fx.fake.upstreamDeniedCalls() != 1 {
		t.Errorf("upstream decide calls = %d, want exactly 1", fx.fake.upstreamDeniedCalls())
	}
}

func TestBeginDecisionRejectsUnknownExpansion(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	if _, err := fx.svc.BeginDecision(context.Background(), fx.principal, "exp-nope", ApproveOnce); !errors.Is(err, ErrExpansionNotPending) {
		t.Errorf("BeginDecision unknown expansion = %v, want ErrExpansionNotPending", err)
	}
}

func TestBeginDecisionRejectsExpiredExpansion(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		fx.delta.RequestedExpiry = fixtureClock.Add(-time.Hour)
		fx.delta.ExpansionDigest = CanonicalExpansionDigest(fx.delta)
		raw, err := json.Marshal(fx.delta)
		if err != nil {
			t.Fatalf("marshal delta: %v", err)
		}
		fx.fake.deltas[fixtureExpansion] = raw
	})
	if _, err := fx.svc.BeginDecision(context.Background(), fx.principal, fixtureExpansion, ApproveOnce); !errors.Is(err, ErrExpansionNotPending) {
		t.Errorf("BeginDecision expired expansion = %v, want ErrExpansionNotPending", err)
	}
}

func TestBeginDecisionRejectsStaleMissionVersion(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		// Upstream moved the mission since the expansion was requested.
		fx.delta.MissionVersion = fixtureMissionVersion + 1
		fx.delta.ExpansionDigest = CanonicalExpansionDigest(fx.delta)
		raw, err := json.Marshal(fx.delta)
		if err != nil {
			t.Fatalf("marshal delta: %v", err)
		}
		fx.fake.deltas[fixtureExpansion] = raw
	})
	if _, err := fx.svc.BeginDecision(context.Background(), fx.principal, fixtureExpansion, ApproveOnce); !errors.Is(err, ErrExpansionStale) {
		t.Errorf("BeginDecision stale delta = %v, want ErrExpansionStale", err)
	}
}

func TestBeginDecisionRejectsTerminalPass(t *testing.T) {
	for _, state := range []missionpass.PassState{
		missionpass.PassCompleted, missionpass.PassFailed,
		missionpass.PassRevoked, missionpass.PassExpired,
	} {
		t.Run(string(state), func(t *testing.T) {
			fx := newExpansionFixture(t, nil)
			ctx := context.Background()
			stored := mustLoadPass(t, fx.st, fixturePass)
			stored.State = string(state)
			if err := fx.st.WithTx(ctx, func(tx store.Tx) error {
				return tx.PutMissionPass(ctx, stored, stored.StoreRevision)
			}); err != nil {
				t.Fatalf("set state: %v", err)
			}
			if _, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce); !errors.Is(err, ErrPassNotDecidable) {
				t.Errorf("BeginDecision on %s pass = %v, want ErrPassNotDecidable", state, err)
			}
		})
	}
}

func TestBeginDecisionRejectsWrongWorkspace(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	other := fx.principal
	other.WorkspaceID = "ws-other"
	if _, err := fx.svc.BeginDecision(context.Background(), other, fixtureExpansion, ApproveOnce); !errors.Is(err, ErrExpansionNotPending) {
		t.Errorf("BeginDecision foreign workspace = %v, want ErrExpansionNotPending", err)
	}
}

func TestFinishRejectsChallengeReplay(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	ctx := context.Background()
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	if _, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); err != nil {
		t.Fatalf("first FinishDecision: %v", err)
	}
	if _, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, authn.ErrCeremonyNotFound) {
		t.Errorf("second FinishDecision = %v, want ErrCeremonyNotFound", err)
	}
}

func TestFinishRejectsBindingChanged(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	ctx := context.Background()
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	// Widen the delta between begin and finish, re-signing the digest so
	// the local row carries a different canonical delta.
	fx.delta.RequestedAuthority = "admin"
	fx.delta.ExpansionDigest = CanonicalExpansionDigest(fx.delta)
	raw, err := json.Marshal(fx.delta)
	if err != nil {
		t.Fatalf("marshal delta: %v", err)
	}
	fx.fake.deltas[fixtureExpansion] = raw
	if _, err := fx.svc.ListPending(ctx, fixtureWorkspace, fixturePass); err != nil {
		t.Fatalf("re-sync: %v", err)
	}
	if _, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, ErrExpansionBindingChanged) {
		t.Errorf("FinishDecision after delta change = %v, want ErrExpansionBindingChanged", err)
	}
	if fx.fake.upstreamDeniedCalls() != 0 {
		t.Errorf("upstream decide calls = %d, want 0 (fail closed before mutation)", fx.fake.upstreamDeniedCalls())
	}
}

func TestFinishRejectsForeignPrincipal(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	ctx := context.Background()
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	other := fx.principal
	other.FounderID = "founder-2"
	if _, err := fx.svc.FinishDecision(ctx, other, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, ErrExpansionBindingChanged) {
		t.Errorf("FinishDecision foreign principal = %v, want ErrExpansionBindingChanged", err)
	}
}

func TestFinishIdempotentOnSameKeyAndBinding(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	ctx := context.Background()
	// Two ceremonies bind the same pending expansion before either
	// finishes. The first finish issues the upstream decision; the
	// second replays it by the same idempotency key and canonical
	// binding without a second mutation.
	firstBegin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("first BeginDecision: %v", err)
	}
	secondBegin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("second BeginDecision: %v", err)
	}
	first, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, firstBegin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err != nil {
		t.Fatalf("first FinishDecision: %v", err)
	}
	second, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, secondBegin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err != nil {
		t.Fatalf("second FinishDecision: %v", err)
	}
	if *second != *first {
		t.Errorf("replay mismatch:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if fx.fake.upstreamDeniedCalls() != 1 {
		t.Errorf("upstream decide calls = %d, want 1 (second finish replays, never re-decides)", fx.fake.upstreamDeniedCalls())
	}
}

func TestFinishConcurrentDecidesOnce(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	ctx := context.Background()
	const n = 4
	begins := make([]*BeginResult, n)
	for i := range begins {
		b, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
		if err != nil {
			t.Fatalf("BeginDecision %d: %v", i, err)
		}
		begins[i] = b
	}
	results := make([]*DecisionResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range begins {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begins[i].ChallengeID, []byte(`{"assertion":"ok"}`))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("FinishDecision %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if *results[i] != *results[0] {
			t.Fatalf("concurrent result %d differs from result 0:\n%+v\n%+v", i, results[i], results[0])
		}
	}
	if fx.fake.upstreamDeniedCalls() != 1 {
		t.Errorf("upstream decide calls = %d, want exactly 1", fx.fake.upstreamDeniedCalls())
	}
	stored := mustLoadPass(t, fx.st, fixturePass)
	if stored.StoreRevision != 2 {
		t.Errorf("store revision = %d, want 2 (settled exactly once)", stored.StoreRevision)
	}
}

func TestFinishTimeoutReconcilesWithoutRepeatMutation(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	ctx := context.Background()
	// The upstream applies the decision but the response is lost.
	fx.fake.failDecideOnce = &coreapi.UpstreamError{StatusCode: 504, Message: "gateway timeout"}
	fx.fake.reconcileState = "completed"
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	if _, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, ErrExpansionPending) {
		t.Fatalf("FinishDecision on timeout = %v, want ErrExpansionPending", err)
	}
	res, err := fx.svc.ReconcileExpansion(ctx, fixtureWorkspace, fixtureExpansion)
	if err != nil {
		t.Fatalf("ReconcileExpansion: %v", err)
	}
	if res == nil {
		t.Fatalf("ReconcileExpansion returned nil after the upstream completed the decision")
	}
	if res.Decision != ApproveOnce || res.AuthScopeMissionVersion != fixtureMissionVersion+1 {
		t.Errorf("reconciled result = %+v, want approve_once at version %d", res, fixtureMissionVersion+1)
	}
	if fx.fake.upstreamDeniedCalls() != 1 {
		t.Errorf("upstream decide calls = %d, want 1 (reconciliation must never repeat DecideExpansion)", fx.fake.upstreamDeniedCalls())
	}
	stored := mustLoadPass(t, fx.st, fixturePass)
	if stored.State != string(missionpass.PassRunning) || stored.AuthScopeMissionVersion != fixtureMissionVersion+1 {
		t.Errorf("pass not settled by reconciliation: %+v", stored)
	}
	// Reconciling again replays the recorded result.
	replayed, err := fx.svc.ReconcileExpansion(ctx, fixtureWorkspace, fixtureExpansion)
	if err != nil {
		t.Fatalf("second ReconcileExpansion: %v", err)
	}
	if *replayed != *res {
		t.Errorf("reconcile replay mismatch:\n%+v\n%+v", replayed, res)
	}
}

func TestReconcileExpansionWithoutIntentIsNoop(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	res, err := fx.svc.ReconcileExpansion(context.Background(), fixtureWorkspace, fixtureExpansion)
	if err != nil {
		t.Fatalf("ReconcileExpansion: %v", err)
	}
	if res != nil {
		t.Errorf("ReconcileExpansion without intent = %+v, want nil", res)
	}
}

func TestDecisionAttestationMutationsDenied(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*identity.SignedDecisionAttestation)
	}{
		{"signature", func(a *identity.SignedDecisionAttestation) { a.Signature[0] ^= 0xff }},
		{"workspace", func(a *identity.SignedDecisionAttestation) { a.Claims.WorkspaceID = "ws-other" }},
		{"audience", func(a *identity.SignedDecisionAttestation) { a.Claims.Audience = "authscope:other" }},
		{"purpose", func(a *identity.SignedDecisionAttestation) { a.Claims.Purpose = "pass_approval" }},
		{"subject", func(a *identity.SignedDecisionAttestation) { a.Claims.SubjectID = "exp-other" }},
		{"decision_digest", func(a *identity.SignedDecisionAttestation) {
			a.Claims.DecisionDigest = "sha256:" + strings.Repeat("0", 64)
		}},
		{"invocation_digest", func(a *identity.SignedDecisionAttestation) {
			a.Claims.InvocationDigest = "sha256:" + strings.Repeat("1", 64)
		}},
		{"auth_method", func(a *identity.SignedDecisionAttestation) { a.Claims.AuthenticationMethod = "pin" }},
		{"proof_digest", func(a *identity.SignedDecisionAttestation) { a.Claims.AuthenticationProofDigest = "not-a-digest" }},
		{"nonce", func(a *identity.SignedDecisionAttestation) {
			var zero [32]byte
			a.Claims.Nonce = zero
		}},
		{"issued_future", func(a *identity.SignedDecisionAttestation) { a.Claims.IssuedAt = time.Now().Add(time.Hour) }},
		{"expiry", func(a *identity.SignedDecisionAttestation) { a.Claims.ExpiresAt = a.Claims.IssuedAt }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newExpansionFixture(t, nil)
			fx.fake.tamper = tt.tamper
			ctx := context.Background()
			begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
			if err != nil {
				t.Fatalf("BeginDecision: %v", err)
			}
			_, err = fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
			if !isUpstreamDenied(err) {
				t.Errorf("FinishDecision = %v, want upstream decision denial", err)
			}
			stored := mustLoadPass(t, fx.st, fixturePass)
			if stored.State != string(missionpass.PassAwaitingExpansion) {
				t.Errorf("state = %q, want awaiting_expansion (denied decision persists nothing)", stored.State)
			}
			if stored.AuthScopeMissionVersion != fixtureMissionVersion {
				t.Errorf("mission version = %d, want %d", stored.AuthScopeMissionVersion, fixtureMissionVersion)
			}
		})
	}
}

func TestDecisionAttestationSignatureVerified(t *testing.T) {
	fx := newExpansionFixture(t, func(fx *expansionFixture) {
		fx.fake.tamper = func(att *identity.SignedDecisionAttestation) {
			// Corrupt the signature: the upstream must deny it.
			if len(att.Signature) > 0 {
				att.Signature[0] ^= 0xFF
			}
		}
	})
	ctx := context.Background()
	begin, err := fx.svc.BeginDecision(ctx, fx.principal, fixtureExpansion, ApproveOnce)
	if err != nil {
		t.Fatalf("BeginDecision: %v", err)
	}
	if _, err := fx.svc.FinishDecision(ctx, fx.principal, fixtureExpansion, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !isUpstreamDenied(err) {
		t.Errorf("FinishDecision = %v, want denial for corrupted attestation signature", err)
	}
}

func TestDecisionAttestationReplayDenied(t *testing.T) {
	fx := newExpansionFixture(t, nil)
	beginFinish(t, fx, ApproveOnce)
	fx.fake.mu.Lock()
	att := fx.fake.attestations[0]
	fx.fake.mu.Unlock()
	// Replay the exact attestation under a fresh idempotency key: the
	// nonce is already spent, so AuthScope denies it.
	_, err := fx.fake.DecideExpansion(context.Background(), fixtureExpansion,
		coreapi.ExpansionDecision{Approve: true}, att,
		coreapi.RequestOptions{WorkspaceID: fixtureWorkspace, IdempotencyKey: "expansion:ws-test:exp-1:replay"})
	if !isUpstreamDenied(err) {
		t.Errorf("replayed attestation = %v, want denial", err)
	}
}
