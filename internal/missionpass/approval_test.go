package missionpass

// Task 7: approval binds the exact proposal and creates only the mission.
// These tests are written before the implementation and drive it.

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
	"sync/atomic"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/github"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// stubDecisionVerifier performs no real WebAuthn cryptography: it accepts
// any well-formed assertion payload, exactly like the stub used by the
// authn package's own decision tests. The sign count increments on every
// assertion so retries do not trip clone detection.
type stubDecisionVerifier struct {
	assertErr error
	signCount *atomic.Int64
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
	return authn.VerifiedAssertion{
		CredentialID: []byte("cred-1"),
		NewSignCount: uint32(s.signCount.Add(1)),
		UserVerified: true,
	}, nil
}

// fakeApprovalAuthority wraps the proposal fake and adds upstream approval
// verification, idempotent upstream deduplication, and tamper hooks.
type fakeApprovalAuthority struct {
	*fakeMissionAuthority

	mission             coreapi.Mission
	approveErr          error
	failApproveOnce     error
	approveCalls        int
	approveKeys         []string
	prepareCalls        int
	missionsCreated     int
	approvedByKey       map[string]coreapi.Mission
	signedAttestations  []identity.SignedDecisionAttestation
	identityRoles       map[string][]string
	identityKeys        map[string]ed25519.PublicKey
	seenNonces          map[string]bool
	expectedBinding     ApprovalBinding
	tamper              func(*identity.SignedDecisionAttestation)
}

func (f *fakeApprovalAuthority) ApproveProposal(_ context.Context, proposalID string, in coreapi.ApproveProposalInput, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Mission, error) {
	f.mu.Lock()
	f.approveCalls++
	f.approveKeys = append(f.approveKeys, opts.IdempotencyKey)
	if f.approvedByKey == nil {
		f.approvedByKey = make(map[string]coreapi.Mission)
	}
	// Dedupe first: an idempotent replay of the same key returns the
	// original mission without re-verifying the attestation, exactly like
	// AuthScope does.
	if m, ok := f.approvedByKey[opts.IdempotencyKey]; ok {
		f.mu.Unlock()
		return m, nil
	}
	if f.failApproveOnce != nil {
		err := f.failApproveOnce
		f.failApproveOnce = nil
		// The call landed upstream and created the mission; only the
		// response was lost.
		f.missionsCreated++
		f.approvedByKey[opts.IdempotencyKey] = f.mission
		f.mu.Unlock()
		return coreapi.Mission{}, err
	}
	f.mu.Unlock()

	if f.approveErr != nil {
		return coreapi.Mission{}, f.approveErr
	}
	if f.tamper != nil {
		f.tamper(&att)
	}
	if err := f.verifyDecisionAttestation(att, proposalID, in); err != nil {
		return coreapi.Mission{}, err
	}
	f.mu.Lock()
	f.missionsCreated++
	f.approvedByKey[opts.IdempotencyKey] = f.mission
	f.signedAttestations = append(f.signedAttestations, att)
	f.mu.Unlock()
	return f.mission, nil
}

func (f *fakeApprovalAuthority) PrepareLaunch(_ context.Context, _ string, _ coreapi.LaunchRequest, _ identity.SignedDecisionAttestation, _ coreapi.RequestOptions) (coreapi.LaunchArtifacts, error) {
	f.mu.Lock()
	f.prepareCalls++
	f.mu.Unlock()
	return coreapi.LaunchArtifacts{}, errors.New("fake: PrepareLaunch must not be called during approval")
}

func (f *fakeApprovalAuthority) deny(format string, args ...any) error {
	return &coreapi.UpstreamError{StatusCode: 403, Code: "decision_denied", Message: fmt.Sprintf(format, args...)}
}

func (f *fakeApprovalAuthority) verifyDecisionAttestation(att identity.SignedDecisionAttestation, proposalID string, in coreapi.ApproveProposalInput) error {
	roles := f.identityRoles[att.IdentityDigest]
	found := false
	for _, r := range roles {
		if r == coreapi.DecisionAttestorRole {
			found = true
			break
		}
	}
	if !found {
		return f.deny("signing identity lacks decision_attestor role")
	}
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
	b := f.expectedBinding
	if c.WorkspaceID != b.WorkspaceID {
		return f.deny("workspace mismatch")
	}
	if c.Audience != identity.AudienceProposalApproval {
		return f.deny("audience mismatch")
	}
	if c.Purpose != identity.PurposePassApproval {
		return f.deny("purpose mismatch")
	}
	if c.SubjectID != proposalID {
		return f.deny("subject mismatch")
	}
	dd := mustSHA256(CanonicalApprovalBytes(approvalRecordForBinding(b)))
	if c.DecisionDigest != "sha256:"+hex.EncodeToString(dd[:]) {
		return f.deny("decision digest mismatch")
	}
	if c.InvocationDigest != b.InvocationDigest {
		return f.deny("invocation digest mismatch")
	}
	if in.ProposalDigest != b.ProposalDigest || in.InvocationDigest != b.InvocationDigest {
		return f.deny("request digests do not match the proposal under review")
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
	f.seenNonces[nonceKey] = true
	return nil
}

func mustSHA256(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// approvalRecordForBinding rebuilds a ProposalRecord from an ApprovalBinding
// so the test can compute the expected canonical approval bytes the same
// way production code does.
func approvalRecordForBinding(b ApprovalBinding) ProposalRecord {
	return ProposalRecord{
		WorkspaceID:      b.WorkspaceID,
		PassID:           b.PassID,
		DraftVersion:     b.DraftVersion,
		ProposalID:       b.ProposalID,
		ProposalDigest:   b.ProposalDigest,
		InvocationDigest: b.InvocationDigest,
		SourceDigest:     b.SourceDigest,
		BaseSHA:          b.BaseSHA,
	}
}

type approvalFixture struct {
	t         *testing.T
	store     store.Store
	source    *github.Source
	proposal  *Service
	fake      *fakeApprovalAuthority
	authnSvc  *authn.Service
	attestor  *identity.DecisionAttestor
	signer    *identity.EphemeralSigner
	svc       *ApprovalService
	principal authn.Principal
	draft     ProposalRecord
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	t.Helper()
	svc, inner, st := newProposalFixture(t)
	ctx := context.Background()

	inst := store.InstanceRecord{
		InstanceID: "inst-approval-1", WorkspaceID: "ws-test",
		Hostname: "ope.example.com", Origin: "https://ope.example.com",
		RPID: "ope.example.com", SessionCookieName: store.DeriveSessionCookieName("inst-approval-1"),
		CreatedAt: fixtureClock,
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error { return tx.BindInstance(ctx, inst) }); err != nil {
		t.Fatalf("BindInstance: %v", err)
	}
	founderID := "founder-1"
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateFounder(ctx, store.FounderRecord{
			WorkspaceID: "ws-test", FounderID: founderID, DisplayName: "Founder", CreatedAt: fixtureClock,
		}); err != nil {
			return err
		}
		return tx.PutWebAuthnCredential(ctx, store.WebAuthnCredentialRecord{
			WorkspaceID: "ws-test",
			CredentialID: base64.RawURLEncoding.EncodeToString([]byte("cred-1")),
			FounderID:   founderID,
			PublicKey:   []byte("pk-1"),
			SignCount:   0,
			CreatedAt:   fixtureClock,
		})
	}); err != nil {
		t.Fatalf("seed founder: %v", err)
	}

	authnSvc, err := authn.NewService(ctx, st, stubDecisionVerifier{signCount: &atomic.Int64{}})
	if err != nil {
		t.Fatalf("authn.NewService: %v", err)
	}

	signer := identity.NewEphemeralSigner()
	attestor := identity.NewDecisionAttestor(signer)

	fake := &fakeApprovalAuthority{fakeMissionAuthority: inner}
	approvalSvc, err := NewApprovalService(ApprovalConfig{
		Store:     st,
		Authority: fake,
		Source:    innerSource(t, st, inner),
		Authn:     authnSvc,
		Attestor:  attestor,
	})
	if err != nil {
		t.Fatalf("NewApprovalService: %v", err)
	}

	rec, _, err := svc.CreateProposal(ctx, "ws-test", founderID, createInput())
	if err != nil {
		t.Fatalf("CreateProposal: %v", err)
	}
	draft := mustLoadProposal(t, st, "ws-test", rec.PassID)

	// The fake upstream expects the exact binding derived from this draft.
	fake.mission = coreapi.Mission{
		MissionID: "mission-1", MissionRef: "mission-1", WorkspaceID: "ws-test",
		State: "active", Version: 3,
	}
	fake.identityRoles = map[string][]string{signer.IdentityDigest(): {coreapi.DecisionAttestorRole}}
	fake.identityKeys = map[string]ed25519.PublicKey{signer.IdentityDigest(): signer.PublicKey()}
	fake.seenNonces = make(map[string]bool)
	fake.expectedBinding = ApprovalBinding{
		WorkspaceID:      "ws-test",
		FounderID:        founderID,
		SessionID:        "sess-1",
		PassID:           draft.PassID,
		DraftVersion:     draft.DraftVersion,
		ProposalID:       draft.ProposalID,
		ProposalDigest:   draft.ProposalDigest,
		InvocationDigest: draft.InvocationDigest,
		SourceDigest:     draft.SourceDigest,
		BaseSHA:          draft.BaseSHA,
		Purpose:          string(authn.DecisionPassApproval),
		Audience:         identity.AudienceProposalApproval,
	}

	return &approvalFixture{
		t: t, store: st, source: approvalSvc.source, proposal: svc,
		fake: fake, authnSvc: authnSvc, attestor: attestor, signer: signer,
		svc: approvalSvc,
		principal: authn.Principal{
			FounderID: founderID, WorkspaceID: "ws-test",
			SessionID: "sess-1", AuthTime: time.Now().UTC(),
		},
		draft: draft,
	}
}

// innerSource rebuilds the same github source the proposal fixture uses so
// the approval service shares its pinned snapshot behavior.
func innerSource(t *testing.T, st store.Store, fake *fakeMissionAuthority) *github.Source {
	t.Helper()
	src, err := github.NewSource(github.SourceConfig{Store: st, Authority: fake})
	if err != nil {
		t.Fatalf("github.NewSource: %v", err)
	}
	return src
}

func mustLoadProposal(t *testing.T, st store.Store, workspaceID, passID string) ProposalRecord {
	t.Helper()
	stored, err := st.GetMissionPass(context.Background(), workspaceID, passID)
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	return fromStoreRecord(stored).ProposalRecord
}

// beginAndFinish runs the full approval ceremony and returns the result.
func (fx *approvalFixture) beginAndFinish(t *testing.T) *ApprovalResult {
	t.Helper()
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	res, err := fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return res
}

func TestApprovalBeginChallengeBindsEveryField(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if begin.ChallengeID == "" || len(begin.OptionsJSON) == 0 {
		t.Fatalf("Begin returned an empty challenge: %+v", begin)
	}
	begun := fx.svc.begunForTest(begin.ChallengeID)
	if begun == nil {
		t.Fatalf("no begun state for challenge %s", begin.ChallengeID)
	}
	want := mustSHA256(CanonicalApprovalBytes(fx.draft))
	if begun.digest != want {
		t.Errorf("challenge digest = %x, want %x (sha256 of canonical approval bytes)", begun.digest[:], want)
	}
	// Mutating any canonical field must change the bound digest.
	mutants := []func(*ProposalRecord){
		func(r *ProposalRecord) { r.WorkspaceID = "ws-other" },
		func(r *ProposalRecord) { r.PassID = "pass-other" },
		func(r *ProposalRecord) { r.DraftVersion++ },
		func(r *ProposalRecord) { r.ProposalDigest = "sha256:" + strings.Repeat("0", 64) },
		func(r *ProposalRecord) { r.InvocationDigest = "sha256:" + strings.Repeat("1", 64) },
		func(r *ProposalRecord) { r.SourceDigest = "sha256:" + strings.Repeat("2", 64) },
		func(r *ProposalRecord) {
			b := []byte(r.BaseSHA)
			b[0] ^= 0x01
			r.BaseSHA = string(b)
		},
	}
	for i, mutate := range mutants {
		mut := fx.draft
		mutate(&mut)
		if got := mustSHA256(CanonicalApprovalBytes(mut)); got == begun.digest {
			t.Errorf("mutant %d: digest unchanged after mutating canonical field", i)
		}
	}
	// The challenge is scoped to purpose and audience.
	if begun.purpose != authn.DecisionPassApproval {
		t.Errorf("purpose = %q, want %q", begun.purpose, authn.DecisionPassApproval)
	}
	if begun.audience != identity.AudienceProposalApproval {
		t.Errorf("audience = %q, want %q", begun.audience, identity.AudienceProposalApproval)
	}
	// Digest is not the passkey challenge material itself: it must not
	// equal the raw nonce.
	if begun.digest == begun.nonce {
		t.Errorf("challenge digest equals the raw nonce; binding is not a hash of canonical claims")
	}
}

func TestApprovalFinishCreatesOnlyMission(t *testing.T) {
	fx := newApprovalFixture(t)
	res := fx.beginAndFinish(t)
	if res.MissionRef != "mission-1" {
		t.Errorf("MissionRef = %q, want mission-1", res.MissionRef)
	}
	if !strings.HasPrefix(res.MissionHash, "sha256:") || len(res.MissionHash) != len("sha256:")+64 {
		t.Errorf("MissionHash = %q, want sha256:<hex>", res.MissionHash)
	}
	if res.AuthScopeMissionVersion != 3 {
		t.Errorf("AuthScopeMissionVersion = %d, want 3", res.AuthScopeMissionVersion)
	}
	if res.ApprovalDecisionRef == "" {
		t.Errorf("ApprovalDecisionRef is empty")
	}
	if fx.fake.approveCalls != 1 {
		t.Errorf("ApproveProposal calls = %d, want 1", fx.fake.approveCalls)
	}
	if fx.fake.prepareCalls != 0 {
		t.Errorf("PrepareLaunch calls = %d, want 0", fx.fake.prepareCalls)
	}
	if fx.fake.missionsCreated != 1 {
		t.Errorf("missions created = %d, want 1", fx.fake.missionsCreated)
	}
	wantKey := "approve:ws-test:pass-1:1"
	if len(fx.fake.approveKeys) != 1 || fx.fake.approveKeys[0] != wantKey {
		t.Errorf("idempotency keys = %v, want [%s]", fx.fake.approveKeys, wantKey)
	}

	stored := mustLoadProposal(t, fx.store, "ws-test", "pass-1")
	if stored.State != PassApproved {
		t.Errorf("state = %q, want approved", stored.State)
	}
	if stored.Reconciliation != ReconciliationSettled {
		t.Errorf("reconciliation = %q, want settled", stored.Reconciliation)
	}
	if stored.ApprovedProposalDigest != stored.ProposalDigest {
		t.Errorf("ApprovedProposalDigest = %q, want %q", stored.ApprovedProposalDigest, stored.ProposalDigest)
	}
	if stored.DraftVersion != 1 {
		t.Errorf("DraftVersion = %d, want 1 (unchanged)", stored.DraftVersion)
	}
	if stored.StoreRevision != 2 {
		t.Errorf("StoreRevision = %d, want 2 (incremented by one)", stored.StoreRevision)
	}
	if stored.AuthScopeMissionVersion != 3 {
		t.Errorf("AuthScopeMissionVersion = %d, want 3", stored.AuthScopeMissionVersion)
	}
	if stored.MissionRef != res.MissionRef || stored.MissionRef == "" {
		t.Errorf("MissionRef = %q, want %q", stored.MissionRef, res.MissionRef)
	}
	if stored.MissionHash != res.MissionHash || stored.MissionHash == "" {
		t.Errorf("MissionHash = %q, want %q", stored.MissionHash, res.MissionHash)
	}
	if stored.ApprovalDecisionRef != res.ApprovalDecisionRef || stored.ApprovalDecisionRef == "" {
		t.Errorf("ApprovalDecisionRef = %q, want %q", stored.ApprovalDecisionRef, res.ApprovalDecisionRef)
	}
	if stored.AttestationDigest == "" || !strings.HasPrefix(stored.AttestationDigest, "sha256:") {
		t.Errorf("AttestationDigest = %q, want sha256:<hex>", stored.AttestationDigest)
	}
	if stored.RunID != "" {
		t.Errorf("RunID = %q, want empty (approval creates no run)", stored.RunID)
	}
	// The stored attestation digest must cover the signed decision.
	if stored.AttestationDigest != fx.lastAttestationDigest(t) {
		t.Errorf("AttestationDigest does not match the signed decision attestation")
	}
}

func TestApprovalFinishResultJSONShape(t *testing.T) {
	res := ApprovalResult{
		MissionRef: "mission-1", MissionHash: "sha256:" + strings.Repeat("f", 64),
		AuthScopeMissionVersion: 3, ApprovalDecisionRef: "dec-1",
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"mission_ref", "mission_hash", "authscope_mission_version", "approval_decision_ref"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("ApprovalResult JSON missing key %q (got %s)", key, raw)
		}
	}
	if len(decoded) != 4 {
		t.Errorf("ApprovalResult JSON has %d keys, want exactly 4 (got %s)", len(decoded), raw)
	}
}

func TestApprovalBeginRejectsNonDraftAndPending(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()

	// Approved passes cannot be approved again.
	storedRec, err := fx.store.GetMissionPass(ctx, "ws-test", fx.draft.PassID)
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	storedRec.State = string(PassApproved)
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, storedRec, storedRec.StoreRevision)
	}); err != nil {
		t.Fatalf("move to approved: %v", err)
	}
	if _, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID); !errors.Is(err, ErrNotDraft) {
		t.Errorf("Begin on approved = %v, want ErrNotDraft", err)
	}

	// Passes with pending reconciliation cannot begin a new approval.
	storedRec.State = string(PassDraft)
	storedRec.Reconciliation = string(ReconciliationPending)
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, storedRec, storedRec.StoreRevision+1)
	}); err != nil {
		t.Fatalf("move to pending: %v", err)
	}
	if _, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID); !errors.Is(err, ErrApprovalReconcilePending) {
		t.Errorf("Begin on pending = %v, want ErrApprovalReconcilePending", err)
	}
}

func TestApprovalBeginRefreshesSourceAndPosture(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	if _, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	foundIssue, foundPosture := false, false
	for _, call := range fx.fake.calls {
		if strings.HasPrefix(call, "ReadGitHubIssue") {
			foundIssue = true
		}
		if strings.HasPrefix(call, "InspectWorkflowPosture") {
			foundPosture = true
		}
	}
	if !foundIssue {
		t.Errorf("Begin did not re-read the pinned issue")
	}
	if !foundPosture {
		t.Errorf("Begin did not re-inspect workflow posture")
	}
}

func TestApprovalBeginRejectsStaleSource(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	fx.fake.issue.SourceRevision = "rev-2"
	if _, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID); !errors.Is(err, ErrStaleSource) {
		t.Errorf("Begin = %v, want ErrStaleSource", err)
	}
}

func TestApprovalBeginRejectsMalformedDigest(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	storedRec, err := fx.store.GetMissionPass(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	storedRec.ProposalDigest = "not-a-digest"
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, storedRec, storedRec.StoreRevision)
	}); err != nil {
		t.Fatalf("corrupt digest: %v", err)
	}
	if _, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID); !errors.Is(err, ErrApprovalDigest) {
		t.Errorf("Begin = %v, want ErrApprovalDigest", err)
	}
}

func TestApprovalFinishStaleProposalFails(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Narrow the limits after begin: the exact proposal moved.
	if _, err := fx.proposal.ReviseProposal(ctx, "ws-test", "founder-1", ReviseProposalInput{
		PassID: fx.draft.PassID, ExpectedStoreRevision: fx.draft.StoreRevision,
		ExpectedDraftVersion: fx.draft.DraftVersion,
		ExpiresAt:            fixtureClock.Add(30 * time.Minute),
		MaxAggregateCostMicros: 5_000_000,
	}); err != nil {
		t.Fatalf("ReviseProposal: %v", err)
	}
	_, err = fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if !errors.Is(err, ErrApprovalBindingChanged) {
		t.Errorf("Finish = %v, want ErrApprovalBindingChanged", err)
	}
	if fx.fake.approveCalls != 0 {
		t.Errorf("ApproveProposal calls = %d, want 0 (stale proposal must not reach upstream)", fx.fake.approveCalls)
	}
}

func TestApprovalFinishWrongPrincipalFails(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	other := fx.principal
	other.SessionID = "sess-2"
	other.FounderID = "founder-2"
	_, err = fx.svc.Finish(ctx, other, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if !errors.Is(err, authn.ErrDecisionBinding) {
		t.Errorf("Finish = %v, want authn.ErrDecisionBinding", err)
	}
	if fx.fake.approveCalls != 0 {
		t.Errorf("ApproveProposal calls = %d, want 0", fx.fake.approveCalls)
	}
}

func TestApprovalFinishReplayOfChallengeFails(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); err != nil {
		t.Fatalf("first Finish: %v", err)
	}
	_, err = fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if !errors.Is(err, authn.ErrCeremonyConsumed) && !errors.Is(err, authn.ErrCeremonyNotFound) {
		t.Errorf("second Finish = %v, want consumed/not-found", err)
	}
	if fx.fake.missionsCreated != 1 {
		t.Errorf("missions created = %d, want 1", fx.fake.missionsCreated)
	}
}

func TestApprovalConcurrentFinishCreatesOneMission(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
		}(i)
	}
	wg.Wait()
	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Errorf("succeeded = %d, want exactly 1 (errs = %v)", succeeded, errs)
	}
	if fx.fake.missionsCreated != 1 {
		t.Errorf("missions created = %d, want 1", fx.fake.missionsCreated)
	}
}

func TestApprovalDeniesWithoutDecisionAttestorRole(t *testing.T) {
	fx := newApprovalFixture(t)
	fx.fake.identityRoles = map[string][]string{} // role revoked
	_, err := fx.beginFinishErr(t)
	if !isUpstreamDenied(err) {
		t.Errorf("Finish = %v, want upstream decision denial", err)
	}
	stored := mustLoadProposal(t, fx.store, "ws-test", "pass-1")
	if stored.State != PassDraft {
		t.Errorf("state = %q, want draft (denied approval must not persist)", stored.State)
	}
}

func TestApprovalAttestationMutationsDenied(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*identity.SignedDecisionAttestation)
	}{
		{"signature", func(a *identity.SignedDecisionAttestation) { a.Signature[0] ^= 0xff }},
		{"workspace", func(a *identity.SignedDecisionAttestation) { a.Claims.WorkspaceID = "ws-other" }},
		{"audience", func(a *identity.SignedDecisionAttestation) { a.Claims.Audience = "authscope:other" }},
		{"decision_digest", func(a *identity.SignedDecisionAttestation) {
			a.Claims.DecisionDigest = "sha256:" + strings.Repeat("0", 64)
		}},
		{"invocation_digest", func(a *identity.SignedDecisionAttestation) {
			a.Claims.InvocationDigest = "sha256:" + strings.Repeat("1", 64)
		}},
		{"auth_method", func(a *identity.SignedDecisionAttestation) {
			a.Claims.AuthenticationMethod = "pin"
		}},
		{"proof_digest", func(a *identity.SignedDecisionAttestation) {
			a.Claims.AuthenticationProofDigest = "not-a-digest"
		}},
		{"nonce", func(a *identity.SignedDecisionAttestation) {
			var zero [32]byte
			a.Claims.Nonce = zero
		}},
		{"issued_future", func(a *identity.SignedDecisionAttestation) {
			a.Claims.IssuedAt = time.Now().Add(time.Hour)
		}},
		{"expiry", func(a *identity.SignedDecisionAttestation) {
			a.Claims.ExpiresAt = a.Claims.IssuedAt
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newApprovalFixture(t)
			fx.fake.tamper = tt.tamper
			_, err := fx.beginFinishErr(t)
			if !isUpstreamDenied(err) {
				t.Errorf("Finish = %v, want upstream decision denial", err)
			}
			if fx.fake.missionsCreated != 0 {
				t.Errorf("missions created = %d, want 0", fx.fake.missionsCreated)
			}
			stored := mustLoadProposal(t, fx.store, "ws-test", "pass-1")
			if stored.State != PassDraft {
				t.Errorf("state = %q, want draft", stored.State)
			}
		})
	}
}

func isUpstreamDenied(err error) bool {
	var ue *coreapi.UpstreamError
	return errors.As(err, &ue) && ue.StatusCode == 403
}

// beginFinishErr runs begin+finish and returns the finish error.
func (fx *approvalFixture) beginFinishErr(t *testing.T) (*ApprovalResult, error) {
	t.Helper()
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
}

func TestApprovalUpstreamTimeoutReturns202AndReconciles(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	fx.fake.failApproveOnce = context.DeadlineExceeded

	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	_, err = fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if !errors.Is(err, ErrPendingReconciliation) {
		t.Fatalf("Finish = %v, want ErrPendingReconciliation", err)
	}
	stored := mustLoadProposal(t, fx.store, "ws-test", "pass-1")
	if stored.State != PassDraft {
		t.Errorf("state = %q, want draft while ambiguous", stored.State)
	}
	if stored.Reconciliation != ReconciliationPending {
		t.Errorf("reconciliation = %q, want pending", stored.Reconciliation)
	}

	// The timed-out call landed upstream, so the second attempt must not
	// create a second mission: the fake dedupes on the idempotency key.
	fx.fake.reconcile = coreapi.OperationResult{OperationID: "op-approve-1", Status: "completed"}
	res, err := fx.svc.ReconcileApproval(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("ReconcileApproval: %v", err)
	}
	if res == nil || res.MissionRef != "mission-1" {
		t.Fatalf("reconcile result = %+v, want the original mission", res)
	}
	if fx.fake.missionsCreated != 1 {
		t.Errorf("missions created = %d, want 1 (no duplicate mission)", fx.fake.missionsCreated)
	}
	if fx.fake.approveCalls != 2 {
		t.Errorf("ApproveProposal calls = %d, want 2 (timed-out replay recovered)", fx.fake.approveCalls)
	}
	stored = mustLoadProposal(t, fx.store, "ws-test", "pass-1")
	if stored.State != PassApproved || stored.Reconciliation != ReconciliationSettled {
		t.Errorf("state = %q reconciliation = %q, want approved/settled", stored.State, stored.Reconciliation)
	}
	// Reconciliation never re-issues the approval: the replay recovered the
	// original result instead.
	if n := fx.fake.reconcileCalls; n != 1 {
		t.Errorf("ReconcileOperation calls = %d, want 1", n)
	}
}

func TestApprovalReconcileWhileInFlightStaysPending(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	fx.fake.failApproveOnce = context.DeadlineExceeded

	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, ErrPendingReconciliation) {
		t.Fatalf("Finish = %v, want ErrPendingReconciliation", err)
	}
	fx.fake.reconcile = coreapi.OperationResult{OperationID: "op-approve-1", Status: "in_flight"}
	res, err := fx.svc.ReconcileApproval(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("ReconcileApproval: %v", err)
	}
	if res != nil {
		t.Errorf("reconcile result = %+v, want nil while in flight", res)
	}
	stored := mustLoadProposal(t, fx.store, "ws-test", "pass-1")
	if stored.Reconciliation != ReconciliationPending {
		t.Errorf("reconciliation = %q, want pending", stored.Reconciliation)
	}
}

func TestApprovalCrashAfterUpstreamSuccessRecoversWithoutDuplicate(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()

	// Crash the service between upstream success and local persistence by
	// failing the settle write exactly once.
	crasher := &failOnceStore{Store: fx.store, failPut: &atomic.Bool{}}
	crasher.failPut.Store(true)
	fx.svc.store = crasher

	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	_, err = fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err == nil {
		t.Fatalf("Finish succeeded despite the injected crash")
	}
	// Upstream holds the mission; locally the pass is still a draft with a
	// begun-but-incomplete idempotency record.
	stored := mustLoadProposal(t, fx.store, "ws-test", "pass-1")
	if stored.State != PassDraft {
		t.Fatalf("state = %q, want draft after crash", stored.State)
	}

	// A fresh operator process retries: new challenge, same deterministic
	// idempotency key. Upstream dedupes on the key and returns the original
	// mission instead of creating a second one.
	fx.svc.store = fx.store
	begin2, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin after crash: %v", err)
	}
	res, err := fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin2.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err != nil {
		t.Fatalf("Finish after crash: %v", err)
	}
	if res.MissionRef != "mission-1" {
		t.Errorf("MissionRef = %q, want the original mission-1", res.MissionRef)
	}
	if fx.fake.missionsCreated != 1 {
		t.Errorf("missions created = %d, want 1 (no duplicate mission after crash)", fx.fake.missionsCreated)
	}
	stored = mustLoadProposal(t, fx.store, "ws-test", "pass-1")
	if stored.State != PassApproved || stored.ApprovedProposalDigest != stored.ProposalDigest {
		t.Errorf("state = %q approved digest = %q, want approved + proposal digest", stored.State, stored.ApprovedProposalDigest)
	}
}

// failOnceStore fails the next PutMissionPass call, simulating a crash
// between upstream success and local persistence.
type failOnceStore struct {
	store.Store
	failPut *atomic.Bool
}

func (s *failOnceStore) WithTx(ctx context.Context, fn func(store.Tx) error) error {
	return s.Store.WithTx(ctx, func(tx store.Tx) error {
		return fn(&failOnceTx{Tx: tx, failPut: s.failPut})
	})
}

type failOnceTx struct {
	store.Tx
	failPut *atomic.Bool
}

func (t *failOnceTx) PutMissionPass(ctx context.Context, rec store.MissionPassRecord, expected int64) error {
	if t.failPut.CompareAndSwap(true, false) {
		return errors.New("injected crash before settle")
	}
	return t.Tx.PutMissionPass(ctx, rec, expected)
}

func TestApprovalIdempotencyMismatchReturns409(t *testing.T) {
	fx := newApprovalFixture(t)
	ctx := context.Background()
	// A different canonical payload under the same deterministic key.
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		_, err := tx.BeginIdempotency(ctx, store.IdempotencyRecord{
			WorkspaceID: "ws-test", Key: "approve:ws-test:pass-1:1",
			CanonicalDigest: "sha256:" + strings.Repeat("9", 64),
		})
		return err
	}); err != nil {
		t.Fatalf("BeginIdempotency: %v", err)
	}
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.draft.PassID)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	_, err = fx.svc.Finish(ctx, fx.principal, fx.draft.PassID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if !errors.Is(err, store.ErrIdempotencyMismatch) {
		t.Errorf("Finish = %v, want store.ErrIdempotencyMismatch", err)
	}
	if fx.fake.approveCalls != 0 {
		t.Errorf("ApproveProposal calls = %d, want 0", fx.fake.approveCalls)
	}
}

// lastAttestationDigest recomputes the digest of the attestation the fake
// last verified, so the test can compare it against the stored value.
func (fx *approvalFixture) lastAttestationDigest(t *testing.T) string {
	t.Helper()
	fx.fake.mu.Lock()
	defer fx.fake.mu.Unlock()
	if len(fx.fake.signedAttestations) == 0 {
		t.Fatalf("no attestation reached the fake")
	}
	att := fx.fake.signedAttestations[len(fx.fake.signedAttestations)-1]
	raw, err := json.Marshal(att)
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
