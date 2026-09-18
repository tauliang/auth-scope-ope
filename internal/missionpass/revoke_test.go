// Mission revocation tests: the founder-bound begin/finish ceremony,
// exact canonical binding, single upstream revoke under concurrency,
// ambiguous-outcome reconciliation, and the result-only CLI handoff.

package missionpass

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// cyclingVerifier hands each concurrent ceremony its own credential so
// simultaneous finishes do not trip sign-count clone detection. The
// revocation dedupe under test sits below the ceremony layer.
type cyclingVerifier struct {
	stubDecisionVerifier
	next *atomic.Int64
}

func (s cyclingVerifier) FinishAssertion(_ context.Context, _ authn.CeremonyUser, _ []authn.StoredCredential, _ []byte, _ []byte) (authn.VerifiedAssertion, error) {
	n := s.next.Add(1)
	return authn.VerifiedAssertion{
		CredentialID: []byte("cred-" + strconv.FormatInt(n, 10)),
		NewSignCount: uint32(s.signCount.Add(1)),
		UserVerified: true,
	}, nil
}

// fakeRevokeAuthority implements just the revocation surface of
// coreapi.Authority. It verifies the exact signed decision attestation,
// dedupes idempotent replays on the idempotency key like AuthScope does,
// and can drop one response to exercise ambiguous-outcome
// reconciliation.
type fakeRevokeAuthority struct {
	coreapi.Authority

	mu             sync.Mutex
	revokeErr      error
	failRevokeOnce error
	revokeCalls    int
	revokeKeys     []string
	revokedByKey   map[string]coreapi.Revocation
	reconcile      map[string]coreapi.OperationResult
	seenNonces     map[string]bool
	identityRoles  map[string][]string
	identityKeys   map[string]ed25519.PublicKey
	binding        RevokeBinding
	bindingSet     bool
	containment    string
}

func (f *fakeRevokeAuthority) deny(format string, args ...any) error {
	return &fakeRevokeError{msg: "revoke denied: " + sprintf(format, args)}
}

type fakeRevokeError struct{ msg string }

func (e *fakeRevokeError) Error() string { return e.msg }

func sprintf(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	out := format
	for _, a := range args {
		out = strings.Replace(out, "%v", sprintArg(a), 1)
		out = strings.Replace(out, "%q", "\""+sprintArg(a)+"\"", 1)
	}
	return out
}

func sprintArg(a any) string {
	switch v := a.(type) {
	case string:
		return v
	case error:
		return v.Error()
	default:
		return "?"
	}
}

func (f *fakeRevokeAuthority) RevokeMission(_ context.Context, missionRef string, in coreapi.RevokeRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Revocation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokeCalls++
	f.revokeKeys = append(f.revokeKeys, opts.IdempotencyKey)
	if f.revokedByKey == nil {
		f.revokedByKey = make(map[string]coreapi.Revocation)
	}
	if f.reconcile == nil {
		f.reconcile = make(map[string]coreapi.OperationResult)
	}
	// Idempotent dedupe: a replay of the same key returns the original
	// revocation without re-verifying the attestation, exactly like
	// AuthScope.
	if rev, ok := f.revokedByKey[opts.IdempotencyKey]; ok {
		return rev, nil
	}
	if f.failRevokeOnce != nil {
		err := f.failRevokeOnce
		f.failRevokeOnce = nil
		// The call landed upstream and revoked the mission; only the
		// response was lost.
		rev := coreapi.Revocation{
			MissionRef: missionRef, Revoked: true,
			RevokedAt:   fixtureClock.Add(time.Minute).UnixMilli(),
			Containment: f.containmentOrDefault(),
		}
		f.revokedByKey[opts.IdempotencyKey] = rev
		f.reconcile[opts.IdempotencyKey] = coreapi.OperationResult{
			OperationID: missionRef, IdempotencyKey: opts.IdempotencyKey,
			Status: "completed", WorkspaceID: opts.WorkspaceID,
		}
		return coreapi.Revocation{}, err
	}
	if f.revokeErr != nil {
		return coreapi.Revocation{}, f.revokeErr
	}
	if err := f.verifyRevocationAttestation(att, missionRef, in); err != nil {
		return coreapi.Revocation{}, err
	}
	rev := coreapi.Revocation{
		MissionRef: missionRef, Revoked: true,
		RevokedAt:   fixtureClock.Add(time.Minute).UnixMilli(),
		Containment: f.containmentOrDefault(),
	}
	f.revokedByKey[opts.IdempotencyKey] = rev
	f.reconcile[opts.IdempotencyKey] = coreapi.OperationResult{
		OperationID: missionRef, IdempotencyKey: opts.IdempotencyKey,
		Status: "completed", WorkspaceID: opts.WorkspaceID,
	}
	return rev, nil
}

func (f *fakeRevokeAuthority) containmentOrDefault() string {
	if f.containment != "" {
		return f.containment
	}
	return store.ContainmentAcknowledged
}

func (f *fakeRevokeAuthority) ReconcileOperation(_ context.Context, idempotencyKey, _ string, opts coreapi.RequestOptions) (coreapi.OperationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.reconcile[idempotencyKey]; ok {
		return r, nil
	}
	return coreapi.OperationResult{IdempotencyKey: idempotencyKey, Status: "in_flight", WorkspaceID: opts.WorkspaceID}, nil
}

func (f *fakeRevokeAuthority) verifyRevocationAttestation(att identity.SignedDecisionAttestation, missionRef string, in coreapi.RevokeRequest) error {
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
	if c.WorkspaceID == "" {
		return f.deny("missing workspace")
	}
	if c.Audience != identity.AudienceMissionRevoke {
		return f.deny("audience mismatch: %q", c.Audience)
	}
	if c.Purpose != identity.PurposeMissionRevoke {
		return f.deny("purpose mismatch: %q", c.Purpose)
	}
	if c.SubjectID != missionRef {
		return f.deny("subject mismatch: %q", c.SubjectID)
	}
	if !f.bindingSet {
		return f.deny("test did not pin the expected binding")
	}
	dd := mustSHA256(CanonicalRevokeBytes(f.binding))
	if c.DecisionDigest != "sha256:"+hex.EncodeToString(dd[:]) {
		return f.deny("decision digest mismatch")
	}
	if !validRevocationReasons[in.Reason] {
		return f.deny("reason outside the fixed enum: %q", in.Reason)
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

type revokeFixture struct {
	t         *testing.T
	store     store.Store
	fake      *fakeRevokeAuthority
	authnSvc  *authn.Service
	attestor  *identity.DecisionAttestor
	signer    *identity.EphemeralSigner
	svc       *RevocationService
	principal authn.Principal
	passID    string
}

func newRevocationFixture(t *testing.T) *revokeFixture {
	t.Helper()
	ctx := context.Background()
	st := openProposalStore(t)

	inst := store.InstanceRecord{
		InstanceID: "inst-revoke-1", WorkspaceID: "ws-test",
		Hostname: "ope.example.com", Origin: "https://ope.example.com",
		RPID: "ope.example.com", SessionCookieName: store.DeriveSessionCookieName("inst-revoke-1"),
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
		for i := 1; i <= 4; i++ {
			credID := "cred-" + strconv.FormatInt(int64(i), 10)
			if err := tx.PutWebAuthnCredential(ctx, store.WebAuthnCredentialRecord{
				WorkspaceID:  "ws-test",
				CredentialID: base64.RawURLEncoding.EncodeToString([]byte(credID)),
				FounderID:    founderID,
				PublicKey:    []byte("pk-" + strconv.FormatInt(int64(i), 10)),
				SignCount:    0,
				CreatedAt:    fixtureClock,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed founder: %v", err)
	}

	authnSvc, err := authn.NewService(ctx, st, stubDecisionVerifier{signCount: &atomic.Int64{}})
	if err != nil {
		t.Fatalf("authn.NewService: %v", err)
	}
	signer := identity.NewEphemeralSigner()
	attestor := identity.NewDecisionAttestor(signer)
	fake := &fakeRevokeAuthority{
		seenNonces:    make(map[string]bool),
		identityRoles: map[string][]string{signer.IdentityDigest(): {coreapi.DecisionAttestorRole}},
		identityKeys:  map[string]ed25519.PublicKey{signer.IdentityDigest(): signer.PublicKey()},
	}
	svc, err := NewRevocationService(RevocationConfig{
		Store:     st,
		Authn:     authnSvc,
		Authority: fake,
		Attestor:  attestor,
		Clock:     func() time.Time { return time.Now().UTC() },
		NewNonce: func() ([32]byte, error) {
			var n [32]byte
			copy(n[:], "revoke-fixture-nonce-00000000001")
			return n, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRevocationService: %v", err)
	}

	passID := "pass-revoke-1"
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID: "ws-test", PassID: passID,
			State:      string(PassRunning),
			MissionRef: "mission-1", AuthScopeMissionVersion: 3,
			Reconciliation: string(ReconciliationSettled),
			CreatedAt:      fixtureClock,
		}, 0)
	}); err != nil {
		t.Fatalf("seed pass: %v", err)
	}

	return &revokeFixture{
		t: t, store: st, fake: fake, authnSvc: authnSvc,
		attestor: attestor, signer: signer, svc: svc,
		principal: authn.Principal{
			FounderID: founderID, WorkspaceID: "ws-test",
			SessionID: "sess-1", AuthTime: time.Now().UTC(),
		},
		passID: passID,
	}
}

// beginAndFinish runs the full revocation ceremony and returns the
// result, pinning the fake's expected binding to the begun challenge.
func (fx *revokeFixture) beginAndFinish(t *testing.T, reason string) *RevocationResult {
	t.Helper()
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, reason)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	fx.fake.mu.Lock()
	fx.fake.binding = fx.svc.begunForTest(begin.ChallengeID).binding
	fx.fake.bindingSet = true
	fx.fake.mu.Unlock()
	res, err := fx.svc.Finish(ctx, fx.principal, fx.passID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return res
}

func TestRevocationBeginBindsEveryField(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "founder_requested")
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
	want := mustSHA256(CanonicalRevokeBytes(begun.binding))
	if begun.digest != want {
		t.Errorf("challenge digest = %x, want %x (sha256 of canonical revoke bytes)", begun.digest[:], want)
	}
	b := begun.binding
	if b.WorkspaceID != "ws-test" || b.FounderID != "founder-1" || b.SessionID != "sess-1" {
		t.Errorf("binding principal = %+v, want ws-test/founder-1/sess-1", b)
	}
	if b.PassID != fx.passID || b.MissionRef != "mission-1" || b.MissionVersion != 3 {
		t.Errorf("binding pass = %+v, want pass-revoke-1/mission-1/v3", b)
	}
	if !b.Descendants {
		t.Errorf("binding descendants = false, want true")
	}
	if b.ReasonCode != RevocationReasonFounderRequested {
		t.Errorf("binding reason = %q, want founder_requested", b.ReasonCode)
	}
	if b.Purpose != string(authn.DecisionMissionRevoke) {
		t.Errorf("binding purpose = %q, want mission_revoke", b.Purpose)
	}
	if b.Audience != identity.AudienceMissionRevoke {
		t.Errorf("binding audience = %q, want authscope:mission-revoke", b.Audience)
	}
	if b.Nonce == "" {
		t.Errorf("binding nonce is empty")
	}
	// Mutating any canonical field must change the bound digest.
	mutants := []func(*RevokeBinding){
		func(x *RevokeBinding) { x.WorkspaceID = "ws-other" },
		func(x *RevokeBinding) { x.FounderID = "founder-2" },
		func(x *RevokeBinding) { x.SessionID = "sess-2" },
		func(x *RevokeBinding) { x.PassID = "pass-other" },
		func(x *RevokeBinding) { x.MissionRef = "mission-2" },
		func(x *RevokeBinding) { x.MissionVersion++ },
		func(x *RevokeBinding) { x.Descendants = false },
		func(x *RevokeBinding) { x.ReasonCode = RevocationReasonSafetyConcern },
		func(x *RevokeBinding) { x.Purpose = "other" },
		func(x *RevokeBinding) { x.Audience = "other" },
		func(x *RevokeBinding) { x.Nonce = "other" },
	}
	for i, mutate := range mutants {
		mut := b
		mutate(&mut)
		if got := mustSHA256(CanonicalRevokeBytes(mut)); got == begun.digest {
			t.Errorf("mutant %d: digest unchanged after mutating canonical field", i)
		}
	}
}

func TestRevocationFinishRevokesOnce(t *testing.T) {
	fx := newRevocationFixture(t)
	res := fx.beginAndFinish(t, "founder_requested")
	if !res.Revoked || res.PassID != fx.passID || res.MissionRef != "mission-1" {
		t.Errorf("result = %+v, want revoked pass-revoke-1/mission-1", res)
	}
	if res.Containment != store.ContainmentAcknowledged {
		t.Errorf("containment = %q, want acknowledged", res.Containment)
	}
	if res.ReasonCode != RevocationReasonFounderRequested {
		t.Errorf("reason = %q, want founder_requested", res.ReasonCode)
	}
	fx.fake.mu.Lock()
	calls := fx.fake.revokeCalls
	keys := append([]string(nil), fx.fake.revokeKeys...)
	fx.fake.mu.Unlock()
	if calls != 1 {
		t.Errorf("upstream revoke calls = %d, want 1", calls)
	}
	if len(keys) != 1 || keys[0] != "revoke:ws-test:pass-revoke-1" {
		t.Errorf("idempotency keys = %v, want [revoke:ws-test:pass-revoke-1]", keys)
	}
	rec, err := fx.store.GetMissionPass(context.Background(), "ws-test", fx.passID)
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if rec.State != string(PassRevoked) {
		t.Errorf("pass state = %q, want revoked", rec.State)
	}
	if rec.Containment != store.ContainmentAcknowledged {
		t.Errorf("pass containment = %q, want acknowledged", rec.Containment)
	}
	if rec.Reconciliation != string(ReconciliationSettled) {
		t.Errorf("pass reconciliation = %q, want settled", rec.Reconciliation)
	}
}

func TestRevocationConcurrentFinishesSingleUpstreamCall(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	// The concurrent finishes run through their own service wired to the
	// cycling verifier, sharing the store and the fake upstream.
	authnSvc, err := authn.NewService(ctx, fx.store, cyclingVerifier{
		stubDecisionVerifier: stubDecisionVerifier{signCount: &atomic.Int64{}},
		next:                 &atomic.Int64{},
	})
	if err != nil {
		t.Fatalf("authn.NewService: %v", err)
	}
	svc, err := NewRevocationService(RevocationConfig{
		Store:     fx.store,
		Authn:     authnSvc,
		Authority: fx.fake,
		Attestor:  fx.attestor,
		Clock:     func() time.Time { return time.Now().UTC() },
		NewNonce: func() ([32]byte, error) {
			var n [32]byte
			copy(n[:], "revoke-fixture-nonce-00000000001")
			return n, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRevocationService: %v", err)
	}
	const n = 4
	challenges := make([]string, n)
	for i := 0; i < n; i++ {
		begin, err := svc.Begin(ctx, fx.principal, fx.passID, "safety_concern")
		if err != nil {
			t.Fatalf("Begin %d: %v", i, err)
		}
		challenges[i] = begin.ChallengeID
	}
	// Pin the binding the fake expects. Every challenge carries the same
	// binding except the nonce; the fake checks the exact attestation
	// only on the first upstream call, and the idempotent replay skips
	// verification.
	fx.fake.mu.Lock()
	fx.fake.binding = svc.begunForTest(challenges[0]).binding
	fx.fake.bindingSet = true
	fx.fake.mu.Unlock()

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = svc.Finish(ctx, fx.principal, fx.passID, challenges[i], []byte(`{"assertion":"ok"}`))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Finish %d: %v", i, err)
		}
	}
	fx.fake.mu.Lock()
	calls := fx.fake.revokeCalls
	fx.fake.mu.Unlock()
	if calls != 1 {
		t.Errorf("upstream revoke calls = %d, want 1 (concurrent finishes share one upstream revoke)", calls)
	}
}

func TestRevocationAmbiguousOutcomeReconciles(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	fx.fake.failRevokeOnce = &coreapi.UpstreamError{StatusCode: 503, Code: "unavailable", Message: "gateway unavailable"}
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "mission_superseded")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	fx.fake.mu.Lock()
	fx.fake.binding = fx.svc.begunForTest(begin.ChallengeID).binding
	fx.fake.bindingSet = true
	fx.fake.mu.Unlock()
	_, err = fx.svc.Finish(ctx, fx.principal, fx.passID, begin.ChallengeID, []byte(`{"assertion":"ok"}`))
	if !errors.Is(err, ErrRevokePending) {
		t.Fatalf("Finish = %v, want ErrRevokePending", err)
	}
	// The intent stays in-flight and the pass records pending
	// reconciliation with pending containment.
	var intent store.RevocationIntentRecord
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetRevocationIntent(ctx, "ws-test", fx.passID)
		return err
	}); err != nil {
		t.Fatalf("GetRevocationIntent: %v", err)
	}
	if intent.State != store.RevocationIntentInFlight {
		t.Errorf("intent state = %q, want in_flight", intent.State)
	}
	rec, err := fx.store.GetMissionPass(ctx, "ws-test", fx.passID)
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if rec.State == string(PassRevoked) {
		t.Errorf("pass moved to revoked on an ambiguous outcome; it must stay pending reconciliation")
	}
	if rec.Reconciliation != string(ReconciliationPending) {
		t.Errorf("pass reconciliation = %q, want pending", rec.Reconciliation)
	}
	// Reconciliation settles the revocation without repeating the upstream
	// revoke: it uses only ReconcileOperation with the original key.
	res, err := fx.svc.ReconcileRevocation(ctx, "ws-test", fx.passID)
	if err != nil {
		t.Fatalf("ReconcileRevocation: %v", err)
	}
	if res == nil || !res.Revoked {
		t.Fatalf("ReconcileRevocation = %+v, want a settled revoked result", res)
	}
	if res.Containment != "pending" {
		t.Errorf("reconciled containment = %q, want pending (no upstream acknowledgment observed)", res.Containment)
	}
	fx.fake.mu.Lock()
	calls := fx.fake.revokeCalls
	fx.fake.mu.Unlock()
	if calls != 1 {
		t.Errorf("upstream revoke calls = %d, want 1 (reconciliation must not repeat the revoke)", calls)
	}
	rec, err = fx.store.GetMissionPass(ctx, "ws-test", fx.passID)
	if err != nil {
		t.Fatalf("GetMissionPass: %v", err)
	}
	if rec.State != string(PassRevoked) || rec.Reconciliation != string(ReconciliationSettled) {
		t.Errorf("pass = state %q reconciliation %q, want revoked/settled", rec.State, rec.Reconciliation)
	}
}

func TestRevocationRejectsInvalidReason(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	for _, reason := range []string{"", "angry", "safety concern", "revoked!!", "founder requested"} {
		if _, err := fx.svc.Begin(ctx, fx.principal, fx.passID, reason); !errors.Is(err, ErrInvalidRevocationReason) {
			t.Errorf("Begin(%q) = %v, want ErrInvalidRevocationReason", reason, err)
		}
	}
	// Normalization is case- and space-insensitive inside the enum.
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "  Safety_Concern ")
	if err != nil {
		t.Fatalf("Begin normalized reason: %v", err)
	}
	if got := fx.svc.begunForTest(begin.ChallengeID).binding.ReasonCode; got != RevocationReasonSafetyConcern {
		t.Errorf("normalized reason = %q, want safety_concern", got)
	}
}

func TestRevocationRejectsNonRevocableState(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, "ws-test", fx.passID)
		if err != nil {
			return err
		}
		rec.State = string(PassCompleted)
		return tx.PutMissionPass(ctx, rec, rec.StoreRevision)
	}); err != nil {
		t.Fatalf("seed completed pass: %v", err)
	}
	if _, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "founder_requested"); !errors.Is(err, ErrPassNotRevocable) {
		t.Errorf("Begin on completed pass = %v, want ErrPassNotRevocable", err)
	}
}

func TestRevocationFinishReplayOfChallengeFails(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "founder_requested")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	fx.fake.mu.Lock()
	fx.fake.binding = fx.svc.begunForTest(begin.ChallengeID).binding
	fx.fake.bindingSet = true
	fx.fake.mu.Unlock()
	if _, err := fx.svc.Finish(ctx, fx.principal, fx.passID, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if _, err := fx.svc.Finish(ctx, fx.principal, fx.passID, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, authn.ErrCeremonyNotFound) {
		t.Errorf("second Finish = %v, want ceremony not found", err)
	}
}

func TestRevocationFinishBindingChangedFails(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "founder_requested")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// The mission version moves between begin and finish.
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, "ws-test", fx.passID)
		if err != nil {
			return err
		}
		rec.AuthScopeMissionVersion = 4
		return tx.PutMissionPass(ctx, rec, rec.StoreRevision)
	}); err != nil {
		t.Fatalf("bump mission version: %v", err)
	}
	if _, err := fx.svc.Finish(ctx, fx.principal, fx.passID, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, ErrRevokeBindingChanged) {
		t.Errorf("Finish after mission change = %v, want ErrRevokeBindingChanged", err)
	}
}

func TestRevocationFinishWrongPrincipalFails(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "founder_requested")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	other := fx.principal
	other.FounderID = "founder-2"
	if _, err := fx.svc.Finish(ctx, other, fx.passID, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, ErrRevokeBindingChanged) {
		t.Errorf("Finish with other founder = %v, want ErrRevokeBindingChanged", err)
	}
}

func TestMapContainment(t *testing.T) {
	cases := map[string]string{
		store.ContainmentAcknowledged: store.ContainmentAcknowledged,
		store.ContainmentPartial:      store.ContainmentPartial,
		store.ContainmentPending:      store.ContainmentPending,
		"":                            store.ContainmentPending,
		"enforced":                    store.ContainmentPending,
	}
	for in, want := range cases {
		if got := mapContainment(in); got != want {
			t.Errorf("mapContainment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalRevocationDigestBindsEveryField(t *testing.T) {
	in := RevocationDigestInput{
		WorkspaceID: "ws-test", PassID: "pass-1",
		MissionRef: "mission-1", MissionVersion: 3,
		ReasonCode: RevocationReasonFounderRequested,
	}
	first := CanonicalRevocationDigest(in)
	if first == "" {
		t.Fatalf("empty digest")
	}
	mutants := []func(*RevocationDigestInput){
		func(x *RevocationDigestInput) { x.WorkspaceID = "ws-other" },
		func(x *RevocationDigestInput) { x.PassID = "pass-2" },
		func(x *RevocationDigestInput) { x.MissionRef = "mission-2" },
		func(x *RevocationDigestInput) { x.MissionVersion++ },
		func(x *RevocationDigestInput) { x.ReasonCode = RevocationReasonSafetyConcern },
	}
	for i, mutate := range mutants {
		mut := in
		mutate(&mut)
		if got := CanonicalRevocationDigest(mut); got == first {
			t.Errorf("mutant %d: digest unchanged after mutating field", i)
		}
	}
	// Descendants=true, purpose, and audience are pinned by the digest
	// itself: the same input always yields the same digest.
	if got := CanonicalRevocationDigest(in); got != first {
		t.Errorf("digest not deterministic")
	}
}

// incrementingTestRequestID returns unique request IDs; the exchange test
// asserts the first one.
func incrementingTestRequestID() func() (string, error) {
	var n atomic.Int64
	return func() (string, error) {
		return "clr-test-" + strconv.FormatInt(n.Add(1), 10), nil
	}
}

// newCLIRevocationFixture wires the result-only handoff service for a
// revocable pass.
func newCLIRevocationFixture(t *testing.T) (*revokeFixture, *CLIRevocationService) {
	t.Helper()
	fx := newRevocationFixture(t)
	svc, err := NewCLIRevocationService(CLIRevocationConfig{
		Store:        fx.store,
		Revocation:   fx.svc,
		WorkspaceID:  "ws-test",
		BrowserURL:   "https://ope.example.com",
		Clock:        func() time.Time { return fixtureClock },
		NewRequestID: incrementingTestRequestID(),
		NewCode:      func() (string, error) { return "code-raw-test-1", nil },
		NewResultRef: func() (string, error) { return "revres-test-1", nil },
	})
	if err != nil {
		t.Fatalf("NewCLIRevocationService: %v", err)
	}
	return fx, svc
}

var testRevocationVerifier = mustTestVerifier()

func mustTestVerifier() string {
	v, err := authn.NewPKCEVerifier()
	if err != nil {
		panic(err)
	}
	return v
}

func testRevocationRegisterRequest() CLIRevocationRegisterRequest {
	return CLIRevocationRegisterRequest{
		PassID:        "pass-revoke-1",
		State:         "state-1",
		CodeChallenge: authn.CodeChallengeS256(testRevocationVerifier),
		RedirectURI:   "http://127.0.0.1:18080/callback",
	}
}

// testRevocationDigestInput is the pass/mission digest the browser
// finish recomputes when minting the CLI result. The founder picks the
// reason in the browser, so the CLI handoff digest carries no reason.
func testRevocationDigestInput() RevocationDigestInput {
	return RevocationDigestInput{
		WorkspaceID: "ws-test", PassID: "pass-revoke-1",
		MissionRef: "mission-1", MissionVersion: 3,
	}
}

func TestCLIRevocationRegisterAndExchange(t *testing.T) {
	_, svc := newCLIRevocationFixture(t)
	ctx := context.Background()
	start, err := svc.Register(ctx, testRevocationRegisterRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if start.RequestID != "clr-test-1" {
		t.Errorf("request ID = %q, want clr-test-1", start.RequestID)
	}
	if !strings.HasPrefix(start.BrowserURL, "https://ope.example.com/mission/pass-revoke-1?cli_revocation=clr-test-1") {
		t.Errorf("browser URL = %q", start.BrowserURL)
	}
	if start.CanonicalDigest == "" {
		t.Errorf("canonical digest is empty")
	}
	// An identical replay returns the existing request, not a conflict.
	again, err := svc.Register(ctx, testRevocationRegisterRequest())
	if err != nil {
		t.Fatalf("Register replay: %v", err)
	}
	if again.RequestID != start.RequestID || again.CanonicalDigest != start.CanonicalDigest {
		t.Errorf("replay returned a different request: %+v vs %+v", again, start)
	}
	// The browser finish ran the registered revocation: mint the result.
	code, err := svc.MintResult(ctx, start.RequestID, testRevocationDigestInput(), store.ContainmentAcknowledged)
	if err != nil {
		t.Fatalf("MintResult: %v", err)
	}
	if code != "code-raw-test-1" {
		t.Errorf("code = %q, want the fixture code", code)
	}
	// Exchange returns only the opaque result reference and the fixed
	// containment state. No credential or session is issued.
	exchanged, err := svc.Exchange(ctx, code, testRevocationVerifier, "http://127.0.0.1:18080/callback", "state-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if exchanged.ResultRef != "revres-test-1" {
		t.Errorf("result ref = %q, want revres-test-1", exchanged.ResultRef)
	}
	if exchanged.Containment != store.ContainmentAcknowledged {
		t.Errorf("containment = %q, want acknowledged", exchanged.Containment)
	}
	// An identical retry after a lost response recovers only the
	// original reference.
	retry, err := svc.Exchange(ctx, code, testRevocationVerifier, "http://127.0.0.1:18080/callback", "state-1")
	if err != nil {
		t.Fatalf("Exchange retry: %v", err)
	}
	if retry.ResultRef != exchanged.ResultRef || retry.Containment != exchanged.Containment {
		t.Errorf("retry = %+v, want the original %+v", retry, exchanged)
	}
}

func TestCLIRevocationRegisterConflict(t *testing.T) {
	_, svc := newCLIRevocationFixture(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, testRevocationRegisterRequest()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A changed state is a different request, not a replay of this one.
	changedState := testRevocationRegisterRequest()
	changedState.State = "state-2"
	if _, err := svc.Register(ctx, changedState); err != nil {
		t.Fatalf("Register changed state (new request): %v", err)
	}
	// A non-loopback redirect is rejected outright.
	bad := testRevocationRegisterRequest()
	bad.State = "state-3"
	bad.RedirectURI = "https://evil.example.com/callback"
	if _, err := svc.Register(ctx, bad); err == nil {
		t.Errorf("Register non-loopback redirect succeeded, want failure")
	}
}

func TestCLIRevocationExchangeGuards(t *testing.T) {
	_, svc := newCLIRevocationFixture(t)
	ctx := context.Background()
	start, err := svc.Register(ctx, testRevocationRegisterRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	code, err := svc.MintResult(ctx, start.RequestID, testRevocationDigestInput(), store.ContainmentPending)
	if err != nil {
		t.Fatalf("MintResult: %v", err)
	}
	// Wrong verifier fails PKCE.
	if _, err := svc.Exchange(ctx, code, "wrong-verifier", "http://127.0.0.1:18080/callback", "state-1"); !errors.Is(err, ErrCLIRevocationConflict) {
		t.Errorf("Exchange wrong verifier = %v, want ErrCLIRevocationConflict", err)
	}
	// Wrong state fails.
	if _, err := svc.Exchange(ctx, code, testRevocationVerifier, "http://127.0.0.1:18080/callback", "state-2"); !errors.Is(err, ErrCLIRevocationConflict) {
		t.Errorf("Exchange wrong state = %v, want ErrCLIRevocationConflict", err)
	}
	// Wrong redirect fails.
	if _, err := svc.Exchange(ctx, code, testRevocationVerifier, "http://127.0.0.1:18081/callback", "state-1"); !errors.Is(err, ErrCLIRevocationConflict) {
		t.Errorf("Exchange wrong redirect = %v, want ErrCLIRevocationConflict", err)
	}
	// Unknown code fails.
	if _, err := svc.Exchange(ctx, "nope", testRevocationVerifier, "http://127.0.0.1:18080/callback", "state-1"); !errors.Is(err, ErrCLIRevocationNotFound) {
		t.Errorf("Exchange unknown code = %v, want ErrCLIRevocationNotFound", err)
	}
}

func TestCLIRevocationMintBindingConflict(t *testing.T) {
	_, svc := newCLIRevocationFixture(t)
	ctx := context.Background()
	start, err := svc.Register(ctx, testRevocationRegisterRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// Minting with a different mission version means the revocation that
	// ran is not the one that was registered.
	mut := testRevocationDigestInput()
	mut.MissionVersion = 4
	if _, err := svc.MintResult(ctx, start.RequestID, mut, store.ContainmentAcknowledged); !errors.Is(err, ErrCLIRevocationConflict) {
		t.Errorf("MintResult changed version = %v, want ErrCLIRevocationConflict", err)
	}
}

func TestCLIRevocationRegisterRejectsNonRevocablePass(t *testing.T) {
	fx, svc := newCLIRevocationFixture(t)
	ctx := context.Background()
	if err := fx.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, "ws-test", fx.passID)
		if err != nil {
			return err
		}
		rec.State = string(PassFailed)
		return tx.PutMissionPass(ctx, rec, rec.StoreRevision)
	}); err != nil {
		t.Fatalf("seed failed pass: %v", err)
	}
	if _, err := svc.Register(ctx, testRevocationRegisterRequest()); !errors.Is(err, ErrPassNotRevocable) {
		t.Errorf("Register on failed pass = %v, want ErrPassNotRevocable", err)
	}
}

func TestCLIRevocationLookupRejectsForeignWorkspace(t *testing.T) {
	_, svc := newCLIRevocationFixture(t)
	ctx := context.Background()
	start, err := svc.Register(ctx, testRevocationRegisterRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := svc.Lookup(ctx, "ws-other", start.RequestID); !errors.Is(err, ErrCLIRevocationNotFound) {
		t.Errorf("Lookup with foreign workspace = %v, want ErrCLIRevocationNotFound", err)
	}
}

func TestRevocationFinishSessionMismatchFails(t *testing.T) {
	fx := newRevocationFixture(t)
	ctx := context.Background()
	begin, err := fx.svc.Begin(ctx, fx.principal, fx.passID, "founder_requested")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	other := fx.principal
	other.SessionID = "session-other"
	if _, err := fx.svc.Finish(ctx, other, fx.passID, begin.ChallengeID, []byte(`{"assertion":"ok"}`)); !errors.Is(err, ErrRevokeBindingChanged) {
		t.Errorf("Finish with other session = %v, want ErrRevokeBindingChanged", err)
	}
}
