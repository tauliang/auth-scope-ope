package launch_test

// Exchange tests: one approved authorization code plus verifier exchanges
// exactly once. A concurrent double submit and a retry after a lost
// response return only the original sealed result with exactly one
// upstream PrepareLaunch call. Changed content after consumption, an
// expired code, a missing in-memory attestation, an altered CLI public
// key, a stale mission version, changed digests, kit, arguments, source,
// base, or posture, an invalid or replayed decision attestation, an
// unsupported kit, and missing enforced isolation are all rejected. Only
// run metadata, the attestation digest, and the envelope digest reach
// durable storage; sealed envelope bytes never do.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/launch"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// testKeyStore builds a trust store pinning one root key, so the
// exchange service can check the sealed envelope's outer key ID.
func testKeyStore(t *testing.T, id string, pub ed25519.PublicKey) *trust.KeyStore {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	sum := sha256.Sum256(pub)
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": "sha256:" + hex.EncodeToString(sum[:]),
		"keys": []any{
			map[string]any{
				"key_id":     id,
				"algorithm":  "Ed25519",
				"public_key": base64.RawURLEncoding.EncodeToString(pub),
				"valid_from": now.Format(time.RFC3339),
				"root":       true,
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing-keys.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := trust.LoadSigningKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func testDigest(seed byte) string {
	sum := sha256.Sum256([]byte{seed})
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fakeAuthority is a strict fake AuthScope: it verifies the decision
// attestation like AuthScope would (signature, workspace, audience, exact
// digests, authentication context, nonce, freshness, replay) and requires
// a registered attestor identity.
type fakeAuthority struct {
	coreapi.Authority

	mu                     sync.Mutex
	workspace              string
	attestorPub            ed25519.PublicKey
	attestorIdentityDigest string
	expectedProposalDigest string
	expectedInvocDigest    string
	missionVersion         int64
	kits                   []coreapi.AgentKit
	isolationProfile       string
	runnerExecutable       string
	runnerArgs             []string
	signingPriv            ed25519.PrivateKey
	signingKeyID           string
	seenNonces             map[string]bool

	prepareCalls   int
	reconcileCalls int
	failPrepare    error // when set, PrepareLaunch records the work then returns this ambiguous error
	dropPrepare    bool  // when set, PrepareLaunch records nothing and returns an ambiguous error
	preparations   map[string]coreapi.LaunchArtifacts
}

func newFakeAuthority() *fakeAuthority {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &fakeAuthority{
		workspace:        "ws-test",
		seenNonces:       make(map[string]bool),
		preparations:     make(map[string]coreapi.LaunchArtifacts),
		isolationProfile: launch.IsolationEnforced,
		signingPriv:      priv,
		signingKeyID:     "fake-signing-1",
	}
}

func (f *fakeAuthority) verifyAttestation(att identity.SignedDecisionAttestation) error {
	c := att.Claims
	if c.WorkspaceID != f.workspace {
		return fmt.Errorf("fake: workspace %q", c.WorkspaceID)
	}
	if c.Audience != identity.AudiencePrepareLaunch {
		return fmt.Errorf("fake: audience %q", c.Audience)
	}
	if c.Purpose != identity.PurposeCLILaunchAuthorization {
		return fmt.Errorf("fake: purpose %q", c.Purpose)
	}
	if c.DecisionDigest != f.expectedProposalDigest {
		return fmt.Errorf("fake: decision digest mismatch")
	}
	if c.InvocationDigest != f.expectedInvocDigest {
		return fmt.Errorf("fake: invocation digest mismatch")
	}
	if c.AuthenticationMethod != identity.AuthMethodWebAuthnUV {
		return fmt.Errorf("fake: auth method %q", c.AuthenticationMethod)
	}
	var zero [32]byte
	if c.Nonce == zero {
		return fmt.Errorf("fake: zero nonce")
	}
	if time.Now().After(c.ExpiresAt) {
		return fmt.Errorf("fake: attestation expired")
	}
	nonceKey := hex.EncodeToString(c.Nonce[:])
	if f.seenNonces[nonceKey] {
		return fmt.Errorf("fake: attestation replay")
	}
	f.seenNonces[nonceKey] = true
	if att.IdentityDigest != f.attestorIdentityDigest {
		return fmt.Errorf("fake: unknown attestor identity")
	}
	canonical, err := identity.CanonicalClaimsJSON(c, att.KeyID, att.IdentityDigest)
	if err != nil {
		return fmt.Errorf("fake: canonical claims: %w", err)
	}
	msg := append(append([]byte(identity.AttestationDomain), 0x00), canonical...)
	if !ed25519.Verify(f.attestorPub, msg, att.Signature) {
		return fmt.Errorf("fake: bad attestation signature")
	}
	return nil
}

func (f *fakeAuthority) buildArtifacts(in coreapi.LaunchRequest, att identity.SignedDecisionAttestation, cliPub [32]byte) (coreapi.LaunchArtifacts, error) {
	kitVersion := ""
	for _, k := range f.kits {
		if k.KitID == in.KitID {
			kitVersion = k.Version
		}
	}
	if kitVersion == "" {
		return coreapi.LaunchArtifacts{}, fmt.Errorf("fake: unknown kit %q", in.KitID)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return coreapi.LaunchArtifacts{}, err
	}
	now := time.Now()
	payload := launch.LaunchPayload{
		Audience:         launch.EnvelopeAudience,
		RunID:            "run-" + hex.EncodeToString(nonce[:8]),
		MissionRef:       "mission-01",
		MissionVersion:   f.missionVersion,
		ProposalDigest:   att.Claims.DecisionDigest,
		InvocationDigest: f.expectedInvocDigest,
		RuntimePolicyID:  "rp-01",
		LeaseID:          "lease-01",
		AgentKitID:       in.KitID,
		AgentKitVersion:  kitVersion,
		RunnerExecutable: f.runnerExecutable,
		RunnerArguments:  append([]string{}, f.runnerArgs...),
		IsolationProfile: f.isolationProfile,
		Nonce:            base64.RawURLEncoding.EncodeToString(nonce[:]),
		IssuedAt:         now.Add(-time.Minute).Unix(),
		ExpiresAt:        now.Add(time.Hour).Unix(),
	}
	sealed, err := launch.SealEnvelope(payload, f.signingPriv, f.signingKeyID, cliPub)
	if err != nil {
		return coreapi.LaunchArtifacts{}, err
	}
	return coreapi.LaunchArtifacts{
		RunID:                   payload.RunID,
		MissionRef:              payload.MissionRef,
		AuthScopeMissionVersion: f.missionVersion,
		RuntimePolicyID:         payload.RuntimePolicyID,
		LeaseID:                 payload.LeaseID,
		AgentKitID:              in.KitID,
		AgentKitVersion:         kitVersion,
		InvocationDigest:        payload.InvocationDigest,
		RunnerExecutable:        f.runnerExecutable,
		RunnerArguments:         append([]string{}, f.runnerArgs...),
		IsolationProfile:        f.isolationProfile,
		EnvelopeKeyID:           f.signingKeyID,
		SealedSignedEnvelope:    sealed,
		ExpiresAt:               now.Add(time.Hour).Unix(),
	}, nil
}

func (f *fakeAuthority) PrepareLaunch(ctx context.Context, missionRef string, in coreapi.LaunchRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.LaunchArtifacts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepareCalls++
	if err := f.verifyAttestation(att); err != nil {
		return coreapi.LaunchArtifacts{}, &coreapi.UpstreamError{StatusCode: 403, Code: "attestation_denied", Message: err.Error()}
	}
	rawPub, err := base64.RawURLEncoding.DecodeString(in.EphemeralPublicKey)
	if err != nil || len(rawPub) != 32 {
		return coreapi.LaunchArtifacts{}, &coreapi.UpstreamError{StatusCode: 400, Code: "bad_ephemeral_key", Message: "bad ephemeral key"}
	}
	var cliPub [32]byte
	copy(cliPub[:], rawPub)
	if f.dropPrepare {
		return coreapi.LaunchArtifacts{}, context.DeadlineExceeded
	}
	art, err := f.buildArtifacts(in, att, cliPub)
	if err != nil {
		return coreapi.LaunchArtifacts{}, err
	}
	// The ambiguous window: the run is prepared upstream, but the
	// response never reaches OPE.
	f.preparations[in.IdempotencyKey] = art
	if f.failPrepare != nil {
		err := f.failPrepare
		f.failPrepare = nil
		return coreapi.LaunchArtifacts{}, err
	}
	return art, nil
}

func (f *fakeAuthority) ReconcileOperation(ctx context.Context, idempotencyKey, operationID string, opts coreapi.RequestOptions) (coreapi.OperationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconcileCalls++
	art, ok := f.preparations[idempotencyKey]
	status := "not_found"
	var artPtr *coreapi.LaunchArtifacts
	if ok {
		status = "completed"
		cpy := art
		artPtr = &cpy
	}
	return coreapi.OperationResult{
		OperationID:    "op-" + idempotencyKey,
		IdempotencyKey: idempotencyKey,
		Status:         status,
		WorkspaceID:    f.workspace,
		Artifacts:      artPtr,
	}, nil
}

func (f *fakeAuthority) IntrospectMission(ctx context.Context, missionRef string, opts coreapi.RequestOptions) (coreapi.MissionStatus, error) {
	return coreapi.MissionStatus{MissionRef: missionRef, State: "active", Version: f.missionVersion, WorkspaceID: f.workspace}, nil
}

func (f *fakeAuthority) ListAgentKits(ctx context.Context, opts coreapi.RequestOptions) ([]coreapi.AgentKit, error) {
	return append([]coreapi.AgentKit{}, f.kits...), nil
}

// fixture wires a complete approved launch handoff: store, pass, approved
// CLI authorization, cached attestation, fake AuthScope, and the service.
type fixture struct {
	t                *testing.T
	ctx              context.Context
	dir              string
	store            store.Store
	svc              *launch.Service
	auth             *fakeAuthority
	cache            *authn.PendingDecisionAttestations
	workspace        string
	passID           string
	authzID          string
	code             string
	codeHashHex      string
	verifier         string
	proposalDigest   string
	invocationDigest string
	kitID            string
	kitVersion       string
	runnerArgs       []string
	runnerExe        string
	missionRef       string
	missionVersion   int64
	signer           *identity.EphemeralSigner
	attestation      identity.SignedDecisionAttestation
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	workspace := "ws-test"
	dir := t.TempDir()
	st, err := store.Open(dir, "development")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.BindInstance(ctx, store.InstanceRecord{
			InstanceID:        "inst-test",
			WorkspaceID:       workspace,
			Hostname:          "example.test",
			Origin:            "https://example.test",
			RPID:              "example.test",
			SessionCookieName: store.DeriveSessionCookieName("inst-test"),
			CreatedAt:         time.Now().UTC(),
		})
	}); err != nil {
		t.Fatal(err)
	}
	webVerifier, err := authn.NewWebAuthnVerifier("example.test", "https://example.test")
	if err != nil {
		t.Fatal(err)
	}
	authnSvc, err := authn.NewService(ctx, st, webVerifier)
	if err != nil {
		t.Fatal(err)
	}
	signer := identity.NewEphemeralSigner()
	attestor := identity.NewDecisionAttestor(signer)
	cliAuth, err := authn.NewCLIAuthorizationService(authn.CLIAuthorizationConfig{
		Store:          st,
		Authn:          authnSvc,
		Attestor:       attestor,
		BrowserBaseURL: "https://example.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	fx := &fixture{
		t: t, ctx: ctx, dir: dir, store: st, workspace: workspace,
		passID:         "pass-01",
		proposalDigest: testDigest(1),
		kitID:          "kit-a",
		kitVersion:     "1.0.0",
		runnerArgs:     []string{"--flag", "x"},
		runnerExe:      "/opt/runners/authscope-agent-run",
		missionRef:     "mission-01",
		missionVersion: 3,
		signer:         signer,
	}
	fx.invocationDigest = authn.InvocationDigestForLaunch(fx.kitID, fx.kitVersion, fx.runnerArgs)

	now := time.Now().UTC()
	pass := store.MissionPassRecord{
		WorkspaceID:             workspace,
		PassID:                  fx.passID,
		DraftVersion:            1,
		AuthScopeMissionVersion: fx.missionVersion,
		ConnectionID:            "conn-1",
		IssueNumber:             42,
		RepositoryName:          "owner/repo",
		ProposalID:              "prop-1",
		ProposalDigest:          fx.proposalDigest,
		ApprovedProposalDigest:  fx.proposalDigest,
		SourceRevision:          "rev-1",
		SourceDigest:            testDigest(2),
		BaseSHA:                 "abc123def456",
		MissionBranch:           "mission/pass-01",
		AgentKitID:              fx.kitID,
		AgentKitVersion:         fx.kitVersion,
		RunnerArguments:         append([]string{}, fx.runnerArgs...),
		InvocationDigest:        fx.invocationDigest,
		ExpiresAt:               now.Add(24 * time.Hour),
		Objective:               "objective",
		ShapedDraftJSON:         "{}",
		State:                   "approved",
		Reconciliation:          "settled",
		MissionRef:              fx.missionRef,
		MissionHash:             testDigest(3),
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, pass, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutWorkflowPosture(ctx, store.WorkflowPostureRecord{
			WorkspaceID:   workspace,
			ConnectionID:  "conn-1",
			Ref:           "ref-1",
			PostureDigest: testDigest(4),
			HeadSHA:       "abc123def456",
			Outcome:       "clean",
			ExpiresAt:     now.Add(time.Hour),
			CheckedAt:     now,
		})
	}); err != nil {
		t.Fatal(err)
	}

	state, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	verifierStr, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := authn.EphemeralX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	start, _, err := cliAuth.Create(ctx, authn.CLIAuthorizationRequest{
		PassID:              fx.passID,
		RedirectURI:         "http://127.0.0.1:45531/callback",
		State:               state,
		CodeChallenge:       authn.CodeChallengeS256(verifierStr),
		CodeChallengeMethod: "S256",
		EphemeralPublicKey:  base64.RawURLEncoding.EncodeToString(pub[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.authzID = start.ID
	fx.verifier = verifierStr

	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	proofSum := sha256.Sum256([]byte("ceremony-proof"))
	att, err := attestor.Attest(ctx, identity.DecisionClaims{
		WorkspaceID:               workspace,
		FounderID:                 "founder-1",
		Audience:                  identity.AudiencePrepareLaunch,
		Purpose:                   identity.PurposeCLILaunchAuthorization,
		SubjectID:                 start.ID,
		DecisionDigest:            fx.proposalDigest,
		InvocationDigest:          fx.invocationDigest,
		AuthenticationMethod:      identity.AuthMethodWebAuthnUV,
		AuthenticationProofDigest: "sha256:" + hex.EncodeToString(proofSum[:]),
		Nonce:                     nonce,
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.attestation = att
	attRaw, err := json.Marshal(att)
	if err != nil {
		t.Fatal(err)
	}
	attSum := sha256.Sum256(attRaw)
	attDigest := "sha256:" + hex.EncodeToString(attSum[:])
	codeRaw := make([]byte, 32)
	if _, err := rand.Read(codeRaw); err != nil {
		t.Fatal(err)
	}
	codeHash := sha256.Sum256(codeRaw)
	fx.code = base64.RawURLEncoding.EncodeToString(codeRaw)
	fx.codeHashHex = hex.EncodeToString(codeHash[:])
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.ApproveCLIAuthorization(ctx, workspace, start.ID, "challenge-test", attDigest, codeHash, now)
	}); err != nil {
		t.Fatal(err)
	}
	fx.cache = cliAuth.Attestations()
	fx.cache.Put(&authn.PendingDecisionAttestation{
		AuthorizationID:   start.ID,
		Attestation:       att,
		AttestationDigest: attDigest,
		CodeHash:          codeHash,
		ExpiresAt:         now.Add(2 * time.Minute),
	})

	fx.auth = newFakeAuthority()
	fx.auth.attestorPub = signer.PublicKey()
	fx.auth.attestorIdentityDigest = signer.IdentityDigest()
	fx.auth.expectedProposalDigest = fx.proposalDigest
	fx.auth.expectedInvocDigest = fx.invocationDigest
	fx.auth.missionVersion = fx.missionVersion
	fx.auth.kits = []coreapi.AgentKit{{KitID: fx.kitID, Name: "Kit A", Version: fx.kitVersion}}
	fx.auth.runnerExecutable = fx.runnerExe
	fx.auth.runnerArgs = append([]string{}, fx.runnerArgs...)

	svc, err := launch.NewService(launch.Config{
		Store:        st,
		WorkspaceID:  workspace,
		Authority:    fx.auth,
		Attestations: fx.cache,
		Keys:         testKeyStore(t, fx.auth.signingKeyID, fx.auth.signingPriv.Public().(ed25519.PublicKey)),
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.svc = svc
	return fx
}

func (fx *fixture) exchange() (launch.ExchangeResult, error) {
	return fx.svc.ExchangeAndPrepare(fx.ctx, launch.ExchangeRequest{Code: fx.code, Verifier: fx.verifier})
}

func (fx *fixture) reloadPass() store.MissionPassRecord {
	fx.t.Helper()
	rec, err := fx.store.GetMissionPass(fx.ctx, fx.workspace, fx.passID)
	if err != nil {
		fx.t.Fatal(err)
	}
	return rec
}

// openRawDB opens a second handle on the fixture database file for
// tamper-evidence checks.
func (fx *fixture) openRawDB() *sql.DB {
	fx.t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(fx.dir, "ope.db"))
	if err != nil {
		fx.t.Fatal(err)
	}
	fx.t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestExchangeAndPrepareSuccess(t *testing.T) {
	fx := newFixture(t)
	before := fx.reloadPass()

	res, err := fx.exchange()
	if err != nil {
		t.Fatalf("ExchangeAndPrepare: %v", err)
	}
	if res.RunID == "" {
		t.Fatal("empty run id")
	}
	if res.MissionRef != fx.missionRef {
		t.Fatalf("mission ref = %q", res.MissionRef)
	}
	if len(res.SealedEnvelope) == 0 {
		t.Fatal("empty sealed envelope")
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1", fx.auth.prepareCalls)
	}
	after := fx.reloadPass()
	if after.State != "launching" {
		t.Fatalf("pass state = %q, want launching", after.State)
	}
	if after.RunID != res.RunID {
		t.Fatalf("pass run id = %q, want %q", after.RunID, res.RunID)
	}
	if after.AuthScopeMissionVersion != fx.missionVersion {
		t.Fatalf("mission version = %d", after.AuthScopeMissionVersion)
	}
	if after.DraftVersion != before.DraftVersion {
		t.Fatalf("draft version changed: %d -> %d", before.DraftVersion, after.DraftVersion)
	}
	if after.StoreRevision != before.StoreRevision+1 {
		t.Fatalf("store revision = %d, want %d", after.StoreRevision, before.StoreRevision+1)
	}
}

func TestExchangeConcurrentDoubleSubmit(t *testing.T) {
	fx := newFixture(t)
	const n = 8
	results := make([]launch.ExchangeResult, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = fx.exchange()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if results[i].RunID != results[0].RunID {
			t.Fatalf("exchange %d run id %q != %q", i, results[i].RunID, results[0].RunID)
		}
		if !bytes.Equal(results[i].SealedEnvelope, results[0].SealedEnvelope) {
			t.Fatalf("exchange %d sealed envelope differs", i)
		}
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want exactly 1", fx.auth.prepareCalls)
	}
}

func TestExchangeRetryAfterLostResponse(t *testing.T) {
	fx := newFixture(t)
	first, err := fx.exchange()
	if err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	second, err := fx.exchange()
	if err != nil {
		t.Fatalf("retry exchange: %v", err)
	}
	if second.RunID != first.RunID {
		t.Fatalf("retry run id %q != %q", second.RunID, first.RunID)
	}
	if !bytes.Equal(second.SealedEnvelope, first.SealedEnvelope) {
		t.Fatal("retry returned different sealed bytes")
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1", fx.auth.prepareCalls)
	}
}

func TestExchangeChangedContentRejected(t *testing.T) {
	fx := newFixture(t)
	if _, err := fx.exchange(); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	otherVerifier, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	// Same code, different verifier: the canonical exchange moved.
	_, err = fx.svc.ExchangeAndPrepare(fx.ctx, launch.ExchangeRequest{Code: fx.code, Verifier: otherVerifier})
	if !errors.Is(err, launch.ErrExchangeConflict) {
		t.Fatalf("changed verifier: err = %v, want ErrExchangeConflict", err)
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1", fx.auth.prepareCalls)
	}
	// Unknown code.
	unknown, err := authn.NewPKCEVerifier()
	if err != nil {
		t.Fatal(err)
	}
	_, err = fx.svc.ExchangeAndPrepare(fx.ctx, launch.ExchangeRequest{Code: unknown, Verifier: fx.verifier})
	if !errors.Is(err, launch.ErrExchangeNotFound) {
		t.Fatalf("unknown code: err = %v, want ErrExchangeNotFound", err)
	}
}

func TestExchangeExpiredCode(t *testing.T) {
	fx := newFixture(t)
	svc, err := launch.NewService(launch.Config{
		Store:        fx.store,
		WorkspaceID:  fx.workspace,
		Authority:    fx.auth,
		Attestations: fx.cache,
		Keys:         testKeyStore(t, fx.auth.signingKeyID, fx.auth.signingPriv.Public().(ed25519.PublicKey)),
		Clock:        func() time.Time { return time.Now().Add(2 * time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	fx.svc = svc
	_, err = fx.exchange()
	if !errors.Is(err, launch.ErrCodeExpired) {
		t.Fatalf("err = %v, want ErrCodeExpired", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func TestExchangeMissingAttestation(t *testing.T) {
	fx := newFixture(t)
	// Simulate a process restart after approval but before any upstream
	// request: the in-memory attestation is gone.
	if _, ok := fx.cache.Take(fx.authzID); !ok {
		t.Fatal("expected cached attestation")
	}
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrAttestationMissing) {
		t.Fatalf("err = %v, want ErrAttestationMissing", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func TestExchangeAlteredEphemeralKey(t *testing.T) {
	fx := newFixture(t)
	// Tamper with the stored authorization record: the canonical digest
	// pinned at create time must catch it.
	otherPub := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	db := fx.openRawDB()
	if _, err := db.Exec(`UPDATE cli_authorizations SET ephemeral_public_key = ? WHERE workspace_id = ? AND authorization_id = ?`,
		otherPub, fx.workspace, fx.authzID); err != nil {
		t.Fatal(err)
	}
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrBindingChanged) {
		t.Fatalf("err = %v, want ErrBindingChanged", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func TestExchangeStaleMissionVersion(t *testing.T) {
	fx := newFixture(t)
	fx.auth.missionVersion = fx.missionVersion + 1
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrStaleMissionVersion) {
		t.Fatalf("err = %v, want ErrStaleMissionVersion", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func TestExchangeChangedProposalDigest(t *testing.T) {
	fx := newFixture(t)
	mutatePass(t, fx, func(r *store.MissionPassRecord) {
		r.ProposalDigest = testDigest(9)
		r.ApprovedProposalDigest = testDigest(9)
	})
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrBindingChanged) {
		t.Fatalf("err = %v, want ErrBindingChanged", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func TestExchangeChangedRunnerArgs(t *testing.T) {
	fx := newFixture(t)
	mutatePass(t, fx, func(r *store.MissionPassRecord) {
		r.RunnerArguments = []string{"x", "--flag"}
	})
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrBindingChanged) {
		t.Fatalf("err = %v, want ErrBindingChanged", err)
	}
}

func TestExchangeChangedKit(t *testing.T) {
	fx := newFixture(t)
	mutatePass(t, fx, func(r *store.MissionPassRecord) {
		r.AgentKitVersion = "2.0.0"
	})
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrBindingChanged) {
		t.Fatalf("err = %v, want ErrBindingChanged", err)
	}
}

func TestExchangeChangedBaseSHA(t *testing.T) {
	fx := newFixture(t)
	mutatePass(t, fx, func(r *store.MissionPassRecord) {
		r.BaseSHA = "deadbeefdeadbeef"
	})
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrBindingChanged) {
		t.Fatalf("err = %v, want ErrBindingChanged", err)
	}
}

func TestExchangeRiskyPosture(t *testing.T) {
	fx := newFixture(t)
	now := time.Now().UTC()
	if err := fx.store.WithTx(fx.ctx, func(tx store.Tx) error {
		return tx.PutWorkflowPosture(fx.ctx, store.WorkflowPostureRecord{
			WorkspaceID:   fx.workspace,
			ConnectionID:  "conn-1",
			Ref:           "ref-1",
			PostureDigest: testDigest(5),
			HeadSHA:       "abc123def456",
			Outcome:       "risky",
			ExpiresAt:     now.Add(time.Hour),
			CheckedAt:     now,
		})
	}); err != nil {
		t.Fatal(err)
	}
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrBindingChanged) {
		t.Fatalf("err = %v, want ErrBindingChanged", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func mutatePass(t *testing.T, fx *fixture, mutate func(*store.MissionPassRecord)) {
	t.Helper()
	rec := fx.reloadPass()
	mutate(&rec)
	if err := fx.store.WithTx(fx.ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(fx.ctx, rec, rec.StoreRevision)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeUnsupportedKit(t *testing.T) {
	fx := newFixture(t)
	fx.auth.kits = []coreapi.AgentKit{{KitID: "other-kit", Name: "Other", Version: "9.9.9"}}
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrUnsupportedKit) {
		t.Fatalf("err = %v, want ErrUnsupportedKit", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func TestExchangeIsolationNotEnforced(t *testing.T) {
	fx := newFixture(t)
	fx.auth.isolationProfile = "observed"
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrIsolationNotEnforced) {
		t.Fatalf("err = %v, want ErrIsolationNotEnforced", err)
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1", fx.auth.prepareCalls)
	}
	// A failed launch preparation returns the pass to approved.
	if got := fx.reloadPass().State; got != "approved" {
		t.Fatalf("pass state = %q, want approved", got)
	}
}

func TestExchangeRejectsUntrustedEnvelopeKey(t *testing.T) {
	fx := newFixture(t)
	// The authority seals under a key the service trust store does not
	// pin: adoption must fail before the pass moves to launching.
	fx.auth.signingKeyID = "rogue-key"
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrBindingChanged) {
		t.Fatalf("err = %v, want ErrBindingChanged", err)
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1", fx.auth.prepareCalls)
	}
	if got := fx.reloadPass().State; got != "approved" {
		t.Fatalf("pass state = %q, want approved", got)
	}
}

func TestExchangeInvalidAttestation(t *testing.T) {
	fx := newFixture(t)
	// Replace the cached attestation with one bound to a different
	// proposal digest: the fake AuthScope must deny it with a definite
	// upstream denial, and PrepareLaunch must not be retried.
	if _, ok := fx.cache.Take(fx.authzID); !ok {
		t.Fatal("expected cached attestation")
	}
	now := time.Now().UTC()
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	proofSum := sha256.Sum256([]byte("other-proof"))
	bad, err := identity.NewDecisionAttestor(fx.signer).Attest(fx.ctx, identity.DecisionClaims{
		WorkspaceID:               fx.workspace,
		FounderID:                 "founder-1",
		Audience:                  identity.AudiencePrepareLaunch,
		Purpose:                   identity.PurposeCLILaunchAuthorization,
		SubjectID:                 fx.authzID,
		DecisionDigest:            testDigest(8),
		InvocationDigest:          fx.invocationDigest,
		AuthenticationMethod:      identity.AuthMethodWebAuthnUV,
		AuthenticationProofDigest: "sha256:" + hex.EncodeToString(proofSum[:]),
		Nonce:                     nonce,
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(bad)
	sum := sha256.Sum256(raw)
	badDigest := "sha256:" + hex.EncodeToString(sum[:])
	codeRaw, err := base64.RawURLEncoding.DecodeString(fx.code)
	if err != nil {
		t.Fatal(err)
	}
	codeHash := sha256.Sum256(codeRaw)
	// The browser ceremony authorized this attestation: pin its digest on
	// the authorization record so the exchange reaches the upstream,
	// which must deny it on its own semantic checks.
	db := fx.openRawDB()
	defer db.Close()
	if _, err := db.Exec(`UPDATE cli_authorizations SET decision_attestation_digest = ? WHERE workspace_id = ? AND authorization_id = ?`,
		badDigest, fx.workspace, fx.authzID); err != nil {
		t.Fatal(err)
	}
	fx.cache.Put(&authn.PendingDecisionAttestation{
		AuthorizationID:   fx.authzID,
		Attestation:       bad,
		AttestationDigest: badDigest,
		CodeHash:          codeHash,
		ExpiresAt:         now.Add(2 * time.Minute),
	})
	_, err = fx.exchange()
	if err == nil {
		t.Fatal("expected error for invalid attestation")
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1", fx.auth.prepareCalls)
	}
	if fx.auth.reconcileCalls != 0 {
		t.Fatalf("ReconcileOperation calls = %d, want 0 for a definite denial", fx.auth.reconcileCalls)
	}
}

func TestFakeAuthorityRejectsReplayedAttestation(t *testing.T) {
	fx := newFixture(t)
	in := coreapi.LaunchRequest{
		KitID:              fx.kitID,
		IdempotencyKey:     "idem-1",
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)),
	}
	if _, err := fx.auth.PrepareLaunch(fx.ctx, fx.missionRef, in, fx.attestation, coreapi.RequestOptions{WorkspaceID: fx.workspace}); err != nil {
		t.Fatalf("first PrepareLaunch: %v", err)
	}
	in.IdempotencyKey = "idem-2"
	if _, err := fx.auth.PrepareLaunch(fx.ctx, fx.missionRef, in, fx.attestation, coreapi.RequestOptions{WorkspaceID: fx.workspace}); err == nil {
		t.Fatal("expected replayed attestation to be denied")
	}
}

func TestExchangeAmbiguousUpstreamReconciles(t *testing.T) {
	fx := newFixture(t)
	fx.auth.failPrepare = context.DeadlineExceeded
	res, err := fx.exchange()
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if res.RunID == "" {
		t.Fatal("empty run id after reconcile")
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1 (never repeated)", fx.auth.prepareCalls)
	}
	if fx.auth.reconcileCalls != 1 {
		t.Fatalf("ReconcileOperation calls = %d, want 1", fx.auth.reconcileCalls)
	}
	if got := fx.reloadPass().State; got != "launching" {
		t.Fatalf("pass state = %q, want launching", got)
	}
}

func TestExchangeAmbiguousUpstreamUnknown(t *testing.T) {
	fx := newFixture(t)
	fx.auth.dropPrepare = true
	_, err := fx.exchange()
	if err == nil {
		t.Fatal("expected error when reconcile finds no operation")
	}
	if fx.auth.prepareCalls != 1 {
		t.Fatalf("PrepareLaunch calls = %d, want 1", fx.auth.prepareCalls)
	}
	if got := fx.reloadPass().State; got != "approved" {
		t.Fatalf("pass state = %q, want approved", got)
	}
}

func TestExchangeStaleReservationRequiresNewAuth(t *testing.T) {
	fx := newFixture(t)
	// Claim the reservation outside the service, as if a previous owner
	// died without settling, then age it.
	if err := fx.store.WithTx(fx.ctx, func(tx store.Tx) error {
		claimed, err := tx.ClaimLaunchExchangeIntent(fx.ctx, store.LaunchExchangeIntent{
			WorkspaceID:       fx.workspace,
			CodeHash:          fx.codeHashHex,
			AuthorizationID:   fx.authzID,
			PassID:            fx.passID,
			AttestationDigest: "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{5}, 32)),
		}, time.Now())
		if err != nil {
			return err
		}
		if !claimed {
			t.Fatal("expected to claim the reservation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	db := fx.openRawDB()
	aged := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := db.Exec(`UPDATE launch_exchange_intents SET updated_at = ? WHERE workspace_id = ? AND code_hash = ?`,
		aged, fx.workspace, fx.codeHashHex); err != nil {
		t.Fatal(err)
	}
	_, err := fx.exchange()
	if !errors.Is(err, launch.ErrExchangeStale) {
		t.Fatalf("err = %v, want ErrExchangeStale", err)
	}
	if fx.auth.prepareCalls != 0 {
		t.Fatalf("PrepareLaunch calls = %d, want 0", fx.auth.prepareCalls)
	}
}

func TestExchangePersistsOnlyDigests(t *testing.T) {
	fx := newFixture(t)
	res, err := fx.exchange()
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	// Read the raw database file: sealed envelope bytes and attestation
	// signature bytes must not appear anywhere.
	dbBytes, err := os.ReadFile(filepath.Join(fx.dir, "ope.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(dbBytes, res.SealedEnvelope) {
		t.Fatal("sealed envelope bytes found in durable storage")
	}
	attRaw, err := json.Marshal(fx.attestation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(dbBytes, attRaw) {
		t.Fatal("attestation bytes found in durable storage")
	}
	// The intent row carries only digests and metadata.
	db := fx.openRawDB()
	var status, attestationDigest, envelopeDigest, failure string
	err = db.QueryRow(`SELECT status, attestation_digest, envelope_digest, error FROM launch_exchange_intents WHERE workspace_id = ? AND code_hash = ?`,
		fx.workspace, fx.codeHashHex).Scan(&status, &attestationDigest, &envelopeDigest, &failure)
	if err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("intent status = %q", status)
	}
	if attestationDigest == "" || envelopeDigest == "" {
		t.Fatal("expected attestation and envelope digests")
	}
	sum := sha256.Sum256(res.SealedEnvelope)
	if want := "sha256:" + hex.EncodeToString(sum[:]); envelopeDigest != want {
		t.Fatalf("envelope digest = %q, want %q", envelopeDigest, want)
	}
	if failure != "" {
		t.Fatalf("unexpected failure: %q", failure)
	}
}

func TestNewServiceRejectsBadConfig(t *testing.T) {
	if _, err := launch.NewService(launch.Config{}); err == nil {
		t.Fatal("expected error for empty config")
	}
}
