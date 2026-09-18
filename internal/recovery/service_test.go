package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeAuthority scripts upstream behavior per test. All methods not
// relevant to recovery return inert zero values.
type fakeAuthority struct {
	mu sync.Mutex

	identity    coreapi.WorkspaceIdentity
	identityErr error

	containCalls int
	containOut   coreapi.WorkspaceContainment
	containErrs  []error // one per call; nil means success
	seenIdemKeys []string
	seenAttests  []identity.SignedDecisionAttestation

	activeMissions [][]coreapi.ActiveMission
	activeErrs     []error
	activeCalls    int
}

var _ coreapi.Authority = (*fakeAuthority)(nil)

func (f *fakeAuthority) VerifyWorkspaceIdentity(ctx context.Context, workspaceID string) (coreapi.WorkspaceIdentity, error) {
	if f.identityErr != nil {
		return coreapi.WorkspaceIdentity{}, f.identityErr
	}
	out := f.identity
	out.WorkspaceID = workspaceID
	return out, nil
}

func (f *fakeAuthority) ContainWorkspace(ctx context.Context, req coreapi.WorkspaceContainmentRequest, attestation identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.WorkspaceContainment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := f.containCalls
	f.containCalls++
	f.seenIdemKeys = append(f.seenIdemKeys, req.IdempotencyKey)
	f.seenAttests = append(f.seenAttests, attestation)
	var err error
	if call < len(f.containErrs) {
		err = f.containErrs[call]
	}
	if err != nil {
		return coreapi.WorkspaceContainment{}, err
	}
	out := f.containOut
	if out.WorkspaceID == "" {
		out.WorkspaceID = opts.WorkspaceID
	}
	return out, nil
}

func (f *fakeAuthority) ListActiveMissions(ctx context.Context, opts coreapi.RequestOptions) ([]coreapi.ActiveMission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	call := f.activeCalls
	f.activeCalls++
	if call < len(f.activeErrs) && f.activeErrs[call] != nil {
		return nil, f.activeErrs[call]
	}
	if len(f.activeMissions) == 0 {
		return nil, nil
	}
	// Exhausted scripts repeat the last response instead of going
	// empty: tests that need a persistently nonempty list script it
	// once and it stays nonempty.
	if call >= len(f.activeMissions) {
		return f.activeMissions[len(f.activeMissions)-1], nil
	}
	return f.activeMissions[call], nil
}

// inert Authority methods
func (f *fakeAuthority) Discover(ctx context.Context) (coreapi.Discovery, error) {
	return coreapi.Discovery{}, nil
}
func (f *fakeAuthority) BeginGitHubBinding(ctx context.Context, in coreapi.GitHubBindingBeginRequest, opts coreapi.RequestOptions) (coreapi.GitHubBindingHandoff, error) {
	return coreapi.GitHubBindingHandoff{}, nil
}
func (f *fakeAuthority) FinishGitHubBinding(ctx context.Context, in coreapi.GitHubBindingFinishRequest, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return coreapi.RepositoryBinding{}, nil
}
func (f *fakeAuthority) GetRepositoryBinding(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return coreapi.RepositoryBinding{}, nil
}
func (f *fakeAuthority) ReadGitHubIssue(ctx context.Context, in coreapi.GitHubIssueRequest, opts coreapi.RequestOptions) (coreapi.GitHubIssueSnapshot, error) {
	return coreapi.GitHubIssueSnapshot{}, nil
}
func (f *fakeAuthority) InspectWorkflowPosture(ctx context.Context, in coreapi.WorkflowPostureRequest, opts coreapi.RequestOptions) (coreapi.WorkflowPosture, error) {
	return coreapi.WorkflowPosture{}, nil
}
func (f *fakeAuthority) ListAgentKits(ctx context.Context, opts coreapi.RequestOptions) ([]coreapi.AgentKit, error) {
	return nil, nil
}
func (f *fakeAuthority) ShapeMission(ctx context.Context, in coreapi.ShapeMissionRequest, opts coreapi.RequestOptions) (coreapi.MissionDraft, error) {
	return coreapi.MissionDraft{}, nil
}
func (f *fakeAuthority) CreateProposal(ctx context.Context, in coreapi.CreateProposalRequest, opts coreapi.RequestOptions) (coreapi.Proposal, error) {
	return coreapi.Proposal{}, nil
}
func (f *fakeAuthority) ApproveProposal(ctx context.Context, s string, in coreapi.ApproveProposalInput, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Mission, error) {
	return coreapi.Mission{}, nil
}
func (f *fakeAuthority) PrepareLaunch(ctx context.Context, s string, in coreapi.LaunchRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.LaunchArtifacts, error) {
	return coreapi.LaunchArtifacts{}, nil
}
func (f *fakeAuthority) IntrospectMission(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.MissionStatus, error) {
	return coreapi.MissionStatus{}, nil
}
func (f *fakeAuthority) RevokeMission(ctx context.Context, s string, in coreapi.RevokeRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Revocation, error) {
	return coreapi.Revocation{}, nil
}
func (f *fakeAuthority) ListExpansions(ctx context.Context, s string, opts coreapi.RequestOptions) ([]coreapi.Expansion, error) {
	return nil, nil
}
func (f *fakeAuthority) GetExpansion(ctx context.Context, s string, opts coreapi.RequestOptions) (json.RawMessage, error) {
	return nil, nil
}
func (f *fakeAuthority) DecideExpansion(ctx context.Context, s string, in coreapi.ExpansionDecision, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.ExpansionResult, error) {
	return coreapi.ExpansionResult{}, nil
}
func (f *fakeAuthority) ReadEvents(ctx context.Context, s1, s2 string, opts coreapi.RequestOptions) (coreapi.EventPage, error) {
	return coreapi.EventPage{}, nil
}
func (f *fakeAuthority) GetReceipt(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.SignedReceiptEnvelope, error) {
	return coreapi.SignedReceiptEnvelope{}, nil
}
func (f *fakeAuthority) GetSigningKeys(ctx context.Context, opts coreapi.RequestOptions) (coreapi.SigningKeyHistory, error) {
	return coreapi.SigningKeyHistory{}, nil
}
func (f *fakeAuthority) PublishGitHubCheck(ctx context.Context, in coreapi.GitHubCheckRequest, opts coreapi.RequestOptions) (coreapi.GitHubCheckResult, error) {
	return coreapi.GitHubCheckResult{}, nil
}
func (f *fakeAuthority) ReconcileOperation(ctx context.Context, s1, s2 string, opts coreapi.RequestOptions) (coreapi.OperationResult, error) {
	return coreapi.OperationResult{}, nil
}

// testClock is a manual clock. Each Now call advances it by step,
// so polling loops observe time passing while timestamps stay
// deterministic.
type testClock struct {
	mu   sync.Mutex
	now  time.Time
	step time.Duration
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now
	c.now = c.now.Add(c.step)
	return t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// counterReader is deterministic rand for tests: every read differs,
// so nonces never repeat. NOT for production.
type counterReader struct {
	mu sync.Mutex
	n  uint64
}

func (r *counterReader) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	for i := range p {
		p[i] = byte(r.n + uint64(i))
	}
	return len(p), nil
}

// fixture builds a bound instance with an enrolled founder, a session,
// a CLI authorization, a passkey credential, and an offline recovery key.
type fixture struct {
	st          store.Store
	attestor    *identity.DecisionAttestor
	ws          string
	founder     string
	recKey      []byte
	sessionHash string
	inst        store.InstanceRecord
	identity    coreapi.WorkspaceIdentity
}

func setupFixture(t *testing.T, ctx context.Context) *fixture {
	t.Helper()
	ws := "ws-test-1"
	founder := "founder-1"
	sessionHash := hex.EncodeToString(sha256.New().Sum([]byte("session-token")))

	dir := t.TempDir()
	st, err := store.OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Build a workload signer and attach its digest to the instance
	// record, mimicking what bindInstance does on first boot.
	signer := identity.NewEphemeralSigner()
	attestor := identity.NewDecisionAttestor(signer)
	digest := signer.IdentityDigest()
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.BindInstance(ctx, store.InstanceRecord{
			InstanceID:        "inst-1",
			WorkspaceID:       ws,
			Hostname:          "host-1",
			Origin:            "https://host-1:8443",
			RPID:              "host-1",
			SessionCookieName: store.DeriveSessionCookieName("inst-1"),
			CreatedAt:         time.Now().UTC(),
		}); err != nil {
			return err
		}
		// The compatibility gate attaches the workload-identity digest
		// exactly once after the binding.
		return tx.AttachWorkloadIdentity(ctx, "", digest)
	}); err != nil {
		t.Fatalf("bind instance: %v", err)
	}
	inst, err := st.GetInstance(ctx)
	if err != nil {
		t.Fatalf("get instance: %v", err)
	}

	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.CreateFounder(ctx, store.FounderRecord{
			WorkspaceID: ws,
			FounderID:   founder,
			DisplayName: "Founder",
			CreatedAt:   time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("create founder: %v", err)
	}

	// Recovery key: raw bytes plus its stored sha256 hex.
	recKey := []byte("test-offline-recovery-key-32bytes!!")
	sum := sha256.Sum256(recKey)
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutOfflineRecoveryKey(ctx, store.OfflineRecoveryKeyRecord{
			WorkspaceID: ws,
			FounderID:   founder,
			KeyHash:     hex.EncodeToString(sum[:]),
			CreatedAt:   time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("put recovery key: %v", err)
	}

	// One web session to be revoked.
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.CreateSession(ctx, store.SessionRecord{
			WorkspaceID:   ws,
			SessionID:     "sess-1",
			SessionHash:   sessionHash,
			FounderID:     founder,
			CSRFTokenHash: "csrf",
			CreatedAt:     time.Now().UTC(),
			ExpiresAt:     time.Now().UTC().Add(time.Hour),
		})
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// One CLI authorization to be invalidated.
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutCLIAuthorization(ctx, store.CLIAuthorization{
			WorkspaceID:        ws,
			AuthorizationID:    "authz-1",
			PassID:             "pass-1",
			State:              "state-1",
			CodeChallenge:      "challenge",
			RedirectURI:        "http://127.0.0.1:9/cb",
			EphemeralPublicKey: "epub",
			ProposalDigest:     "pd",
			InvocationDigest:   "id",
			AgentKitID:         "kit",
			AgentKitVersion:    "1",
			MissionRef:         "m1",
			MissionVersion:     1,
			CreatedAt:          time.Now().UTC(),
			ExpiresAt:          time.Now().UTC().Add(time.Hour),
		})
	}); err != nil {
		t.Fatalf("put CLI authorization: %v", err)
	}

	// One passkey credential to be deleted.
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutWebAuthnCredential(ctx, store.WebAuthnCredentialRecord{
			WorkspaceID:  ws,
			CredentialID: "cred-1",
			FounderID:    founder,
			PublicKey:    []byte("public-key"),
			CreatedAt:    time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("put webauthn credential: %v", err)
	}

	return &fixture{
		st:          st,
		attestor:    attestor,
		ws:          ws,
		founder:     founder,
		recKey:      recKey,
		sessionHash: sessionHash,
		inst:        inst,
		identity: coreapi.WorkspaceIdentity{
			WorkspaceID:    ws,
			IdentityDigest: digest,
			Roles:          []string{coreapi.DecisionAttestorRole},
		},
	}
}

func newTestService(fx *fixture, fa *fakeAuthority, clock *testClock) *Service {
	svc, err := NewService(Config{
		Store:            fx.st,
		Authority:        fa,
		Attestor:         fx.attestor,
		Clock:            clock.Now,
		Rand:             &counterReader{},
		PollInterval:     10 * time.Millisecond,
		EmptyListTimeout: 2 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	return svc
}

func missionRef(ref string) coreapi.ActiveMission {
	return coreapi.ActiveMission{MissionRef: ref, WorkspaceID: "ws-test-1", State: "running"}
}

func sessionRevoked(t *testing.T, ctx context.Context, st store.Store, ws, sessionHash string) bool {
	t.Helper()
	sess, err := st.GetSessionByHash(ctx, ws, sessionHash)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	return sess.Revoked
}

func cliAuthorizationGone(t *testing.T, ctx context.Context, st store.Store, ws, authorizationID string) bool {
	t.Helper()
	_, err := st.GetCLIAuthorization(ctx, ws, authorizationID)
	return errors.Is(err, store.ErrNotFound)
}

func TestResetOfflineSuccess(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{
		identity:       fx.identity,
		containOut:     coreapi.WorkspaceContainment{Contained: true, Generation: 7},
		activeMissions: [][]coreapi.ActiveMission{{missionRef("m1")}, {missionRef("m1")}, {}},
	}
	var printedCode string
	var printedExpiry time.Time
	svc := newTestService(fx, fa, clock)
	svc.bootstrapCodeSink = func(code string, exp time.Time) {
		printedCode = code
		printedExpiry = exp
	}

	res, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID:      fx.ws,
		RecoveryKey:      fx.recKey,
		ConfirmWorkspace: fx.ws,
	})
	if err != nil {
		t.Fatalf("ResetOffline: %v", err)
	}
	if res.ContainedMissionCount != 1 {
		t.Fatalf("contained missions = %d, want 1", res.ContainedMissionCount)
	}
	if res.RevokedSessionCount != 1 {
		t.Fatalf("revoked sessions = %d, want 1", res.RevokedSessionCount)
	}
	if res.RecoveryEventID == "" {
		t.Fatal("empty recovery event id")
	}
	if printedCode == "" {
		t.Fatal("bootstrap code was not delivered to the sink")
	}
	if printedExpiry.IsZero() {
		t.Fatal("bootstrap expiry missing")
	}
	// The bootstrap code must validate through the normal redemption
	// path and expire in about ten minutes.
	founders, err := fx.st.ListFounders(ctx, fx.ws)
	if err != nil {
		t.Fatalf("list founders: %v", err)
	}
	if len(founders) != 0 {
		t.Fatalf("founder rows = %d, want 0 after reset", len(founders))
	}
	if !sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Fatal("sessions not revoked")
	}
	if _, err := fx.st.GetOfflineRecoveryKey(ctx, fx.ws, fx.founder); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovery key not consumed: %v", err)
	}
	creds, err := fx.st.ListWebAuthnCredentials(ctx, fx.ws, fx.founder)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Fatalf("credentials = %d, want 0", len(creds))
	}
	if !cliAuthorizationGone(t, ctx, fx.st, fx.ws, "authz-1") {
		t.Fatal("CLI authorization not invalidated")
	}
	// The bootstrap code must be redeemable through the store: its hash
	// matches the printed code and it expires in about ten minutes.
	bcRec, err := fx.st.GetBootstrapCode(ctx, fx.ws)
	if err != nil {
		t.Fatalf("get bootstrap code: %v", err)
	}
	rawCode, err := base64.RawURLEncoding.DecodeString(printedCode)
	if err != nil {
		t.Fatalf("decode printed code: %v", err)
	}
	codeSum := sha256.Sum256(rawCode)
	if bcRec.CodeHash != hex.EncodeToString(codeSum[:]) {
		t.Fatal("stored bootstrap code hash does not match the printed code")
	}
	if ttl := bcRec.ExpiresAt.Sub(clock.Now()); ttl < 9*time.Minute || ttl > 10*time.Minute+time.Second {
		t.Fatalf("bootstrap ttl = %v, want about 10m", ttl)
	}
	// Idempotency key is stable and the attestation carried the exact
	// purpose/audience/method.
	if len(fa.seenIdemKeys) != 1 {
		t.Fatalf("contain calls = %d, want 1", len(fa.seenIdemKeys))
	}
	if len(fa.seenIdemKeys[0]) == 0 {
		t.Fatal("empty idempotency key")
	}
	if len(fa.seenAttests) != 1 {
		t.Fatalf("attestations = %d, want 1", len(fa.seenAttests))
	}
	claims := fa.seenAttests[0].Claims
	if claims.Purpose != identity.PurposeOfflineRecoveryContain {
		t.Fatalf("purpose = %q", claims.Purpose)
	}
	if claims.Audience != identity.AudienceWorkspaceContain {
		t.Fatalf("audience = %q", claims.Audience)
	}
	if claims.AuthenticationMethod != identity.AuthMethodOfflineRecovery {
		t.Fatalf("method = %q", claims.AuthenticationMethod)
	}
	if claims.AuthenticationProofDigest == "" || len(claims.AuthenticationProofDigest) < 8 || claims.AuthenticationProofDigest[:7] != "sha256:" {
		t.Fatalf("proof digest = %q", claims.AuthenticationProofDigest)
	}
	if len(fa.seenAttests[0].Signature) == 0 {
		t.Fatal("attestation not signed")
	}
	// Recovery event is non-secret: no key, no raw code.
	events, err := fx.st.ListRecoveryEvents(ctx, fx.ws, 10)
	if err != nil {
		t.Fatalf("list recovery events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.EventID != res.RecoveryEventID {
		t.Fatal("event id mismatch")
	}
	if ev.AttestationDigest == "" || ev.RecoveryProofDigest == "" || ev.BootstrapCodeHash == "" {
		t.Fatal("event missing digests")
	}
}

func TestResetOfflineWrongKey(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{identity: fx.identity}
	svc := newTestService(fx, fa, clock)

	wrong := []byte("wrong-recovery-key-32bytes!!!!!!!!")
	_, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID: fx.ws, RecoveryKey: wrong, ConfirmWorkspace: fx.ws,
	})
	if !errors.Is(err, ErrInvalidRecoveryKey) {
		t.Fatalf("err = %v, want ErrInvalidRecoveryKey", err)
	}
	if fa.containCalls != 0 {
		t.Fatal("contain called with wrong key")
	}
	if sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Fatal("sessions mutated on wrong key")
	}
}

func TestResetOfflineWrongConfirmation(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{identity: fx.identity}
	svc := newTestService(fx, fa, clock)

	_, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: "other-ws",
	})
	if !errors.Is(err, ErrWorkspaceConfirmationMismatch) {
		t.Fatalf("err = %v, want ErrWorkspaceConfirmationMismatch", err)
	}
	if fa.containCalls != 0 {
		t.Fatal("contain called with wrong confirmation")
	}
}

func TestResetOfflineIdentityWithoutRole(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	id := fx.identity
	id.Roles = []string{"some_other_role"}
	fa := &fakeAuthority{identity: id}
	svc := newTestService(fx, fa, clock)

	_, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws,
	})
	if !errors.Is(err, ErrIdentityNotVerified) {
		t.Fatalf("err = %v, want ErrIdentityNotVerified", err)
	}
	if fa.containCalls != 0 {
		t.Fatal("contain called with roleless identity")
	}
}

func TestResetOfflineUpstreamOnlyMissionsContained(t *testing.T) {
	// Missions known only to AuthScope (never seen locally) must be
	// contained before the local reset.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{
		identity:   fx.identity,
		containOut: coreapi.WorkspaceContainment{Contained: true, Generation: 3},
		activeMissions: [][]coreapi.ActiveMission{
			{missionRef("upstream-only-1"), missionRef("upstream-only-2")},
			{},
		},
	}
	svc := newTestService(fx, fa, clock)

	res, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws,
	})
	if err != nil {
		t.Fatalf("ResetOffline: %v", err)
	}
	if res.ContainedMissionCount != 2 {
		t.Fatalf("contained = %d, want 2", res.ContainedMissionCount)
	}
}

func TestResetOfflineNonEmptyListLeavesStateUnchanged(t *testing.T) {
	// If the authoritative list never comes back empty, no local
	// authentication state changes and the intent stays pending.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	// The clock steps forward on every read so the poll deadline is
	// reachable with a frozen manual clock.
	clock := &testClock{now: time.Now().UTC(), step: 500 * time.Millisecond}
	fa := &fakeAuthority{
		identity:   fx.identity,
		containOut: coreapi.WorkspaceContainment{Contained: true, Generation: 3},
		activeMissions: [][]coreapi.ActiveMission{
			{missionRef("m1")},
			{missionRef("m1")},
		},
	}
	svc := newTestService(fx, fa, clock)

	_, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws,
	})
	if !errors.Is(err, ErrActiveMissionsRemain) {
		t.Fatalf("err = %v, want ErrActiveMissionsRemain", err)
	}
	if sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Fatal("sessions changed without authoritative empty list")
	}
	if _, err := fx.st.GetOfflineRecoveryKey(ctx, fx.ws, fx.founder); err != nil {
		t.Fatalf("recovery key consumed without authoritative empty list: %v", err)
	}
	creds, err := fx.st.ListWebAuthnCredentials(ctx, fx.ws, fx.founder)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Fatal("credentials changed without authoritative empty list")
	}
	events, err := fx.st.ListRecoveryEvents(ctx, fx.ws, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 0 {
		t.Fatal("recovery event recorded without authoritative empty list")
	}
}

func TestResetOfflineAmbiguousContainmentReconciles(t *testing.T) {
	// An ambiguous first call (5xx) retries once by the same idempotency
	// key with a fresh attestation; the nonce differs between attempts.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{
		identity:   fx.identity,
		containOut: coreapi.WorkspaceContainment{Contained: true, Generation: 9},
		containErrs: []error{
			&coreapi.UpstreamError{StatusCode: 503, Message: "unavailable"},
			nil,
		},
		activeMissions: [][]coreapi.ActiveMission{{}},
	}
	svc := newTestService(fx, fa, clock)

	_, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws,
	})
	if err != nil {
		t.Fatalf("ResetOffline: %v", err)
	}
	if fa.containCalls != 2 {
		t.Fatalf("contain calls = %d, want 2", fa.containCalls)
	}
	if fa.seenIdemKeys[0] != fa.seenIdemKeys[1] {
		t.Fatal("idempotency key changed across reconcile")
	}
	if fa.seenAttests[0].Claims.Nonce == fa.seenAttests[1].Claims.Nonce {
		t.Fatal("nonce reused across reconcile attempts")
	}
}

func TestResetOfflineDefinitiveDenialFails(t *testing.T) {
	// A definitive 4xx denial is not retried and changes nothing.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{
		identity:    fx.identity,
		containErrs: []error{&coreapi.UpstreamError{StatusCode: 403, Message: "denied"}},
	}
	svc := newTestService(fx, fa, clock)

	_, err := svc.ResetOffline(ctx, RecoveryRequest{
		WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if fa.containCalls != 1 {
		t.Fatalf("contain calls = %d, want 1", fa.containCalls)
	}
	if sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Fatal("sessions changed after denial")
	}
}

func TestResetOfflineCrashAfterIntentResumes(t *testing.T) {
	// A crash after intent persistence but before containment resumes
	// from the intent: the second attempt reuses the stored idempotency
	// key and completes the reset exactly once.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{
		identity:       fx.identity,
		containOut:     coreapi.WorkspaceContainment{Contained: true, Generation: 5},
		activeErrs:     []error{errors.New("crash before containment")},
		activeMissions: [][]coreapi.ActiveMission{{}},
	}
	svc := newTestService(fx, fa, clock)
	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	// First attempt: the intent is persisted, then the baseline mission
	// list fails. Containment is never reached.
	if _, err := svc.ResetOffline(ctx, req); err == nil {
		t.Fatal("first attempt succeeded despite mission list failure")
	}
	if fa.containCalls != 0 {
		t.Fatalf("first attempt contained %d times, want 0", fa.containCalls)
	}
	sum := sha256.Sum256(fx.recKey)
	key := idempotencyKey(fx.ws, hex.EncodeToString(sum[:]))
	intent, err := fx.st.GetRecoveryIntent(ctx, fx.ws, key)
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if intent.State != store.RecoveryIntentPending {
		t.Fatalf("intent state %q, want pending", intent.State)
	}
	// Second attempt resumes from the stored intent: it reuses the
	// idempotency key and completes exactly once.
	fa.activeErrs = nil
	res, err := svc.ResetOffline(ctx, req)
	if err != nil {
		t.Fatalf("resumed ResetOffline: %v", err)
	}
	if len(fa.seenIdemKeys) != 1 || fa.seenIdemKeys[0] != key {
		t.Fatalf("resumed attempt did not reuse the stored idempotency key: %v", fa.seenIdemKeys)
	}
	if res.ContainedMissionCount != 0 {
		t.Fatalf("contained = %d, want 0", res.ContainedMissionCount)
	}
	events, err := fx.st.ListRecoveryEvents(ctx, fx.ws, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1 (no double reset)", len(events))
	}
}

func TestResetOfflineConcurrentRacesOneWins(t *testing.T) {
	// Two concurrent resets with the same key: exactly one completes,
	// the other sees in-progress or replays the completed result.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC()}
	fa := &fakeAuthority{
		identity:   fx.identity,
		containOut: coreapi.WorkspaceContainment{Contained: true, Generation: 11},
		activeMissions: [][]coreapi.ActiveMission{
			{}, {}, {}, {},
		},
	}
	svc1 := newTestService(fx, fa, clock)
	svc2 := newTestService(fx, fa, clock)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			svc := svc1
			if i == 1 {
				svc = svc2
			}
			_, errs[i] = svc.ResetOffline(ctx, RecoveryRequest{
				WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws,
			})
		}(i)
	}
	wg.Wait()
	var successes int
	for _, err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrRecoveryInProgress) && !errors.Is(err, ErrInvalidRecoveryKey) {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want 1; errs = %v", successes, errs)
	}
	events, err := fx.st.ListRecoveryEvents(ctx, fx.ws, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want exactly 1", len(events))
	}
}

func TestResetOfflineProofDigestIsStableAndSecretFree(t *testing.T) {
	// The proof digest over the verified record is deterministic and
	// never embeds the key.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	rec := recoveryRecord{
		WorkspaceID: fx.ws,
		FounderID:   fx.founder,
		KeyHash:     "hash",
		CreatedAt:   "2026-01-01T00:00:00Z",
	}
	d1, err := taggedDigest(rec)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d2, err := taggedDigest(rec)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if d1 != d2 {
		t.Fatal("proof digest not deterministic")
	}
	if len(d1) < 8 || d1[:7] != "sha256:" {
		t.Fatalf("digest = %q, want sha256: tag", d1)
	}
	raw, err := canonicalJSON(rec)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if stringContains(string(raw), string(fx.recKey)) {
		t.Fatal("canonical record embeds key material")
	}
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// Ensure the io import is referenced for future extensions.
var _ io.Reader = (*counterReader)(nil)

func TestNewServiceRejectsNilAttestor(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	fa := &fakeAuthority{}
	_, err := NewService(Config{Store: fx.st, Authority: fa, Attestor: nil})
	if err == nil {
		t.Fatal("NewService accepted a nil attestor")
	}
}

func TestResetOfflineReplayedKeyFails(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC(), step: time.Second}
	fa := &fakeAuthority{identity: fx.identity, containOut: coreapi.WorkspaceContainment{Contained: true, Generation: 3}}
	svc := newTestService(fx, fa, clock)

	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	if _, err := svc.ResetOffline(ctx, req); err != nil {
		t.Fatalf("first reset: %v", err)
	}
	// The key was consumed by the first reset: replaying it must fail,
	// and must not produce a second event. The founder row is gone too,
	// so the replay surfaces as not-enrolled rather than invalid-key;
	// either way the replay is rejected.
	if _, err := svc.ResetOffline(ctx, req); err == nil {
		t.Fatal("replay succeeded with a consumed recovery key")
	} else if !errors.Is(err, ErrInvalidRecoveryKey) && !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("replay: got %v, want ErrInvalidRecoveryKey or ErrNotEnrolled", err)
	}
	events, err := fx.st.ListRecoveryEvents(ctx, fx.ws, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("replay produced %d recovery events, want 1", len(events))
	}
}

func TestResetOfflineAttestationIsFreshAndScoped(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC(), step: time.Second}
	fa := &fakeAuthority{
		identity:    fx.identity,
		containOut:  coreapi.WorkspaceContainment{Contained: true, Generation: 3},
		containErrs: []error{errors.New("timeout")}, // ambiguous: forces one retry
	}
	svc := newTestService(fx, fa, clock)

	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	if _, err := svc.ResetOffline(ctx, req); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if len(fa.seenAttests) != 2 {
		t.Fatalf("saw %d attestations, want 2 (initial plus retry)", len(fa.seenAttests))
	}
	for i, att := range fa.seenAttests {
		c := att.Claims
		if c.Purpose != identity.PurposeOfflineRecoveryContain {
			t.Errorf("attestation %d purpose %q", i, c.Purpose)
		}
		if c.Audience != identity.AudienceWorkspaceContain {
			t.Errorf("attestation %d audience %q", i, c.Audience)
		}
		if c.AuthenticationMethod != identity.AuthMethodOfflineRecovery {
			t.Errorf("attestation %d method %q", i, c.AuthenticationMethod)
		}
		if c.WorkspaceID != fx.ws || c.SubjectID != fx.ws {
			t.Errorf("attestation %d scoped to %q/%q", i, c.WorkspaceID, c.SubjectID)
		}
		if ttl := c.ExpiresAt.Sub(c.IssuedAt); ttl != 15*time.Minute {
			t.Errorf("attestation %d TTL %s, want 15m", i, ttl)
		}
		if c.IssuedAt.Before(clock.now.Add(-time.Hour)) || c.IssuedAt.After(clock.now.Add(time.Hour)) {
			t.Errorf("attestation %d issued at %s, not fresh", i, c.IssuedAt)
		}
		var zero [32]byte
		if c.Nonce == zero {
			t.Errorf("attestation %d has a zero nonce", i)
		}
	}
	// The retry must carry a fresh one-use nonce, never the first one.
	if fa.seenAttests[0].Claims.Nonce == fa.seenAttests[1].Claims.Nonce {
		t.Error("retry reused the initial attestation nonce")
	}
}

func TestResetOfflinePersistentAmbiguousLeavesPending(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC(), step: time.Second}
	fa := &fakeAuthority{
		identity:    fx.identity,
		containErrs: []error{errors.New("timeout"), errors.New("timeout")},
	}
	svc := newTestService(fx, fa, clock)

	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	if _, err := svc.ResetOffline(ctx, req); err == nil {
		t.Fatal("reset succeeded despite persistent ambiguous containment")
	}
	// No local mutation: the session is still valid and the key is not
	// consumed (consumption deletes the row).
	if sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Error("session revoked before authoritative empty")
	}
	if cliAuthorizationGone(t, ctx, fx.st, fx.ws, "authz-1") {
		t.Error("CLI authorization cleared before authoritative empty")
	}
	if _, err := fx.st.GetOfflineRecoveryKey(ctx, fx.ws, fx.founder); err != nil {
		t.Errorf("recovery key missing after failed reset: %v", err)
	}
	// The intent stays pending for a later retry.
	sum := sha256.Sum256(fx.recKey)
	intent, err := fx.st.GetRecoveryIntent(ctx, fx.ws, idempotencyKey(fx.ws, hex.EncodeToString(sum[:])))
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if intent.State != store.RecoveryIntentPending {
		t.Errorf("intent state %q, want pending", intent.State)
	}
}

func TestResetOfflineMissionListUnavailableLeavesContained(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC(), step: time.Second}
	fa := &fakeAuthority{
		identity:       fx.identity,
		containOut:     coreapi.WorkspaceContainment{Contained: true, Generation: 3},
		activeMissions: [][]coreapi.ActiveMission{{missionRef("m-1")}},
		activeErrs:     []error{nil, errors.New("upstream unavailable")},
	}
	// Shorten the empty-list deadline so the test does not wait.
	svc, err := NewService(Config{
		Store: fx.st, Authority: fa, Attestor: fx.attestor,
		Clock: clock.Now, Rand: &counterReader{},
		PollInterval: 10 * time.Millisecond, EmptyListTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	if _, err := svc.ResetOffline(ctx, req); err == nil {
		t.Fatal("reset succeeded despite unavailable mission list")
	}
	if sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Error("session revoked without an authoritative empty list")
	}
	sum := sha256.Sum256(fx.recKey)
	intent, err := fx.st.GetRecoveryIntent(ctx, fx.ws, idempotencyKey(fx.ws, hex.EncodeToString(sum[:])))
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if intent.State != store.RecoveryIntentContained {
		t.Errorf("intent state %q, want contained", intent.State)
	}
}

func TestResetOfflineResumeFromContained(t *testing.T) {
	// Crash after the contained transition (mission list unavailable):
	// the next run must skip containment and resume at polling.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC(), step: time.Second}
	fa := &fakeAuthority{
		identity:   fx.identity,
		containOut: coreapi.WorkspaceContainment{Contained: true, Generation: 7},
		// Baseline sees one mission; the first post-containment poll
		// fails; later polls (the resumed run) see the empty list.
		activeMissions: [][]coreapi.ActiveMission{{missionRef("m-1")}, {}},
		activeErrs:     []error{nil, errors.New("upstream unavailable")},
	}
	svc := newTestService(fx, fa, clock)
	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	if _, err := svc.ResetOffline(ctx, req); err == nil {
		t.Fatal("first run succeeded despite unavailable mission list")
	}
	if fa.containCalls != 1 {
		t.Fatalf("first run called ContainWorkspace %d times, want 1", fa.containCalls)
	}

	// Upstream recovers. The resumed run must not re-contain.
	fa.activeErrs = nil
	res, err := svc.ResetOffline(ctx, req)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if fa.containCalls != 1 {
		t.Errorf("resumed run called ContainWorkspace %d more times, want 0", fa.containCalls-1)
	}
	if res.RecoveryEventID == "" {
		t.Error("resume produced no recovery event")
	}
	if !sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Error("session was not revoked by the resumed reset")
	}
}

// failPutEventStore wraps a store and fails PutRecoveryEvent inside the
// transaction, simulating a crash during the final reset after the
// verified-empty transition was durably recorded.
type failPutEventStore struct {
	store.Store
	fail error
}

func (s *failPutEventStore) WithTx(ctx context.Context, fn func(store.Tx) error) error {
	return s.Store.WithTx(ctx, func(tx store.Tx) error {
		return fn(&failPutEventTx{Tx: tx, fail: s.fail})
	})
}

type failPutEventTx struct {
	store.Tx
	fail error
}

func (t *failPutEventTx) PutRecoveryEvent(ctx context.Context, rec store.RecoveryEventRecord) error {
	return t.fail
}

func TestResetOfflineResumeFromVerifiedEmpty(t *testing.T) {
	// Crash during the final reset after verified_empty was recorded:
	// the next run must go straight to the local reset without
	// re-containing or re-polling.
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC(), step: time.Second}
	fa := &fakeAuthority{
		identity:   fx.identity,
		containOut: coreapi.WorkspaceContainment{Contained: true, Generation: 7},
	}
	crashing, err := NewService(Config{
		Store:     &failPutEventStore{Store: fx.st, fail: errors.New("disk full")},
		Authority: fa, Attestor: fx.attestor,
		Clock: clock.Now, Rand: &counterReader{},
		PollInterval: 10 * time.Millisecond, EmptyListTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	if _, err := crashing.ResetOffline(ctx, req); err == nil {
		t.Fatal("first run succeeded despite injected reset failure")
	}
	sum := sha256.Sum256(fx.recKey)
	intent, err := fx.st.GetRecoveryIntent(ctx, fx.ws, idempotencyKey(fx.ws, hex.EncodeToString(sum[:])))
	if err != nil {
		t.Fatalf("get intent: %v", err)
	}
	if intent.State != store.RecoveryIntentVerifiedEmpty {
		t.Fatalf("intent state %q, want verified_empty", intent.State)
	}
	if sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Fatal("session revoked by the crashed reset: the transaction did not roll back")
	}

	// Resume with the healthy store: no re-containment, no re-polling.
	svc := newTestService(fx, fa, clock)
	containCalls, activeCalls := fa.containCalls, fa.activeCalls
	if _, err := svc.ResetOffline(ctx, req); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if fa.containCalls != containCalls {
		t.Errorf("resumed run re-contained the workspace")
	}
	if fa.activeCalls != activeCalls {
		t.Errorf("resumed run re-polled the mission list")
	}
	if !sessionRevoked(t, ctx, fx.st, fx.ws, fx.sessionHash) {
		t.Error("session was not revoked by the resumed reset")
	}
}

func TestResetOfflineCorruptIntentDigestFails(t *testing.T) {
	ctx := context.Background()
	fx := setupFixture(t, ctx)
	clock := &testClock{now: time.Now().UTC(), step: time.Second}
	sum := sha256.Sum256(fx.recKey)
	key := idempotencyKey(fx.ws, hex.EncodeToString(sum[:]))
	now := time.Now().UTC()
	if err := fx.st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutRecoveryIntent(ctx, store.RecoveryIntentRecord{
			WorkspaceID: fx.ws, IdempotencyKey: key, IntentID: "intent-1",
			CanonicalDigest: "tampered-digest", Nonce: "nonce",
			State: store.RecoveryIntentPending, CreatedAt: now, UpdatedAt: now,
		})
	}); err != nil {
		t.Fatalf("seed intent: %v", err)
	}

	fa := &fakeAuthority{identity: fx.identity}
	svc := newTestService(fx, fa, clock)
	req := RecoveryRequest{WorkspaceID: fx.ws, RecoveryKey: fx.recKey, ConfirmWorkspace: fx.ws}
	if _, err := svc.ResetOffline(ctx, req); !errors.Is(err, ErrRecoveryStateCorrupt) {
		t.Fatalf("got %v, want ErrRecoveryStateCorrupt", err)
	}
	if fa.containCalls != 0 {
		t.Errorf("corrupt intent still called ContainWorkspace %d times", fa.containCalls)
	}
}
