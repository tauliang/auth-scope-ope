package authn

// Task 8: one-use browser PKCE handoff for CLI launch authorization.
// These tests cover PKCE S256 verification, strict loopback redirect
// validation, creation of the pending authorization bound to the exact
// approved proposal, the browser begin/finish decision, the bounded
// in-memory attestation cache, and restart semantics.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

func TestPKCES256Verification(t *testing.T) {
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatalf("NewPKCEVerifier: %v", err)
	}
	if len(verifier) != 43 {
		t.Fatalf("verifier length = %d, want 43 (256-bit base64url)", len(verifier))
	}
	raw, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil || len(raw) != 32 {
		t.Fatalf("verifier decodes to %d bytes, want 32", len(raw))
	}
	challenge := CodeChallengeS256(verifier)
	sum := sha256.Sum256([]byte(verifier))
	if challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("challenge = %q, want base64url(sha256(verifier))", challenge)
	}
	if !VerifyCodeChallenge(challenge, verifier) {
		t.Fatal("correct verifier rejected")
	}
	wrong, err := NewPKCEVerifier()
	if err != nil {
		t.Fatalf("NewPKCEVerifier: %v", err)
	}
	if VerifyCodeChallenge(challenge, wrong) {
		t.Fatal("wrong S256 verifier accepted")
	}
	if VerifyCodeChallenge(challenge, verifier[:42]+"AA") {
		t.Fatal("truncated verifier accepted")
	}
	if VerifyCodeChallenge("not-a-challenge", verifier) {
		t.Fatal("malformed challenge accepted")
	}
}

func TestLoopbackRedirectValidation(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"ephemeral port", "http://127.0.0.1:54321/callback", false},
		{"lowest unprivileged", "http://127.0.0.1:1024/callback", false},
		{"highest port", "http://127.0.0.1:65535/callback", false},
		{"localhost rejected", "http://localhost:54321/callback", true},
		{"non-loopback rejected", "http://192.168.1.10:54321/callback", true},
		{"public host rejected", "http://example.com:54321/callback", true},
		{"privileged port rejected", "http://127.0.0.1:80/callback", true},
		{"port 1023 rejected", "http://127.0.0.1:1023/callback", true},
		{"missing port rejected", "http://127.0.0.1/callback", true},
		{"wrong path rejected", "http://127.0.0.1:54321/other", true},
		{"root path rejected", "http://127.0.0.1:54321/", true},
		{"https rejected", "https://127.0.0.1:54321/callback", true},
		{"query rejected", "http://127.0.0.1:54321/callback?x=1", true},
		{"fragment rejected", "http://127.0.0.1:54321/callback#x", true},
		{"userinfo rejected", "http://user@127.0.0.1:54321/callback", true},
		{"empty rejected", "", true},
		{"garbage rejected", "not a uri", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateLoopbackRedirectURI(tc.uri)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateLoopbackRedirectURI(%q) err = %v, wantErr = %v", tc.uri, err, tc.wantErr)
			}
		})
	}
}

// cliTestFixture seeds an approved pass and wires the CLI authorization
// service with a fake WebAuthn verifier and an ephemeral signer.
type cliTestFixture struct {
	authn        *Service
	fv           *fakeVerifier
	db           store.Store
	clock        *testClock
	svc          *CLIAuthorizationService
	sessionToken string
}

func newCLITestFixture(t *testing.T) *cliTestFixture {
	t.Helper()
	authnSvc, fv, db, clock := newTestService(t)
	_, sessionToken, _ := enrollFounder(t, authnSvc, fv, RecoveryMethodPasskey)
	seedApprovedPass(t, db)
	attestor := identity.NewDecisionAttestor(identity.NewEphemeralSigner())
	svc, err := NewCLIAuthorizationService(CLIAuthorizationConfig{
		Store:          db,
		Authn:          authnSvc,
		Attestor:       attestor,
		BrowserBaseURL: "https://ope.example.com",
		Clock:          clock.Now,
	})
	if err != nil {
		t.Fatalf("new CLI authorization service: %v", err)
	}
	return &cliTestFixture{authn: authnSvc, fv: fv, db: db, clock: clock, svc: svc, sessionToken: sessionToken}
}

// approvedPassValues are the exact approved proposal values the fixture
// binds. The invocation digest is the pinned digest over the kit and
// ordered arguments, matching the fake AuthScope behavior.
var (
	cliPassID           = "pass-cli-1"
	cliProposalDigest   = "sha256:" + strings.Repeat("f", 64)
	cliAgentKitID       = "authscope-agent-kit"
	cliAgentKitVersion  = "1.0.0"
	cliRunnerArgs       = []string{"authscope-agent-run", "--mission", "pass-cli-1"}
	cliInvocationDigest = ""
)

func seedApprovedPass(t *testing.T, db store.Store) {
	t.Helper()
	cliInvocationDigest = InvocationDigestForLaunch(cliAgentKitID, cliAgentKitVersion, cliRunnerArgs)
	now := time.Now().UTC().Truncate(time.Second)
	rec := store.MissionPassRecord{
		WorkspaceID:             "ws-test",
		PassID:                  cliPassID,
		StoreRevision:           1,
		DraftVersion:            2,
		AuthScopeMissionVersion: 3,
		ConnectionID:            "conn-1",
		IssueNumber:             42,
		RepositoryName:          "octo-org/repo",
		ProposalID:              "prop-cli-1",
		ProposalDigest:          cliProposalDigest,
		ApprovedProposalDigest:  cliProposalDigest,
		SourceRevision:          "rev-1",
		SourceDigest:            "sha256:" + strings.Repeat("b", 64),
		BaseSHA:                 strings.Repeat("a", 40),
		MissionBranch:           "authscope/pass-cli-1-42",
		AgentKitID:              cliAgentKitID,
		AgentKitVersion:         cliAgentKitVersion,
		RunnerArguments:         cliRunnerArgs,
		InvocationDigest:        cliInvocationDigest,
		ExpiresAt:               now.Add(time.Hour),
		Objective:               "Add retries",
		State:                   "approved",
		Reconciliation:          "settled",
		MissionRef:              "mission-cli-1",
		MissionHash:             "sha256:" + strings.Repeat("e", 64),
		ApprovalDecisionRef:     "approval-decision:ws-test:pass-cli-1:2",
		AttestationDigest:       "sha256:" + strings.Repeat("9", 64),
		CreatedAt:               now,
		UpdatedAt:               now,
	}
	if err := db.WithTx(context.Background(), func(tx store.Tx) error {
		return tx.PutMissionPass(context.Background(), rec, 0)
	}); err != nil {
		t.Fatalf("seed approved pass: %v", err)
	}
}

// cliCreateRequest builds a valid create request with fresh secrets.
func cliCreateRequest(t *testing.T, passID, redirectURI string) (CLIAuthorizationRequest, string, string) {
	t.Helper()
	verifier, err := NewPKCEVerifier()
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	state, err := NewPKCEVerifier()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	return CLIAuthorizationRequest{
		PassID:              passID,
		RedirectURI:         redirectURI,
		State:               state,
		CodeChallenge:       CodeChallengeS256(verifier),
		CodeChallengeMethod: "S256",
		EphemeralPublicKey:  base64.RawURLEncoding.EncodeToString(pub),
	}, verifier, state
}

func TestCLIAuthCreateHappyPath(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	start, replayed, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if replayed {
		t.Fatal("fresh create reported replay")
	}
	if start.ID == "" {
		t.Fatal("missing authorization ID")
	}
	// Create must return the exact approved proposal digest, agent-kit
	// ID/version, ordered arguments, and invocation digest.
	if start.ProposalDigest != cliProposalDigest {
		t.Errorf("proposal digest = %q, want %q", start.ProposalDigest, cliProposalDigest)
	}
	if start.AgentKitID != cliAgentKitID || start.AgentKitVersion != cliAgentKitVersion {
		t.Errorf("kit = %q %q, want %q %q", start.AgentKitID, start.AgentKitVersion, cliAgentKitID, cliAgentKitVersion)
	}
	if len(start.RunnerArguments) != len(cliRunnerArgs) {
		t.Fatalf("args = %v, want %v", start.RunnerArguments, cliRunnerArgs)
	}
	for i := range cliRunnerArgs {
		if start.RunnerArguments[i] != cliRunnerArgs[i] {
			t.Fatalf("args = %v, want %v", start.RunnerArguments, cliRunnerArgs)
		}
	}
	if start.InvocationDigest != cliInvocationDigest {
		t.Errorf("invocation digest = %q, want %q", start.InvocationDigest, cliInvocationDigest)
	}
	// The CLI recomputes the pinned invocation digest and must agree.
	if got := InvocationDigestForLaunch(start.AgentKitID, start.AgentKitVersion, start.RunnerArguments); got != start.InvocationDigest {
		t.Errorf("recomputed invocation digest = %q, want %q", got, start.InvocationDigest)
	}
	if !strings.HasPrefix(start.BrowserURL, "https://ope.example.com/authorize/cli/") {
		t.Errorf("browser URL = %q", start.BrowserURL)
	}
	// The durable record stores only hashes of secret values: the
	// verifier and the raw code must not be recoverable from the store.
	// Before approval there is no code, so the code hash is zero; the
	// state is kept so the finish step can redirect the original value.
	rec, err := f.db.GetCLIAuthorization(context.Background(), "ws-test", start.ID)
	if err != nil {
		t.Fatalf("load authorization: %v", err)
	}
	if rec.State == "" || rec.CodeChallenge == "" {
		t.Fatal("expected state and code challenge in the record")
	}
	var zeroHash [32]byte
	if rec.CodeHash != zeroHash {
		t.Fatal("code hash must be zero before approval")
	}
	if rec.ApprovedAt != nil {
		t.Fatal("authorization must not be approved before the browser decision")
	}
}

func TestCLIAuthCreateValidation(t *testing.T) {
	f := newCLITestFixture(t)
	newReq := func() CLIAuthorizationRequest {
		req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
		return req
	}
	cases := []struct {
		name    string
		mutate  func(*CLIAuthorizationRequest)
		wantErr error
	}{
		{"unknown pass", func(r *CLIAuthorizationRequest) { r.PassID = "pass-nope" }, ErrCLIAuthorizationNotFound},
		{"localhost redirect", func(r *CLIAuthorizationRequest) { r.RedirectURI = "http://localhost:54321/callback" }, ErrInvalidRedirectURI},
		{"non-loopback redirect", func(r *CLIAuthorizationRequest) { r.RedirectURI = "http://10.0.0.5:54321/callback" }, ErrInvalidRedirectURI},
		{"privileged port", func(r *CLIAuthorizationRequest) { r.RedirectURI = "http://127.0.0.1:443/callback" }, ErrInvalidRedirectURI},
		{"wrong path", func(r *CLIAuthorizationRequest) { r.RedirectURI = "http://127.0.0.1:54321/cb" }, ErrInvalidRedirectURI},
		{"plain method rejected", func(r *CLIAuthorizationRequest) { r.CodeChallengeMethod = "plain" }, ErrInvalidPKCE},
		{"empty method rejected", func(r *CLIAuthorizationRequest) { r.CodeChallengeMethod = "" }, ErrInvalidPKCE},
		{"malformed challenge", func(r *CLIAuthorizationRequest) { r.CodeChallenge = "short" }, ErrInvalidPKCE},
		{"malformed state", func(r *CLIAuthorizationRequest) { r.State = "short" }, ErrInvalidPKCE},
		{"malformed ephemeral key", func(r *CLIAuthorizationRequest) { r.EphemeralPublicKey = "short" }, ErrInvalidEphemeralKey},
		{"empty pass", func(r *CLIAuthorizationRequest) { r.PassID = "" }, ErrCLIAuthorizationNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := newReq()
			tc.mutate(&req)
			if _, _, err := f.svc.Create(context.Background(), req); !isErr(err, tc.wantErr) {
				t.Fatalf("Create err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestCLIAuthCreateRequiresApprovedPass(t *testing.T) {
	f := newCLITestFixture(t)
	// Flip the seeded pass back to draft: Create must fail closed.
	rec, err := f.db.GetMissionPass(context.Background(), "ws-test", cliPassID)
	if err != nil {
		t.Fatalf("load pass: %v", err)
	}
	rec.State = "draft"
	rec.ApprovedProposalDigest = ""
	if err := f.db.WithTx(context.Background(), func(tx store.Tx) error {
		return tx.PutMissionPass(context.Background(), rec, rec.StoreRevision)
	}); err != nil {
		t.Fatalf("unapprove pass: %v", err)
	}
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	if _, _, err := f.svc.Create(context.Background(), req); !isErr(err, ErrPassNotApproved) {
		t.Fatalf("Create err = %v, want ErrPassNotApproved", err)
	}
}

func TestCLIAuthCreateIdempotentReplay(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	first, replayed, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if replayed {
		t.Fatal("first create reported replay")
	}
	second, replayed, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if !replayed {
		t.Fatal("identical canonical request did not replay")
	}
	if second.ID != first.ID {
		t.Fatalf("replay ID = %q, want %q", second.ID, first.ID)
	}
}

func TestCLIAuthCreateConcurrentDuplicatesReplay(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	// Concurrent identical creates must converge on one authorization:
	// the unique (workspace, pass, state) constraint keeps a single row
	// and every caller replays the winner.
	const callers = 8
	type outcome struct {
		start    CLIAuthorizationStart
		replayed bool
		err      error
	}
	results := make([]outcome, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start, replayed, err := f.svc.Create(context.Background(), req)
			results[i] = outcome{start, replayed, err}
		}(i)
	}
	wg.Wait()
	winner := ""
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("caller %d Create: %v", i, r.err)
		}
		if r.start.ID == "" {
			t.Fatalf("caller %d missing authorization ID", i)
		}
		if winner == "" {
			winner = r.start.ID
		} else if r.start.ID != winner {
			t.Fatalf("caller %d ID = %q, want winner %q", i, r.start.ID, winner)
		}
	}
	// Exactly one durable row exists for the state.
	rec, err := f.db.GetCLIAuthorizationByState(context.Background(), "ws-test", cliPassID, req.State)
	if err != nil {
		t.Fatalf("load by state: %v", err)
	}
	if rec.AuthorizationID != winner {
		t.Fatalf("stored ID = %q, want winner %q", rec.AuthorizationID, winner)
	}
}

func TestCLIAuthCreateMissionChangedConflicts(t *testing.T) {
	f := newCLITestFixture(t)
	ctx := context.Background()
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	start, replayed, err := f.svc.Create(ctx, req)
	if err != nil || replayed {
		t.Fatalf("first Create: start=%+v replayed=%v err=%v", start, replayed, err)
	}
	// The stored record pins the mission reference and version.
	rec, err := f.db.GetCLIAuthorization(ctx, "ws-test", start.ID)
	if err != nil {
		t.Fatalf("load authorization: %v", err)
	}
	if rec.MissionRef != "mission-cli-1" || rec.MissionVersion != 3 {
		t.Fatalf("stored mission = %q/%d, want mission-cli-1/3", rec.MissionRef, rec.MissionVersion)
	}
	if rec.CanonicalRequestDigest == ([32]byte{}) {
		t.Fatal("stored canonical request digest is empty")
	}
	// Move the pass to a new mission version: the identical create must
	// conflict instead of replaying, and the pending authorization must
	// fail closed at begin.
	pass, err := f.db.GetMissionPass(ctx, "ws-test", cliPassID)
	if err != nil {
		t.Fatalf("load pass: %v", err)
	}
	pass.MissionRef = "mission-cli-2"
	pass.AuthScopeMissionVersion = 4
	if err := f.db.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, pass, pass.StoreRevision)
	}); err != nil {
		t.Fatalf("move pass mission: %v", err)
	}
	if _, _, err := f.svc.Create(ctx, req); !isErr(err, ErrCLIAuthorizationConflict) {
		t.Fatalf("moved-mission Create err = %v, want ErrCLIAuthorizationConflict", err)
	}
	p := mustPrincipal(t, f.authn, f.sessionToken)
	if _, err := f.svc.BeginBrowserDecision(ctx, p, start.ID); !isErr(err, ErrCLIBindingChanged) {
		t.Fatalf("moved-mission begin err = %v, want ErrCLIBindingChanged", err)
	}
}

func TestCLIAuthCreateChangedContentConflicts(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	if _, _, err := f.svc.Create(context.Background(), req); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	// Same state, different PKCE challenge: the canonical request
	// changed, so this must conflict instead of replaying.
	verifier2, _ := NewPKCEVerifier()
	req.CodeChallenge = CodeChallengeS256(verifier2)
	if _, _, err := f.svc.Create(context.Background(), req); !isErr(err, ErrCLIAuthorizationConflict) {
		t.Fatalf("changed Create err = %v, want ErrCLIAuthorizationConflict", err)
	}
}

// beginFinishCLI runs the browser begin/finish decision with a queued
// assertion and returns the redirect URL.
func beginFinishCLI(t *testing.T, f *cliTestFixture, authorizationID string) string {
	t.Helper()
	ctx := context.Background()
	p := mustPrincipal(t, f.authn, f.sessionToken)
	begun, err := f.svc.BeginBrowserDecision(ctx, p, authorizationID)
	if err != nil {
		t.Fatalf("BeginBrowserDecision: %v", err)
	}
	if begun.ChallengeID == "" || len(begun.OptionsJSON) == 0 {
		t.Fatalf("begin missing challenge: %+v", begun)
	}
	if begun.PassID != cliPassID || begun.ProposalDigest != cliProposalDigest ||
		begun.InvocationDigest != cliInvocationDigest || begun.AgentKitID != cliAgentKitID ||
		begun.AgentKitVersion != cliAgentKitVersion {
		t.Fatalf("begin binding mismatch: %+v", begun)
	}
	if len(begun.RunnerArguments) != len(cliRunnerArgs) {
		t.Fatalf("begin args = %v", begun.RunnerArguments)
	}
	f.fv.assertOutcomes = append(f.fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 1, userVerified: true,
	})
	redirect, err := f.svc.FinishBrowserDecision(ctx, p, authorizationID, begun.ChallengeID, []byte(`{}`))
	if err != nil {
		t.Fatalf("FinishBrowserDecision: %v", err)
	}
	return redirect
}

func TestCLIAuthBrowserDecisionHappyPath(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, state := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54444/callback")
	start, _, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	redirect := beginFinishCLI(t, f, start.ID)
	if !strings.HasPrefix(redirect, "http://127.0.0.1:54444/callback?code=") {
		t.Fatalf("redirect = %q", redirect)
	}
	if !strings.Contains(redirect, "state="+state) {
		t.Fatalf("redirect missing original state: %q", redirect)
	}
	code := strings.TrimPrefix(redirect, "http://127.0.0.1:54444/callback?code=")
	code = code[:strings.Index(code, "&")]
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || len(raw) != 32 {
		t.Fatalf("code is not 256-bit base64url: %q", code)
	}
	// The signed attestation lives only in the bounded in-memory cache;
	// the durable record keeps only its digest plus the code hash.
	rec, err := f.db.GetCLIAuthorization(context.Background(), "ws-test", start.ID)
	if err != nil {
		t.Fatalf("load authorization: %v", err)
	}
	if rec.ApprovedAt == nil {
		t.Fatal("authorization not marked approved")
	}
	if rec.DecisionAttestationDigest == "" {
		t.Fatal("missing attestation digest")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(rec.CodeHash[:]) {
		t.Fatal("stored code hash does not match the issued code")
	}
	pending, ok := f.svc.Attestations().Take(start.ID)
	if !ok {
		t.Fatal("attestation missing from the pending cache")
	}
	if pending.AttestationDigest != rec.DecisionAttestationDigest {
		t.Fatal("cached attestation digest mismatch")
	}
	if pending.CodeHash != rec.CodeHash {
		t.Fatal("cached code hash mismatch")
	}
	// One-use: a second take fails.
	if _, ok := f.svc.Attestations().Take(start.ID); ok {
		t.Fatal("attestation cache entry was not one-use")
	}
	// The durable record must not contain the signed attestation bytes.
	durableJSON := rec.DecisionAttestationDigest + rec.State + rec.CodeChallenge
	if strings.Contains(durableJSON, "signature") {
		t.Fatal("durable record leaks attestation material")
	}
}

func TestCLIAuthDuplicateFinishRejected(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	start, _, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_ = beginFinishCLI(t, f, start.ID)
	// A second browser decision for the same authorization is rejected:
	// the authorization is already approved, so begin conflicts, and a
	// direct finish fails closed too.
	p := mustPrincipal(t, f.authn, f.sessionToken)
	if _, err := f.svc.BeginBrowserDecision(context.Background(), p, start.ID); !isErr(err, ErrCLIAuthorizationConflict) {
		t.Fatalf("second begin err = %v, want conflict", err)
	}
	if _, err := f.svc.FinishBrowserDecision(context.Background(), p, start.ID, "nope", []byte(`{}`)); !isErr(err, ErrCLIAuthorizationConflict) {
		t.Fatalf("second finish err = %v, want conflict", err)
	}
}

func TestCLIAuthBeginUnauthenticatedWorkspace(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	start, _, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	p := mustPrincipal(t, f.authn, f.sessionToken)
	p.WorkspaceID = "ws-other"
	if _, err := f.svc.BeginBrowserDecision(context.Background(), p, start.ID); !isErr(err, ErrDecisionBinding) {
		t.Fatalf("cross-workspace begin err = %v, want ErrDecisionBinding", err)
	}
}

func TestCLIAuthExpiredAuthorization(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	start, _, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Move the clock past the two-minute expiry.
	f.clock.now = f.clock.now.Add(3 * time.Minute)
	p := mustPrincipal(t, f.authn, f.sessionToken)
	if _, err := f.svc.BeginBrowserDecision(context.Background(), p, start.ID); !isErr(err, ErrCLIAuthorizationExpired) {
		t.Fatalf("expired begin err = %v, want ErrCLIAuthorizationExpired", err)
	}
}

func TestCLIAuthBindingChangedAfterBegin(t *testing.T) {
	f := newCLITestFixture(t)
	req, _, _ := cliCreateRequest(t, cliPassID, "http://127.0.0.1:54321/callback")
	start, _, err := f.svc.Create(context.Background(), req)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ctx := context.Background()
	p := mustPrincipal(t, f.authn, f.sessionToken)
	begun, err := f.svc.BeginBrowserDecision(ctx, p, start.ID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	// The approved proposal moves under the begun challenge: finish must
	// fail closed without consuming the authorization.
	mut, err := f.db.GetMissionPass(ctx, "ws-test", cliPassID)
	if err != nil {
		t.Fatalf("load pass: %v", err)
	}
	mut.ApprovedProposalDigest = "sha256:" + strings.Repeat("1", 64)
	if err := f.db.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, mut, mut.StoreRevision)
	}); err != nil {
		t.Fatalf("mutate pass: %v", err)
	}
	f.fv.assertOutcomes = append(f.fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 2, userVerified: true,
	})
	if _, err := f.svc.FinishBrowserDecision(ctx, p, start.ID, begun.ChallengeID, []byte(`{}`)); !isErr(err, ErrCLIBindingChanged) {
		t.Fatalf("finish err = %v, want ErrCLIBindingChanged", err)
	}
}

func TestPendingDecisionAttestationsBounded(t *testing.T) {
	c := NewPendingDecisionAttestations()
	for i := 0; i < maxPendingAttestations+10; i++ {
		id := fmt.Sprintf("authz-%04d", i)
		c.Put(&PendingDecisionAttestation{
			AuthorizationID:   id,
			AttestationDigest: "sha256:" + strings.Repeat("c", 64),
			ExpiresAt:         time.Now().Add(time.Minute),
		})
	}
	if got := c.Len(); got != maxPendingAttestations {
		t.Fatalf("cache len = %d, want bounded %d", got, maxPendingAttestations)
	}
	// Expiry eviction drops stale entries.
	c2 := NewPendingDecisionAttestations()
	c2.Put(&PendingDecisionAttestation{
		AuthorizationID:   "stale",
		AttestationDigest: "sha256:" + strings.Repeat("c", 64),
		ExpiresAt:         time.Now().Add(-time.Minute),
	})
	c2.EvictExpired(time.Now())
	if c2.Len() != 0 {
		t.Fatal("expired entry was not evicted")
	}
	if _, ok := c2.Take("stale"); ok {
		t.Fatal("expired entry takeable")
	}
}

func isErr(err, want error) bool {
	if want == nil {
		return err == nil
	}
	return err != nil && (err == want || strings.Contains(err.Error(), want.Error()))
}
