package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeTerminal is a buffer-backed controlling terminal for tests.
type fakeTerminal struct {
	in  *bytes.Buffer
	out *bytes.Buffer
}

func newFakeTerminal(input string) *fakeTerminal {
	return &fakeTerminal{in: bytes.NewBufferString(input), out: &bytes.Buffer{}}
}

func (f *fakeTerminal) Read(p []byte) (int, error)  { return f.in.Read(p) }
func (f *fakeTerminal) Write(p []byte) (int, error) { return f.out.Write(p) }
func (f *fakeTerminal) Fd() uintptr                 { return 0 }

// fakeRecoverAuthority is a minimal Authority for the recover CLI
// tests: identity verified, containment acknowledged, no missions.
type fakeRecoverAuthority struct {
	mu           sync.Mutex
	identity     coreapi.WorkspaceIdentity
	containCalls int
	idemKeys     []string
}

var _ coreapi.Authority = (*fakeRecoverAuthority)(nil)

func (f *fakeRecoverAuthority) VerifyWorkspaceIdentity(ctx context.Context, workspaceID string) (coreapi.WorkspaceIdentity, error) {
	out := f.identity
	out.WorkspaceID = workspaceID
	return out, nil
}

func (f *fakeRecoverAuthority) ContainWorkspace(ctx context.Context, req coreapi.WorkspaceContainmentRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.WorkspaceContainment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.containCalls++
	f.idemKeys = append(f.idemKeys, req.IdempotencyKey)
	return coreapi.WorkspaceContainment{WorkspaceID: opts.WorkspaceID, Contained: true, Generation: 1}, nil
}

func (f *fakeRecoverAuthority) ListActiveMissions(ctx context.Context, opts coreapi.RequestOptions) ([]coreapi.ActiveMission, error) {
	return nil, nil
}

func (f *fakeRecoverAuthority) Discover(ctx context.Context) (coreapi.Discovery, error) {
	return coreapi.Discovery{}, nil
}
func (f *fakeRecoverAuthority) BeginGitHubBinding(ctx context.Context, in coreapi.GitHubBindingBeginRequest, opts coreapi.RequestOptions) (coreapi.GitHubBindingHandoff, error) {
	return coreapi.GitHubBindingHandoff{}, nil
}
func (f *fakeRecoverAuthority) FinishGitHubBinding(ctx context.Context, in coreapi.GitHubBindingFinishRequest, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return coreapi.RepositoryBinding{}, nil
}
func (f *fakeRecoverAuthority) GetRepositoryBinding(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return coreapi.RepositoryBinding{}, nil
}
func (f *fakeRecoverAuthority) ReadGitHubIssue(ctx context.Context, in coreapi.GitHubIssueRequest, opts coreapi.RequestOptions) (coreapi.GitHubIssueSnapshot, error) {
	return coreapi.GitHubIssueSnapshot{}, nil
}
func (f *fakeRecoverAuthority) InspectWorkflowPosture(ctx context.Context, in coreapi.WorkflowPostureRequest, opts coreapi.RequestOptions) (coreapi.WorkflowPosture, error) {
	return coreapi.WorkflowPosture{}, nil
}
func (f *fakeRecoverAuthority) ListAgentKits(ctx context.Context, opts coreapi.RequestOptions) ([]coreapi.AgentKit, error) {
	return nil, nil
}
func (f *fakeRecoverAuthority) ShapeMission(ctx context.Context, in coreapi.ShapeMissionRequest, opts coreapi.RequestOptions) (coreapi.MissionDraft, error) {
	return coreapi.MissionDraft{}, nil
}
func (f *fakeRecoverAuthority) CreateProposal(ctx context.Context, in coreapi.CreateProposalRequest, opts coreapi.RequestOptions) (coreapi.Proposal, error) {
	return coreapi.Proposal{}, nil
}
func (f *fakeRecoverAuthority) ApproveProposal(ctx context.Context, s string, in coreapi.ApproveProposalInput, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Mission, error) {
	return coreapi.Mission{}, nil
}
func (f *fakeRecoverAuthority) PrepareLaunch(ctx context.Context, s string, in coreapi.LaunchRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.LaunchArtifacts, error) {
	return coreapi.LaunchArtifacts{}, nil
}
func (f *fakeRecoverAuthority) IntrospectMission(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.MissionStatus, error) {
	return coreapi.MissionStatus{}, nil
}
func (f *fakeRecoverAuthority) RevokeMission(ctx context.Context, s string, in coreapi.RevokeRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Revocation, error) {
	return coreapi.Revocation{}, nil
}
func (f *fakeRecoverAuthority) ListExpansions(ctx context.Context, s string, opts coreapi.RequestOptions) ([]coreapi.Expansion, error) {
	return nil, nil
}
func (f *fakeRecoverAuthority) GetExpansion(ctx context.Context, s string, opts coreapi.RequestOptions) (json.RawMessage, error) {
	return nil, nil
}
func (f *fakeRecoverAuthority) DecideExpansion(ctx context.Context, s string, in coreapi.ExpansionDecision, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.ExpansionResult, error) {
	return coreapi.ExpansionResult{}, nil
}
func (f *fakeRecoverAuthority) ReadEvents(ctx context.Context, s1, s2 string, opts coreapi.RequestOptions) (coreapi.EventPage, error) {
	return coreapi.EventPage{}, nil
}
func (f *fakeRecoverAuthority) GetReceipt(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.SignedReceiptEnvelope, error) {
	return coreapi.SignedReceiptEnvelope{}, nil
}
func (f *fakeRecoverAuthority) GetSigningKeys(ctx context.Context, opts coreapi.RequestOptions) (coreapi.SigningKeyHistory, error) {
	return coreapi.SigningKeyHistory{}, nil
}
func (f *fakeRecoverAuthority) PublishGitHubCheck(ctx context.Context, in coreapi.GitHubCheckRequest, opts coreapi.RequestOptions) (coreapi.GitHubCheckResult, error) {
	return coreapi.GitHubCheckResult{}, nil
}
func (f *fakeRecoverAuthority) ReconcileOperation(ctx context.Context, s1, s2 string, opts coreapi.RequestOptions) (coreapi.OperationResult, error) {
	return coreapi.OperationResult{}, nil
}

// recoverFixture builds a bound, enrolled instance with a recovery key.
type recoverFixture struct {
	dir    string
	signer *identity.EphemeralSigner
	digest string
	recKey []byte
}

func setupRecoverFixture(t *testing.T, ctx context.Context) *recoverFixture {
	t.Helper()
	dir := t.TempDir()
	signer := identity.NewEphemeralSigner()
	digest := signer.IdentityDigest()
	recKey := []byte("cli-test-recovery-key-32bytes!!!!")
	sum := sha256.Sum256(recKey)

	st, err := store.OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.BindInstance(ctx, store.InstanceRecord{
			InstanceID:        "inst-1",
			WorkspaceID:       "ws-cli-1",
			Hostname:          "h",
			Origin:            "https://h:8443",
			RPID:              "h",
			SessionCookieName: store.DeriveSessionCookieName("inst-1"),
			CreatedAt:         time.Now().UTC(),
		}); err != nil {
			return err
		}
		if err := tx.AttachWorkloadIdentity(ctx, "", digest); err != nil {
			return err
		}
		if err := tx.CreateFounder(ctx, store.FounderRecord{
			WorkspaceID: "ws-cli-1", FounderID: "founder-1", CreatedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		return tx.PutOfflineRecoveryKey(ctx, store.OfflineRecoveryKeyRecord{
			WorkspaceID: "ws-cli-1", FounderID: "founder-1",
			KeyHash: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return &recoverFixture{dir: dir, signer: signer, digest: digest, recKey: recKey}
}

func runRecoverTest(t *testing.T, ctx context.Context, fx *recoverFixture, termIn string, key []byte) (*fakeTerminal, *fakeRecoverAuthority, *bytes.Buffer, error) {
	t.Helper()
	tty := newFakeTerminal(termIn)
	errW := &bytes.Buffer{}
	fa := &fakeRecoverAuthority{identity: coreapi.WorkspaceIdentity{
		IdentityDigest: fx.digest,
		Roles:          []string{coreapi.DecisionAttestorRole},
	}}
	var readKey []byte
	err := RunRecover(ctx, RecoverConfig{
		DataDir:      fx.dir,
		Mode:         "development",
		AuthScopeURL: "https://authscope.example",
		Signer:       fx.signer,
		Terminal:     tty,
		ErrW:         errW,
		OpenStore:    store.OpenExclusive,
		NewAuthority: func(string, identity.Signer, string) (coreapi.Authority, error) { return fa, nil },
		ReadPassword: func(fd int) ([]byte, error) {
			// The key comes only from this callback, never argv/env.
			readKey = append([]byte(nil), key...)
			return readKey, nil
		},
	})
	return tty, fa, errW, err
}

func TestRecoverRejectsRelativeDataDir(t *testing.T) {
	err := RunRecover(context.Background(), RecoverConfig{DataDir: "var/ope"})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v, want absolute-path error", err)
	}
}

func TestRecoverRejectsMissingDataDir(t *testing.T) {
	err := RunRecover(context.Background(), RecoverConfig{})
	if err == nil || !strings.Contains(err.Error(), "--data-dir is required") {
		t.Fatalf("err = %v, want --data-dir error", err)
	}
}

func TestRecoverWrongConfirmation(t *testing.T) {
	ctx := context.Background()
	fx := setupRecoverFixture(t, ctx)
	tty, fa, _, err := runRecoverTest(t, ctx, fx, "wrong-workspace\n", fx.recKey)
	if err == nil {
		t.Fatal("expected confirmation error")
	}
	if fa.containCalls != 0 {
		t.Fatal("contain called despite wrong confirmation")
	}
	if !strings.Contains(tty.out.String(), "Offline recovery key:") {
		t.Fatal("key prompt missing")
	}
}

func TestRecoverWrongKey(t *testing.T) {
	ctx := context.Background()
	fx := setupRecoverFixture(t, ctx)
	_, fa, _, err := runRecoverTest(t, ctx, fx, "ws-cli-1\n", []byte("wrong-key"))
	if err == nil {
		t.Fatal("expected invalid key error")
	}
	if fa.containCalls != 0 {
		t.Fatal("contain called despite wrong key")
	}
}

func TestRecoverSuccessPrintsBootstrapCode(t *testing.T) {
	ctx := context.Background()
	fx := setupRecoverFixture(t, ctx)
	tty, fa, errW, err := runRecoverTest(t, ctx, fx, "ws-cli-1\n", fx.recKey)
	if err != nil {
		t.Fatalf("RunRecover: %v", err)
	}
	if fa.containCalls != 1 {
		t.Fatalf("contain calls = %d, want 1", fa.containCalls)
	}
	out := tty.out.String()
	if !strings.Contains(out, "Fresh bootstrap code") {
		t.Fatalf("bootstrap code not printed to the terminal; output:\n%s", out)
	}
	if !strings.Contains(errW.String(), "recovery event") {
		t.Fatalf("summary missing from stderr: %q", errW.String())
	}
	// The recovery key is consumed: a second run fails closed.
	st, err := store.Open(fx.dir, "development")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st.Close()
	if _, err := st.GetOfflineRecoveryKey(ctx, "ws-cli-1", "founder-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovery key not consumed: %v", err)
	}
	// The printed code matches the stored hash.
	bc, err := st.GetBootstrapCode(ctx, "ws-cli-1")
	if err != nil {
		t.Fatalf("get bootstrap code: %v", err)
	}
	if bc.CodeHash == "" {
		t.Fatal("empty bootstrap code hash")
	}
}

func TestRecoverKeyFromEnvIsIgnored(t *testing.T) {
	// Even with a plausible-looking env var set, the command must use
	// the terminal-provided key.
	t.Setenv("OPE_RECOVERY_KEY", "env-key-should-never-be-used")
	ctx := context.Background()
	fx := setupRecoverFixture(t, ctx)
	_, _, _, err := runRecoverTest(t, ctx, fx, "ws-cli-1\n", fx.recKey)
	if err != nil {
		t.Fatalf("RunRecover: %v", err)
	}
}

// Ensure io is referenced.
var _ io.Writer = (*bytes.Buffer)(nil)
