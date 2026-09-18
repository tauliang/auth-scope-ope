package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeDoctorAuthority scripts every doctor upstream probe.
type fakeDoctorAuthority struct {
	discovery    coreapi.Discovery
	discoveryErr error
	identity     coreapi.WorkspaceIdentity
	identityErr  error
	keys         coreapi.SigningKeyHistory
	keysErr      error
	binding      coreapi.RepositoryBinding
	bindingErr   error
	posture      coreapi.WorkflowPosture
	postureErr   error
	kits         []coreapi.AgentKit
	kitsErr      error
	serverTime   time.Time
	serverErr    error
}

var _ coreapi.Authority = (*fakeDoctorAuthority)(nil)
var _ doctorAuthority = (*fakeDoctorAuthority)(nil)

func (f *fakeDoctorAuthority) Discover(ctx context.Context) (coreapi.Discovery, error) {
	return f.discovery, f.discoveryErr
}
func (f *fakeDoctorAuthority) VerifyWorkspaceIdentity(ctx context.Context, ws string) (coreapi.WorkspaceIdentity, error) {
	if f.identityErr != nil {
		return coreapi.WorkspaceIdentity{}, f.identityErr
	}
	out := f.identity
	out.WorkspaceID = ws
	return out, nil
}
func (f *fakeDoctorAuthority) GetSigningKeys(ctx context.Context, opts coreapi.RequestOptions) (coreapi.SigningKeyHistory, error) {
	return f.keys, f.keysErr
}
func (f *fakeDoctorAuthority) GetRepositoryBinding(ctx context.Context, id string, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return f.binding, f.bindingErr
}
func (f *fakeDoctorAuthority) InspectWorkflowPosture(ctx context.Context, in coreapi.WorkflowPostureRequest, opts coreapi.RequestOptions) (coreapi.WorkflowPosture, error) {
	return f.posture, f.postureErr
}
func (f *fakeDoctorAuthority) ListAgentKits(ctx context.Context, opts coreapi.RequestOptions) ([]coreapi.AgentKit, error) {
	return f.kits, f.kitsErr
}
func (f *fakeDoctorAuthority) ServerTime(ctx context.Context) (time.Time, error) {
	return f.serverTime, f.serverErr
}
func (f *fakeDoctorAuthority) BeginGitHubBinding(ctx context.Context, in coreapi.GitHubBindingBeginRequest, opts coreapi.RequestOptions) (coreapi.GitHubBindingHandoff, error) {
	return coreapi.GitHubBindingHandoff{}, nil
}
func (f *fakeDoctorAuthority) FinishGitHubBinding(ctx context.Context, in coreapi.GitHubBindingFinishRequest, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return coreapi.RepositoryBinding{}, nil
}
func (f *fakeDoctorAuthority) ReadGitHubIssue(ctx context.Context, in coreapi.GitHubIssueRequest, opts coreapi.RequestOptions) (coreapi.GitHubIssueSnapshot, error) {
	return coreapi.GitHubIssueSnapshot{}, nil
}
func (f *fakeDoctorAuthority) ShapeMission(ctx context.Context, in coreapi.ShapeMissionRequest, opts coreapi.RequestOptions) (coreapi.MissionDraft, error) {
	return coreapi.MissionDraft{}, nil
}
func (f *fakeDoctorAuthority) CreateProposal(ctx context.Context, in coreapi.CreateProposalRequest, opts coreapi.RequestOptions) (coreapi.Proposal, error) {
	return coreapi.Proposal{}, nil
}
func (f *fakeDoctorAuthority) ApproveProposal(ctx context.Context, s string, in coreapi.ApproveProposalInput, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Mission, error) {
	return coreapi.Mission{}, nil
}
func (f *fakeDoctorAuthority) PrepareLaunch(ctx context.Context, s string, in coreapi.LaunchRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.LaunchArtifacts, error) {
	return coreapi.LaunchArtifacts{}, nil
}
func (f *fakeDoctorAuthority) IntrospectMission(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.MissionStatus, error) {
	return coreapi.MissionStatus{}, nil
}
func (f *fakeDoctorAuthority) RevokeMission(ctx context.Context, s string, in coreapi.RevokeRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.Revocation, error) {
	return coreapi.Revocation{}, nil
}
func (f *fakeDoctorAuthority) ListExpansions(ctx context.Context, s string, opts coreapi.RequestOptions) ([]coreapi.Expansion, error) {
	return nil, nil
}
func (f *fakeDoctorAuthority) GetExpansion(ctx context.Context, s string, opts coreapi.RequestOptions) (json.RawMessage, error) {
	return nil, nil
}
func (f *fakeDoctorAuthority) DecideExpansion(ctx context.Context, s string, in coreapi.ExpansionDecision, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.ExpansionResult, error) {
	return coreapi.ExpansionResult{}, nil
}
func (f *fakeDoctorAuthority) ReadEvents(ctx context.Context, s1, s2 string, opts coreapi.RequestOptions) (coreapi.EventPage, error) {
	return coreapi.EventPage{}, nil
}
func (f *fakeDoctorAuthority) GetReceipt(ctx context.Context, s string, opts coreapi.RequestOptions) (coreapi.SignedReceiptEnvelope, error) {
	return coreapi.SignedReceiptEnvelope{}, nil
}
func (f *fakeDoctorAuthority) PublishGitHubCheck(ctx context.Context, in coreapi.GitHubCheckRequest, opts coreapi.RequestOptions) (coreapi.GitHubCheckResult, error) {
	return coreapi.GitHubCheckResult{}, nil
}
func (f *fakeDoctorAuthority) ReconcileOperation(ctx context.Context, s1, s2 string, opts coreapi.RequestOptions) (coreapi.OperationResult, error) {
	return coreapi.OperationResult{}, nil
}
func (f *fakeDoctorAuthority) ContainWorkspace(ctx context.Context, req coreapi.WorkspaceContainmentRequest, att identity.SignedDecisionAttestation, opts coreapi.RequestOptions) (coreapi.WorkspaceContainment, error) {
	return coreapi.WorkspaceContainment{}, nil
}
func (f *fakeDoctorAuthority) ListActiveMissions(ctx context.Context, opts coreapi.RequestOptions) ([]coreapi.ActiveMission, error) {
	return nil, nil
}

// repoRoot finds the repository root by walking up from this test file
// to the directory containing contracts/.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "contracts", "authscope.lock.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

// doctorFixture builds a bound instance doctor can inspect.
type doctorFixture struct {
	dir    string
	signer *identity.EphemeralSigner
	digest string
	now    time.Time
}

func setupDoctorFixture(t *testing.T, ctx context.Context) *doctorFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	signer := identity.NewEphemeralSigner()
	digest := signer.IdentityDigest()
	st, err := store.Open(dir, "development")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.BindInstance(ctx, store.InstanceRecord{
			InstanceID:        "inst-1",
			WorkspaceID:       "ws-doc-1",
			Hostname:          "doc-host",
			Origin:            "https://doc-host:8443",
			RPID:              "doc-host",
			SessionCookieName: store.DeriveSessionCookieName("inst-1"),
			CreatedAt:         time.Now().UTC(),
		}); err != nil {
			return err
		}
		return tx.AttachWorkloadIdentity(ctx, "", digest)
	}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return &doctorFixture{dir: dir, signer: signer, digest: digest, now: time.Now().UTC()}
}

func healthyAuthority(fx *doctorFixture) *fakeDoctorAuthority {
	return &fakeDoctorAuthority{
		discovery: coreapi.Discovery{
			Version:       "1.0.0",
			OpenAPISHA256: "sha256:" + strings.Repeat("a", 64),
			Capabilities:  []string{},
		},
		identity: coreapi.WorkspaceIdentity{
			IdentityID:     "wid-1",
			IdentityDigest: fx.digest,
			Roles:          []string{coreapi.DecisionAttestorRole},
		},
		keys:       coreapi.SigningKeyHistory{Keys: []coreapi.SigningKeyRecord{}},
		posture:    coreapi.WorkflowPosture{Posture: coreapi.WorkflowPostureClean},
		kits:       []coreapi.AgentKit{{KitID: "kit-1", Name: "Kit", Version: "1"}},
		serverTime: fx.now,
	}
}

func runDoctorTest(t *testing.T, ctx context.Context, fx *doctorFixture, fa *fakeDoctorAuthority, mutate func(*DoctorConfig)) []DoctorCheck {
	t.Helper()
	out := &bytes.Buffer{}
	// A runner fixture with owner-only-writable permissions.
	runnerPath := filepath.Join(t.TempDir(), "runner")
	if err := os.WriteFile(runnerPath, []byte("#!/bin/sh\necho test-1.0\n"), 0o755); err != nil {
		t.Fatalf("write runner fixture: %v", err)
	}
	cfg := DoctorConfig{
		DataDir:           fx.dir,
		Mode:              "development",
		AuthScopeURL:      "https://authscope.example",
		WorkspaceID:       "ws-doc-1",
		Hostname:          "doc-host",
		Origin:            "https://doc-host:8443",
		RPID:              "doc-host",
		InstanceID:        "inst-1",
		SessionCookieName: store.DeriveSessionCookieName("inst-1"),
		RunnerPath:        runnerPath,
		RootDir:           repoRoot(t),
		BindAddr:          "127.0.0.1:8080",
		Signer:            fx.signer,
		Out:               out,
		Clock:             func() time.Time { return fx.now },
		OpenStore:         store.Open,
		NewAuthority:      func(string, identity.Signer, string) (coreapi.Authority, error) { return fa, nil },
		RunnerVersion:     func(ctx context.Context, path string) (string, error) { return "test-1.0", nil },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	checks, err := RunDoctor(ctx, cfg)
	if err != nil {
		t.Fatalf("RunDoctor: %v", err)
	}
	return checks
}

func checkByName(checks []DoctorCheck, name string) DoctorCheck {
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	return DoctorCheck{Name: name, Reason: "check missing"}
}

func TestDoctorHealthy(t *testing.T) {
	ctx := context.Background()
	fx := setupDoctorFixture(t, ctx)
	fa := healthyAuthority(fx)
	// The vendored discovery must satisfy the real compatibility gate;
	// use the actual locked contract values.
	lock := coreapi.LockedContract()
	fa.discovery.Version = lock.CoreVersion
	fa.discovery.OpenAPISHA256 = lock.OpenAPISHA256
	for _, op := range coreapi.RequiredManifest().RequiredOperations {
		fa.discovery.Capabilities = append(fa.discovery.Capabilities, op.Capability)
	}
	checks := runDoctorTest(t, ctx, fx, fa, nil)
	for _, c := range checks {
		if !c.Pass {
			t.Errorf("check %s failed: %s", c.Name, c.Reason)
		}
	}
}

func TestDoctorReadOnly(t *testing.T) {
	// Doctor must not rewrite the binding or attach identity: run it
	// against a binding with no digest attached and verify the digest
	// is still empty afterwards.
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	st, err := store.Open(dir, "development")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.BindInstance(ctx, store.InstanceRecord{
			InstanceID:        "inst-1",
			WorkspaceID:       "ws-doc-1",
			Hostname:          "doc-host",
			Origin:            "https://doc-host:8443",
			RPID:              "doc-host",
			SessionCookieName: store.DeriveSessionCookieName("inst-1"),
			CreatedAt:         time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	st.Close()

	fx := &doctorFixture{dir: dir, signer: identity.NewEphemeralSigner(), now: time.Now().UTC()}
	fa := healthyAuthority(fx)
	fa.identity.IdentityDigest = ""
	checks := runDoctorTest(t, ctx, fx, fa, nil)
	if got := checkByName(checks, "workload_identity_digest"); got.Pass {
		t.Error("digest check passed with no digest attached")
	}
	st2, err := store.Open(dir, "development")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	inst, err := st2.GetInstance(ctx)
	if err != nil {
		t.Fatalf("get instance: %v", err)
	}
	if inst.WorkloadIdentityDigest != "" {
		t.Error("doctor attached a workload identity digest")
	}
}

func TestDoctorClockSkew(t *testing.T) {
	ctx := context.Background()
	fx := setupDoctorFixture(t, ctx)
	fa := healthyAuthority(fx)
	lock := coreapi.LockedContract()
	fa.discovery.Version = lock.CoreVersion
	fa.discovery.OpenAPISHA256 = lock.OpenAPISHA256
	for _, op := range coreapi.RequiredManifest().RequiredOperations {
		fa.discovery.Capabilities = append(fa.discovery.Capabilities, op.Capability)
	}
	fa.serverTime = fx.now.Add(-5 * time.Minute)
	checks := runDoctorTest(t, ctx, fx, fa, nil)
	if got := checkByName(checks, "clock_skew"); got.Pass {
		t.Errorf("clock_skew passed with 5m skew: %s", got.Reason)
	}
}

func TestDoctorWorkspaceMismatch(t *testing.T) {
	ctx := context.Background()
	fx := setupDoctorFixture(t, ctx)
	fa := healthyAuthority(fx)
	checks := runDoctorTest(t, ctx, fx, fa, func(cfg *DoctorConfig) {
		cfg.WorkspaceID = "other-workspace"
	})
	if got := checkByName(checks, "instance_binding"); got.Pass {
		t.Errorf("instance_binding passed despite workspace mismatch: %s", got.Reason)
	}
}

func TestDoctorMissingBinding(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	fx := &doctorFixture{dir: dir, signer: identity.NewEphemeralSigner(), now: time.Now().UTC()}
	fa := healthyAuthority(fx)
	checks := runDoctorTest(t, ctx, fx, fa, nil)
	if got := checkByName(checks, "instance_binding"); got.Pass {
		t.Error("instance_binding passed with no binding")
	}
}

func TestDoctorInsecureOrigin(t *testing.T) {
	ctx := context.Background()
	fx := setupDoctorFixture(t, ctx)
	fa := healthyAuthority(fx)
	checks := runDoctorTest(t, ctx, fx, fa, func(cfg *DoctorConfig) {
		cfg.Origin = "http://doc-host:8080"
	})
	if got := checkByName(checks, "passkey_secure_context"); got.Pass {
		t.Errorf("passkey_secure_context passed for non-loopback http: %s", got.Reason)
	}
}

func TestDoctorNonLoopbackBind(t *testing.T) {
	ctx := context.Background()
	fx := setupDoctorFixture(t, ctx)
	fa := healthyAuthority(fx)
	checks := runDoctorTest(t, ctx, fx, fa, func(cfg *DoctorConfig) {
		cfg.BindAddr = "0.0.0.0:8080"
	})
	if got := checkByName(checks, "isolation"); got.Pass {
		t.Errorf("isolation passed for 0.0.0.0 bind: %s", got.Reason)
	}
}

func TestDoctorRiskyPosture(t *testing.T) {
	ctx := context.Background()
	fx := setupDoctorFixture(t, ctx)
	// Add a GitHub connection so the posture check has something to
	// inspect.
	st, err := store.Open(fx.dir, "development")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutConnection(ctx, store.ConnectionRecord{
			WorkspaceID:          "ws-doc-1",
			ConnectionID:         "conn-1",
			RepositoryBindingRef: "binding-1",
			RepositoryID:         1,
			RepositoryName:       "org/repo",
			CreatedAt:            time.Now().UTC(),
		})
	}); err != nil {
		t.Fatalf("put connection: %v", err)
	}
	st.Close()

	fa := healthyAuthority(fx)
	fa.binding = coreapi.RepositoryBinding{BindingID: "binding-1", WorkspaceID: "ws-doc-1"}
	fa.posture = coreapi.WorkflowPosture{Posture: coreapi.WorkflowPostureRisky,
		Findings: []coreapi.WorkflowFinding{{Path: ".github/workflows/x.yml"}}}
	checks := runDoctorTest(t, ctx, fx, fa, nil)
	if got := checkByName(checks, "github_binding"); !got.Pass {
		t.Errorf("github_binding failed: %s", got.Reason)
	}
	if got := checkByName(checks, "workflow_posture"); got.Pass {
		t.Errorf("workflow_posture passed with risky findings: %s", got.Reason)
	}
}
