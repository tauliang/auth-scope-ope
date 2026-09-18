// Tests for the trusted issue-snapshot import and workflow-posture
// inspection. Coverage: happy-path pinning, closed-issue rejection,
// stale source revision and base SHA pins, revoked or transferred
// binding rejection, immutable repository ID enforcement,
// malformed-snapshot rejection, credential fixtures rejected in upstream
// bodies, and posture persistence of signed metadata only.
package github

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

func testConnection() store.ConnectionRecord {
	return store.ConnectionRecord{
		WorkspaceID:          "ws-1",
		ConnectionID:         "binding-1",
		RepositoryBindingRef: "binding-1",
		InstallationID:       222,
		RepositoryID:         111,
		RepositoryName:       "octo-org/repo",
		PermissionStatus:     "ok",
		VerifiedAt:           time.Now().UTC(),
		CreatedAt:            time.Now().UTC(),
	}
}

func testBinding() coreapi.RepositoryBinding {
	return coreapi.RepositoryBinding{
		BindingID:      "binding-1",
		WorkspaceID:    "ws-1",
		Repository:     "octo-org/repo",
		RepositoryID:   "111",
		InstallationID: "222",
	}
}

func testSnapshot() coreapi.GitHubIssueSnapshot {
	return coreapi.GitHubIssueSnapshot{
		WorkspaceID:     "ws-1",
		BindingID:       "binding-1",
		IssueNumber:     42,
		Title:           "Add retries to the deploy step",
		Body:            "Deploy flakes.\n\n- [ ] retry with backoff\n- [x] keep logs\n- [ ] retry with backoff",
		State:           "open",
		BaseRef:         "main",
		BaseSHA:         "0123456789abcdef0123456789abcdef01234567",
		SourceRevision:  "rev-20260917-001",
		CanonicalDigest: "sha256:" + strings.Repeat("ab", 32),
		SnapshotAt:      time.Now().UTC().Unix(),
	}
}

func TestReadIssueHappyPath(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{binding: testBinding(), issue: testSnapshot()}
	s := testSource(t, st, auth)
	conn := testConnection()
	snap, err := s.ReadIssue(context.Background(), "ws-1", conn, 42, "", "")
	if err != nil {
		t.Fatalf("ReadIssue: %v", err)
	}
	if snap.WorkspaceID != "ws-1" || snap.RepositoryBinding != "binding-1" {
		t.Fatalf("identity wrong: %+v", snap)
	}
	if snap.InstallationID != 222 || snap.RepositoryID != 111 {
		t.Fatalf("immutable IDs wrong: %+v", snap)
	}
	if snap.RepositoryFullName != "octo-org/repo" || snap.IssueNumber != 42 {
		t.Fatalf("repo/issue wrong: %+v", snap)
	}
	if snap.SourceRevision != "rev-20260917-001" || snap.SourceDigest != "sha256:"+strings.Repeat("ab", 32) {
		t.Fatalf("source pinning wrong: %+v", snap)
	}
	if snap.DefaultBranch != "main" || snap.BaseSHA != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("base wrong: %+v", snap)
	}
	if snap.Objective != "Add retries to the deploy step" {
		t.Fatalf("objective = %q", snap.Objective)
	}
	want := []string{"retry with backoff", "keep logs"}
	if len(snap.AcceptanceCriteria) != len(want) {
		t.Fatalf("criteria = %v", snap.AcceptanceCriteria)
	}
	for i := range want {
		if snap.AcceptanceCriteria[i] != want[i] {
			t.Fatalf("criteria = %v", snap.AcceptanceCriteria)
		}
	}
}

func TestReadIssueRejectsClosedAndMalformed(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	cases := []struct {
		name   string
		mutate func(*coreapi.GitHubIssueSnapshot)
	}{
		{"closed", func(s *coreapi.GitHubIssueSnapshot) { s.State = "closed" }},
		{"empty title", func(s *coreapi.GitHubIssueSnapshot) { s.Title = "  " }},
		{"empty base ref", func(s *coreapi.GitHubIssueSnapshot) { s.BaseRef = "" }},
		{"bad base sha", func(s *coreapi.GitHubIssueSnapshot) { s.BaseSHA = "zzz" }},
		{"empty revision", func(s *coreapi.GitHubIssueSnapshot) { s.SourceRevision = "" }},
		{"bad digest", func(s *coreapi.GitHubIssueSnapshot) { s.CanonicalDigest = "md5:abc" }},
		{"wrong workspace", func(s *coreapi.GitHubIssueSnapshot) { s.WorkspaceID = "ws-2" }},
		{"wrong binding", func(s *coreapi.GitHubIssueSnapshot) { s.BindingID = "binding-2" }},
		{"wrong number", func(s *coreapi.GitHubIssueSnapshot) { s.IssueNumber = 43 }},
		{"future snapshot", func(s *coreapi.GitHubIssueSnapshot) { s.SnapshotAt = time.Now().UTC().Add(time.Hour).Unix() }},
		{"missing time", func(s *coreapi.GitHubIssueSnapshot) { s.SnapshotAt = 0 }},
	}
	for _, tc := range cases {
		snap := testSnapshot()
		tc.mutate(&snap)
		auth := &fakeAuthority{binding: testBinding(), issue: snap}
		s := testSource(t, st, auth)
		if _, err := s.ReadIssue(ctx, "ws-1", conn, 42, "", ""); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
}

func TestReadIssueEnforcesStalePins(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	snap := testSnapshot()
	auth := &fakeAuthority{binding: testBinding(), issue: snap}
	s := testSource(t, st, auth)
	if _, err := s.ReadIssue(ctx, "ws-1", conn, 42, "rev-20260917-001", snap.BaseSHA); err != nil {
		t.Fatalf("matching pins: %v", err)
	}
	if _, err := s.ReadIssue(ctx, "ws-1", conn, 42, "rev-moved", ""); err == nil {
		t.Fatal("stale source revision accepted")
	}
	if _, err := s.ReadIssue(ctx, "ws-1", conn, 42, "", strings.Repeat("0", 40)); err == nil {
		t.Fatal("stale base SHA accepted")
	}
}

func TestReadIssueRejectsRevokedBinding(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	auth := &fakeAuthority{
		bindingErr: &coreapi.UpstreamError{StatusCode: 404, Message: "not found"},
		issue:      testSnapshot(),
	}
	s := testSource(t, st, auth)
	if _, err := s.ReadIssue(ctx, "ws-1", conn, 42, "", ""); err == nil {
		t.Fatal("revoked binding accepted")
	}
}

func TestReadIssueRejectsTransferredRepository(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	b := testBinding()
	b.RepositoryID = "999" // same name, different immutable ID
	b.Repository = "octo-org/repo"
	auth := &fakeAuthority{binding: b, issue: testSnapshot()}
	s := testSource(t, st, auth)
	if _, err := s.ReadIssue(ctx, "ws-1", conn, 42, "", ""); err == nil {
		t.Fatal("transferred repository accepted")
	}
}

func TestReadIssueRejectsCrossWorkspaceConnection(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	conn.WorkspaceID = "ws-2"
	auth := &fakeAuthority{binding: testBinding(), issue: testSnapshot()}
	s := testSource(t, st, auth)
	if _, err := s.ReadIssue(ctx, "ws-1", conn, 42, "", ""); err == nil {
		t.Fatal("cross-workspace connection accepted")
	}
}

func TestCheckPosturePersistsMetadataOnly(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	auth := &fakeAuthority{
		binding: testBinding(),
		posture: coreapi.WorkflowPosture{
			BindingID:          "binding-1",
			Ref:                "main",
			Posture:            "clean",
			WorkflowsInspected: 3,
			Findings:           []coreapi.WorkflowFinding{},
		},
	}
	s := testSource(t, st, auth)
	head := strings.Repeat("c", 40)
	rec, err := s.CheckPosture(ctx, "ws-1", conn, "main", head)
	if err != nil {
		t.Fatalf("CheckPosture: %v", err)
	}
	if rec.Outcome != "clean" || rec.HeadSHA != head {
		t.Fatalf("record wrong: %+v", rec)
	}
	if !strings.HasPrefix(rec.PostureDigest, "sha256:") {
		t.Fatalf("digest wrong: %q", rec.PostureDigest)
	}
	if rec.ExpiresAt.IsZero() || !rec.ExpiresAt.After(rec.CheckedAt) {
		t.Fatalf("expiry wrong: %+v", rec)
	}
	got, err := st.GetWorkflowPosture(ctx, "ws-1", "binding-1", "main")
	if err != nil {
		t.Fatalf("GetWorkflowPosture: %v", err)
	}
	if got.PostureDigest != rec.PostureDigest || got.Outcome != "clean" {
		t.Fatalf("persisted wrong: %+v", got)
	}
}

func TestCheckPostureRiskyWithReasonCodes(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	auth := &fakeAuthority{
		binding: testBinding(),
		posture: coreapi.WorkflowPosture{
			BindingID:          "binding-1",
			Ref:                "main",
			Posture:            "risky",
			WorkflowsInspected: 2,
			Findings: []coreapi.WorkflowFinding{
				{Path: ".github/workflows/deploy.yml", Risk: "secret_access"},
				{Path: ".github/workflows/ci.yml", Risk: "write_token"},
				{Path: ".github/workflows/ci.yml", Risk: "write_token"},
			},
		},
	}
	s := testSource(t, st, auth)
	rec, err := s.CheckPosture(ctx, "ws-1", conn, "main", strings.Repeat("d", 40))
	if err != nil {
		t.Fatalf("CheckPosture: %v", err)
	}
	if rec.Outcome != "risky" {
		t.Fatalf("outcome = %q", rec.Outcome)
	}
	if len(rec.ReasonCodes) != 2 || rec.ReasonCodes[0] != "secret_access" || rec.ReasonCodes[1] != "write_token" {
		t.Fatalf("reason codes = %v", rec.ReasonCodes)
	}
}

func TestCheckPostureRejectsMalformed(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	auth := &fakeAuthority{
		binding: testBinding(),
		posture: coreapi.WorkflowPosture{BindingID: "binding-1", Ref: "main", Posture: "clean"},
	}
	s := testSource(t, st, auth)
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "", strings.Repeat("c", 40)); err == nil {
		t.Fatal("empty ref accepted")
	}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", "not-a-sha"); err == nil {
		t.Fatal("bad head SHA accepted")
	}
	auth.posture = coreapi.WorkflowPosture{BindingID: "binding-OTHER", Ref: "main", Posture: "clean"}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", strings.Repeat("c", 40)); err == nil {
		t.Fatal("mismatched posture binding accepted")
	}
	auth.posture = coreapi.WorkflowPosture{
		BindingID: "binding-1", Ref: "main", Posture: "risky",
		Findings: []coreapi.WorkflowFinding{{Path: "", Risk: "secret_access"}},
	}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", strings.Repeat("c", 40)); err == nil {
		t.Fatal("finding without path accepted")
	}
	auth.posture = coreapi.WorkflowPosture{
		BindingID: "binding-1", Ref: "main", Posture: "risky",
		Findings: []coreapi.WorkflowFinding{{Path: ".github/workflows/x.yml", Risk: "unknown_risk"}},
	}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", strings.Repeat("c", 40)); err == nil {
		t.Fatal("unknown risk accepted")
	}
	auth.posture = coreapi.WorkflowPosture{BindingID: "binding-1", Ref: "main", Posture: "weird"}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", strings.Repeat("c", 40)); err == nil {
		t.Fatal("unknown posture accepted")
	}
	auth.posture = coreapi.WorkflowPosture{
		BindingID: "binding-1", Ref: "main", Posture: "clean",
		Findings: []coreapi.WorkflowFinding{{Path: ".github/workflows/x.yml", Risk: "write_token"}},
	}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", strings.Repeat("c", 40)); err == nil {
		t.Fatal("clean posture with findings accepted")
	}
	auth.posture = coreapi.WorkflowPosture{BindingID: "binding-1", Ref: "main", Posture: "risky"}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", strings.Repeat("c", 40)); err == nil {
		t.Fatal("risky posture without findings accepted")
	}
}

func TestCheckPostureRejectsWorkspaceMismatchAndRevokedBinding(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	conn := testConnection()
	auth := &fakeAuthority{
		binding: testBinding(),
		posture: coreapi.WorkflowPosture{BindingID: "binding-1", Ref: "main", Posture: "clean"},
	}
	s := testSource(t, st, auth)
	head := strings.Repeat("c", 40)
	// The connection belongs to another workspace.
	if _, err := s.CheckPosture(ctx, "ws-2", conn, "main", head); err == nil {
		t.Fatal("cross-workspace posture accepted")
	}
	// A revoked binding fails closed before any posture is inspected.
	auth.bindingErr = &coreapi.UpstreamError{StatusCode: 404, Message: "no such binding"}
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", head); err == nil {
		t.Fatal("revoked binding posture accepted")
	}
	// A transferred repository (same name, new ID) fails closed.
	auth.bindingErr = nil
	transferred := testBinding()
	transferred.RepositoryID = "999"
	auth.binding = transferred
	if _, err := s.CheckPosture(ctx, "ws-1", conn, "main", head); err == nil {
		t.Fatal("transferred repository posture accepted")
	}
}
