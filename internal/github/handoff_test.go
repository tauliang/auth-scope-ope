// Tests for the AuthScope-hosted GitHub App installation handoff.
// Coverage: binding-code in-memory only (restart drops raw codes),
// constant-time state and binding-code digest comparison, exact-three-
// field callback validation, one-time callback consumption, state
// mismatch, cross-workspace rejection, upstream origin rejection,
// unknown-handoff callback rejection, session binding on finish,
// reconnection replacing a revoked binding transactionally, idempotent
// begin/finish replay, and the absence of raw credential material from
// every table.
package github

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeAuthority implements the AuthScope broker surface used by the
// handoff and issue source. Callback and token material never appear
// here; fixtures are recognizably fake values only for the credential
// rejection tests.
type fakeAuthority struct {
	coreapi.Authority
	beginHandoff     coreapi.GitHubBindingHandoff
	beginErr         error
	reconcileOp      coreapi.OperationResult
	reconcileErr     error
	finishBinding    coreapi.RepositoryBinding
	finishErr        error
	binding          coreapi.RepositoryBinding
	bindingErr       error
	issue            coreapi.GitHubIssueSnapshot
	issueErr         error
	posture          coreapi.WorkflowPosture
	postureErr       error
	beginKeys        []string
	finishHandoffIDs []string
}

func (f *fakeAuthority) BeginGitHubBinding(_ context.Context, in coreapi.GitHubBindingBeginRequest, opts coreapi.RequestOptions) (coreapi.GitHubBindingHandoff, error) {
	f.beginKeys = append(f.beginKeys, opts.IdempotencyKey)
	if in.Repository == "" {
		return coreapi.GitHubBindingHandoff{}, &coreapi.UpstreamError{StatusCode: 400, Message: "repository required"}
	}
	return f.beginHandoff, f.beginErr
}

func (f *fakeAuthority) ReconcileOperation(_ context.Context, idemKey, _ string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	return f.reconcileOp, f.reconcileErr
}

func (f *fakeAuthority) FinishGitHubBinding(_ context.Context, in coreapi.GitHubBindingFinishRequest, _ coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	f.finishHandoffIDs = append(f.finishHandoffIDs, in.HandoffID)
	return f.finishBinding, f.finishErr
}

func (f *fakeAuthority) GetRepositoryBinding(_ context.Context, _ string, _ coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	return f.binding, f.bindingErr
}

func (f *fakeAuthority) ReadGitHubIssue(_ context.Context, _ coreapi.GitHubIssueRequest, _ coreapi.RequestOptions) (coreapi.GitHubIssueSnapshot, error) {
	return f.issue, f.issueErr
}

func (f *fakeAuthority) InspectWorkflowPosture(_ context.Context, _ coreapi.WorkflowPostureRequest, _ coreapi.RequestOptions) (coreapi.WorkflowPosture, error) {
	return f.posture, f.postureErr
}

func testStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testHandoff(t *testing.T, st store.Store, auth coreapi.Authority) *Handoff {
	t.Helper()
	h, err := NewHandoff(HandoffConfig{
		Store:           st,
		Authority:       auth,
		AuthScopeOrigin: "https://authscope.local",
		CompletionPath:  "/connect/github/done",
		Clock:           func() time.Time { return time.Now().UTC() },
		UpstreamTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewHandoff: %v", err)
	}
	return h
}

func testSource(t *testing.T, st store.Store, auth *fakeAuthority) *Source {
	t.Helper()
	s, err := NewSource(SourceConfig{
		Store:           st,
		Authority:       auth,
		Clock:           func() time.Time { return time.Now().UTC() },
		UpstreamTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSource: %v", err)
	}
	return s
}

// callbackQuery builds the exact three-field callback query from a begin
// result, extracting the state AuthScope round-trips from the
// installation URL.
func callbackQuery(t *testing.T, begin BeginResult, code string) url.Values {
	t.Helper()
	u, err := url.Parse(begin.InstallationURL)
	if err != nil {
		t.Fatalf("parse installation URL: %v", err)
	}
	q := u.Query()
	state := q.Get("state")
	if state == "" {
		t.Fatal("installation URL missing state")
	}
	if q.Get("handoff_id") != begin.HandoffID {
		t.Fatal("installation URL handoff mismatch")
	}
	return url.Values{
		"handoff_id": {begin.HandoffID},
		"code":       {code},
		"state":      {state},
	}
}

func beginFixture(handoffID string) coreapi.GitHubBindingHandoff {
	return coreapi.GitHubBindingHandoff{
		HandoffID:       handoffID,
		BindingCode:     "recognizably-fake-binding-code-not-a-credential",
		InstallationURL: "https://authscope.local/install/github?handoff_id=" + handoffID,
		ExpiresAt:       time.Now().UTC().Add(10 * time.Minute).Unix(),
	}
}

func TestBeginSuccessNeverExposesBindingCode(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{beginHandoff: beginFixture("upstream-handoff-1")}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-1")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if begin.HandoffID == "" {
		t.Fatal("empty handoff ID")
	}
	if !strings.HasPrefix(begin.InstallationURL, "https://authscope.local/install/github?") {
		t.Fatalf("installation URL origin wrong: %q", begin.InstallationURL)
	}
	if strings.Contains(begin.InstallationURL, "recognizably-fake-binding-code") {
		t.Fatal("binding code leaked into installation URL")
	}
	if len(auth.beginKeys) != 1 || auth.beginKeys[0] != "idem-key-1" {
		t.Fatalf("idempotency key not sent upstream: %v", auth.beginKeys)
	}
	rec, err := st.GetGitHubHandoff(ctx, "ws-1", begin.HandoffID)
	if err != nil {
		t.Fatalf("GetGitHubHandoff: %v", err)
	}
	if rec.BindingCodeDigest != "" {
		t.Fatalf("begin persisted a code digest before callback: %q", rec.BindingCodeDigest)
	}
	if strings.Contains(rec.StateHash, "recognizably-fake-binding-code") {
		t.Fatal("state hash leaks binding code")
	}
}

func TestBeginRejectsInvalidRepositoryNames(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	for _, repo := range []string{
		"", "noslash", "org/", "/repo", "org/re po",
		strings.Repeat("a", 200) + "/repo",
		"org/../repo", "org/repo?x=1", "github.com/org/repo",
	} {
		if _, err := h.Begin(ctx, "ws-1", "sess-1", repo, "idem"); err == nil {
			t.Fatalf("repository %q accepted", repo)
		}
	}
	if len(auth.beginKeys) != 0 {
		t.Fatalf("invalid names reached upstream: %v", auth.beginKeys)
	}
}

func TestBeginRejectsUpstreamOriginMismatch(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{beginHandoff: coreapi.GitHubBindingHandoff{
		HandoffID:       "upstream-handoff-6",
		BindingCode:     "binding-code-6",
		InstallationURL: "https://attacker.example/install/github",
		ExpiresAt:       time.Now().UTC().Add(10 * time.Minute).Unix(),
	}}
	h := testHandoff(t, st, auth)
	if _, err := h.Begin(context.Background(), "ws-1", "sess-1", "octo-org/repo", "idem-key-8"); err == nil {
		t.Fatal("foreign installation URL origin accepted")
	}
	// No handoff row may be minted when the origin check fails.
	if _, err := st.GetGitHubHandoffByID(context.Background(), "upstream-handoff-6"); err == nil {
		t.Fatal("handoff row minted despite origin mismatch")
	}
}

func TestBeginIdempotentReplay(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{beginHandoff: beginFixture("upstream-handoff-r")}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	first, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-r")
	if err != nil {
		t.Fatalf("first Begin: %v", err)
	}
	second, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-r")
	if err != nil {
		t.Fatalf("replayed Begin: %v", err)
	}
	if second.HandoffID != first.HandoffID || second.InstallationURL != first.InstallationURL {
		t.Fatalf("replay mismatch: %+v vs %+v", first, second)
	}
	if len(auth.beginKeys) != 1 {
		t.Fatalf("replay called upstream again: %v", auth.beginKeys)
	}
}

func TestCallbackAcceptsExactlyThreeFields(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{beginHandoff: beginFixture("upstream-handoff-2")}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-2")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	good := callbackQuery(t, begin, "one-use-code")
	redirect, err := h.RecordCallback(ctx, good)
	if err != nil {
		t.Fatalf("RecordCallback: %v", err)
	}
	if redirect != "/connect/github/done" {
		t.Fatalf("redirect = %q", redirect)
	}
	if strings.Contains(redirect, "one-use-code") {
		t.Fatal("redirect leaks callback code")
	}

	state := good.Get("state")
	bads := []url.Values{
		{"handoff_id": {begin.HandoffID}, "code": {"c"}, "state": {state}, "extra": {"x"}},
		{"handoff_id": {begin.HandoffID}, "code": {"c"}},
		{"handoff_id": {begin.HandoffID}, "code": {"c"}, "state": {state, "dup"}},
		{"handoff_id": {begin.HandoffID}, "code": {"c"}, "state": {state[:len(state)-1] + "0"}},
		{"handoff_id": {"other"}, "code": {"c"}, "state": {state}},
		{"handoff_id": {begin.HandoffID}, "code": {""}, "state": {state}},
		{"handoff_id": {"no-such-handoff"}, "code": {"c"}, "state": {state}},
	}
	for i, q := range bads {
		if _, err := h.RecordCallback(ctx, q); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestCallbackReplayIsOneTime(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{beginHandoff: beginFixture("upstream-handoff-3")}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-3")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	q := callbackQuery(t, begin, "one-use-code-3")
	if _, err := h.RecordCallback(ctx, q); err != nil {
		t.Fatalf("first callback: %v", err)
	}
	if _, err := h.RecordCallback(ctx, q); err == nil {
		t.Fatal("replayed callback accepted")
	}
	// The durable digest is the SHA-256 of the code, never the code.
	rec, err := st.GetGitHubHandoff(ctx, "ws-1", begin.HandoffID)
	if err != nil {
		t.Fatalf("GetGitHubHandoff: %v", err)
	}
	if len(rec.BindingCodeDigest) != 64 || strings.Contains(rec.BindingCodeDigest, "one-use-code") {
		t.Fatalf("code digest wrong: %q", rec.BindingCodeDigest)
	}
}

func TestFinishHappyPathConsumesHandoff(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-4"),
		finishBinding: coreapi.RepositoryBinding{
			BindingID:      "binding-4",
			WorkspaceID:    "ws-1",
			Repository:     "octo-org/repo",
			RepositoryID:   "111",
			InstallationID: "222",
		},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-4")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-4")); err != nil {
		t.Fatalf("callback: %v", err)
	}
	done, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-5")
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if done.Connection.ConnectionID != "binding-4" || done.Connection.RepositoryName != "octo-org/repo" {
		t.Fatalf("unexpected result: %+v", done)
	}
	if done.Connection.InstallationID != 222 || done.Connection.RepositoryID != 111 {
		t.Fatalf("immutable IDs wrong: %+v", done.Connection)
	}
	if len(auth.finishHandoffIDs) != 1 || auth.finishHandoffIDs[0] != "upstream-handoff-4" {
		t.Fatalf("upstream finish got %v", auth.finishHandoffIDs)
	}
	conn, err := st.GetConnection(ctx, "ws-1", "binding-4")
	if err != nil {
		t.Fatalf("GetConnection: %v", err)
	}
	if conn.PermissionStatus != "ok" || conn.RepositoryBindingRef != "binding-4" {
		t.Fatalf("connection wrong: %+v", conn)
	}
	// A retried finish with the same idempotency key replays the stored
	// result without a second upstream mutation, even though the handoff
	// is consumed.
	done2, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-5")
	if err != nil {
		t.Fatalf("replayed Finish: %v", err)
	}
	if done2.Connection.ConnectionID != done.Connection.ConnectionID {
		t.Fatalf("replay result mismatch: %+v vs %+v", done2, done)
	}
	if len(auth.finishHandoffIDs) != 1 {
		t.Fatalf("second finish reached upstream: %v", auth.finishHandoffIDs)
	}
	// Callback after finish is rejected.
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-4")); err == nil {
		t.Fatal("callback after finish accepted")
	}
}

func TestFinishRequiresOriginalSession(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-s"),
		finishBinding: coreapi.RepositoryBinding{
			BindingID: "binding-s", WorkspaceID: "ws-1", Repository: "octo-org/repo",
			RepositoryID: "111", InstallationID: "222",
		},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-s")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-s")); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if _, err := h.Finish(ctx, "ws-1", "sess-other", begin.HandoffID, "idem-key-sf"); err == nil {
		t.Fatal("finish with a different session accepted")
	}
	if len(auth.finishHandoffIDs) != 0 {
		t.Fatalf("session mismatch reached upstream: %v", auth.finishHandoffIDs)
	}
}

func TestFinishWithoutCallbackFails(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{beginHandoff: beginFixture("upstream-handoff-5")}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-6")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-7"); err == nil {
		t.Fatal("finish without callback accepted")
	}
}

func TestFinishRejectsCrossWorkspaceBinding(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-8"),
		finishBinding: coreapi.RepositoryBinding{
			BindingID: "binding-8", WorkspaceID: "ws-other", Repository: "octo-org/repo",
			RepositoryID: "111", InstallationID: "222",
		},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-11")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-8")); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if _, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-12"); err == nil {
		t.Fatal("finish accepted cross-workspace binding")
	}
	if _, err := st.GetConnection(ctx, "ws-1", "binding-8"); err == nil {
		t.Fatal("cross-workspace connection written")
	}
}

func TestFinishRejectsNonNumericIDs(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-n"),
		finishBinding: coreapi.RepositoryBinding{
			BindingID: "binding-n", WorkspaceID: "ws-1", Repository: "octo-org/repo",
			RepositoryID: "not-a-number", InstallationID: "222",
		},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-n")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-n")); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if _, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-nf"); err == nil {
		t.Fatal("finish accepted non-numeric repository ID")
	}
}

func TestReconnectionReplacesRevokedBindingTransactionally(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	old := store.ConnectionRecord{
		WorkspaceID:          "ws-1",
		ConnectionID:         "binding-old",
		RepositoryBindingRef: "binding-old",
		InstallationID:       1,
		RepositoryID:         111,
		RepositoryName:       "octo-org/repo",
		PermissionStatus:     "ok",
		VerifiedAt:           time.Now().UTC(),
		CreatedAt:            time.Now().UTC(),
	}
	if err := st.WithTx(ctx, func(tx store.Tx) error { return tx.PutConnection(ctx, old) }); err != nil {
		t.Fatalf("seed old connection: %v", err)
	}
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-9"),
		finishBinding: coreapi.RepositoryBinding{
			BindingID: "binding-new", WorkspaceID: "ws-1", Repository: "octo-org/repo",
			RepositoryID: "111", InstallationID: "333",
		},
	}
	h := testHandoff(t, st, auth)
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-13")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-9")); err != nil {
		t.Fatalf("callback: %v", err)
	}
	done, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-14")
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if done.Connection.ConnectionID != "binding-new" {
		t.Fatalf("connection = %q", done.Connection.ConnectionID)
	}
	if _, err := st.GetConnection(ctx, "ws-1", "binding-old"); err == nil {
		t.Fatal("revoked binding survived reconnection")
	}
	conns, err := st.ListConnections(ctx, "ws-1")
	if err != nil {
		t.Fatalf("ListConnections: %v", err)
	}
	if len(conns) != 1 || conns[0].ConnectionID != "binding-new" {
		t.Fatalf("connections = %+v", conns)
	}
}

func TestProcessRestartDropsBindingCodeCache(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{beginHandoff: beginFixture("upstream-handoff-10")}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-15")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	q := callbackQuery(t, begin, "one-use-code-10")
	if _, err := h.RecordCallback(ctx, q); err != nil {
		t.Fatalf("callback: %v", err)
	}
	// Simulate a restart: a fresh Handoff over the same store and
	// database. The raw code cache is gone; finish must be rejected and a
	// fresh handoff started. The durable digest alone cannot complete it.
	h2 := testHandoff(t, st, auth)
	if _, err := h2.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-16"); err == nil {
		t.Fatal("finish completed after restart dropped the code cache")
	}
}

func TestStoreNeverHoldsRawCredentials(t *testing.T) {
	// Open the database through the store, then scan the raw file
	// separately so no store helper can hide a leaked value.
	dir := t.TempDir()
	st, err := store.Open(dir, "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	raw := "ghp_recognizablyfakecredential_000000000000000000"
	auth := &fakeAuthority{
		beginHandoff: coreapi.GitHubBindingHandoff{
			HandoffID:       "upstream-handoff-11",
			BindingCode:     raw,
			InstallationURL: "https://authscope.local/install/github?handoff_id=upstream-handoff-11",
			ExpiresAt:       time.Now().UTC().Add(10 * time.Minute).Unix(),
		},
		finishBinding: coreapi.RepositoryBinding{
			BindingID: "binding-11", WorkspaceID: "ws-1", Repository: "octo-org/repo",
			RepositoryID: "111", InstallationID: "222",
		},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-key-17")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, raw)); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if _, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-key-18"); err != nil {
		t.Fatalf("finish: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "ope.db"))
	if err != nil {
		t.Fatalf("open db file: %v", err)
	}
	defer db.Close()
	for _, table := range []string{"github_handoffs", "github_connections", "github_posture_checks"} {
		rows, err := db.Query("SELECT * FROM " + table)
		if err != nil {
			t.Fatalf("%s query: %v", table, err)
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatalf("%s columns: %v", table, err)
		}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				t.Fatalf("%s scan: %v", table, err)
			}
			for i, v := range vals {
				switch c := v.(type) {
				case string:
					if strings.Contains(c, raw) {
						rows.Close()
						t.Fatalf("%s.%s holds raw credential", table, cols[i])
					}
				case []byte:
					if strings.Contains(string(c), raw) {
						rows.Close()
						t.Fatalf("%s.%s holds raw credential", table, cols[i])
					}
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("%s rows: %v", table, err)
		}
	}
}

func TestNormalizeAuthScopeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://authscope.example.com":     "https://authscope.example.com",
		"https://authscope.example.com/":    "https://authscope.example.com",
		"HTTPS://AuthScope.Example.COM":     "https://authscope.example.com",
		"http://localhost:8080":             "http://localhost:8080",
		"  https://authscope.example.com  ": "https://authscope.example.com",
	} {
		got, err := NormalizeAuthScopeOrigin(in)
		if err != nil {
			t.Fatalf("NormalizeAuthScopeOrigin(%q) error: %v", in, err)
		}
		if got != want {
			t.Fatalf("NormalizeAuthScopeOrigin(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{
		"",
		"not a url",
		"https://authscope.example.com/base",
		"https://authscope.example.com/?x=1",
		"https://authscope.example.com/#frag",
		"https://user@authscope.example.com",
		"ftp://authscope.example.com",
	} {
		if got, err := NormalizeAuthScopeOrigin(in); err == nil {
			t.Fatalf("NormalizeAuthScopeOrigin(%q) = %q, want error", in, got)
		}
	}
}

func TestNewHandoffRejectsUnnormalizableOrigin(t *testing.T) {
	if _, err := NewHandoff(HandoffConfig{
		Store:           testStore(t),
		Authority:       &fakeAuthority{},
		AuthScopeOrigin: "https://authscope.example.com/base",
		CompletionPath:  "/connect/github/done",
	}); err == nil {
		t.Fatal("origin with path accepted")
	}
}

// seedInflightBegin inserts an unsettled idempotency record for the begin
// canonical digest so the next Begin takes the reconciliation path.
func seedInflightBegin(t *testing.T, st store.Store, workspaceID, sessionID, repository, key string) {
	t.Helper()
	err := st.WithTx(context.Background(), func(tx store.Tx) error {
		_, err := tx.BeginIdempotency(context.Background(), store.IdempotencyRecord{
			WorkspaceID:     workspaceID,
			Key:             key,
			CanonicalDigest: canonicalDigest("ope/github-begin/v1", workspaceID, sessionID, repository),
		})
		return err
	})
	if err != nil {
		t.Fatalf("seed idempotency: %v", err)
	}
}

func TestBeginReplayInflightReportsOperationInFlight(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-inflight"),
		reconcileOp: coreapi.OperationResult{
			OperationID: "op-1", IdempotencyKey: "idem-inflight", Status: "in_progress",
		},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	seedInflightBegin(t, st, "ws-1", "sess-1", "octo-org/repo", "idem-inflight")
	if _, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-inflight"); !errors.Is(err, ErrOperationInFlight) {
		t.Fatalf("in-flight begin err = %v, want ErrOperationInFlight", err)
	}
	if len(auth.beginKeys) != 0 {
		t.Fatalf("in-flight operation repeated upstream: %v", auth.beginKeys)
	}
}

func TestBeginReplayAbsentProceedsAsNew(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-absent"),
		reconcileErr: &coreapi.UpstreamError{StatusCode: 404, Message: "no such operation"},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	seedInflightBegin(t, st, "ws-1", "sess-1", "octo-org/repo", "idem-absent")
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-absent")
	if err != nil {
		t.Fatalf("absent begin: %v", err)
	}
	if begin.HandoffID == "" {
		t.Fatal("no handoff minted for absent operation")
	}
	if len(auth.beginKeys) != 1 || auth.beginKeys[0] != "idem-absent" {
		t.Fatalf("absent begin upstream keys = %v", auth.beginKeys)
	}
}

func TestFinishAmbiguousInflightReportsOperationInFlight(t *testing.T) {
	st := testStore(t)
	auth := &fakeAuthority{
		beginHandoff: beginFixture("upstream-handoff-amb"),
		finishErr:    &coreapi.UpstreamError{StatusCode: 503, Message: "try again"},
		reconcileOp: coreapi.OperationResult{
			OperationID: "op-2", IdempotencyKey: "idem-amb", Status: "pending",
		},
		finishBinding: coreapi.RepositoryBinding{
			BindingID: "binding-amb", WorkspaceID: "ws-1",
			Repository: "octo-org/repo", RepositoryID: "111", InstallationID: "222",
		},
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-amb-begin")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-amb")); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if _, err := h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-amb"); !errors.Is(err, ErrOperationInFlight) {
		t.Fatalf("ambiguous finish err = %v, want ErrOperationInFlight", err)
	}
	if len(auth.finishHandoffIDs) != 1 {
		t.Fatalf("ambiguous finish upstream calls = %v", auth.finishHandoffIDs)
	}
}

// blockingFinishAuthority blocks the first upstream finish call so a
// second concurrent Finish is in flight while the first holds the
// per-handoff lock.
type blockingFinishAuthority struct {
	fakeAuthority
	entered chan struct{}
	release chan struct{}
	calls   int32
}

func (b *blockingFinishAuthority) FinishGitHubBinding(ctx context.Context, in coreapi.GitHubBindingFinishRequest, opts coreapi.RequestOptions) (coreapi.RepositoryBinding, error) {
	if atomic.AddInt32(&b.calls, 1) == 1 {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return coreapi.RepositoryBinding{}, ctx.Err()
		}
	}
	return b.fakeAuthority.FinishGitHubBinding(ctx, in, opts)
}

func TestFinishConcurrentDifferentKeysSingleUpstreamCall(t *testing.T) {
	st := testStore(t)
	auth := &blockingFinishAuthority{
		fakeAuthority: fakeAuthority{
			beginHandoff: beginFixture("upstream-handoff-conc"),
			finishBinding: coreapi.RepositoryBinding{
				BindingID: "binding-conc", WorkspaceID: "ws-1",
				Repository: "octo-org/repo", RepositoryID: "111", InstallationID: "222",
			},
		},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	h := testHandoff(t, st, auth)
	ctx := context.Background()
	begin, err := h.Begin(ctx, "ws-1", "sess-1", "octo-org/repo", "idem-conc-begin")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := h.RecordCallback(ctx, callbackQuery(t, begin, "one-use-code-conc")); err != nil {
		t.Fatalf("callback: %v", err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = h.Finish(ctx, "ws-1", "sess-1", begin.HandoffID, "idem-conc-"+string(rune('a'+i)))
		}(i)
	}
	<-auth.entered
	close(auth.release)
	wg.Wait()

	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("concurrent finishes: %d succeeded, want exactly 1 (errs %v)", succeeded, errs)
	}
	if n := atomic.LoadInt32(&auth.calls); n != 1 {
		t.Fatalf("upstream finish calls = %d, want 1", n)
	}
}
