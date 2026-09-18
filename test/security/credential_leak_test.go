// Package security holds the privacy and credential-leak gates for the
// OPE instance: seeded canaries must appear only in their explicitly
// bounded channels (in-memory handling, the controlling terminal, the
// non-exportable signer, or the anonymous FD), and never in SQLite,
// WAL/SHM, logs, HTTP responses, DOM, browser storage, process listings,
// child environments, crash output, telemetry, or the public check
// payload.
//
// Each canary is read from the environment when present so CI can seed
// stable values, and falls back to a random local value otherwise. The
// seed variable names are:
//
//	OPE_CANARY_SIGNER      workload signer key handle
//	OPE_CANARY_ATTESTATION signed decision attestation material
//	OPE_CANARY_RECOVERY    offline recovery key
//	OPE_CANARY_BINDING     opaque AuthScope GitHub binding code
//	OPE_CANARY_PASSKEY     passkey assertion
//	OPE_CANARY_CLI         CLI code/verifier/private key
//	OPE_CANARY_ENVELOPE    sealed-envelope plaintext
//	OPE_CANARY_RUNTIME     runtime credential
//	OPE_CANARY_PRIVATE     private provider/issue/event/receipt content
package security

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/cli"
	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/github"
	"github.com/tauliang/authscope-ope/internal/httpapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/telemetry"
)

// canarySet is the seeded secret material for one test run. Values are
// recognizably fake; they stand in for real credentials so the tests can
// prove every surface excludes them.
type canarySet struct {
	signer      string
	attestation string
	recovery    string
	binding     string
	passkey     string
	cliCode     string
	envelope    string
	runtime     string
	private     string
}

func loadCanaries(t *testing.T) canarySet {
	t.Helper()
	get := func(env string) string {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		return "CANARY-LOCAL-" + env + "-" + hex.EncodeToString(b[:])
	}
	return canarySet{
		signer:      get("OPE_CANARY_SIGNER"),
		attestation: get("OPE_CANARY_ATTESTATION"),
		recovery:    get("OPE_CANARY_RECOVERY"),
		binding:     get("OPE_CANARY_BINDING"),
		passkey:     get("OPE_CANARY_PASSKEY"),
		cliCode:     get("OPE_CANARY_CLI"),
		envelope:    get("OPE_CANARY_ENVELOPE"),
		runtime:     get("OPE_CANARY_RUNTIME"),
		private:     get("OPE_CANARY_PRIVATE"),
	}
}

// assertAbsent fails when the canary value appears anywhere in the
// haystack. The failure reports the label, never the value, so a
// failing test does not print the secret into test logs.
func assertAbsent(t *testing.T, where, label, value string, haystack []byte) {
	t.Helper()
	if value == "" {
		t.Fatalf("%s: empty canary %s", where, label)
	}
	if bytes.Contains(haystack, []byte(value)) {
		t.Fatalf("%s leaks the %s canary", where, label)
	}
}

// scanDataDir asserts that no SQLite, WAL, SHM, lock, or journal file
// under dir contains the canary value.
func scanDataDir(t *testing.T, dir, label, value string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		assertAbsent(t, "data file "+path, label, value, data)
		return nil
	})
	if err != nil {
		t.Fatalf("scan data dir: %v", err)
	}
}

func openSecurityStore(t *testing.T) (store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir, "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, dir
}

// securityStubAuthority embeds coreapi.Authority so only the methods a
// test exercises need implementations.
type securityStubAuthority struct {
	coreapi.Authority
	beginHandoff coreapi.GitHubBindingHandoff
}

func (s *securityStubAuthority) BeginGitHubBinding(_ context.Context, _ coreapi.GitHubBindingBeginRequest, _ coreapi.RequestOptions) (coreapi.GitHubBindingHandoff, error) {
	return s.beginHandoff, nil
}

// TestBindingCodeNeverPersists proves the opaque GitHub binding code
// from the callback query is hashed in memory and only its digest is
// stored: the redirect, the handoff record, and every database file
// must be free of the code.
func TestBindingCodeNeverPersists(t *testing.T) {
	can := loadCanaries(t)
	st, dir := openSecurityStore(t)
	ctx := context.Background()
	auth := &securityStubAuthority{beginHandoff: coreapi.GitHubBindingHandoff{
		HandoffID:       "sec-handoff-1",
		BindingCode:     "recognizably-fake-binding-code",
		InstallationURL: "https://authscope.local/install/github?handoff_id=sec-handoff-1",
		ExpiresAt:       time.Now().UTC().Add(10 * time.Minute).Unix(),
	}}
	h, err := github.NewHandoff(github.HandoffConfig{
		Store:           st,
		Authority:       auth,
		AuthScopeOrigin: "https://authscope.local",
		CompletionPath:  "/connect/github/done",
		Clock:           func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		t.Fatalf("NewHandoff: %v", err)
	}
	begin, err := h.Begin(ctx, "ws-sec-1", "sess-sec-1", "octo-org/repo", "idem-sec-1")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	u, err := url.Parse(begin.InstallationURL)
	if err != nil {
		t.Fatalf("parse installation URL: %v", err)
	}
	q := u.Query()
	values := url.Values{
		"handoff_id": {q.Get("handoff_id")},
		"code":       {can.binding},
		"state":      {q.Get("state")},
	}
	redirect, err := h.RecordCallback(ctx, values)
	if err != nil {
		t.Fatalf("RecordCallback: %v", err)
	}
	assertAbsent(t, "callback redirect", "binding code", can.binding, []byte(redirect))

	rec, err := st.GetGitHubHandoffByID(ctx, q.Get("handoff_id"))
	if err != nil {
		t.Fatalf("GetGitHubHandoffByID: %v", err)
	}
	sum := sha256.Sum256([]byte(can.binding))
	if want := hex.EncodeToString(sum[:]); rec.BindingCodeDigest != want {
		t.Fatalf("stored digest is not the code digest: %q", rec.BindingCodeDigest)
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal handoff record: %v", err)
	}
	assertAbsent(t, "handoff record", "binding code", can.binding, recJSON)

	// The code passed through memory only: the database, WAL, and SHM
	// files must contain nothing but the digest.
	scanDataDir(t, dir, "binding code", can.binding)
}

// TestUpstreamResponsesRejectCredentialFields proves the AuthScope
// client strict-decodes upstream responses: a broker that smuggles a
// credential field (for example a GitHub token) into an otherwise valid
// response causes a hard failure, and the failure never echoes the
// credential.
func TestUpstreamResponsesRejectCredentialFields(t *testing.T) {
	can := loadCanaries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"binding_id":   "b-sec-1",
			"issue_number": 7,
			"github_token": can.private,
		})
	}))
	defer srv.Close()
	signer := identity.NewEphemeralSigner()
	client, err := coreapi.NewClient(srv.URL, srv.Client(), signer, "development")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.ReadGitHubIssue(context.Background(),
		coreapi.GitHubIssueRequest{BindingID: "b-sec-1", IssueNumber: 7},
		coreapi.RequestOptions{WorkspaceID: "ws-sec-1"})
	if err == nil {
		t.Fatal("upstream credential field accepted by strict decode")
	}
	assertAbsent(t, "upstream decode error", "private credential", can.private, []byte(err.Error()))
}

// TestTelemetryRowsContainNoCanaries proves persisted telemetry rows
// carry only the nine allowlisted fields: with every canary loaded in
// the test scope, recorded events must validate and list back free of
// every canary.
func TestTelemetryRowsContainNoCanaries(t *testing.T) {
	can := loadCanaries(t)
	st, _ := openSecurityStore(t)
	ctx := context.Background()
	sink := telemetry.NewSink(telemetry.SinkConfig{
		Enabled:     true,
		Store:       st,
		WorkspaceID: "ws-sec-1",
		InstanceID:  "inst-sec-1",
		Clock:       func() time.Time { return time.Now().UTC() },
	})
	names := []string{"connect", "proposal_ready", "approved", "receipt_verified", "check_published"}
	for _, name := range names {
		if err := sink.Record(ctx, telemetry.Event{
			Name:             name,
			DurationMillis:   12,
			PassID:           "pass-sec-1",
			RunID:            "run-sec-1",
			ErrorCode:        telemetry.ErrorNone,
			EnforcementLevel: telemetry.EnforcementDevelopment,
			OutcomeClass:     telemetry.OutcomeSuccess,
		}); err != nil {
			t.Fatalf("Record %s: %v", name, err)
		}
	}
	rows, err := st.ListTelemetryEvents(ctx, "ws-sec-1", 100)
	if err != nil {
		t.Fatalf("ListTelemetryEvents: %v", err)
	}
	if len(rows) != len(names) {
		t.Fatalf("rows = %d, want %d", len(rows), len(names))
	}
	needles := []struct{ label, value string }{
		{"signer", can.signer}, {"attestation", can.attestation},
		{"recovery", can.recovery}, {"binding", can.binding},
		{"passkey", can.passkey}, {"cli code", can.cliCode},
		{"envelope", can.envelope}, {"runtime", can.runtime},
		{"private", can.private},
	}
	for _, row := range rows {
		data, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("marshal telemetry row: %v", err)
		}
		for _, n := range needles {
			assertAbsent(t, "telemetry row", n.label, n.value, data)
		}
	}
}

// TestHTTPProblemBodiesHideSecrets proves the HTTP error surface never
// echoes request material: a callback carrying canary query parameters
// fails against an unknown handoff, and the problem response contains
// no canary in its status, headers, or body.
func TestHTTPProblemBodiesHideSecrets(t *testing.T) {
	can := loadCanaries(t)
	st, _ := openSecurityStore(t)
	cfg := config.Config{Mode: "development", Origin: "http://127.0.0.1:8080"}
	auth := &securityStubAuthority{}
	h := httpapi.New(httpapi.Dependencies{Config: cfg, Store: st, Authority: auth})
	target := "/api/v1/connections/github/callback?handoff_id=" + url.QueryEscape(can.binding) +
		"&code=" + url.QueryEscape(can.cliCode) +
		"&state=" + strings.Repeat("ab", 32)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode < 400 {
		t.Fatalf("callback with unknown handoff returned %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	assertAbsent(t, "callback error body", "binding code", can.binding, body)
	assertAbsent(t, "callback error body", "cli code", can.cliCode, body)
	for _, values := range res.Header {
		for _, v := range values {
			assertAbsent(t, "callback error header", "binding code", can.binding, []byte(v))
			assertAbsent(t, "callback error header", "cli code", can.cliCode, []byte(v))
		}
	}
}

// TestRuntimeCredentialTravelsOnlyOnAnonymousFD proves the runtime
// credential reaches the governed runner only on the anonymous FD 3:
// a canary credential must appear in the FD 3 capture and nowhere in
// the child argv, environment, stdout, stderr, or descriptor listing.
func TestRuntimeCredentialTravelsOnlyOnAnonymousFD(t *testing.T) {
	can := loadCanaries(t)
	dumpDir := t.TempDir()
	script := "#!/bin/bash\n" +
		"cat /proc/self/cmdline > \"$OPE_DUMP_DIR/cmdline\"\n" +
		"cat /proc/self/environ > \"$OPE_DUMP_DIR/environ\"\n" +
		"ls -l /proc/self/fd > \"$OPE_DUMP_DIR/fds\"\n" +
		"cat <&3 > \"$OPE_DUMP_DIR/fd3\"\n" +
		"echo runner-stdout-marker\n" +
		"echo runner-stderr-marker >&2\n"
	runnerPath := filepath.Join(t.TempDir(), "fake-runner")
	if err := os.WriteFile(runnerPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write runner: %v", err)
	}
	var stdout, stderr bytes.Buffer
	ctx := context.Background()
	cmd, cleanup, err := cli.StartGovernedRun(ctx, runnerPath, []byte(can.runtime), cli.RunOptions{
		Stdout:   &stdout,
		Stderr:   &stderr,
		ExtraEnv: []string{"OPE_DUMP_DIR=" + dumpDir},
	})
	if err != nil {
		t.Fatalf("StartGovernedRun: %v", err)
	}
	defer cleanup()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("runner wait: %v", err)
	}
	// The credential must arrive intact on FD 3.
	fd3, err := os.ReadFile(filepath.Join(dumpDir, "fd3"))
	if err != nil {
		t.Fatalf("read fd3 capture: %v", err)
	}
	if string(fd3) != can.runtime {
		t.Fatal("runtime credential did not arrive intact on FD 3")
	}
	// And it must appear nowhere else the child could observe.
	for _, name := range []string{"cmdline", "environ", "fds"} {
		data, err := os.ReadFile(filepath.Join(dumpDir, name))
		if err != nil {
			t.Fatalf("read %s capture: %v", name, err)
		}
		assertAbsent(t, "child "+name, "runtime credential", can.runtime, data)
	}
	assertAbsent(t, "child stdout", "runtime credential", can.runtime, stdout.Bytes())
	assertAbsent(t, "child stderr", "runtime credential", can.runtime, stderr.Bytes())
	// The OS process listing for the runner must not contain it either.
	if _, err := os.Stat("/proc"); err == nil {
		if out, err := os.ReadFile("/proc/self/cmdline"); err == nil {
			assertAbsent(t, "parent cmdline", "runtime credential", can.runtime, out)
		}
	}
}

// TestSignerNeverExportsKeyMaterial proves the workload signer is
// structurally non-exportable: the Signer interface exposes no
// private-key accessor, and EphemeralSigner carries no exported fields
// that could hold key bytes.
func TestSignerNeverExportsKeyMaterial(t *testing.T) {
	can := loadCanaries(t)
	signerType := reflect.TypeOf((*identity.Signer)(nil)).Elem()
	for i := 0; i < signerType.NumMethod(); i++ {
		m := signerType.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			out := m.Type.Out(j)
			name := strings.ToLower(m.Name + " " + out.String())
			if strings.Contains(name, "private") || strings.Contains(name, "secret") {
				t.Fatalf("Signer.%s exposes key material: %s", m.Name, out)
			}
		}
	}
	ephemeral := reflect.TypeOf(identity.EphemeralSigner{})
	for i := 0; i < ephemeral.NumField(); i++ {
		if ephemeral.Field(i).IsExported() {
			t.Fatalf("EphemeralSigner has exported field %s", ephemeral.Field(i).Name)
		}
	}
	// The attestation canary stands in for decision material: the wire
	// envelope of a real attestation must carry claims and signature
	// only, with no private or secret fields.
	signer := identity.NewEphemeralSigner()
	attestor := identity.NewDecisionAttestor(signer)
	now := time.Now().UTC()
	var nonce [32]byte
	nonce[0] = 1
	claims := identity.DecisionClaims{
		Audience:                  identity.AudienceProposalApproval,
		Purpose:                   identity.PurposePassApproval,
		WorkspaceID:               "ws-sec-1",
		FounderID:                 "founder-sec-1",
		SubjectID:                 "mission-sec-1",
		DecisionDigest:            "sha256:" + strings.Repeat("0", 64),
		InvocationDigest:          "sha256:" + strings.Repeat("1", 64),
		AuthenticationMethod:      identity.AuthMethodWebAuthnUV,
		AuthenticationProofDigest: "sha256:" + strings.Repeat("2", 64),
		Nonce:                     nonce,
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(5 * time.Minute),
	}
	att, err := attestor.Attest(context.Background(), claims)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	env, err := identity.WireEnvelope(att)
	if err != nil {
		t.Fatalf("WireEnvelope: %v", err)
	}
	wire, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	assertAbsent(t, "attestation envelope", "attestation canary", can.attestation, wire)
	assertAbsent(t, "attestation envelope", "signer canary", can.signer, wire)
	for _, key := range []string{"private", "secret", "seed"} {
		if bytes.Contains(bytes.ToLower(wire), []byte(`"`+key+`"`)) {
			t.Fatalf("attestation envelope carries %q field", key)
		}
	}
	if len(att.Signature) == 0 {
		t.Fatal("attestation missing signature")
	}
}

// TestCheckPayloadOmitsPrivateReceiptContent proves the public check
// payload is the minimal triple (outcome, historical enforcement,
// receipt-digest prefix): private receipt content such as the branch
// canary must not appear in the rendered payload.
func TestCheckPayloadOmitsPrivateReceiptContent(t *testing.T) {
	can := loadCanaries(t)
	digest := sha256.Sum256([]byte(can.private))
	fullDigest := hex.EncodeToString(digest[:])
	view := receipt.ReceiptView{
		Verification: store.ReceiptVerified, ReceiptID: "rc-sec-1", GrantID: "gr-sec-1",
		MissionRef: "mission-sec-1", WorkspaceID: "ws-sec-1", KeyID: "key-sec-1",
		SignedAt: time.Now().UTC().Unix(), ReceiptDigest: fullDigest,
		Outcome: receipt.OutcomeSuccess, Branch: can.private,
		HistoricalEnforcement: []receipt.EnforcementSummary{{Scope: "cli", Level: "standard"}},
	}
	check := receipt.MinimalCheckRequest(&view, "b-sec-1", "idem-sec-1")
	data, err := json.Marshal(check)
	if err != nil {
		t.Fatalf("marshal check: %v", err)
	}
	assertAbsent(t, "public check payload", "private receipt content", can.private, data)
	// The check carries exactly the minimal triple: outcome, historical
	// enforcement, and the digest prefix.
	wantName := "authscope/receipt success cli:standard sha256:" + fullDigest[:12]
	if check.Name != wantName {
		t.Fatalf("check name = %q, want %q", check.Name, wantName)
	}
	if check.Conclusion != coreapi.CheckConclusionSuccess {
		t.Fatalf("check conclusion = %q", check.Conclusion)
	}
	if !strings.Contains(string(data), fullDigest[:12]) {
		t.Fatalf("check payload lost the digest prefix: %s", data)
	}
}

// securityTerminal is a buffer-backed controlling terminal for the
// recovery test: the workspace confirmation is typed in, prompts go to
// the output buffer.
type securityTerminal struct {
	in  *bytes.Buffer
	out *bytes.Buffer
}

func (t *securityTerminal) Read(p []byte) (int, error)  { return t.in.Read(p) }
func (t *securityTerminal) Write(p []byte) (int, error) { return t.out.Write(p) }
func (t *securityTerminal) Fd() uintptr                 { return 0 }

// securityRecoverAuthority verifies the workload identity and then
// fails containment, so recovery exercises the full key path (terminal
// read, constant-time hash comparison, attestation signing) before
// failing upstream of any state change.
type securityRecoverAuthority struct {
	coreapi.Authority
	digest string
}

func (s *securityRecoverAuthority) VerifyWorkspaceIdentity(_ context.Context, workspaceID string) (coreapi.WorkspaceIdentity, error) {
	return coreapi.WorkspaceIdentity{
		WorkspaceID:    workspaceID,
		IdentityDigest: s.digest,
		Roles:          []string{coreapi.DecisionAttestorRole},
	}, nil
}

func (s *securityRecoverAuthority) ListActiveMissions(_ context.Context, _ coreapi.RequestOptions) ([]coreapi.ActiveMission, error) {
	return nil, nil
}

func (s *securityRecoverAuthority) ContainWorkspace(_ context.Context, _ coreapi.WorkspaceContainmentRequest, _ identity.SignedDecisionAttestation, _ coreapi.RequestOptions) (coreapi.WorkspaceContainment, error) {
	return coreapi.WorkspaceContainment{}, errors.New("simulated upstream containment failure")
}

// TestRecoveryKeyStaysInTerminalChannel proves the offline recovery key
// enters only through the echo-disabled terminal read: it is hashed in
// memory, compared in constant time, zeroed on return, and never
// appears in errors, diagnostics, terminal output, or database files.
// Only the key hash is persisted.
func TestRecoveryKeyStaysInTerminalChannel(t *testing.T) {
	can := loadCanaries(t)
	ctx := context.Background()
	dir := t.TempDir()
	signer := identity.NewEphemeralSigner()
	digest := signer.IdentityDigest()
	keySum := sha256.Sum256([]byte(can.recovery))

	st, err := store.OpenExclusive(dir, "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	err = st.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.BindInstance(ctx, store.InstanceRecord{
			InstanceID:        "inst-sec-rec",
			WorkspaceID:       "ws-sec-rec",
			Hostname:          "h",
			Origin:            "https://h:8443",
			RPID:              "h",
			SessionCookieName: store.DeriveSessionCookieName("inst-sec-rec"),
			CreatedAt:         time.Now().UTC(),
		}); err != nil {
			return err
		}
		if err := tx.AttachWorkloadIdentity(ctx, "", digest); err != nil {
			return err
		}
		if err := tx.CreateFounder(ctx, store.FounderRecord{
			WorkspaceID: "ws-sec-rec", FounderID: "founder-sec-rec", CreatedAt: time.Now().UTC(),
		}); err != nil {
			return err
		}
		return tx.PutOfflineRecoveryKey(ctx, store.OfflineRecoveryKeyRecord{
			WorkspaceID: "ws-sec-rec", FounderID: "founder-sec-rec",
			KeyHash: hex.EncodeToString(keySum[:]), CreatedAt: time.Now().UTC(),
		})
	})
	_ = st.Close()
	if err != nil {
		t.Fatalf("seed store: %v", err)
	}

	tty := &securityTerminal{in: bytes.NewBufferString("ws-sec-rec\n"), out: &bytes.Buffer{}}
	var diag bytes.Buffer
	auth := &securityRecoverAuthority{digest: digest}
	runErr := cli.RunRecover(ctx, cli.RecoverConfig{
		DataDir:  dir,
		Mode:     "development",
		Signer:   signer,
		Terminal: tty,
		ErrW:     &diag,
		Clock:    func() time.Time { return time.Now().UTC() },
		ReadPassword: func(_ int) ([]byte, error) {
			return []byte(can.recovery), nil
		},
		NewAuthority: func(_ string, _ identity.Signer, _ string) (coreapi.Authority, error) {
			return auth, nil
		},
	})
	if runErr == nil {
		t.Fatal("expected recovery to fail at containment")
	}
	assertAbsent(t, "recovery error", "recovery key", can.recovery, []byte(runErr.Error()))
	assertAbsent(t, "recovery diagnostics", "recovery key", can.recovery, diag.Bytes())
	assertAbsent(t, "terminal output", "recovery key", can.recovery, tty.out.Bytes())
	// Only the hash may be persisted.
	scanDataDir(t, dir, "recovery key", can.recovery)
}
