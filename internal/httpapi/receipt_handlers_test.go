// Tests for GET /api/v1/mission-passes/{id}/receipt: the authenticated,
// privacy-safe private receipt view. There is no unauthenticated route
// and no manual publish endpoint; the handler renders only the fixed
// verified projection, never raw envelopes or private detail.
package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

type receiptHTTPUpstream struct {
	coreapi.Authority
	envelope *coreapi.SignedReceiptEnvelope
	calls    int
}

func (f *receiptHTTPUpstream) GetReceipt(_ context.Context, _ string, _ coreapi.RequestOptions) (coreapi.SignedReceiptEnvelope, error) {
	f.calls++
	if f.envelope == nil {
		return coreapi.SignedReceiptEnvelope{}, &coreapi.UpstreamError{StatusCode: http.StatusNotFound}
	}
	return *f.envelope, nil
}

func (f *receiptHTTPUpstream) GetSigningKeys(_ context.Context, _ coreapi.RequestOptions) (coreapi.SigningKeyHistory, error) {
	return coreapi.SigningKeyHistory{}, nil
}

func (f *receiptHTTPUpstream) PublishGitHubCheck(_ context.Context, req coreapi.GitHubCheckRequest, opts coreapi.RequestOptions) (coreapi.GitHubCheckResult, error) {
	return coreapi.GitHubCheckResult{
		CheckRunID: "chk-http-1", BindingID: req.BindingID, WorkspaceID: opts.WorkspaceID,
		HeadSHA: req.HeadSHA, Name: req.Name, Status: req.Status, Conclusion: req.Conclusion,
		IdempotencyKey: req.IdempotencyKey, CreatedAt: time.Now().UTC().Unix(),
	}, nil
}

func (f *receiptHTTPUpstream) ReconcileOperation(_ context.Context, idempotencyKey, operationID string, _ coreapi.RequestOptions) (coreapi.OperationResult, error) {
	return coreapi.OperationResult{OperationID: operationID, IdempotencyKey: idempotencyKey, Status: "completed"}, nil
}

type receiptHTTPFixture struct {
	*authTestFixture
	up      *receiptHTTPUpstream
	service *receipt.Service
	signer  struct {
		id   string
		pub  ed25519.PublicKey
		priv ed25519.PrivateKey
	}
}

func newReceiptHTTPFixture(t *testing.T) *receiptHTTPFixture {
	t.Helper()
	f := newAuthTestFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sum := sha256.Sum256(pub)
	rootFP := "sha256:" + hex.EncodeToString(sum[:])
	raw, err := json.Marshal(map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": rootFP,
		"keys": []any{map[string]any{
			"key_id":     "receipt-key-1",
			"algorithm":  "Ed25519",
			"public_key": base64.RawURLEncoding.EncodeToString(pub),
			"root":       true,
			"valid_from": now.Add(-time.Hour).Format(time.RFC3339),
		}},
	})
	if err != nil {
		t.Fatalf("marshal pin: %v", err)
	}
	pinPath := t.TempDir() + "/pin.json"
	if err := os.WriteFile(pinPath, raw, 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	ks, err := trust.LoadSigningKeys(pinPath, rootFP)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	up := &receiptHTTPUpstream{}
	svc, err := receipt.NewService(receipt.Config{
		Store: f.store, Authority: up, Keys: ks,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	f.handler = New(Dependencies{
		Config: f.config,
		Contract: coreapi.ContractReport{
			CoreVersion:        "ope-v1.0.0",
			DigestMatch:        true,
			OperationsRequired: 36,
			OperationsPresent:  36,
		},
		Store:   f.store,
		Authn:   f.authn,
		Receipt: svc,
	})
	rf := &receiptHTTPFixture{authTestFixture: f, up: up, service: svc}
	rf.signer.id = "receipt-key-1"
	rf.signer.pub = pub
	rf.signer.priv = priv
	return rf
}

func (f *receiptHTTPFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	return f.doRaw(t, http.MethodGet, path, "", map[string]string{"Host": "ope.example.com"})
}

func (f *receiptHTTPFixture) seedVerifiedPass(t *testing.T, passID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.PutConnection(ctx, store.ConnectionRecord{
			WorkspaceID: "ws-test", ConnectionID: "conn-1",
			RepositoryBindingRef: "binding-1", InstallationID: 222,
			RepositoryID: 111, RepositoryName: "octo-org/repo",
			PermissionStatus: "ok", VerifiedAt: now, CreatedAt: now,
		}); err != nil {
			return err
		}
		return tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID: "ws-test", PassID: passID,
			State:          string(missionpass.PassOutcomePending),
			Reconciliation: string(missionpass.ReconciliationSettled),
			ConnectionID:   "conn-1", IssueNumber: 42,
			RepositoryName: "octo-org/repo",
			MissionRef:     "mission-1", RunID: "run-1",
			Objective: "Add retries", StoreRevision: 1,
		}, 0)
	}); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	seedEvents := []missionpass.SafeEvent{
		{EventID: "ev-1", Cursor: "c1", Type: missionpass.EventRunSucceeded,
			OccurredAt: now.Add(-time.Hour), AuthScopeMissionVersion: 3,
			ResourceDigest: "sha256:" + strings.Repeat("d", 64),
			Branch:         "authscope/mission-1", HeadSHA: strings.Repeat("a", 40)},
		{EventID: "ev-2", Cursor: "c2", Type: missionpass.EventPullRequestCreated,
			OccurredAt: now.Add(-50 * time.Minute), AuthScopeMissionVersion: 3,
			ResourceDigest: "sha256:" + strings.Repeat("e", 64),
			Branch:         "authscope/mission-1", HeadSHA: strings.Repeat("a", 40),
			PullRequestNumber: 7},
	}
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		for _, se := range seedEvents {
			raw, err := json.Marshal(se)
			if err != nil {
				return err
			}
			if _, err := tx.PutEventIfAbsent(ctx, store.MissionEventRecord{
				WorkspaceID: "ws-test", PassID: passID, EventID: se.EventID,
				EventType: se.Type, Cursor: se.Cursor, Payload: string(raw), OccurredAt: se.OccurredAt,
			}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed events: %v", err)
	}
	p := receipt.Payload{
		ReceiptID: "rcpt-1", GrantID: "run-1", MissionRef: "mission-1",
		WorkspaceID: "ws-test", KeyID: f.signer.id, SignedAt: now.Unix(),
		Outcome:               receipt.OutcomeSuccess,
		MissionVersions:       []int64{3},
		ExpansionDecisionRefs: []string{},
		RepositoryID:          111, IssueNumber: 42,
		Branch: "authscope/mission-1", PullRequestNumber: 7,
		HeadSHA:   strings.Repeat("a", 40),
		Checks:    []receipt.CheckSummary{{Kind: "unit_tests", Outcome: "passed"}},
		StartedAt: now.Add(-time.Hour).Unix(), FinishedAt: now.Add(-time.Minute).Unix(),
		AggregateCostMicros: 100,
		SettlementDigest:    "sha256:" + strings.Repeat("b", 64),
		// Signed free-text evidence: covered by the signature, but the
		// verified projection never carries it into a rendered view.
		AcceptanceEvidence:    []string{"founder private note"},
		TestSummaries:         []string{"120 tests passed"},
		ExceptionSummaries:    []string{"sk-test-SECRET-123"},
		HistoricalEnforcement: []receipt.EnforcementSummary{{Scope: "github", Level: "enforced"}},
	}
	raw, err := receipt.CanonicalPayloadBytes(p)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	sig := ed25519.Sign(f.signer.priv, raw)
	f.up.envelope = &coreapi.SignedReceiptEnvelope{
		Algorithm: "Ed25519", KeyID: f.signer.id, Payload: raw,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	if _, err := f.service.VerifyReceipt(ctx, "ws-test", passID); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := f.service.PublishVerifiedCheck(ctx, "ws-test", passID); err != nil {
		t.Fatalf("publish: %v", err)
	}
}

func TestReceiptViewVerified(t *testing.T) {
	f := newReceiptHTTPFixture(t)
	f.enrollOverHTTP(t)
	f.seedVerifiedPass(t, "pass-1")

	rec := f.get(t, "/api/v1/mission-passes/pass-1/receipt")
	if rec.Code != http.StatusOK {
		t.Fatalf("receipt: status %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		PassID       string `json:"pass_id"`
		Verification string `json:"verification"`
		View         struct {
			Outcome       string `json:"outcome"`
			ReceiptDigest string `json:"receipt_digest"`
			HeadSHA       string `json:"head_sha"`
		} `json:"view"`
		Publication struct {
			State string `json:"state"`
		} `json:"publication"`
	}
	decodeBody(t, rec, &body)
	if body.Verification != "verified" || body.View.Outcome != "success" {
		t.Errorf("body = %+v, want verified success", body)
	}
	if body.Publication.State != "settled" {
		t.Errorf("publication = %+v, want settled", body.Publication)
	}
	for _, secret := range []string{"sk-test-SECRET-123", "founder private note", "payload", "signature"} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("receipt view leaks %q", secret)
		}
	}
}

func TestReceiptViewPending(t *testing.T) {
	f := newReceiptHTTPFixture(t)
	f.enrollOverHTTP(t)
	ctx := context.Background()
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID: "ws-test", PassID: "pass-9",
			State:          string(missionpass.PassOutcomePending),
			Reconciliation: string(missionpass.ReconciliationSettled),
			MissionRef:     "mission-9", RunID: "run-9",
			Objective: "x", StoreRevision: 1,
		}, 0)
	}); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	rec := f.get(t, "/api/v1/mission-passes/pass-9/receipt")
	if rec.Code != http.StatusOK {
		t.Fatalf("receipt: status %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Verification string `json:"verification"`
	}
	decodeBody(t, rec, &body)
	if body.Verification != "pending" {
		t.Errorf("verification = %q, want pending", body.Verification)
	}
}

func TestReceiptViewUnknownPass(t *testing.T) {
	f := newReceiptHTTPFixture(t)
	f.enrollOverHTTP(t)
	rec := f.get(t, "/api/v1/mission-passes/nope/receipt")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestReceiptViewForeignWorkspace(t *testing.T) {
	f := newReceiptHTTPFixture(t)
	f.enrollOverHTTP(t)
	ctx := context.Background()
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID: "ws-other", PassID: "pass-x",
			State:          string(missionpass.PassOutcomePending),
			Reconciliation: string(missionpass.ReconciliationSettled),
			MissionRef:     "mission-x", RunID: "run-x",
			Objective: "x", StoreRevision: 1,
		}, 0)
	}); err != nil {
		t.Fatalf("seed pass: %v", err)
	}
	rec := f.get(t, "/api/v1/mission-passes/pass-x/receipt")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (uniform for foreign passes)", rec.Code)
	}
}

func TestReceiptViewUnauthenticated(t *testing.T) {
	f := newReceiptHTTPFixture(t)
	rec := f.get(t, "/api/v1/mission-passes/pass-1/receipt")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}
