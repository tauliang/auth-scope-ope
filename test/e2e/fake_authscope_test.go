package e2e

// The end-to-end journeys. Each journey drives the real coreapi.Client
// against the fake AuthScope and the fake enforcing gateway, proving the
// pinned contract on the wire.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/launch"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// runHappyPath drives the full Connect -> Authorize -> Mission journey
// and returns the mission ref, grant id, and proposal digests for reuse.
func runHappyPath(t *testing.T, f *journeyFixture) (missionRef, grantID, proposalID, invocationDigest string) {
	t.Helper()
	ctx := context.Background()
	st := connectAndAuthorize(t, f)
	missionRef = st.missionRef
	proposalID = st.proposal.ProposalID
	invocationDigest = st.invocationDigest
	prepareRun(t, f, &st)
	grantID = st.grantID

	// Mission: consume and settle the execution.
	status, raw := f.doRaw("POST", "/v1/executions/"+grantID+"/consume",
		map[string]any{"amount_micros": 1000, "idempotency_key": "idem-consume-1"}, nil)
	if status != 200 {
		t.Fatalf("consume execution: status %d: %s", status, raw)
	}
	status, raw = f.doRaw("POST", "/v1/executions/settle",
		map[string]any{"grant_id": grantID, "outcome": "success", "idempotency_key": "idem-settle-1"}, nil)
	if status != 200 {
		t.Fatalf("settle execution: status %d: %s", status, raw)
	}

	// Mission: events are cursor-resumable and carry only known types.
	page, err := f.client.ReadEvents(ctx, missionRef, "", f.opts())
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range page.Events {
		seen[e.EventType] = true
		if !knownEventTypes[e.EventType] {
			t.Fatalf("unknown event type reached the client: %q", e.EventType)
		}
	}
	for _, want := range []string{missionpass.EventMissionStarted, missionpass.EventRunSucceeded} {
		if !seen[want] {
			t.Fatalf("event %q missing from the page: %v", want, seen)
		}
	}
	again, err := f.client.ReadEvents(ctx, missionRef, page.NextCursor, f.opts())
	if err != nil {
		t.Fatalf("read events at cursor: %v", err)
	}
	if len(again.Events) != 0 {
		t.Fatalf("expected no events after the cursor, got %d", len(again.Events))
	}
	replay, err := f.client.ReadEvents(ctx, missionRef, "", f.opts())
	if err != nil {
		t.Fatalf("re-read events: %v", err)
	}
	if len(replay.Events) != len(page.Events) {
		t.Fatalf("event loss: first read %d events, re-read %d", len(page.Events), len(replay.Events))
	}

	// Mission: request and approve an exact expansion delta.
	delta := json.RawMessage(`{"actions":["run.execute"],"resources":["refs/heads/mission-x"]}`)
	status, raw = f.doRaw("POST", "/v1/missions/"+missionRef+"/expansion-requests",
		map[string]any{"title": "Extend run scope", "delta": delta, "idempotency_key": "idem-exp-1"}, nil)
	if status != 200 {
		t.Fatalf("request expansion: status %d: %s", status, raw)
	}
	var expWire struct {
		ExpansionID    string `json:"expansion_id"`
		DecisionDigest string `json:"decision_digest"`
	}
	if err := json.Unmarshal(raw, &expWire); err != nil {
		t.Fatalf("cannot decode expansion: %v", err)
	}
	expAtt := f.signAttestation(identity.PurposeExpansionDecision, identity.AudienceExpansionDecision,
		expWire.ExpansionID, expWire.DecisionDigest, st.invocationDigest)
	expResult, err := f.client.DecideExpansion(ctx, expWire.ExpansionID,
		coreapi.ExpansionDecision{Approve: true, Reason: "The run needs the extra ref"},
		expAtt, f.idemOpts("idem-exp-dec-1"))
	if err != nil {
		t.Fatalf("decide expansion: %v", err)
	}
	if expResult.Decision != "approve" {
		t.Fatalf("expansion decision = %q, want approve", expResult.Decision)
	}

	// Mission: publish the idempotent launch check.
	check, err := f.client.PublishGitHubCheck(ctx, coreapi.GitHubCheckRequest{
		BindingID: st.bindingID, HeadSHA: st.issue.SourceRevision, Name: "ope/launch",
		Status: "completed", Conclusion: "success", IdempotencyKey: "idem-check-1",
	}, f.idemOpts("idem-check-1"))
	if err != nil {
		t.Fatalf("publish check: %v", err)
	}
	if check.CheckRunID == "" {
		t.Fatalf("check run has no id")
	}

	// Mission: the signed receipt verifies against the signing-key history.
	receipt, err := f.client.GetReceipt(ctx, grantID, f.opts())
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	verifyReceiptSignature(t, f, receipt)

	// Mission: one active mission before revocation.
	active, err := f.client.ListActiveMissions(ctx, f.opts())
	if err != nil {
		t.Fatalf("list active missions: %v", err)
	}
	if len(active) != 1 || active[0].MissionRef != missionRef {
		t.Fatalf("active missions = %v, want exactly the journey mission", active)
	}
	return missionRef, grantID, proposalID, invocationDigest
}

// openLaunchEnvelope opens the sealed envelope with the real
// launch.OpenEnvelope, pinning the fake's signing key. The fake seals
// with the production envelope construction, so this proves a
// fake-issued envelope passes the same verification the CLI performs.
func openLaunchEnvelope(t *testing.T, f *journeyFixture, cliPriv, envelope []byte, proposalDigest string) *launch.LaunchPayload {
	t.Helper()
	if len(cliPriv) != 32 {
		t.Fatalf("CLI private key is %d bytes, want 32", len(cliPriv))
	}
	var priv [32]byte
	copy(priv[:], cliPriv)
	keys := pinFakeSigningKey(t, f.fake, f.now)
	payload, _, err := launch.OpenEnvelope(envelope, priv, keys, launch.ExpectedBinding{
		ProposalDigest:   proposalDigest,
		InvocationDigest: authn.InvocationDigestForLaunch("kit-cli-minimal", "1.0.0", []string{"run", "--mission"}),
		AgentKitID:       "kit-cli-minimal",
		AgentKitVersion:  "1.0.0",
		RunnerExecutable: "ope-runner",
		RunnerArguments:  []string{"run", "--mission"},
	}, launch.NewNonceCache(), f.now)
	if err != nil {
		t.Fatalf("open launch envelope: %v", err)
	}
	return payload
}

// pinFakeSigningKey builds a trust.KeyStore pinning the fake's signing
// key as the root, so the real verifiers can check fake-issued
// envelopes and receipts.
func pinFakeSigningKey(t *testing.T, fake *FakeAuthScope, now time.Time) *trust.KeyStore {
	t.Helper()
	sum := sha256.Sum256(fake.SigningPublicKey())
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": "sha256:" + hex.EncodeToString(sum[:]),
		"keys": []any{
			map[string]any{
				"key_id":      fake.SigningKeyID(),
				"algorithm":   "Ed25519",
				"public_key":  base64.RawURLEncoding.EncodeToString(fake.SigningPublicKey()),
				"valid_from":  now.Add(-time.Hour).Format(time.RFC3339),
				"valid_until": now.Add(time.Hour).Format(time.RFC3339),
				"root":        true,
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
	ks, err := trust.LoadSigningKeys(path, "")
	if err != nil {
		t.Fatalf("load signing keys: %v", err)
	}
	return ks
}

// verifyReceiptSignature verifies the receipt envelope signature against
// the fake's published signing-key history.
func verifyReceiptSignature(t *testing.T, f *journeyFixture, receipt coreapi.SignedReceiptEnvelope) {
	t.Helper()
	if receipt.Algorithm != "Ed25519" {
		t.Fatalf("receipt algorithm = %q, want Ed25519", receipt.Algorithm)
	}
	keys, err := f.client.GetSigningKeys(context.Background(), f.opts())
	if err != nil {
		t.Fatalf("get signing keys: %v", err)
	}
	var pub []byte
	for _, k := range keys.Keys {
		if k.KeyID == receipt.KeyID {
			pub, err = base64.RawURLEncoding.DecodeString(k.PublicKey)
			if err != nil {
				t.Fatalf("cannot decode signing key: %v", err)
			}
		}
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("signing key %q not found in history", receipt.KeyID)
	}
	sig, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil {
		t.Fatalf("cannot decode receipt signature: %v", err)
	}
	if !ed25519.Verify(pub, receipt.Payload, sig) {
		t.Fatalf("receipt signature does not verify")
	}
}

func TestHappyPathJourney(t *testing.T) {
	f := newJourneyFixture(t, nil)
	runHappyPath(t, f)
}

// gatewayDecision performs one enforcing-gateway authorization check.
func gatewayDecision(t *testing.T, f *journeyFixture, missionRef, action, resource string) (int, map[string]any) {
	t.Helper()
	status, raw := f.doRawGateway("/v1/gateway/authorize", map[string]any{
		"workspace_id": f.workspace, "mission_ref": missionRef,
		"action": action, "resource": resource,
	})
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return status, out
}

func TestRevokeThenContain(t *testing.T) {
	f := newJourneyFixture(t, nil)
	missionRef, _, _, _ := runHappyPath(t, f)
	ctx := context.Background()

	// Revocation takes effect at the enforcing gateway immediately.
	revAtt := f.signAttestation(identity.PurposeMissionRevoke, identity.AudienceMissionRevoke,
		missionRef, digestHex([]byte("revoke-decision")), "")
	rev, err := f.client.RevokeMission(ctx, missionRef, coreapi.RevokeRequest{Reason: "Journey complete"},
		revAtt, f.idemOpts("idem-revoke-1"))
	if err != nil {
		t.Fatalf("revoke mission: %v", err)
	}
	if !rev.Revoked {
		t.Fatalf("revocation not recorded")
	}
	status, decision := gatewayDecision(t, f, missionRef, "git.push", "refs/heads/mission/"+missionRef)
	if status != 200 || decision["decision"] != "deny" || decision["reason"] != "mission_revoked" {
		t.Fatalf("gateway after revoke: status %d decision %v", status, decision)
	}

	// Active-mission listing no longer shows the revoked mission.
	active, err := f.client.ListActiveMissions(ctx, f.opts())
	if err != nil {
		t.Fatalf("list active missions: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("revoked mission still listed as active: %v", active)
	}

	// Workspace containment denies everything at the gateway.
	containAtt := f.signAttestation(identity.PurposeOfflineRecoveryContain, identity.AudienceWorkspaceContain,
		f.workspace, digestHex([]byte("contain-decision")), "")
	contained, err := f.client.ContainWorkspace(ctx,
		coreapi.WorkspaceContainmentRequest{Founder: "founder-e2e", IdempotencyKey: "idem-contain-1"},
		containAtt, f.idemOpts("idem-contain-1"))
	if err != nil {
		t.Fatalf("contain workspace: %v", err)
	}
	if !contained.Contained {
		t.Fatalf("containment not recorded")
	}
	status, decision = gatewayDecision(t, f, missionRef, "git.push", "refs/heads/mission/"+missionRef)
	if status != 200 || decision["decision"] != "deny" || decision["reason"] != "workspace_contained" {
		t.Fatalf("gateway after containment: status %d decision %v", status, decision)
	}

	// Reconciliation of every mutation key returns its settled result.
	for _, key := range []string{"idem-prop-1", "idem-apr-1", "idem-launch-1", "idem-exp-dec-1", "idem-revoke-1", "idem-contain-1"} {
		res, err := f.client.ReconcileOperation(ctx, key, "", f.opts())
		if err != nil {
			t.Fatalf("reconcile %q: %v", key, err)
		}
		if res.Status != "completed" {
			t.Fatalf("reconcile %q: status %q, want completed", key, res.Status)
		}
	}
}
