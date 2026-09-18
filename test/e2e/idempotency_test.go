package e2e

// Idempotency and reconciliation: replaying the same key with the
// canonical body returns the original result; reusing a key with changed
// content is a 409; reconciliation returns the settled result.

import (
	"context"
	"testing"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
)

func TestIdempotencyReplay(t *testing.T) {
	f := newJourneyFixture(t, nil)
	ctx := context.Background()
	st := connectAndPropose(t, f)

	// First presentation: the approval consumes the attestation nonce and
	// creates the mission.
	approveAtt := f.signAttestation(identity.PurposePassApproval, identity.AudienceProposalApproval,
		st.proposal.ProposalID, st.proposal.ProposalDigest, st.proposal.InvocationDigest)
	approve := func(key string, att identity.SignedDecisionAttestation, digest string) (coreapi.Mission, error) {
		return f.client.ApproveProposal(ctx, st.proposal.ProposalID,
			coreapi.ApproveProposalInput{ProposalDigest: digest, InvocationDigest: st.proposal.InvocationDigest},
			att, f.idemOpts(key))
	}
	mission, err := approve("idem-apr-r1", approveAtt, st.proposal.ProposalDigest)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Replay the identical body with the same key: the original mission is
	// returned even though the attestation nonce was already consumed.
	mission2, err := approve("idem-apr-r1", approveAtt, st.proposal.ProposalDigest)
	if err != nil {
		t.Fatalf("replay approval: %v", err)
	}
	if mission2.MissionRef != mission.MissionRef {
		t.Fatalf("replay returned mission %q, want %q", mission2.MissionRef, mission.MissionRef)
	}

	// The same idempotency key with changed content is a 409.
	approveAtt2 := f.signAttestation(identity.PurposePassApproval, identity.AudienceProposalApproval,
		st.proposal.ProposalID, st.proposal.ProposalDigest, st.proposal.InvocationDigest)
	_, err = approve("idem-apr-r1", approveAtt2,
		"sha256:0000000000000000000000000000000000000000000000000000000000000000")
	requireUpstreamCode(t, err, 409, "idempotency_key_reused")

	// The GitHub handoff code is one-use: replaying finish is rejected.
	status, raw := f.doRaw("POST", "/v1/integrations/github/bindings/finish",
		map[string]any{"handoff_id": "handoff_unknown", "binding_code": "code_unknown"}, nil)
	if status != 403 {
		t.Fatalf("finish with unknown handoff: status %d, want 403: %s", status, raw)
	}
	mustContainCode(t, raw, "handoff_consumed")

	// Reconciliation returns the settled approval result by key.
	res, err := f.client.ReconcileOperation(ctx, "idem-apr-r1", "", f.opts())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("reconcile status = %q, want completed", res.Status)
	}

	// An unknown key reconciles as not found, not as an error-shaped guess.
	_, err = f.client.ReconcileOperation(ctx, "idem-never-used", "", f.opts())
	requireUpstreamCode(t, err, 404, "operation_not_found")
}

func TestFailedRunJourney(t *testing.T) {
	f := newJourneyFixture(t, nil)
	ctx := context.Background()
	st := connectAndAuthorize(t, f)
	prepareRun(t, f, &st)

	// Settle the run as a failure: the run_failed event is emitted and the
	// receipt records the failure outcome.
	status, raw := f.doRaw("POST", "/v1/executions/"+st.grantID+"/consume",
		map[string]any{"amount_micros": 500, "idempotency_key": "idem-consume-f1"}, nil)
	if status != 200 {
		t.Fatalf("consume: status %d: %s", status, raw)
	}
	status, raw = f.doRaw("POST", "/v1/executions/settle",
		map[string]any{"grant_id": st.grantID, "outcome": "failure", "idempotency_key": "idem-settle-f1"}, nil)
	if status != 200 {
		t.Fatalf("settle: status %d: %s", status, raw)
	}
	page, err := f.client.ReadEvents(ctx, st.missionRef, "", f.opts())
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	found := false
	for _, e := range page.Events {
		if e.EventType == "run_failed" {
			found = true
		}
		if !knownEventTypes[e.EventType] {
			t.Fatalf("unknown event type: %q", e.EventType)
		}
	}
	if !found {
		t.Fatalf("run_failed event missing after failed settle")
	}
	receipt, err := f.client.GetReceipt(ctx, st.grantID, f.opts())
	if err != nil {
		t.Fatalf("get receipt: %v", err)
	}
	verifyReceiptSignature(t, f, receipt)
	var payload struct {
		Outcome string `json:"outcome"`
	}
	mustUnmarshal(t, receipt.Payload, &payload)
	if payload.Outcome != "failure" {
		t.Fatalf("receipt outcome = %q, want failure", payload.Outcome)
	}
}

func TestIncompatibleCore(t *testing.T) {
	f := newJourneyFixture(t, func(o *FakeOptions) { o.IncompatibleCore = true })
	ctx := context.Background()
	discovery, err := f.client.Discover(ctx)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	err = coreapi.CheckCompatibility(ctx, discovery, coreapi.LockedContract(), coreapi.RequiredManifest())
	if err == nil {
		t.Fatalf("compatibility gate passed against an incompatible core")
	}
	t.Logf("gate correctly rejected incompatible core: %v", err)
}

func TestUnknownEventIncompatible(t *testing.T) {
	f := newJourneyFixture(t, func(o *FakeOptions) { o.ExtraEventTypes = []string{"future_event_v9"} })
	ctx := context.Background()
	st := connectAndAuthorize(t, f)
	_, err := f.client.ReadEvents(ctx, st.missionRef, "", f.opts())
	requireUpstreamCode(t, err, 409, "incompatible_events")
}
