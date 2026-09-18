package e2e

// Cardinality: the journey's one-of-each denials. Every second attempt
// fails with the exact upstream code and leaves OPE state unchanged.

import (
	"context"
	"testing"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
)

func TestCardinalityDenials(t *testing.T) {
	f := newJourneyFixture(t, nil)
	ctx := context.Background()
	st := connectAndAuthorize(t, f)
	prepareRun(t, f, &st)

	introBefore, err := f.client.IntrospectMission(ctx, st.missionRef, f.opts())
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}

	// A second GitHub binding is denied: one repository per workspace.
	_, err = f.client.BeginGitHubBinding(ctx,
		coreapi.GitHubBindingBeginRequest{Repository: "acme/other"}, f.idemOpts("idem-begin-2"))
	requireUpstreamCode(t, err, 409, "binding_exists")

	// A second proposal is denied.
	_, err = f.client.CreateProposal(ctx, coreapi.CreateProposalRequest{
		Title: "Another idea", Objective: "Something else",
		InvocationDigest: st.invocationDigest, IdempotencyKey: "idem-prop-2",
	}, f.idemOpts("idem-prop-2"))
	requireUpstreamCode(t, err, 409, "proposal_exists")

	// A second approval with a fresh attestation is denied.
	approveAtt := f.signAttestation(identity.PurposePassApproval, identity.AudienceProposalApproval,
		st.proposal.ProposalID, st.proposal.ProposalDigest, st.proposal.InvocationDigest)
	_, err = f.client.ApproveProposal(ctx, st.proposal.ProposalID,
		coreapi.ApproveProposalInput{ProposalDigest: st.proposal.ProposalDigest, InvocationDigest: st.proposal.InvocationDigest},
		approveAtt, f.idemOpts("idem-apr-2"))
	requireUpstreamCode(t, err, 409, "proposal_already_approved")

	// A second launch with a fresh attestation is denied.
	_, cliPub, err := newX25519Keypair()
	if err != nil {
		t.Fatalf("cannot generate CLI keypair: %v", err)
	}
	launchAtt := f.signAttestation(identity.PurposeCLILaunchAuthorization, identity.AudiencePrepareLaunch,
		st.missionRef, digestHex([]byte("launch-decision-2")), st.invocationDigest)
	_, err = f.client.PrepareLaunch(ctx, st.missionRef, coreapi.LaunchRequest{
		KitID: "kit-cli-minimal", IdempotencyKey: "idem-launch-2",
		EphemeralPublicKey: b64url(cliPub),
	}, launchAtt, f.idemOpts("idem-launch-2"))
	requireUpstreamCode(t, err, 409, "launch_exists")

	// A second open expansion is denied while one is open.
	delta := jsonRaw(`{"actions":["run.execute"],"resources":["refs/heads/mission-x"]}`)
	status, raw := f.doRaw("POST", "/v1/missions/"+st.missionRef+"/expansion-requests",
		map[string]any{"title": "First scope", "delta": delta, "idempotency_key": "idem-exp-c1"}, nil)
	if status != 200 {
		t.Fatalf("request expansion: status %d: %s", status, raw)
	}
	var first struct {
		ExpansionID    string `json:"expansion_id"`
		DecisionDigest string `json:"decision_digest"`
	}
	mustUnmarshal(t, raw, &first)
	status, raw = f.doRaw("POST", "/v1/missions/"+st.missionRef+"/expansion-requests",
		map[string]any{"title": "Second scope", "delta": delta, "idempotency_key": "idem-exp-c2"}, nil)
	if status != 409 {
		t.Fatalf("second open expansion: status %d, want 409: %s", status, raw)
	}
	mustContainCode(t, raw, "expansion_open")

	// Deciding the open expansion with the exact delta succeeds.
	expAtt := f.signAttestation(identity.PurposeExpansionDecision, identity.AudienceExpansionDecision,
		first.ExpansionID, first.DecisionDigest, st.invocationDigest)
	expResult, err := f.client.DecideExpansion(ctx, first.ExpansionID,
		coreapi.ExpansionDecision{Approve: true, Reason: "Needed"}, expAtt, f.idemOpts("idem-exp-cd-1"))
	if err != nil {
		t.Fatalf("decide expansion: %v", err)
	}
	if expResult.Decision != "approve" {
		t.Fatalf("expansion decision = %q, want approve", expResult.Decision)
	}

	// No denial changed OPE state: one active mission, version moved only
	// by the legitimate expansion approval.
	active, err := f.client.ListActiveMissions(ctx, f.opts())
	if err != nil {
		t.Fatalf("list active missions: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("active missions = %d, want 1 after denials", len(active))
	}
	introAfter, err := f.client.IntrospectMission(ctx, st.missionRef, f.opts())
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if introAfter.Version != introBefore.Version+1 {
		t.Fatalf("mission version moved %d -> %d, want exactly one legitimate bump",
			introBefore.Version, introAfter.Version)
	}
}
