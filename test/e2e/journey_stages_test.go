package e2e

// Staged journey drivers. connectAndAuthorize runs Connect and Authorize
// (register through proposal approval); prepareRun prepares the governed
// run and verifies the sealed envelope. runHappyPath composes the stages
// with the remaining Mission legs.

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
)

// journeyState carries the artifacts of a driven journey.
type journeyState struct {
	bindingID        string
	issue            coreapi.GitHubIssueSnapshot
	proposal         coreapi.Proposal
	missionRef       string
	grantID          string
	cliPriv          []byte
	invocationDigest string
}

// connectAndPropose drives Connect and Authorize through proposal creation,
// stopping before approval so attack tests can use an unapproved proposal.
func connectAndPropose(t *testing.T, f *journeyFixture) journeyState {
	t.Helper()
	var st journeyState
	ctx := context.Background()

	// The compatibility gate: discovery against the locked contract.
	discovery, err := f.client.Discover(ctx)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	if err := coreapi.CheckCompatibility(ctx, discovery, coreapi.LockedContract(), coreapi.RequiredManifest()); err != nil {
		t.Fatalf("compatibility gate failed: %v", err)
	}

	// Connect: register the workload identity (one-time, attestor role).
	status, raw := f.doRaw("POST", "/v1/identities/workload/register",
		f.registrationBody(f.workspace, []string{"mission.operator"}), nil)
	if status != 200 {
		t.Fatalf("register identity: status %d: %s", status, raw)
	}
	ver, err := f.client.VerifyWorkspaceIdentity(ctx, f.workspace)
	if err != nil {
		t.Fatalf("verify identity: %v", err)
	}
	if !ver.HasRole(coreapi.DecisionAttestorRole) {
		t.Fatalf("identity lacks %q role: %v", coreapi.DecisionAttestorRole, ver.Roles)
	}

	// Connect: begin and finish the GitHub binding handoff.
	begin, err := f.client.BeginGitHubBinding(ctx,
		coreapi.GitHubBindingBeginRequest{Repository: "acme/demo"}, f.idemOpts("idem-begin-1"))
	if err != nil {
		t.Fatalf("begin binding: %v", err)
	}
	if begin.HandoffID == "" || begin.BindingCode == "" {
		t.Fatalf("begin binding returned an empty handoff: %+v", begin)
	}
	binding, err := f.client.FinishGitHubBinding(ctx,
		coreapi.GitHubBindingFinishRequest{HandoffID: begin.HandoffID, BindingCode: begin.BindingCode},
		f.idemOpts("idem-finish-1"))
	if err != nil {
		t.Fatalf("finish binding: %v", err)
	}
	st.bindingID = binding.BindingID

	// Authorize: brokered issue snapshot and workflow posture.
	issue, err := f.client.ReadGitHubIssue(ctx,
		coreapi.GitHubIssueRequest{BindingID: st.bindingID, IssueNumber: 1}, f.opts())
	if err != nil {
		t.Fatalf("read issue: %v", err)
	}
	if issue.CanonicalDigest == "" {
		t.Fatalf("issue snapshot has no canonical digest")
	}
	posture, err := f.client.InspectWorkflowPosture(ctx,
		coreapi.WorkflowPostureRequest{BindingID: st.bindingID, Ref: "main"}, f.opts())
	if err != nil {
		t.Fatalf("inspect posture: %v", err)
	}
	if posture.Posture != coreapi.WorkflowPostureClean {
		t.Fatalf("expected a clean posture for the happy path, got %q", posture.Posture)
	}

	// Authorize: shape then create the proposal.
	draft, err := f.client.ShapeMission(ctx, coreapi.ShapeMissionRequest{
		Title: "Fix the flaky scheduler", Objective: "Make the nightly scheduler deterministic",
		BudgetMicros: 1_000_000, TTLSeconds: 3600,
	}, f.opts())
	if err != nil {
		t.Fatalf("shape mission: %v", err)
	}
	prop, err := f.client.CreateProposal(ctx, coreapi.CreateProposalRequest{
		Title: "Fix the flaky scheduler", Objective: "Make the nightly scheduler deterministic",
		BudgetMicros: 1_000_000, TTLSeconds: 3600,
		InvocationDigest: draft.InvocationDigest, IdempotencyKey: "idem-prop-1",
	}, f.idemOpts("idem-prop-1"))
	if err != nil {
		t.Fatalf("create proposal: %v", err)
	}
	st.proposal = prop
	st.invocationDigest = prop.InvocationDigest
	st.issue = issue
	return st
}

// connectAndAuthorize drives Connect and Authorize through approval.
func connectAndAuthorize(t *testing.T, f *journeyFixture) journeyState {
	t.Helper()
	ctx := context.Background()
	st := connectAndPropose(t, f)
	prop := st.proposal
	// Authorize: approve with a signed decision attestation.
	approveAtt := f.signAttestation(identity.PurposePassApproval, identity.AudienceProposalApproval,
		prop.ProposalID, prop.ProposalDigest, prop.InvocationDigest)
	mission, err := f.client.ApproveProposal(ctx, prop.ProposalID,
		coreapi.ApproveProposalInput{ProposalDigest: prop.ProposalDigest, InvocationDigest: prop.InvocationDigest},
		approveAtt, f.idemOpts("idem-apr-1"))
	if err != nil {
		t.Fatalf("approve proposal: %v", err)
	}
	if mission.State != "active" {
		t.Fatalf("mission state = %q, want active", mission.State)
	}
	st.missionRef = mission.MissionRef
	return st
}

// prepareRun prepares the governed run and verifies the sealed envelope.
func prepareRun(t *testing.T, f *journeyFixture, st *journeyState) coreapi.LaunchArtifacts {
	t.Helper()

	ctx := context.Background()
	intro, err := f.client.IntrospectMission(ctx, st.missionRef, f.opts())
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if intro.Version != 1 {
		t.Fatalf("mission version = %d, want 1", intro.Version)
	}
	kits, err := f.client.ListAgentKits(ctx, f.opts())
	if err != nil {
		t.Fatalf("list agent kits: %v", err)
	}
	if len(kits) == 0 {
		t.Fatalf("no agent kits listed")
	}

	// Mission: prepare the governed run with a signed launch attestation,
	// then independently decrypt and verify the sealed signed envelope.
	cliPriv, cliPub, err := newX25519Keypair()
	if err != nil {
		t.Fatalf("cannot generate CLI keypair: %v", err)
	}
	launchAtt := f.signAttestation(identity.PurposeCLILaunchAuthorization, identity.AudiencePrepareLaunch,
		st.missionRef, digestHex([]byte("launch-decision")), st.invocationDigest)
	artifacts, err := f.client.PrepareLaunch(ctx, st.missionRef, coreapi.LaunchRequest{
		KitID: "kit-cli-minimal", IdempotencyKey: "idem-launch-1",
		EphemeralPublicKey: base64.RawURLEncoding.EncodeToString(cliPub),
	}, launchAtt, f.idemOpts("idem-launch-1"))
	if err != nil {
		t.Fatalf("prepare launch: %v", err)
	}
	payload := openLaunchEnvelope(t, f, cliPriv, artifacts.SealedSignedEnvelope, st.proposal.ProposalDigest)
	if payload.RunID != artifacts.RunID || payload.MissionRef != st.missionRef {
		t.Fatalf("envelope payload does not match artifacts: %+v", payload)
	}

	gid, ok := f.fake.GrantForMission(st.missionRef)
	if !ok {
		t.Fatalf("no execution grant for mission")
	}
	st.grantID = gid
	return artifacts
}
