package e2e

// Attestation security: the fake independently verifies every decision
// attestation and rejects forgeries, replays, expirations, stale claims,
// and bindings that do not match the decision being authorized.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
)

// attackClaims builds valid claims the tests then mutate for one attack.
func attackClaims(f *journeyFixture, st journeyState) identity.DecisionClaims {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		f.t.Fatalf("cannot generate nonce: %v", err)
	}
	proofSum := sha256.Sum256([]byte("proof\x00" + identity.PurposePassApproval + "\x00" + st.proposal.ProposalID))
	return identity.DecisionClaims{
		WorkspaceID:               f.workspace,
		FounderID:                 "founder-e2e",
		Audience:                  identity.AudienceProposalApproval,
		Purpose:                   identity.PurposePassApproval,
		SubjectID:                 st.proposal.ProposalID,
		DecisionDigest:            st.proposal.ProposalDigest,
		InvocationDigest:          st.proposal.InvocationDigest,
		AuthenticationMethod:      identity.AuthMethodWebAuthnUV,
		AuthenticationProofDigest: "sha256:" + hex.EncodeToString(proofSum[:]),
		Nonce:                     nonce,
		IssuedAt:                  f.now,
		ExpiresAt:                 f.now.Add(5 * time.Minute),
	}
}

func approveWith(t *testing.T, f *journeyFixture, st journeyState, att identity.SignedDecisionAttestation, key string) error {
	t.Helper()
	_, err := f.client.ApproveProposal(context.Background(), st.proposal.ProposalID,
		coreapi.ApproveProposalInput{ProposalDigest: st.proposal.ProposalDigest, InvocationDigest: st.proposal.InvocationDigest},
		att, f.idemOpts(key))
	return err
}

// proposedFixture returns a fresh fixture with a proposal that has not
// been approved yet, so attack attestations hit verification instead of
// the already-approved denial.
func proposedFixture(t *testing.T) (*journeyFixture, journeyState) {
	t.Helper()
	f := newJourneyFixture(t, nil)
	return f, connectAndPropose(t, f)
}

func TestAttestationSecurity(t *testing.T) {

	t.Run("tampered_signature", func(t *testing.T) {
		f, st := proposedFixture(t)
		att := tamperSignature(f.signAttestationClaims(attackClaims(f, st)))
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-tamper"), 403, "attestation_signature_invalid")
	})

	t.Run("replayed_attestation", func(t *testing.T) {
		f, st := proposedFixture(t)
		att := f.signAttestationClaims(attackClaims(f, st))
		if err := approveWith(t, f, st, att, "idem-att-replay-1"); err != nil {
			t.Fatalf("first presentation failed: %v", err)
		}
		// Same attestation, fresh idempotency key: the nonce is consumed.
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-replay-2"), 403, "attestation_replayed")
	})

	t.Run("wrong_audience", func(t *testing.T) {
		f, st := proposedFixture(t)
		// An attestation for a different purpose/audience pair that the
		// signer accepts honestly, presented at proposal approval.
		c := attackClaims(f, st)
		c.Purpose = identity.PurposeCLILaunchAuthorization
		c.Audience = identity.AudiencePrepareLaunch
		c.SubjectID = "some-run"
		att := f.signAttestationClaims(c)
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-audience"), 403, "attestation_audience_mismatch")
	})

	t.Run("wrong_subject", func(t *testing.T) {
		f, st := proposedFixture(t)
		att := f.signAttestation(identity.PurposePassApproval, identity.AudienceProposalApproval,
			"other-proposal", st.proposal.ProposalDigest, st.proposal.InvocationDigest)
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-subject"), 403, "attestation_subject_mismatch")
	})

	t.Run("wrong_decision_digest", func(t *testing.T) {
		f, st := proposedFixture(t)
		c := attackClaims(f, st)
		c.DecisionDigest = digestHex([]byte("attacker-decision"))
		att := f.signAttestationClaims(c)
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-decision"), 403, "attestation_decision_mismatch")
	})

	t.Run("wrong_workspace", func(t *testing.T) {
		f, st := proposedFixture(t)
		c := attackClaims(f, st)
		c.WorkspaceID = "ws-attacker"
		att := f.signAttestationClaims(c)
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-workspace"), 403, "attestation_workspace_mismatch")
	})

	t.Run("expired_attestation", func(t *testing.T) {
		f, st := proposedFixture(t)
		c := attackClaims(f, st)
		c.IssuedAt = f.now.Add(-10 * time.Minute)
		c.ExpiresAt = f.now.Add(-5 * time.Minute)
		att := f.signAttestationClaims(c)
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-expired"), 403, "attestation_expired")
	})

	t.Run("stale_attestation", func(t *testing.T) {
		f, st := proposedFixture(t)
		// Issued 16 minutes ago: not fresh, and the 15-minute TTL means it
		// also expired, so the expiry check fires first.
		c := attackClaims(f, st)
		c.IssuedAt = f.now.Add(-16 * time.Minute)
		c.ExpiresAt = f.now.Add(-1 * time.Minute)
		att := f.signAttestationClaims(c)
		requireUpstreamCode(t, approveWith(t, f, st, att, "idem-att-stale"), 403, "attestation_expired")
	})

	t.Run("missing_attestation", func(t *testing.T) {
		f, st := proposedFixture(t)
		status, raw := f.doRaw("POST", "/v1/mission-proposals/"+st.proposal.ProposalID+"/approve",
			map[string]any{
				"proposal_digest":   st.proposal.ProposalDigest,
				"invocation_digest": st.proposal.InvocationDigest,
			}, map[string]string{"Idempotency-Key": "idem-att-missing"})
		if status != 400 {
			t.Fatalf("missing attestation: status %d, want 400: %s", status, raw)
		}
		mustContainCode(t, raw, "missing_attestation")
	})
}
