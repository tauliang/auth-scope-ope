// Package missionpass shapes and creates the exact AuthScope mission
// proposal a founder reviews before approval. The local template in
// template.go is input validation and presentation metadata only:
// AuthScope shapes and evaluates authority. The proposal service stores
// AuthScope's returned proposal ID, algorithm-tagged proposal and
// invocation digests, fixed agent-kit identity, and ordered runner
// arguments byte-for-byte, and never computes a substitute authority
// digest.
package missionpass

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// EditableLimits are the only two founder-editable values of a draft: an
// earlier expiry and a lower aggregate-cost ceiling.
type EditableLimits struct {
	ExpiresAt              time.Time `json:"expires_at"`
	MaxAggregateCostMicros int64     `json:"max_aggregate_cost_micros"`
}

// ProposalRecord is the immutable local proposal revision. StoreRevision
// is the only local compare-and-swap token. DraftVersion changes only when
// a founder-visible proposal is revised. AuthScopeMissionVersion is zero
// before approval and changes only when AuthScope creates or revises
// mission authority. ProposalDigest and InvocationDigest are the exact
// algorithm-tagged canonical digests AuthScope returned; the proposal
// digest covers the invocation digest. ApprovedProposalDigest stays empty
// until approval copies the approved value.
type ProposalRecord struct {
	WorkspaceID             string              `json:"workspace_id"`
	PassID                  string              `json:"pass_id"`
	StoreRevision           int64               `json:"store_revision"`
	DraftVersion            int64               `json:"draft_version"`
	AuthScopeMissionVersion int64               `json:"authscope_mission_version"`
	ProposalID              string              `json:"proposal_id"`
	ProposalDigest          string              `json:"proposal_digest"`
	ApprovedProposalDigest  string              `json:"approved_proposal_digest"`
	SourceRevision          string              `json:"source_revision"`
	SourceDigest            string              `json:"source_digest"`
	BaseSHA                 string              `json:"base_sha"`
	MissionBranch           string              `json:"mission_branch"`
	AgentKitID              string              `json:"agent_kit_id"`
	AgentKitVersion         string              `json:"agent_kit_version"`
	RunnerArguments         []string            `json:"runner_arguments"`
	InvocationDigest        string              `json:"invocation_digest"`
	Limits                  EditableLimits      `json:"limits"`
	State                   PassState           `json:"state"`
	Reconciliation          ReconciliationState `json:"reconciliation"`
}

// PassState is the lifecycle state of a mission pass. Terminal states
// (completed, failed, revoked, expired) never transition.
type PassState string

const (
	PassDraft             PassState = "draft"
	PassApproved          PassState = "approved"
	PassLaunching         PassState = "launching"
	PassRunning           PassState = "running"
	PassAwaitingExpansion PassState = "awaiting_expansion"
	PassOutcomePending    PassState = "outcome_pending"
	PassCompleted         PassState = "completed"
	PassFailed            PassState = "failed"
	PassRevoked           PassState = "revoked"
	PassExpired           PassState = "expired"
)

// ReconciliationState tracks whether the last upstream proposal mutation
// has a known outcome. It is orthogonal to the pass state.
type ReconciliationState string

const (
	ReconciliationSettled  ReconciliationState = "settled"
	ReconciliationPending  ReconciliationState = "pending"
	ReconciliationDisputed ReconciliationState = "disputed"
)

// passTransitions is the complete legal transition table. A run-success or
// run-failure event enters outcome_pending; only a locally verified receipt
// enters completed or failed. A failed launch preparation returns the pass
// to approved so the founder may retry or revoke; it never enters failed
// without a verified receipt.
var passTransitions = map[PassState]map[PassState]bool{
	PassDraft: {
		PassApproved: true, PassRevoked: true, PassExpired: true,
	},
	PassApproved: {
		PassLaunching: true, PassRevoked: true, PassExpired: true,
	},
	PassLaunching: {
		PassApproved: true, PassRunning: true, PassRevoked: true, PassExpired: true,
	},
	PassRunning: {
		PassAwaitingExpansion: true, PassOutcomePending: true,
		PassRevoked: true, PassExpired: true,
	},
	PassAwaitingExpansion: {
		PassRunning: true, PassRevoked: true, PassExpired: true,
	},
	PassOutcomePending: {
		PassCompleted: true, PassFailed: true, PassRevoked: true,
	},
}

var knownPassStates = map[PassState]bool{
	PassDraft: true, PassApproved: true, PassLaunching: true,
	PassRunning: true, PassAwaitingExpansion: true, PassOutcomePending: true,
	PassCompleted: true, PassFailed: true, PassRevoked: true, PassExpired: true,
}

// Transition reports whether from may move to to. Unknown states and every
// transition out of a terminal state fail closed.
func Transition(from, to PassState) error {
	if !knownPassStates[from] {
		return fmt.Errorf("missionpass: unknown pass state %q", from)
	}
	if !knownPassStates[to] {
		return fmt.Errorf("missionpass: unknown pass state %q", to)
	}
	if passTransitions[from][to] {
		return nil
	}
	return fmt.Errorf("missionpass: illegal pass transition %q to %q", from, to)
}

// approvalDomain separates the founder's passkey approval binding from
// every other digest in the system.
const approvalDomain = "authscope-ope/pass-approval/v1"

func writeApprovalField(b *bytes.Buffer, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	b.Write(lenBuf[:])
	b.WriteString(s)
}

// CanonicalApprovalBytes returns the exact canonical bytes the founder's
// passkey decision binds to: the domain separator, the workspace and pass
// IDs, and AuthScope's exact proposal and invocation digests. Every field
// is length-prefixed so ambiguous concatenations cannot collide. Task 7's
// approval flow signs these bytes; the decision attests the proposal and
// invocation digests the founder reviewed, nothing else.
func CanonicalApprovalBytes(record ProposalRecord) []byte {
	var b bytes.Buffer
	b.WriteString(approvalDomain)
	writeApprovalField(&b, record.WorkspaceID)
	writeApprovalField(&b, record.PassID)
	writeApprovalField(&b, record.ProposalDigest)
	writeApprovalField(&b, record.InvocationDigest)
	return b.Bytes()
}
