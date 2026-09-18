// Package receipt verifies AuthScope execution receipts locally and
// publishes one privacy-safe GitHub check per verified pass. OPE never
// asks AuthScope whether its own receipt is valid: verification is
// Ed25519 over the exact canonical payload bytes, with strict
// unknown-field rejection, signing-time key validity, and refreshed
// key history only when chained to the pinned root. An invalid receipt
// leaves the pass in outcome_pending.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Receipt outcomes attested by the payload.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Fixed reason codes for an unverifiable receipt. The private receipt
// view carries only one of these; the raw envelope is never stored or
// rendered.
const (
	ReasonBadSignature = "bad_signature"
	ReasonBadKey       = "bad_key"
	ReasonBadPayload   = "bad_payload"
	ReasonBadBinding   = "bad_binding"
)

// CheckSummary is one verified check line inside the receipt payload.
type CheckSummary struct {
	Kind    string `json:"kind"`
	Outcome string `json:"outcome"`
}

// EnforcementSummary is one verified historical enforcement line
// inside the receipt payload.
type EnforcementSummary struct {
	Level string `json:"level"`
	Scope string `json:"scope"`
}

// Payload is the signed receipt body. Fields are declared in
// alphabetical order so encoding/json emits canonical key order: the
// signature covers exactly these bytes, and verification re-encodes
// the parsed payload and requires byte equality.
type Payload struct {
	AcceptanceEvidence    []string             `json:"acceptance_evidence"`
	AggregateCostMicros   int64                `json:"aggregate_cost_micros"`
	Branch                string               `json:"branch"`
	BudgetMicros          int64                `json:"budget_micros"`
	BudgetNote            string               `json:"budget_note"`
	Checks                []CheckSummary       `json:"checks"`
	ExceptionSummaries    []string             `json:"exception_summaries"`
	ExpansionDecisionRefs []string             `json:"expansion_decision_refs"`
	FinishedAt            int64                `json:"finished_at"`
	GrantID               string               `json:"grant_id"`
	HeadSHA               string               `json:"head_sha"`
	HistoricalEnforcement []EnforcementSummary `json:"historical_enforcement"`
	IssueNumber           int64                `json:"issue_number"`
	KeyID                 string               `json:"key_id"`
	MissionRef            string               `json:"mission_ref"`
	MissionVersions       []int64              `json:"mission_versions"`
	Outcome               string               `json:"outcome"`
	PullRequestNumber     int64                `json:"pull_request_number"`
	ReceiptID             string               `json:"receipt_id"`
	RepositoryID          int64                `json:"repository_id"`
	SettlementDigest      string               `json:"settlement_digest"`
	SignedAt              int64                `json:"signed_at"`
	StartedAt             int64                `json:"started_at"`
	TestSummaries         []string             `json:"test_summaries"`
	WorkspaceID           string               `json:"workspace_id"`
}

// Binding is the locally projected pass binding the receipt claims are
// checked against. Every field comes from OPE's own store: the pass
// record, its projected events, its decided expansions, and its
// repository connection.
type Binding struct {
	WorkspaceID           string
	MissionRef            string
	GrantID               string
	Outcome               string
	MissionVersions       []int64
	ExpansionDecisionRefs []string
	RepositoryID          int64
	IssueNumber           int64
	Branch                string
	PullRequestNumber     int64
	HeadSHA               string
}

// ReceiptView is the private verified receipt projection. It is built
// field by field only after local verification and carries the fixed
// verified fields only: no raw envelope, no issue bodies, logs,
// patches, transcripts, private detail URLs, or secrets. The signed
// free-text evidence (acceptance notes, test and exception summaries,
// budget note) is verified as part of the signature but is never
// projected into any rendered view.
type ReceiptView struct {
	Verification          string               `json:"verification"`
	ReasonCode            string               `json:"reason_code,omitempty"`
	ReceiptID             string               `json:"receipt_id"`
	GrantID               string               `json:"grant_id"`
	MissionRef            string               `json:"mission_ref"`
	WorkspaceID           string               `json:"workspace_id"`
	KeyID                 string               `json:"key_id"`
	SignedAt              int64                `json:"signed_at"`
	ReceiptDigest         string               `json:"receipt_digest"`
	SettlementDigest      string               `json:"settlement_digest"`
	Outcome               string               `json:"outcome"`
	MissionVersions       []int64              `json:"mission_versions"`
	ExpansionDecisionRefs []string             `json:"expansion_decision_refs"`
	RepositoryID          int64                `json:"repository_id"`
	IssueNumber           int64                `json:"issue_number"`
	Branch                string               `json:"branch"`
	PullRequestNumber     int64                `json:"pull_request_number"`
	HeadSHA               string               `json:"head_sha"`
	Checks                []CheckSummary       `json:"checks"`
	StartedAt             int64                `json:"started_at"`
	FinishedAt            int64                `json:"finished_at"`
	AggregateCostMicros   int64                `json:"aggregate_cost_micros"`
	BudgetMicros          int64                `json:"budget_micros"`
	HistoricalEnforcement []EnforcementSummary `json:"historical_enforcement"`
}

// CanonicalPayloadBytes renders the exact bytes the receipt signature
// covers: canonical key order, no whitespace, and nil slices normalized
// to empty arrays so a signer and a verifier always agree.
func CanonicalPayloadBytes(p Payload) ([]byte, error) {
	if p.AcceptanceEvidence == nil {
		p.AcceptanceEvidence = []string{}
	}
	if p.Checks == nil {
		p.Checks = []CheckSummary{}
	}
	if p.ExceptionSummaries == nil {
		p.ExceptionSummaries = []string{}
	}
	if p.ExpansionDecisionRefs == nil {
		p.ExpansionDecisionRefs = []string{}
	}
	if p.HistoricalEnforcement == nil {
		p.HistoricalEnforcement = []EnforcementSummary{}
	}
	if p.MissionVersions == nil {
		p.MissionVersions = []int64{}
	}
	if p.TestSummaries == nil {
		p.TestSummaries = []string{}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("receipt: canonical payload: %w", err)
	}
	return raw, nil
}

// DigestPayload returns the sha256 hex digest of the exact canonical
// payload bytes. The digest is the receipt identity used for storage
// and for the publication idempotency key; the public check exposes
// only a prefix of it.
func DigestPayload(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
