// Package coreapi wire types: the narrow typed surface of the upstream
// AuthScope mission-authority service. Field names follow the vendored
// contract (contracts/authscope-v1.yaml); where the contract pins an enum,
// decoding rejects unknown values so a changed upstream fails closed
// instead of silently misinterpreting authority.
package coreapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// RequestOptions sets workspace, actor, trace, idempotency, and
// optimistic mission-version headers consistently on every upstream call.
// The authenticated transport supplies the workload identity; callers never
// select it.
type RequestOptions struct {
	// WorkspaceID scopes the call. Required on every operation.
	WorkspaceID string
	// ActorID is the local founder the call acts for, for audit.
	ActorID string
	// TraceID correlates the call across local logs and upstream.
	TraceID string
	// RequestID is the idempotency-safe request identifier. Generated when empty.
	RequestID string
	// IdempotencyKey marks the operation idempotent upstream when set.
	IdempotencyKey string
	// MissionVersion is the optimistic concurrency token; sent when positive.
	MissionVersion int64
	// Timeout bounds one operation. Zero selects the client default.
	Timeout time.Duration
}

// strictEnum decodes s and rejects values outside the allowed set.
func strictEnum[T ~string](field, s string, allowed ...string) (T, error) {
	for _, a := range allowed {
		if s == a {
			return T(s), nil
		}
	}
	return "", fmt.Errorf("coreapi: unknown %s %q", field, s)
}

// WorkflowRisk is a workflow-posture finding risk. Unknown risks fail
// closed: OPE must not understate a finding it does not recognize.
type WorkflowRisk string

const (
	WorkflowRiskSecretAccess     WorkflowRisk = "secret_access"
	WorkflowRiskWriteToken       WorkflowRisk = "write_token"
	WorkflowRiskDeploymentTarget WorkflowRisk = "deployment_target"
)

// UnmarshalJSON implements json.Unmarshaler with strict enum checking.
func (r *WorkflowRisk) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := strictEnum[WorkflowRisk]("workflow risk", s,
		string(WorkflowRiskSecretAccess), string(WorkflowRiskWriteToken), string(WorkflowRiskDeploymentTarget))
	if err != nil {
		return err
	}
	*r = v
	return nil
}

// WorkflowPostureKind is the inspected workflow posture.
type WorkflowPostureKind string

const (
	WorkflowPostureClean WorkflowPostureKind = "clean"
	WorkflowPostureRisky WorkflowPostureKind = "risky"
)

// UnmarshalJSON implements json.Unmarshaler with strict enum checking.
func (k *WorkflowPostureKind) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := strictEnum[WorkflowPostureKind]("workflow posture", s,
		string(WorkflowPostureClean), string(WorkflowPostureRisky))
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// CheckStatus is a GitHub check-run status.
type CheckStatus string

const (
	CheckStatusQueued     CheckStatus = "queued"
	CheckStatusInProgress CheckStatus = "in_progress"
	CheckStatusCompleted  CheckStatus = "completed"
)

// UnmarshalJSON implements json.Unmarshaler with strict enum checking.
func (s *CheckStatus) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	parsed, err := strictEnum[CheckStatus]("check status", v,
		string(CheckStatusQueued), string(CheckStatusInProgress), string(CheckStatusCompleted))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// CheckConclusion is a GitHub check-run conclusion.
type CheckConclusion string

const (
	CheckConclusionEmpty   CheckConclusion = ""
	CheckConclusionSuccess CheckConclusion = "success"
	CheckConclusionFailure CheckConclusion = "failure"
	CheckConclusionNeutral CheckConclusion = "neutral"
)

// UnmarshalJSON implements json.Unmarshaler with strict enum checking.
func (c *CheckConclusion) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	parsed, err := strictEnum[CheckConclusion]("check conclusion", v,
		string(CheckConclusionEmpty), string(CheckConclusionSuccess),
		string(CheckConclusionFailure), string(CheckConclusionNeutral))
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// WorkspaceIdentity is the workload identity AuthScope derives from the
// authenticated transport. AuthScope never trusts a client-selected
// identity header.
type WorkspaceIdentity struct {
	IdentityID      string   `json:"identity_id"`
	IdentityDigest  string   `json:"identity_digest"`
	WorkspaceID     string   `json:"workspace_id"`
	Roles           []string `json:"roles"`
	RegistryVersion int64    `json:"registry_version"`
}

// DecisionAttestorRole is the role a workload identity must carry for OPE
// to submit decision attestations.
const DecisionAttestorRole = "decision_attestor"

// HasRole reports whether the identity carries the named role.
func (w WorkspaceIdentity) HasRole(role string) bool {
	for _, r := range w.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// GitHubBindingBeginRequest starts the one-time GitHub App binding
// handoff for owner/repository.
type GitHubBindingBeginRequest struct {
	Repository string `json:"repository"`
}

// GitHubBindingHandoff is the AuthScope-hosted installation handoff. The
// binding code is one-use and opaque; no GitHub OAuth material reaches OPE.
type GitHubBindingHandoff struct {
	HandoffID       string `json:"handoff_id"`
	InstallationURL string `json:"installation_url"`
	BindingCode     string `json:"binding_code"`
	ExpiresAt       int64  `json:"expires_at"`
}

// GitHubBindingFinishRequest completes the handoff with the opaque
// one-use binding code AuthScope redirected back.
type GitHubBindingFinishRequest struct {
	HandoffID   string `json:"handoff_id"`
	BindingCode string `json:"binding_code"`
}

// RepositoryBinding is the resulting repository binding reference. OPE
// persists only this reference plus immutable repository identity.
type RepositoryBinding struct {
	BindingID      string `json:"binding_id"`
	WorkspaceID    string `json:"workspace_id"`
	InstallationID string `json:"installation_id"`
	RepositoryID   string `json:"repository_id"`
	Repository     string `json:"repository"`
	CreatedAt      int64  `json:"created_at"`
}

// GitHubIssueRequest asks AuthScope's broker for a trusted issue snapshot.
type GitHubIssueRequest struct {
	BindingID   string `json:"binding_id"`
	IssueNumber int64  `json:"issue_number"`
}

// GitHubIssueSnapshot is the brokered, canonical issue snapshot. AuthScope
// performs the provider read; no provider credential reaches OPE.
type GitHubIssueSnapshot struct {
	BindingID       string `json:"binding_id"`
	WorkspaceID     string `json:"workspace_id"`
	IssueNumber     int64  `json:"issue_number"`
	Title           string `json:"title"`
	Body            string `json:"body"`
	State           string `json:"state"`
	BaseRef         string `json:"base_ref"`
	BaseSHA         string `json:"base_sha"`
	SourceRevision  string `json:"source_revision"`
	CanonicalDigest string `json:"canonical_digest"`
	SnapshotAt      int64  `json:"snapshot_at"`
}

// WorkflowPostureRequest asks for workflow-posture inspection at a ref.
type WorkflowPostureRequest struct {
	BindingID string `json:"binding_id"`
	Ref       string `json:"ref"`
}

// WorkflowFinding is one risky workflow finding.
type WorkflowFinding struct {
	Path string       `json:"path"`
	Risk WorkflowRisk `json:"risk"`
}

// WorkflowPosture reports workflows able to run agent code with secrets,
// write tokens, or deployment authority.
type WorkflowPosture struct {
	BindingID          string              `json:"binding_id"`
	Ref                string              `json:"ref"`
	WorkflowsInspected int64               `json:"workflows_inspected"`
	Findings           []WorkflowFinding   `json:"findings"`
	Posture            WorkflowPostureKind `json:"posture"`
}

// AgentKit is one supported coding-agent kit.
type AgentKit struct {
	KitID               string   `json:"kit_id"`
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	RuntimeRequirements []string `json:"runtime_requirements"`
}

// agentKitList unwraps the contract AgentKitList envelope.
type agentKitList struct {
	Kits []AgentKit `json:"kits"`
}

// ShapeMissionRequest shapes a mission draft from founder intent.
type ShapeMissionRequest struct {
	Title          string   `json:"title"`
	Objective      string   `json:"objective"`
	Constraints    []string `json:"constraints,omitempty"`
	BudgetMicros   int64    `json:"budget_micros"`
	TTLSeconds     int64    `json:"ttl_seconds"`
	RequestedRoles []string `json:"requested_roles,omitempty"`
}

// MissionDraft is the shaped, reviewable draft with its digests. The
// invocation fields are fixed by AuthScope during shaping: the exact
// agent-kit ID and version, the ordered runner argument array, and the
// algorithm-tagged invocation digest over them. OPE validates the shaped
// draft against its fixed local template and never reshapes authority
// itself.
type MissionDraft struct {
	ProposalDigest   string          `json:"proposal_digest"`
	InvocationDigest string          `json:"invocation_digest"`
	AgentKitID       string          `json:"agent_kit_id"`
	AgentKitVersion  string          `json:"agent_kit_version"`
	RunnerArguments  []string        `json:"runner_arguments"`
	DecisionDigest   string          `json:"decision_digest"`
	BudgetMicros     int64           `json:"budget_micros"`
	TTLSeconds       int64           `json:"ttl_seconds"`
	CanonicalDraft   json.RawMessage `json:"canonical_draft"`
	ShapedAt         int64           `json:"shaped_at"`
	WorkspaceID      string          `json:"workspace_id"`
}

// CreateProposalRequest creates an upstream mission proposal.
type CreateProposalRequest struct {
	Title            string   `json:"title"`
	Objective        string   `json:"objective"`
	Constraints      []string `json:"constraints,omitempty"`
	BudgetMicros     int64    `json:"budget_micros"`
	TTLSeconds       int64    `json:"ttl_seconds"`
	InvocationDigest string   `json:"invocation_digest"`
	IdempotencyKey   string   `json:"idempotency_key"`
}

// Proposal is the created upstream mission proposal. The proposal digest
// and invocation digest are the exact algorithm-tagged canonical digests
// AuthScope returned; OPE stores them byte-for-byte and never computes a
// substitute authority digest. The proposal digest covers the invocation
// digest: the proposal must carry the exact invocation digest the shaping
// fixed.
type Proposal struct {
	ProposalID       string   `json:"proposal_id"`
	ProposalDigest   string   `json:"proposal_digest"`
	InvocationDigest string   `json:"invocation_digest"`
	AgentKitID       string   `json:"agent_kit_id"`
	AgentKitVersion  string   `json:"agent_kit_version"`
	RunnerArguments  []string `json:"runner_arguments"`
	Status           string   `json:"status"`
	WorkspaceID      string   `json:"workspace_id"`
	DecisionDigest   string   `json:"decision_digest"`
	CreatedAt        int64    `json:"created_at"`
}

// LaunchRequest prepares a governed run of an approved mission. The
// ephemeral public key is the CLI X25519 key the sealed signed envelope
// is sealed to.
type LaunchRequest struct {
	KitID              string `json:"kit_id"`
	IdempotencyKey     string `json:"idempotency_key"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
}

// LaunchArtifacts are the signed runtime artifacts for a prepared run.
// The sealed signed envelope is opaque to OPE: only its digest is ever
// persisted.
type LaunchArtifacts struct {
	RunID                   string   `json:"run_id"`
	MissionRef              string   `json:"mission_ref"`
	AuthScopeMissionVersion int64    `json:"authscope_mission_version"`
	RuntimePolicyID         string   `json:"runtime_policy_id"`
	LeaseID                 string   `json:"lease_id"`
	AgentKitID              string   `json:"agent_kit_id"`
	AgentKitVersion         string   `json:"agent_kit_version"`
	InvocationDigest        string   `json:"invocation_digest"`
	RunnerExecutable        string   `json:"runner_executable"`
	RunnerArguments         []string `json:"runner_arguments"`
	IsolationProfile        string   `json:"isolation_profile"`
	EnvelopeKeyID           string   `json:"envelope_key_id"`
	SealedSignedEnvelope    []byte   `json:"sealed_signed_envelope"`
	ExpiresAt               int64    `json:"expires_at"`
}

// Mission is the upstream mission record.
type Mission struct {
	MissionID   string `json:"mission_id"`
	MissionRef  string `json:"mission_ref"`
	WorkspaceID string `json:"workspace_id"`
	State       string `json:"state"`
	Version     int64  `json:"version"`
	// MissionHash is the algorithm-tagged digest of the created mission.
	// Older responses may omit it; approval then derives it locally.
	MissionHash string `json:"mission_hash,omitempty"`
	// ApprovalDecisionRef is the upstream reference for the signed
	// approval decision. Older responses may omit it.
	ApprovalDecisionRef string `json:"approval_decision_ref,omitempty"`
	// AttestationDigest is the digest of the signed decision attestation.
	// Older responses may omit it.
	AttestationDigest string `json:"attestation_digest,omitempty"`
}

// MissionStatus is the introspected mission state.
type MissionStatus struct {
	MissionRef  string `json:"mission_ref"`
	State       string `json:"state"`
	Version     int64  `json:"version"`
	WorkspaceID string `json:"workspace_id"`
}

// RevokeRequest asks AuthScope to revoke a mission.
type RevokeRequest struct {
	Reason string `json:"reason"`
}

// Revocation is the recorded revocation of a mission.
type Revocation struct {
	MissionRef  string `json:"mission_ref"`
	Revoked     bool   `json:"revoked"`
	RevokedAt   int64  `json:"revoked_at"`
	WorkspaceID string `json:"workspace_id"`
	// Containment is the gateway containment acknowledged by the
	// upstream: "acknowledged", "pending", or "partial".
	Containment string `json:"containment"`
}

// Expansion is one requested authority expansion.
type Expansion struct {
	ExpansionID string `json:"expansion_id"`
	MissionRef  string `json:"mission_ref"`
	Status      string `json:"status"`
	RequestedAt int64  `json:"requested_at"`
}

// expansionPage unwraps the contract ExpansionPage envelope.
type expansionPage struct {
	Items      []Expansion `json:"items"`
	NextCursor string      `json:"next_cursor"`
}

// ExpansionDecision approves or denies one expansion request.
type ExpansionDecision struct {
	Approve bool
	Reason  string
}

// expansionDecisionRequest is the wire body for an expansion decision.
type expansionDecisionRequest struct {
	Decision    string         `json:"decision"`
	Reason      string         `json:"reason,omitempty"`
	Attestation map[string]any `json:"attestation"`
}

// ExpansionResult is the recorded expansion decision.
type ExpansionResult struct {
	ExpansionID string `json:"expansion_id"`
	Decision    string `json:"decision"`
	DecidedAt   int64  `json:"decided_at"`
	// MissionVersion is the upstream mission version the decision
	// produced, used to settle the pass without widening the delta.
	MissionVersion int64 `json:"mission_version,omitempty"`
}

// MissionEvent is one authoritative mission event.
type MissionEvent struct {
	EventID    string          `json:"event_id"`
	EventType  string          `json:"event_type"`
	OccurredAt int64           `json:"occurred_at"`
	Payload    json.RawMessage `json:"payload"`
}

// EventPage is one page of mission events.
type EventPage struct {
	Events     []MissionEvent `json:"events"`
	NextCursor string         `json:"next_cursor"`
}

// eventPageWire unwraps the contract EventPage envelope.
type eventPageWire struct {
	Items      []MissionEvent `json:"items"`
	NextCursor string         `json:"next_cursor"`
}

// SignedReceiptEnvelope is the signed execution receipt envelope OPE
// verifies locally. The signature covers the exact canonical payload
// bytes; OPE never asks AuthScope whether its own receipt is valid.
// The envelope carries no interpreted claims: every claim inside the
// payload is checked by the receipt verifier against the local binding.
type SignedReceiptEnvelope struct {
	// Algorithm is the signature algorithm. Only "Ed25519" is accepted.
	Algorithm string `json:"algorithm"`
	// KeyID identifies the signing key; it must be valid at signing time.
	KeyID string `json:"key_id"`
	// Payload is the raw canonical receipt payload bytes.
	Payload json.RawMessage `json:"payload"`
	// Signature is the base64url Ed25519 signature over Payload.
	Signature string `json:"signature"`
}

// SigningKeyRecord is one key in the signing-key history.
type SigningKeyRecord struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`
	ValidFrom   int64  `json:"valid_from"`
	ValidUntil  int64  `json:"valid_until"`
	RotatedFrom string `json:"rotated_from,omitempty"`
}

// SigningKeyHistory is the served signing-key history.
type SigningKeyHistory struct {
	Keys     []SigningKeyRecord `json:"keys"`
	ServedAt int64              `json:"served_at"`
}

// GitHubCheckRequest publishes an idempotent GitHub check run.
type GitHubCheckRequest struct {
	BindingID      string          `json:"binding_id"`
	HeadSHA        string          `json:"head_sha"`
	Name           string          `json:"name"`
	Status         CheckStatus     `json:"status"`
	Conclusion     CheckConclusion `json:"conclusion,omitempty"`
	IdempotencyKey string          `json:"idempotency_key"`
}

// GitHubCheckResult is the published check run.
type GitHubCheckResult struct {
	CheckRunID     string          `json:"check_run_id"`
	BindingID      string          `json:"binding_id"`
	WorkspaceID    string          `json:"workspace_id"`
	HeadSHA        string          `json:"head_sha"`
	Name           string          `json:"name"`
	Status         CheckStatus     `json:"status"`
	Conclusion     CheckConclusion `json:"conclusion"`
	IdempotencyKey string          `json:"idempotency_key"`
	CreatedAt      int64           `json:"created_at"`
}

// OperationResult is the reconciled state of an idempotent operation.
// Artifacts carries the prepared launch when the operation completed.
type OperationResult struct {
	OperationID    string           `json:"operation_id"`
	IdempotencyKey string           `json:"idempotency_key"`
	Status         string           `json:"status"`
	WorkspaceID    string           `json:"workspace_id"`
	Artifacts      *LaunchArtifacts `json:"artifacts,omitempty"`
}

// ActiveMission is one workspace-scoped active mission.
type ActiveMission struct {
	MissionRef  string `json:"mission_ref"`
	State       string `json:"state"`
	WorkspaceID string `json:"workspace_id"`
}

// activeMissionList unwraps the list-active-missions envelope.
type activeMissionList struct {
	Missions []ActiveMission `json:"missions"`
}

// WorkspaceContainmentRequest asks AuthScope to contain a workspace.
type WorkspaceContainmentRequest struct {
	Founder        string `json:"founder"`
	IdempotencyKey string `json:"idempotency_key"`
}

// WorkspaceContainment is the recorded containment state.
type WorkspaceContainment struct {
	WorkspaceID       string `json:"workspace_id"`
	Contained         bool   `json:"contained"`
	Generation        int64  `json:"generation"`
	AttestationDigest string `json:"attestation_digest"`
	ContainedAt       int64  `json:"contained_at"`
}

// approveProposalRequest is the wire body for proposal approval.
// ApproveProposalInput carries the exact proposal the approval decision
// binds. AuthScope approves only when these digests match the proposal
// under review; the browser never supplies them.
type ApproveProposalInput struct {
	ProposalDigest   string `json:"proposal_digest"`
	InvocationDigest string `json:"invocation_digest"`
}

type approveProposalRequest struct {
	ProposalDigest   string         `json:"proposal_digest"`
	InvocationDigest string         `json:"invocation_digest"`
	Attestation      map[string]any `json:"attestation"`
}

// prepareLaunchRequest is the wire body for launch preparation.
type prepareLaunchRequest struct {
	IdempotencyKey     string         `json:"idempotency_key"`
	KitID              string         `json:"kit_id"`
	EphemeralPublicKey string         `json:"ephemeral_public_key"`
	Attestation        map[string]any `json:"attestation"`
}

// revokeMissionRequest is the wire body for mission revocation.
type revokeMissionRequest struct {
	Reason      string         `json:"reason,omitempty"`
	Attestation map[string]any `json:"attestation"`
}

// containWorkspaceRequest is the wire body for workspace containment.
type containWorkspaceRequest struct {
	Founder        string         `json:"founder"`
	IdempotencyKey string         `json:"idempotency_key"`
	Attestation    map[string]any `json:"attestation"`
}

// UpstreamError is a decoded non-2xx AuthScope response. The mapping to a
// local HTTP status is purely status-driven: an upstream denial is never
// translated into a retryable allow path, and the upstream retryable hint
// is recorded but not trusted for mapping.
type UpstreamError struct {
	// StatusCode is the upstream HTTP status.
	StatusCode int
	// Code is the upstream machine-readable error code.
	Code string
	// Message is the upstream message, truncated for safe logging.
	Message string
	// RequestID correlates with the upstream request.
	RequestID string
	// Retryable is the upstream hint. Mapping never trusts it.
	Retryable bool
}

// upstreamProblem is the wire shape of an upstream problem response.
type upstreamProblem struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Retryable bool   `json:"retryable"`
}

// Error renders a redacted summary: status, code, and a truncated message.
// Headers, bodies, signatures, and tokens never appear here.
func (e *UpstreamError) Error() string {
	msg := e.Message
	if len(msg) > 160 {
		msg = msg[:160] + "..."
	}
	msg = strings.ReplaceAll(msg, "\n", " ")
	if e.Code != "" {
		return fmt.Sprintf("coreapi: upstream %d code %q: %s", e.StatusCode, e.Code, msg)
	}
	return fmt.Sprintf("coreapi: upstream %d: %s", e.StatusCode, msg)
}

// LocalStatus maps the upstream status to the local fail-closed HTTP
// status: authentication to 401, forbidden/denied to 403, missing
// workspace-qualified objects to 404, stale version/idempotency mismatch
// to 409, unavailable verified context to 412, rate limits to 429, and all
// other upstream uncertainty to 503.
func (e *UpstreamError) LocalStatus() int {
	switch e.StatusCode {
	case 401:
		return 401
	case 403:
		return 403
	case 404:
		return 404
	case 409:
		return 409
	case 412:
		return 412
	case 429:
		return 429
	default:
		return 503
	}
}
