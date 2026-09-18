package missionpass

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
)

// The fixed local template. These constants bound every mission pass;
// AuthScope shapes and evaluates authority inside them. The template is
// input validation and presentation metadata only: it never authorizes an
// action.
const (
	// MissionBranchPrefix prefixes every generated mission branch; the
	// full branch is authscope/<pass-id>-<issue-number>.
	MissionBranchPrefix = "authscope/"
	// MaxTTL bounds founder-requested expiry at two hours.
	MaxTTL = 2 * time.Hour
	// MaxTTLSeconds is MaxTTL in seconds for wire comparisons.
	MaxTTLSeconds = 7200
	// MaxAggregateCostMicros bounds founder-requested spend at USD 20.
	MaxAggregateCostMicros = 20_000_000
	// FixedAgentKitID and FixedAgentKitVersion pin the one supported
	// AuthScope agent kit. The shaped response must match them exactly.
	FixedAgentKitID      = "authscope-agent-kit"
	FixedAgentKitVersion = "1.0.0"
	// MaxPendingExpansions allows one pending expansion at a time.
	MaxPendingExpansions = 1
)

// ProtectedPaths are the fixed paths a mission can never touch.
var ProtectedPaths = []string{
	".github/workflows/",
	".github/actions/",
	"Dockerfile",
	"docker-compose.yml",
	".env",
	"secrets/",
}

// Enforcement labels are honest about where enforcement happens: in
// AuthScope, never in OPE.
const (
	EnforcementLabelGitHub  = "GitHub actions are brokered and enforced by AuthScope"
	EnforcementLabelRuntime = "Agent runtime actions are compiled and enforced by AuthScope"
)

// Capability summaries for the compact Authorize review.
var (
	CapabilityCan = []string{
		"Work on the generated mission branch",
		"Run the repository's configured tests",
		"Open one pull request",
	}
	CapabilityWillAsk = []string{
		"Any operation outside the approved grant needs a one-time founder-approved expansion",
	}
	CapabilityCannot = []string{
		"Touch the default branch",
		"Modify protected paths or workflows",
		"Deploy or change release targets",
		"Read secrets",
		"Administer the repository",
	}
)

// MissionBranch derives the generated mission branch for a pass.
func MissionBranch(passID string, issueNumber int64) string {
	return MissionBranchPrefix + passID + "-" + strconv.FormatInt(issueNumber, 10)
}

// canonicalDigestPattern pins the algorithm-tagged digest shape OPE
// accepts from AuthScope. An untagged or differently-tagged digest fails
// closed instead of being trusted as the authority digest.
var canonicalDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateShaped requires the shaped mission draft to remain inside the
// fixed template and the requested limits. ttlSeconds and budgetMicros are
// what OPE asked AuthScope to shape; a shaped result wider than either, or
// wider than the template, fails closed. The invocation digest must be
// algorithm-tagged; AuthScope is the authority on its value.
func ValidateShaped(draft coreapi.MissionDraft, ttlSeconds, budgetMicros int64) error {
	if !canonicalDigestPattern.MatchString(draft.ProposalDigest) {
		return fmt.Errorf("%w: malformed shaped proposal digest", ErrTemplateViolation)
	}
	if !canonicalDigestPattern.MatchString(draft.InvocationDigest) {
		return fmt.Errorf("%w: malformed shaped invocation digest", ErrTemplateViolation)
	}
	if draft.AgentKitID != FixedAgentKitID {
		return fmt.Errorf("%w: shaped agent-kit ID %q, want %q", ErrTemplateViolation, draft.AgentKitID, FixedAgentKitID)
	}
	if draft.AgentKitVersion != FixedAgentKitVersion {
		return fmt.Errorf("%w: shaped agent-kit version %q, want %q", ErrTemplateViolation, draft.AgentKitVersion, FixedAgentKitVersion)
	}
	if len(draft.RunnerArguments) == 0 {
		return fmt.Errorf("%w: shaped runner arguments are empty", ErrTemplateViolation)
	}
	for i, arg := range draft.RunnerArguments {
		if arg == "" {
			return fmt.Errorf("%w: shaped runner argument %d is empty", ErrTemplateViolation, i)
		}
	}
	if draft.BudgetMicros <= 0 || draft.BudgetMicros > budgetMicros {
		return fmt.Errorf("%w: shaped budget %d outside requested %d", ErrTemplateViolation, draft.BudgetMicros, budgetMicros)
	}
	if draft.BudgetMicros > MaxAggregateCostMicros {
		return fmt.Errorf("%w: shaped budget %d above template maximum", ErrTemplateViolation, draft.BudgetMicros)
	}
	if draft.TTLSeconds <= 0 || draft.TTLSeconds > ttlSeconds {
		return fmt.Errorf("%w: shaped TTL %d outside requested %d", ErrTemplateViolation, draft.TTLSeconds, ttlSeconds)
	}
	if draft.TTLSeconds > MaxTTLSeconds {
		return fmt.Errorf("%w: shaped TTL %d above template maximum", ErrTemplateViolation, draft.TTLSeconds)
	}
	if len(draft.CanonicalDraft) == 0 {
		return fmt.Errorf("%w: shaped canonical draft is empty", ErrTemplateViolation)
	}
	return nil
}

// ValidateProposal requires the created proposal to stay inside the fixed
// template and to carry exactly what shaping fixed. The proposal digest
// covers the invocation digest: the proposal must carry the exact
// invocation digest, agent-kit identity, and ordered runner arguments from
// the shaped draft, byte-for-byte. Any mutation fails closed.
func ValidateProposal(shaped coreapi.MissionDraft, proposal coreapi.Proposal) error {
	if proposal.ProposalID == "" {
		return fmt.Errorf("%w: empty proposal ID", ErrProposalMismatch)
	}
	if !canonicalDigestPattern.MatchString(proposal.ProposalDigest) {
		return fmt.Errorf("%w: malformed proposal digest", ErrProposalMismatch)
	}
	if !canonicalDigestPattern.MatchString(proposal.InvocationDigest) {
		return fmt.Errorf("%w: malformed invocation digest", ErrProposalMismatch)
	}
	if proposal.InvocationDigest != shaped.InvocationDigest {
		return fmt.Errorf("%w: invocation digest differs from the shaped draft", ErrProposalMismatch)
	}
	if proposal.AgentKitID != FixedAgentKitID || proposal.AgentKitVersion != FixedAgentKitVersion {
		return fmt.Errorf("%w: proposal kit %q %q, want the fixed template kit",
			ErrProposalMismatch, proposal.AgentKitID, proposal.AgentKitVersion)
	}
	if len(proposal.RunnerArguments) != len(shaped.RunnerArguments) {
		return fmt.Errorf("%w: runner argument count %d, want %d",
			ErrProposalMismatch, len(proposal.RunnerArguments), len(shaped.RunnerArguments))
	}
	for i := range shaped.RunnerArguments {
		if proposal.RunnerArguments[i] != shaped.RunnerArguments[i] {
			return fmt.Errorf("%w: runner argument %d %q, want %q",
				ErrProposalMismatch, i, proposal.RunnerArguments[i], shaped.RunnerArguments[i])
		}
	}
	return nil
}
