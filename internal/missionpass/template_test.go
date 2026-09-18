package missionpass

import (
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
)

func TestTemplateConstants(t *testing.T) {
	if MaxTTL != 2*time.Hour {
		t.Errorf("MaxTTL = %v, want 2h", MaxTTL)
	}
	if MaxAggregateCostMicros != 20_000_000 {
		t.Errorf("MaxAggregateCostMicros = %d, want 20000000 (USD 20 in micros)", MaxAggregateCostMicros)
	}
	if FixedAgentKitID == "" || FixedAgentKitVersion == "" {
		t.Error("fixed agent-kit ID and version must be pinned constants")
	}
	if MaxPendingExpansions != 1 {
		t.Errorf("MaxPendingExpansions = %d, want 1", MaxPendingExpansions)
	}
	if len(ProtectedPaths) == 0 {
		t.Error("ProtectedPaths must list the fixed protected paths")
	}
	if EnforcementLabelGitHub == "" || EnforcementLabelRuntime == "" {
		t.Error("enforcement labels must be set")
	}
	if len(CapabilityCan) == 0 || len(CapabilityWillAsk) == 0 || len(CapabilityCannot) == 0 {
		t.Error("Can / Will ask / Cannot summaries must be set")
	}
}

func TestMissionBranchPrefix(t *testing.T) {
	branch := MissionBranch("pass-1", 42)
	if !strings.HasPrefix(branch, "authscope/pass-1-") {
		t.Errorf("MissionBranch = %q, want prefix %q", branch, "authscope/pass-1-")
	}
	if strings.Contains(branch, " ") {
		t.Errorf("MissionBranch %q must not contain spaces", branch)
	}
}

func validShapedDraft() coreapi.MissionDraft {
	return coreapi.MissionDraft{
		ProposalDigest:   "sha256:" + strings.Repeat("a", 64),
		InvocationDigest: "sha256:" + strings.Repeat("b", 64),
		AgentKitID:       FixedAgentKitID,
		AgentKitVersion:  FixedAgentKitVersion,
		RunnerArguments:  []string{"authscope-agent-run", "--mission", "pass-1"},
		DecisionDigest:   "sha256:" + strings.Repeat("c", 64),
		BudgetMicros:     10_000_000,
		TTLSeconds:       3600,
		CanonicalDraft:   []byte(`{"objective":"Add retries"}`),
		ShapedAt:         1_700_000_000,
		WorkspaceID:      "ws-test",
	}
}

func TestValidateShapedAcceptsTemplateConformantDraft(t *testing.T) {
	if err := ValidateShaped(validShapedDraft(), 3600, 10_000_000); err != nil {
		t.Fatalf("ValidateShaped = %v, want nil", err)
	}
}

func TestValidateShapedRejectsWidenedResult(t *testing.T) {
	// A shaped result wider than the requested limits or the fixed
	// template fails closed: OPE never presents authority it did not ask
	// AuthScope to shape inside the template.
	cases := map[string]func(*coreapi.MissionDraft){
		"budget above requested": func(d *coreapi.MissionDraft) { d.BudgetMicros = 15_000_000 },
		"budget above template":  func(d *coreapi.MissionDraft) { d.BudgetMicros = 30_000_000 },
		"zero budget":            func(d *coreapi.MissionDraft) { d.BudgetMicros = 0 },
		"ttl above requested":    func(d *coreapi.MissionDraft) { d.TTLSeconds = 7200 },
		"ttl above template":     func(d *coreapi.MissionDraft) { d.TTLSeconds = 10800 },
		"zero ttl":               func(d *coreapi.MissionDraft) { d.TTLSeconds = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := validShapedDraft()
			mutate(&d)
			if err := ValidateShaped(d, 3600, 10_000_000); err == nil {
				t.Error("ValidateShaped = nil, want template violation")
			}
		})
	}
}

func TestValidateShapedRejectsMutatedKit(t *testing.T) {
	cases := map[string]func(*coreapi.MissionDraft){
		"kit id":      func(d *coreapi.MissionDraft) { d.AgentKitID = "other-kit" },
		"kit version": func(d *coreapi.MissionDraft) { d.AgentKitVersion = "9.9.9" },
		"empty kit":   func(d *coreapi.MissionDraft) { d.AgentKitID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := validShapedDraft()
			mutate(&d)
			if err := ValidateShaped(d, 3600, 10_000_000); err == nil {
				t.Error("ValidateShaped = nil, want template violation")
			}
		})
	}
}

func TestValidateShapedRejectsBadDigests(t *testing.T) {
	cases := map[string]func(*coreapi.MissionDraft){
		"proposal digest untagged":   func(d *coreapi.MissionDraft) { d.ProposalDigest = strings.Repeat("a", 64) },
		"proposal digest bad hex":    func(d *coreapi.MissionDraft) { d.ProposalDigest = "sha256:" + strings.Repeat("z", 64) },
		"proposal digest md5":        func(d *coreapi.MissionDraft) { d.ProposalDigest = "md5:" + strings.Repeat("a", 32) },
		"invocation digest untagged": func(d *coreapi.MissionDraft) { d.InvocationDigest = strings.Repeat("b", 64) },
		"invocation digest empty":    func(d *coreapi.MissionDraft) { d.InvocationDigest = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := validShapedDraft()
			mutate(&d)
			if err := ValidateShaped(d, 3600, 10_000_000); err == nil {
				t.Error("ValidateShaped = nil, want digest violation")
			}
		})
	}
}

func TestValidateShapedRejectsBadRunnerArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"empty":   {},
		"nil":     nil,
		"blank":   {""},
		"one bad": {"authscope-agent-run", ""},
	} {
		t.Run(name, func(t *testing.T) {
			d := validShapedDraft()
			d.RunnerArguments = args
			if err := ValidateShaped(d, 3600, 10_000_000); err == nil {
				t.Error("ValidateShaped = nil, want runner-argument violation")
			}
		})
	}
}

func TestValidateShapedRejectsMissingCanonicalDraft(t *testing.T) {
	d := validShapedDraft()
	d.CanonicalDraft = nil
	if err := ValidateShaped(d, 3600, 10_000_000); err == nil {
		t.Error("ValidateShaped = nil for missing canonical draft, want error")
	}
}

func validUpstreamProposal() coreapi.Proposal {
	return coreapi.Proposal{
		ProposalID:       "prop-1",
		ProposalDigest:   "sha256:" + strings.Repeat("d", 64),
		InvocationDigest: validShapedDraft().InvocationDigest,
		AgentKitID:       FixedAgentKitID,
		AgentKitVersion:  FixedAgentKitVersion,
		RunnerArguments:  []string{"authscope-agent-run", "--mission", "pass-1"},
		Status:           "draft",
		WorkspaceID:      "ws-test",
		DecisionDigest:   "sha256:" + strings.Repeat("c", 64),
		CreatedAt:        1_700_000_000,
	}
}

func TestValidateProposalAcceptsExactMatch(t *testing.T) {
	if err := ValidateProposal(validShapedDraft(), validUpstreamProposal()); err != nil {
		t.Fatalf("ValidateProposal = %v, want nil", err)
	}
}

func TestValidateProposalRejectsMutations(t *testing.T) {
	shaped := validShapedDraft()
	cases := map[string]func(*coreapi.Proposal){
		"empty proposal id": func(p *coreapi.Proposal) { p.ProposalID = "" },
		// A well-formed but different proposal digest is a different
		// upstream proposal, not a local forgery: OPE stores AuthScope's
		// digest byte-for-byte and never computes a substitute, so only
		// malformed digests fail here. The invocation digest it must
		// cover is pinned byte-for-byte below.
		"proposal digest untagged": func(p *coreapi.Proposal) {
			p.ProposalDigest = strings.Repeat("d", 64)
		},
		"invocation digest swapped": func(p *coreapi.Proposal) {
			p.InvocationDigest = "sha256:" + strings.Repeat("f", 64)
		},
		"invocation digest empty": func(p *coreapi.Proposal) { p.InvocationDigest = "" },
		"kit id swapped":          func(p *coreapi.Proposal) { p.AgentKitID = "other-kit" },
		"kit version swapped":     func(p *coreapi.Proposal) { p.AgentKitVersion = "9.9.9" },
		"runner arg reordered": func(p *coreapi.Proposal) {
			p.RunnerArguments = []string{"--mission", "authscope-agent-run", "pass-1"}
		},
		"runner arg changed": func(p *coreapi.Proposal) {
			p.RunnerArguments = []string{"authscope-agent-run", "--mission", "pass-2"}
		},
		"runner arg appended": func(p *coreapi.Proposal) {
			p.RunnerArguments = append(append([]string{}, p.RunnerArguments...), "--extra")
		},
		"runner arg dropped": func(p *coreapi.Proposal) {
			p.RunnerArguments = p.RunnerArguments[:2]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validUpstreamProposal()
			mutate(&p)
			if err := ValidateProposal(shaped, p); err == nil {
				t.Error("ValidateProposal = nil, want mismatch error")
			}
		})
	}
}
