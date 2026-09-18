package missionpass

import (
	"strings"
	"testing"
)

// validTransitions is the complete legal pass-state table. Terminal states
// (completed, failed, revoked, expired) never transition. A run-success or
// run-failure event enters outcome_pending; only a locally verified receipt
// enters completed or failed. Reconciliation stays orthogonal to pass state.
var validTransitions = map[PassState][]PassState{
	PassDraft:             {PassApproved, PassRevoked, PassExpired},
	PassApproved:          {PassLaunching, PassRevoked, PassExpired},
	PassLaunching:         {PassApproved, PassRunning, PassRevoked, PassExpired},
	PassRunning:           {PassAwaitingExpansion, PassOutcomePending, PassRevoked, PassExpired},
	PassAwaitingExpansion: {PassRunning, PassRevoked, PassExpired},
	PassOutcomePending:    {PassCompleted, PassFailed, PassRevoked},
}

var allPassStates = []PassState{
	PassDraft, PassApproved, PassLaunching, PassRunning, PassAwaitingExpansion,
	PassOutcomePending, PassCompleted, PassFailed, PassRevoked, PassExpired,
}

func TestPassStateTransitions(t *testing.T) {
	allowed := map[PassState]map[PassState]bool{}
	for from, tos := range validTransitions {
		allowed[from] = map[PassState]bool{}
		for _, to := range tos {
			allowed[from][to] = true
		}
	}
	for _, from := range allPassStates {
		for _, to := range allPassStates {
			err := Transition(from, to)
			if allowed[from][to] {
				if err != nil {
					t.Errorf("Transition(%q, %q) = %v, want nil", from, to, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("Transition(%q, %q) = nil, want error", from, to)
			}
		}
	}
}

func TestPassStateTerminalNeverTransitions(t *testing.T) {
	for _, terminal := range []PassState{PassCompleted, PassFailed, PassRevoked, PassExpired} {
		for _, to := range allPassStates {
			if err := Transition(terminal, to); err == nil {
				t.Errorf("terminal Transition(%q, %q) = nil, want error", terminal, to)
			}
		}
	}
}

func TestPassStateUnknownStatesFail(t *testing.T) {
	if err := Transition("bogus", PassApproved); err == nil {
		t.Error("Transition(bogus, approved) = nil, want error")
	}
	if err := Transition(PassDraft, "bogus"); err == nil {
		t.Error("Transition(draft, bogus) = nil, want error")
	}
	if err := Transition("", ""); err == nil {
		t.Error("Transition(empty, empty) = nil, want error")
	}
}

func TestPassStateValues(t *testing.T) {
	want := map[PassState]string{
		PassDraft: "draft", PassApproved: "approved", PassLaunching: "launching",
		PassRunning: "running", PassAwaitingExpansion: "awaiting_expansion",
		PassOutcomePending: "outcome_pending", PassCompleted: "completed",
		PassFailed: "failed", PassRevoked: "revoked", PassExpired: "expired",
	}
	for state, s := range want {
		if string(state) != s {
			t.Errorf("PassState %q, want %q", state, s)
		}
	}
	if string(ReconciliationSettled) != "settled" ||
		string(ReconciliationPending) != "pending" ||
		string(ReconciliationDisputed) != "disputed" {
		t.Error("ReconciliationState values changed")
	}
}

func TestCanonicalApprovalBytes(t *testing.T) {
	rec := ProposalRecord{
		WorkspaceID:      "ws-test",
		PassID:           "pass-1",
		ProposalDigest:   "sha256:" + strings.Repeat("a", 64),
		InvocationDigest: "sha256:" + strings.Repeat("b", 64),
	}
	got := CanonicalApprovalBytes(rec)
	// The approval binding is domain-separated and carries the pass and
	// workspace IDs plus both AuthScope digests, so the founder's passkey
	// decision binds exactly the proposal and invocation under review.
	for _, want := range []string{
		"ws-test", "pass-1",
		"sha256:" + strings.Repeat("a", 64),
		"sha256:" + strings.Repeat("b", 64),
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("approval bytes missing %q", want)
		}
	}
	if !strings.HasPrefix(string(got), "authscope-ope/") {
		t.Errorf("approval bytes %q lack a domain-separated prefix", got)
	}
	// Deterministic.
	if again := CanonicalApprovalBytes(rec); string(again) != string(got) {
		t.Error("CanonicalApprovalBytes is not deterministic")
	}
	// Length-prefixed framing: ambiguous concatenations must not collide.
	ambiguous := rec
	ambiguous.PassID = "pass-1sha256:" + strings.Repeat("a", 64)
	ambiguous.ProposalDigest = "x"
	if string(CanonicalApprovalBytes(ambiguous)) == string(got) {
		t.Error("approval bytes collide across field boundaries")
	}
	// Changing any bound value changes the bytes.
	for _, mutate := range []func(*ProposalRecord){
		func(r *ProposalRecord) { r.WorkspaceID = "ws-other" },
		func(r *ProposalRecord) { r.PassID = "pass-2" },
		func(r *ProposalRecord) { r.ProposalDigest = "sha256:" + strings.Repeat("c", 64) },
		func(r *ProposalRecord) { r.InvocationDigest = "sha256:" + strings.Repeat("d", 64) },
	} {
		other := rec
		mutate(&other)
		if string(CanonicalApprovalBytes(other)) == string(got) {
			t.Error("approval bytes unchanged after mutating a bound value")
		}
	}
}
