// Tests for the privacy filters around receipt publication. The GitHub
// check is public, so its content must be the fixed minimal triple and
// must never leak acceptance evidence, prompts, patches, logs, or any
// other private receipt content. The canary sweep makes that structural.
package receipt_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/store"
)

// canaries are strings that look like private receipt content. Every
// public artifact derived from a receipt must contain none of them.
var canaries = []string{
	"sk-test-SECRET-123",
	"the founder asked for retry with backoff",
	"120 tests passed, 2 skipped",
	"panic: runtime error in worker",
	"budget stays under 5000 micros",
	"https://ope.example.com/private/passes/pass-1/logs",
	"patch: diff --git a/main.go b/main.go",
	"transcript of the agent session",
	"shengquan@example.com",
}

func canaryView() *receipt.ReceiptView {
	return &receipt.ReceiptView{
		Verification:          store.ReceiptVerified,
		ReceiptID:             "rcpt-1",
		GrantID:               "run-1",
		MissionRef:            "mission-1",
		WorkspaceID:           "ws-test",
		KeyID:                 "receipt-key-1",
		SignedAt:              1758260000,
		ReceiptDigest:         strings.Repeat("ab", 32),
		Outcome:               receipt.OutcomeSuccess,
		MissionVersions:       []int64{3, 4},
		ExpansionDecisionRefs: []string{"exp-1"},
		RepositoryID:          111,
		IssueNumber:           42,
		Branch:                "authscope/mission-1",
		PullRequestNumber:     7,
		HeadSHA:               strings.Repeat("a", 40),
		Checks: []receipt.CheckSummary{
			{Kind: "unit_tests", Outcome: "passed"},
		},
		StartedAt:           1758256000,
		FinishedAt:          1758259000,
		AggregateCostMicros: 1234,
		BudgetMicros:        1234,
		HistoricalEnforcement: []receipt.EnforcementSummary{
			{Scope: "github", Level: "enforced"},
			{Scope: "agent_runtime", Level: "checked"},
		},
	}
}

func TestMinimalCheckRequestCarriesOnlyFixedFields(t *testing.T) {
	view := canaryView()
	key := receipt.PublicationIDKey("ws-test", view.ReceiptDigest, 111, 7, view.HeadSHA)
	req := receipt.MinimalCheckRequest(view, "binding-1", key)
	if req.BindingID != "binding-1" {
		t.Errorf("binding_id = %q", req.BindingID)
	}
	if req.HeadSHA != strings.Repeat("a", 40) {
		t.Errorf("head_sha = %q", req.HeadSHA)
	}
	if req.Status != coreapi.CheckStatusCompleted {
		t.Errorf("status = %q, want completed", req.Status)
	}
	if req.Conclusion != coreapi.CheckConclusionSuccess {
		t.Errorf("conclusion = %q, want success", req.Conclusion)
	}
	if req.IdempotencyKey != key {
		t.Errorf("idempotency key mismatch")
	}
	name := req.Name
	for _, c := range canaries {
		if strings.Contains(name, c) {
			t.Errorf("check name leaks canary %q: %q", c, name)
		}
	}
	if !strings.HasPrefix(name, "authscope/receipt ") {
		t.Errorf("check name %q does not start with the fixed prefix", name)
	}
	if !strings.Contains(name, "success") {
		t.Errorf("check name %q missing outcome", name)
	}
	if !strings.Contains(name, "github:enforced,agent_runtime:checked") {
		t.Errorf("check name %q missing signed enforcement", name)
	}
	digestPrefix := "sha256:" + strings.Repeat("ab", 6)
	if !strings.Contains(name, digestPrefix) {
		t.Errorf("check name %q missing receipt digest prefix %q", name, digestPrefix)
	}
	if strings.Contains(name, "rcpt-1") || strings.Contains(name, "mission-1") ||
		strings.Contains(name, "exp-1") || strings.Contains(name, "the founder") {
		t.Errorf("check name %q leaks receipt identifiers", name)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	for _, c := range canaries {
		if strings.Contains(string(raw), c) {
			t.Errorf("check request leaks canary %q", c)
		}
	}
	// The conclusion for a failed outcome must be failure.
	view.Outcome = receipt.OutcomeFailure
	req = receipt.MinimalCheckRequest(view, "binding-1", key)
	if req.Conclusion != coreapi.CheckConclusionFailure {
		t.Errorf("conclusion = %q, want failure", req.Conclusion)
	}
	if !strings.Contains(req.Name, "failure") {
		t.Errorf("check name %q missing failure outcome", req.Name)
	}
	for _, c := range canaries {
		if strings.Contains(req.Name, c) {
			t.Errorf("check name leaks canary %q", c)
		}
	}
}

func TestPublicationIDKey(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	a := receipt.PublicationIDKey("ws-test", digest, 111, 7, strings.Repeat("a", 40))
	b := receipt.PublicationIDKey("ws-test", digest, 111, 7, strings.Repeat("a", 40))
	if a != b || a == "" {
		t.Fatalf("idempotency key not deterministic: %q %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("idempotency key %q is not 64 hex chars", a)
	}
	for _, r := range a {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("idempotency key %q is not lowercase hex", a)
		}
	}
	if c := receipt.PublicationIDKey("ws-test", digest, 111, 8, strings.Repeat("a", 40)); c == a {
		t.Error("different PR number must change the key")
	}
	if c := receipt.PublicationIDKey("ws-test", strings.Repeat("cd", 32), 111, 7, strings.Repeat("a", 40)); c == a {
		t.Error("different receipt digest must change the key")
	}
	if c := receipt.PublicationIDKey("ws-other", digest, 111, 7, strings.Repeat("a", 40)); c == a {
		t.Error("different workspace must change the key")
	}
}

func TestMinimalCheckRequestUnverifiedRefused(t *testing.T) {
	view := canaryView()
	view.Verification = store.ReceiptUnverifiable
	if req := receipt.MinimalCheckRequest(view, "binding-1", "key"); req.Name != "" {
		t.Errorf("unverifiable view produced check request %+v", req)
	}
	view = canaryView()
	view.Outcome = "maybe"
	if req := receipt.MinimalCheckRequest(view, "binding-1", "key"); req.Name != "" {
		t.Errorf("unknown outcome produced check request %+v", req)
	}
	if req := receipt.MinimalCheckRequest(nil, "binding-1", "key"); req.Name != "" {
		t.Errorf("nil view produced check request %+v", req)
	}
}
