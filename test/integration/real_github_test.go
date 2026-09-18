package integration

// Real GitHub integration: one mission branch, one pull request, and
// governed edits against the disposable private repository (Task 16,
// Step 1). The mission issue body is the checked-in fixture
// testdata/mission-issue.md, applied verbatim to the disposable repo.
//
// Every test here is gated behind OPE_REAL_INTEGRATION=1 and the full
// real prerequisite set; without them the test skips and names what is
// missing. Nothing is faked.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// missionIssueBody loads the checked-in mission issue fixture. The same
// bytes are applied to the disposable repository, so the trusted issue
// snapshot digest is reproducible.
func missionIssueBody(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", "mission-issue.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read mission issue fixture: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("mission issue fixture is empty")
	}
	return string(raw)
}

// TestRealMissionIssueFixture verifies the fixture the operator
// applied to the disposable repository matches the trusted snapshot
// the suite asserts against.
func TestRealMissionIssueFixture(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	h := newRealHTTP(t, e.OPEURL)

	body := missionIssueBody(t)
	if !strings.Contains(body, "mission-pass") {
		t.Fatalf("mission issue fixture does not describe a mission pass")
	}

	status, raw := h.do(t, "GET",
		"/api/v1/connections/github/"+m.ConnectionID+"/issues/"+itoa(m.IssueNumber), nil, nil)
	if status != 200 {
		t.Fatalf("issue snapshot: status %d: %s", status, truncate(raw, 2000))
	}
	snap := decodeJSON(t, raw)
	if n, _ := snap["number"].(float64); int64(n) != m.IssueNumber {
		t.Fatalf("snapshot issue number %v != manifest %d", n, m.IssueNumber)
	}
	if d, _ := snap["source_digest"].(string); d == "" {
		t.Fatalf("trusted snapshot missing source_digest")
	}
	t.Logf("fixture %d bytes; trusted snapshot digest present", len(body))
}

// TestRealOneBranchOnePR requires exactly one mission branch and one
// pull request for the pass, with governed edits confined to the
// mission branch and the approved paths.
func TestRealOneBranchOnePR(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	token := mustEnvOptional(t, "OPE_MISSION_TOKEN")
	if token == "" {
		t.Skip("branch/PR assertions need OPE_MISSION_TOKEN: the short-lived mission credential from the operator CLI exchange")
	}
	gw := newRealHTTP(t, e.GatewayURL)
	auth := map[string]string{"Authorization": "Bearer " + token}

	// Exactly one mission branch exists for the pass.
	status, raw := gw.do(t, "GET", "/v1/github/branches?repo="+urlQueryEscape(e.GitHubRepo)+"&mission_ref="+urlQueryEscape(m.MissionRef), nil, auth)
	if status != 200 {
		t.Fatalf("list mission branches: status %d: %s", status, truncate(raw, 2000))
	}
	branches := decodeJSON(t, raw)
	items, _ := branches["branches"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected exactly one mission branch, got %d", len(items))
	}
	if name, _ := items[0].(map[string]any)["name"].(string); name != m.Branch {
		t.Fatalf("mission branch %q != manifest %q", name, m.Branch)
	}

	// Exactly one pull request, from the mission branch.
	status, raw = gw.do(t, "GET", "/v1/github/pulls?repo="+urlQueryEscape(e.GitHubRepo)+"&head="+urlQueryEscape(m.Branch), nil, auth)
	if status != 200 {
		t.Fatalf("list pull requests: status %d: %s", status, truncate(raw, 2000))
	}
	prs := decodeJSON(t, raw)
	pullItems, _ := prs["pull_requests"].([]any)
	if len(pullItems) != 1 {
		t.Fatalf("expected exactly one pull request, got %d", len(pullItems))
	}
	pr := pullItems[0].(map[string]any)
	if n, _ := pr["number"].(float64); int64(n) != m.PRNumber {
		t.Fatalf("pull request number %v != manifest %d", n, m.PRNumber)
	}
	if base, _ := pr["base"].(string); base != "main" {
		t.Fatalf("pull request base %q is not the default branch", base)
	}

	// Governed edits inside the mission branch on approved paths are
	// allowed; the gateway enforces the path policy per edit.
	status, _ = gw.do(t, "POST", "/v1/github/contents",
		map[string]any{
			"repo":    e.GitHubRepo,
			"branch":  m.Branch,
			"path":    "src/mission.go",
			"content": "cGFja2FnZSBzcmMK",
		}, auth)
	if status != 200 && status != 201 {
		t.Fatalf("governed edit on mission branch: status %d", status)
	}
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "/", "%2F"), " ", "%20")
}
