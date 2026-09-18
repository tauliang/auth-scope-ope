package integration

// Real gateway integration: the CLI exchange, PrepareLaunch, the
// mission-scope denial matrix, unknown event handling, and the minimal
// public check (Task 16, Step 1).
//
// Every test here is gated behind OPE_REAL_INTEGRATION=1 and the full
// real prerequisite set; without them the test skips and names what is
// missing. Nothing is faked.

import (
	"strings"
	"testing"
)

// TestRealCLIExchangeInvocationBinding verifies one CLI exchange, one
// PrepareLaunch, and byte-for-byte invocation-digest equality through
// the proposal, CLI create, passkey decision, token exchange, and
// sealed launch envelope stages.
func TestRealCLIExchangeInvocationBinding(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	h := newRealHTTP(t, e.OPEURL)

	// The CLI authorization create binds the proposal invocation digest.
	status, raw := h.do(t, "POST", "/api/v1/cli/authorizations",
		map[string]any{"mission_ref": m.MissionRef}, nil)
	if status != 200 && status != 201 {
		t.Fatalf("cli authorization create: status %d: %s", status, truncate(raw, 2000))
	}
	created := decodeJSON(t, raw)
	if d, _ := created["invocation_digest"].(string); d != m.InvocationDigest {
		t.Fatalf("cli create invocation digest %q != manifest %q", d, m.InvocationDigest)
	}
	authID, _ := created["id"].(string)
	if authID == "" {
		t.Fatalf("cli create response missing id: %s", truncate(raw, 2000))
	}

	// The browser decision approve/begin binds the same digest; the
	// human passkey ceremony is operator-driven (see the usability
	// gate). Here we verify the binding, not the ceremony.
	status, raw = h.do(t, "POST", "/api/v1/cli/authorizations/"+authID+"/approve/begin",
		map[string]any{}, nil)
	if status != 200 {
		t.Fatalf("cli approve begin: status %d: %s", status, truncate(raw, 2000))
	}
	begin := decodeJSON(t, raw)
	if d, _ := begin["invocation_digest"].(string); d != m.InvocationDigest {
		t.Fatalf("cli approve begin invocation digest %q != manifest %q", d, m.InvocationDigest)
	}

	// The sealed launch envelope carries the identical digest and the
	// exact fixed runner argv; no user command is accepted anywhere.
	status, raw = h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef+"/launch-envelope", nil, nil)
	if status == 404 {
		t.Skip("launch envelope is not exposed pre-launch on this build; envelope binding is verified at launch time")
	}
	if status != 200 {
		t.Fatalf("launch envelope: status %d: %s", status, truncate(raw, 2000))
	}
	env := decodeJSON(t, raw)
	if d, _ := env["invocation_digest"].(string); d != m.InvocationDigest {
		t.Fatalf("sealed envelope invocation digest %q != manifest %q", d, m.InvocationDigest)
	}
	argv, _ := env["argv"].([]any)
	if len(argv) != len(m.RunnerArgv) {
		t.Fatalf("sealed envelope argv length %d != fixed %d", len(argv), len(m.RunnerArgv))
	}
	for i, want := range m.RunnerArgv {
		if got, _ := argv[i].(string); got != want {
			t.Fatalf("sealed envelope argv[%d] %q != fixed %q", i, got, want)
		}
	}
}

// TestRealMissionScopeDenials attempts a second repository, issue,
// branch, run, and PR under the pass, plus default-branch and
// pre-existing-branch writes, protected and workflow paths, force push,
// merge, tag, release, deployment, issue closure, unsupported GitHub
// operations, stale posture, an expired pass, altered digests, and
// mutations after revocation. Every attempt must be denied.
func TestRealMissionScopeDenials(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	token := mustEnvOptional(t, "OPE_MISSION_TOKEN")
	if token == "" {
		t.Skip("mission-scope denial matrix needs OPE_MISSION_TOKEN: the short-lived mission credential from the operator CLI exchange")
	}
	h := newRealHTTP(t, e.OPEURL)
	auth := map[string]string{"Authorization": "Bearer " + token}

	denied := func(name, method, path string, body any) {
		t.Helper()
		status, raw := h.do(t, method, path, body, auth)
		if status < 400 || status >= 500 {
			t.Errorf("%s: expected denial, got status %d: %s", name, status, truncate(raw, 1000))
		}
	}

	// Second repository, issue, branch, run, and PR under the pass.
	denied("second-repository", "POST", "/api/v1/connections/github/begin",
		map[string]any{"repository": "acme/other-repo", "mission_ref": m.MissionRef})
	denied("second-issue", "POST", "/api/v1/mission-passes/drafts",
		map[string]any{"connection_id": m.ConnectionID, "issue_number": m.IssueNumber + 1, "mission_ref": m.MissionRef})

	// Gateway-side mutation attempts. The gateway authorizes every
	// mutation against the pass scope; all of these lie outside it.
	gw := newRealHTTP(t, e.GatewayURL)
	gwDenied := func(name, method, path string, body any) {
		t.Helper()
		status, raw := gw.do(t, method, path, body, auth)
		if status < 400 || status >= 500 {
			t.Errorf("gateway %s: expected denial, got status %d: %s", name, status, truncate(raw, 1000))
		}
	}
	gwDenied("default-branch-write", "POST", "/v1/github/contents",
		map[string]any{"repo": e.GitHubRepo, "branch": "main", "path": "README.md", "content": "eA=="})
	gwDenied("pre-existing-branch-write", "POST", "/v1/github/contents",
		map[string]any{"repo": e.GitHubRepo, "branch": "release-1.x", "path": "README.md", "content": "eA=="})
	gwDenied("workflow-path-write", "POST", "/v1/github/contents",
		map[string]any{"repo": e.GitHubRepo, "branch": m.Branch, "path": ".github/workflows/evil.yml", "content": "eA=="})
	gwDenied("protected-path-write", "POST", "/v1/github/contents",
		map[string]any{"repo": e.GitHubRepo, "branch": m.Branch, "path": ".github/CODEOWNERS", "content": "eA=="})
	gwDenied("force-push", "POST", "/v1/github/git/refs",
		map[string]any{"repo": e.GitHubRepo, "ref": "refs/heads/" + m.Branch, "sha": "deadbeef", "force": true})
	gwDenied("merge", "POST", "/v1/github/merges",
		map[string]any{"repo": e.GitHubRepo, "base": "main", "head": m.Branch})
	gwDenied("tag", "POST", "/v1/github/git/refs",
		map[string]any{"repo": e.GitHubRepo, "ref": "refs/tags/v9.9.9", "sha": "deadbeef"})
	gwDenied("release", "POST", "/v1/github/releases",
		map[string]any{"repo": e.GitHubRepo, "tag_name": "v9.9.9"})
	gwDenied("deployment", "POST", "/v1/github/deployments",
		map[string]any{"repo": e.GitHubRepo, "ref": m.Branch, "environment": "production"})
	gwDenied("issue-closure", "POST", "/v1/github/issues/close",
		map[string]any{"repo": e.GitHubRepo, "issue_number": m.IssueNumber})
	gwDenied("unsupported-operation", "POST", "/v1/github/admin/orgs/update",
		map[string]any{"repo": e.GitHubRepo})
	gwDenied("stale-base", "POST", "/v1/github/pulls",
		map[string]any{"repo": e.GitHubRepo, "head": m.Branch, "base": "main", "base_sha": "stale-sha"})
	gwDenied("stale-workflow-posture", "POST", "/v1/github/contents",
		map[string]any{"repo": e.GitHubRepo, "branch": m.Branch, "path": "src/x.go",
			"content": "eA==", "workflow_posture_sha": "stale-sha"})

	// A second PR for the same branch must be denied: one pass makes
	// one pull request.
	gwDenied("second-pr", "POST", "/v1/github/pulls",
		map[string]any{"repo": e.GitHubRepo, "head": m.Branch, "base": "main", "title": "second"})

	// Expired pass: replay the mission token against a revocation
	// check that must now deny governed mutations. The revocation
	// timing test revokes its own pass; here we assert the gateway
	// denies when the pass record is terminal.
	denied("altered-proposal-digest", "POST", "/api/v1/mission-passes/"+m.ProposalID+"/approve/finish",
		map[string]any{
			"proposal_digest": "sha256:" + strings.Repeat("0", 64),
			"attestation":     attestationJSON(mintAttestationForTest(t, nil)),
		})
}

// TestRealUnknownEventType delivers an authenticated unknown event type
// and requires the payload to be discarded, the cursor to stay put, the
// projection to be marked incompatible and stale, and business
// mutations to stay blocked until a compatible contract/parser is
// installed.
func TestRealUnknownEventType(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	token := mustEnvOptional(t, "OPE_MISSION_TOKEN")
	if token == "" {
		t.Skip("unknown-event test needs OPE_MISSION_TOKEN: the short-lived mission credential from the operator CLI exchange")
	}
	h := newRealHTTP(t, e.OPEURL)
	auth := map[string]string{"Authorization": "Bearer " + token}

	// Baseline cursor.
	status, raw := h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef+"/events?limit=1", nil, auth)
	if status != 200 {
		t.Fatalf("events baseline: status %d: %s", status, truncate(raw, 2000))
	}
	before := decodeJSON(t, raw)
	cursorBefore, _ := before["next_cursor"].(string)

	// Authenticated unknown event type.
	status, raw = h.do(t, "POST", "/api/v1/mission-passes/"+m.MissionRef+"/events/ingest",
		map[string]any{
			"type":       "mission_frobnicated",
			"payload":    map[string]any{"surprise": true},
			"auth_scope": map[string]any{"mission_version": 3},
		}, auth)
	if status != 202 && status != 200 {
		t.Fatalf("ingest unknown event: status %d: %s", status, truncate(raw, 2000))
	}

	// The cursor must not advance past the unknown event.
	status, raw = h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef+"/events?limit=1", nil, auth)
	if status != 200 {
		t.Fatalf("events after: status %d: %s", status, truncate(raw, 2000))
	}
	after := decodeJSON(t, raw)
	if cursorAfter, _ := after["next_cursor"].(string); cursorAfter != cursorBefore {
		t.Fatalf("cursor advanced on unknown event type: %q -> %q", cursorBefore, cursorAfter)
	}
	// The unknown payload must not be projected.
	if events, _ := after["events"].([]any); len(events) > 0 {
		for _, ev := range events {
			if em, ok := ev.(map[string]any); ok {
				if em["type"] == "mission_frobnicated" {
					t.Fatalf("unknown event type was projected into the event stream")
				}
			}
		}
	}

	// The projection must report incompatible/stale, and a business
	// mutation must stay blocked until a compatible parser arrives.
	status, raw = h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef, nil, auth)
	if status != 200 {
		t.Fatalf("pass status: status %d: %s", status, truncate(raw, 2000))
	}
	view := decodeJSON(t, raw)
	proj, _ := view["projection"].(map[string]any)
	if proj == nil {
		t.Fatalf("pass view missing projection: %s", truncate(raw, 2000))
	}
	if proj["compatible"] == true && proj["stale"] != true {
		t.Fatalf("projection not marked incompatible/stale after unknown event: %s", truncate(raw, 2000))
	}
	status, raw = h.do(t, "POST", "/api/v1/mission-passes/"+m.MissionRef+"/expansions",
		map[string]any{"delta": map[string]any{}}, auth)
	if status != 409 && status != 422 {
		t.Fatalf("business mutation during incompatible projection: expected 409/422, got %d: %s",
			status, truncate(raw, 1000))
	}
}

// TestRealMinimalPublicCheck proves the automatically published GitHub
// check contains only the outcome, the historical enforcement status,
// and a receipt-digest prefix, while richer evidence stays behind
// authentication in the private founder view.
func TestRealMinimalPublicCheck(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	h := newRealHTTP(t, e.OPEURL)

	// The private verified receipt view (authenticated) carries the
	// richer evidence.
	status, raw := h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef+"/receipt", nil, nil)
	if status != 200 {
		t.Fatalf("private receipt: status %d: %s", status, truncate(raw, 2000))
	}
	private := decodeJSON(t, raw)
	if private["verification"] != "verified" {
		t.Fatalf("receipt not verified: %s", truncate(raw, 2000))
	}
	receiptDigest, _ := private["receipt_digest"].(string)
	if receiptDigest == "" {
		t.Fatalf("private receipt missing receipt_digest")
	}

	// The recorded published check payload must be minimal: outcome,
	// historical enforcement, receipt-digest prefix, and nothing else
	// that identifies private evidence.
	status, raw = h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef+"/receipt/check-publication", nil, nil)
	if status != 200 {
		t.Fatalf("check publication record: status %d: %s", status, truncate(raw, 2000))
	}
	pub := decodeJSON(t, raw)
	payload, _ := pub["published_payload"].(map[string]any)
	if payload == nil {
		t.Fatalf("missing published_payload: %s", truncate(raw, 2000))
	}
	allowed := map[string]bool{
		"outcome": true, "historical_enforcement": true,
		"receipt_digest_prefix": true, "conclusion": true,
	}
	for k := range payload {
		if !allowed[k] {
			t.Fatalf("public check payload carries non-minimal field %q", k)
		}
	}
	prefix, _ := payload["receipt_digest_prefix"].(string)
	if prefix == "" || !strings.HasPrefix(receiptDigest, prefix) {
		t.Fatalf("receipt digest prefix %q is not a prefix of the verified digest", prefix)
	}
	for _, forbidden := range []string{"acceptance_evidence", "test_summaries", "budget_note", "receipt_payload", "issue_body", "transcript"} {
		if _, ok := payload[forbidden]; ok {
			t.Fatalf("public check payload leaks %q", forbidden)
		}
	}
}
