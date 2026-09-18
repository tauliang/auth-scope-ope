package e2e

// Workspace matrix: every resource lookup is workspace-scoped. Foreign
// IDs get a uniform 404 that never reveals whether the resource exists
// elsewhere, and a workspace header can never select another workspace.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestWorkspaceIsolation404(t *testing.T) {
	f := newJourneyFixture(t, nil)
	ctx := context.Background()
	st := connectAndAuthorize(t, f)
	prepareRun(t, f, &st)

	foreign := map[string]string{
		"proposal":           "prop_foreign00000000000000000000001",
		"mission":            "msn_foreign00000000000000000000001",
		"execution_grant":    "grant_foreign000000000000000000001",
		"expansion":          "exp_foreign00000000000000000000001",
		"operation":          "idem-foreign",
		"repository_binding": "bind_foreign0000000000000000000001",
	}
	digest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	cases := []struct {
		method, path, kind string
		body               any
	}{
		{"POST", "/v1/mission-proposals/" + foreign["proposal"] + "/approve", "proposal",
			map[string]any{"proposal_digest": digest, "invocation_digest": digest}},
		{"GET", "/v1/missions/" + foreign["mission"] + "/introspect", "mission", nil},
		{"POST", "/v1/missions/" + foreign["mission"] + "/launch/prepare", "mission", nil},
		{"GET", "/v1/executions/" + foreign["execution_grant"] + "/receipt", "execution_grant", nil},
		{"POST", "/v1/expansion-requests/" + foreign["expansion"] + "/approve", "expansion", nil},
		{"GET", "/v1/operations/" + foreign["operation"], "operation", nil},
		{"GET", "/v1/events?mission_ref=" + foreign["mission"], "mission", nil},
	}
	for _, tc := range cases {
		status, raw := f.doRaw(tc.method, tc.path, tc.body, nil)
		if status != 404 {
			t.Errorf("%s %s: status %d, want 404: %s", tc.method, tc.path, status, raw)
			continue
		}
		mustContainCode(t, raw, tc.kind+"_not_found")
	}

	// Real IDs from this workspace still resolve: the 404s above are
	// scoping, not breakage.
	if _, err := f.client.IntrospectMission(ctx, st.missionRef, f.opts()); err != nil {
		t.Fatalf("own mission no longer resolves: %v", err)
	}
}

func TestWorkspaceHeaderCannotOverride(t *testing.T) {
	a := newJourneyFixture(t, nil)
	b := newJourneyFixture(t, func(o *FakeOptions) { o.WorkspaceID = "ws-e2e-2" })
	if a.workspace == b.workspace {
		t.Fatalf("fixtures share a workspace id: %q", a.workspace)
	}

	// Sign a request with workspace B's workload key, but present it to
	// workspace A's server. The key is unknown there, so authentication
	// fails closed instead of selecting B's workspace.
	var body []byte
	sum := sha256.Sum256(body)
	ts := strconv.FormatInt(b.now.Unix(), 10)
	payload := []byte(strings.Join([]string{
		workloadAuthDomain, ts, "GET", "/v1/discovery", hex.EncodeToString(sum[:]),
	}, "\n"))
	sig, err := b.signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}
	req, err := http.NewRequest("GET", a.server.URL+"/v1/discovery", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("cannot build request: %v", err)
	}
	req.Header.Set("X-AuthScope-Workload-KeyID", b.signer.KeyID())
	req.Header.Set("X-AuthScope-Workload-Timestamp", ts)
	req.Header.Set("X-AuthScope-Workload-Signature", b64url(sig))
	req.Header.Set("X-AuthScope-Workspace", b.workspace)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("cross-workspace request: status %d, want 401: %s", resp.StatusCode, raw)
	}
	mustContainCode(t, raw, "unknown_workload_key")
}
