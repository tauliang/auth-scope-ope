// Package e2e: the enforcing-gateway fake. It implements the pinned
// gateway_authorize operation (POST /v1/gateway/authorize) against the
// same state the fake AuthScope mutates, so revocation and containment
// take effect at enforcement immediately.
package e2e

import (
	"bytes"
	"net/http"
	"strings"
	"sync"
)

// GatewayAuthorizeRequest is the fake's typed interpretation of the
// pinned gateway authorization check.
type GatewayAuthorizeRequest struct {
	WorkspaceID string `json:"workspace_id"`
	MissionRef  string `json:"mission_ref"`
	Action      string `json:"action"`
	Resource    string `json:"resource,omitempty"`
}

// GatewayDecision is the fake's authorization decision.
type GatewayDecision struct {
	Decision    string `json:"decision"` // allow | deny
	Reason      string `json:"reason"`
	EvaluatedAt int64  `json:"evaluated_at"`
}

// Actions the v1 template never grants, whatever the mission state.
var gatewayUngrantedActions = map[string]bool{
	"pull_request.merge": true,
	"release.create":     true,
	"deployment.create":  true,
	"issue.close":        true,
}

// defaultBranches are never writable by a governed run.
var gatewayDefaultBranches = map[string]bool{"main": true, "master": true}

// FakeGateway is the enforcing-gateway fake.
type FakeGateway struct {
	auth *FakeAuthScope
	mu   sync.Mutex
	// protectedPaths are repository paths a governed run may never write.
	protectedPaths []string
	// calls records authorization calls for test assertions.
	calls []GatewayAuthorizeRequest
}

// NewFakeGateway builds a gateway fake sharing state with auth.
func NewFakeGateway(auth *FakeAuthScope) *FakeGateway {
	return &FakeGateway{
		auth:           auth,
		protectedPaths: []string{".github/workflows/", ".ope/policy/"},
	}
}

// Handler builds the gateway's HTTP handler.
func (g *FakeGateway) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/gateway/authorize", g.authorize)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readBody(r)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "cannot read request body", r.Header.Get("X-Request-ID"))
			return
		}
		// The gateway is AuthScope-operated: it verifies the same workload
		// transport authentication as the fake authority.
		if r.URL.EscapedPath() != "/healthz" && !g.auth.authenticate(w, r, body) {
			return
		}
		r = r.WithContext(contextWithBody(r, body))
		mux.ServeHTTP(w, r)
	})
}

// Calls returns the authorization calls the gateway has seen.
func (g *FakeGateway) Calls() []GatewayAuthorizeRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]GatewayAuthorizeRequest{}, g.calls...)
}

func (g *FakeGateway) authorize(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	var in GatewayAuthorizeRequest
	if !decodeBody(rawBody(r), &in, requestID, w) {
		return
	}
	if in.MissionRef == "" || in.Action == "" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "mission_ref and action are required", requestID)
		return
	}
	g.mu.Lock()
	g.calls = append(g.calls, in)
	g.mu.Unlock()

	decision := g.decide(in)
	if decision.Decision == "deny" && decision.Reason == "unknown_mission" {
		writeProblem(w, http.StatusNotFound, "mission_not_found", "mission not found in this workspace", requestID)
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

// decide applies the enforcement policy. Unknown missions are 404s;
// revoked missions and contained workspaces deny everything; the v1
// template never grants merge, release, deployment, or issue-close;
// default-branch pushes, workflow-file writes, and protected-path writes
// are denied outright.
func (g *FakeGateway) decide(in GatewayAuthorizeRequest) GatewayDecision {
	now := g.auth.opts.now().Unix()
	deny := func(reason string) GatewayDecision {
		return GatewayDecision{Decision: "deny", Reason: reason, EvaluatedAt: now}
	}
	branch, known := g.auth.MissionBranch(in.MissionRef)
	if !known {
		return deny("unknown_mission")
	}
	if g.auth.Contained() {
		return deny("workspace_contained")
	}
	if g.auth.Revoked(in.MissionRef) {
		return deny("mission_revoked")
	}
	if gatewayUngrantedActions[in.Action] {
		return deny("action_not_granted")
	}
	switch in.Action {
	case "git.push":
		ref := branchRef(in.Resource)
		if gatewayDefaultBranches[ref] {
			return deny("default_branch_protected")
		}
		for _, p := range g.protectedPaths {
			if strings.HasPrefix(in.Resource, p) {
				return deny("protected_path")
			}
		}
		if ref != "" && ref != strings.TrimPrefix(branch, "mission/") && ref != branch {
			return deny("branch_not_granted")
		}
	case "file.write":
		for _, p := range g.protectedPaths {
			if strings.HasPrefix(in.Resource, p) {
				if strings.HasPrefix(in.Resource, ".github/workflows/") {
					return deny("workflow_file_protected")
				}
				return deny("protected_path")
			}
		}
	case "run.execute":
		// Allowed: the prepared run executes on its isolated branch.
	default:
		return deny("unknown_action")
	}
	return GatewayDecision{Decision: "allow", Reason: "mission_active", EvaluatedAt: now}
}

// branchRef extracts a branch name from a git ref resource.
func branchRef(resource string) string {
	if strings.HasPrefix(resource, "refs/heads/") {
		return strings.TrimPrefix(resource, "refs/heads/")
	}
	return resource
}

// readBody reads the full request body.
func readBody(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	return buf.Bytes(), nil
}
