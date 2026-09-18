package e2e

// Enforcing-gateway policy: the fake gateway authorizes each action
// against the mission grant. Governed actions on the isolated branch are
// allowed; everything the v1 template never grants is denied with an
// exact reason, and a second distinct resource of each denied kind is
// denied too.

import (
	"testing"
)

func TestGatewayPolicy(t *testing.T) {
	f := newJourneyFixture(t, nil)
	missionRef, _, _, _ := runHappyPath(t, f)
	branch := "refs/heads/mission/" + missionRef

	t.Run("allows", func(t *testing.T) {
		allows := []struct{ action, resource string }{
			{"git.push", branch},
			{"file.write", "src/scheduler.ts"},
			{"run.execute", ""},
		}
		for _, a := range allows {
			status, decision := gatewayDecision(t, f, missionRef, a.action, a.resource)
			if status != 200 || decision["decision"] != "allow" {
				t.Errorf("%s %s: status %d decision %v, want allow",
					a.action, a.resource, status, decision)
			}
			if decision["reason"] != "mission_active" {
				t.Errorf("%s %s: reason %v, want mission_active",
					a.action, a.resource, decision["reason"])
			}
		}
	})

	t.Run("denies", func(t *testing.T) {
		denies := []struct{ action, resource, reason string }{
			// Default branches are never writable by a governed run.
			{"git.push", "refs/heads/main", "default_branch_protected"},
			{"git.push", "refs/heads/master", "default_branch_protected"},
			// Non-granted branches are denied.
			{"git.push", "refs/heads/feature-x", "branch_not_granted"},
			{"git.push", "refs/heads/feature-y", "branch_not_granted"},
			// Workflow files are never writable.
			{"file.write", ".github/workflows/ci.yml", "workflow_file_protected"},
			{"file.write", ".github/workflows/deploy.yml", "workflow_file_protected"},
			// Protected policy paths are never writable.
			{"file.write", ".ope/policy/custom.rego", "protected_path"},
			{"file.write", ".ope/policy/other.rego", "protected_path"},
			// The v1 template never grants these actions.
			{"pull_request.merge", "1", "action_not_granted"},
			{"pull_request.merge", "2", "action_not_granted"},
			{"release.create", "v1.0.0", "action_not_granted"},
			{"release.create", "v1.0.1", "action_not_granted"},
			{"deployment.create", "prod", "action_not_granted"},
			{"deployment.create", "staging", "action_not_granted"},
			{"issue.close", "1", "action_not_granted"},
			{"issue.close", "2", "action_not_granted"},
			// Unknown actions fail closed.
			{"db.drop", "", "unknown_action"},
			{"secret.read", "", "unknown_action"},
		}
		for _, d := range denies {
			status, decision := gatewayDecision(t, f, missionRef, d.action, d.resource)
			if status != 200 || decision["decision"] != "deny" || decision["reason"] != d.reason {
				t.Errorf("%s %s: status %d decision %v, want deny %q",
					d.action, d.resource, status, decision, d.reason)
			}
		}
	})

	t.Run("unknown_mission_404", func(t *testing.T) {
		status, raw := f.doRawGateway("/v1/gateway/authorize", map[string]any{
			"workspace_id": f.workspace, "mission_ref": "msn_nope",
			"action": "run.execute",
		})
		if status != 404 {
			t.Fatalf("unknown mission: status %d, want 404: %s", status, raw)
		}
		mustContainCode(t, raw, "mission_not_found")
	})

	t.Run("bad_request", func(t *testing.T) {
		status, raw := f.doRawGateway("/v1/gateway/authorize", map[string]any{
			"workspace_id": f.workspace,
		})
		if status != 400 {
			t.Fatalf("missing fields: status %d, want 400: %s", status, raw)
		}
		mustContainCode(t, raw, "invalid_request")
	})
}
