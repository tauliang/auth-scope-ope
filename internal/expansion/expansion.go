// Package expansion implements the exact one-use expansion decision
// ceremony: the founder reviews one canonical upstream delta through a
// passkey challenge and decides approve_once or deny. The browser never
// submits or widens the authority delta; the service binds the exact
// canonical fields into the decision attestation and settles the result
// without ever re-issuing the upstream mutation.
package expansion

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Decision is the founder's expansion decision. Only approve_once and
// deny decode; anything else fails closed.
type Decision string

const (
	// ApproveOnce grants the requested authority for exactly one use,
	// bounded by the effective expiry.
	ApproveOnce Decision = "approve_once"
	// Deny refuses the expansion; the prior authority is left
	// byte-identical.
	Deny Decision = "deny"
)

// UnmarshalJSON rejects every decision outside the fixed enum.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("expansion: decode decision: %w", err)
	}
	switch Decision(s) {
	case ApproveOnce, Deny:
		*d = Decision(s)
		return nil
	default:
		return fmt.Errorf("expansion: unknown decision %q: want approve_once or deny", s)
	}
}

// Delta is AuthScope's canonical expansion delta: the exact authority
// change under review. It strict-decodes with unknown fields rejected;
// unknown fields are never retained. AgentRationale is agent-authored,
// displayed labeled as such, and never part of the decision digest.
type Delta struct {
	ExpansionID               string    `json:"expansion_id"`
	MissionRef                string    `json:"mission_ref"`
	MissionVersion            int64     `json:"mission_version"`
	BlockedOperation          string    `json:"blocked_operation"`
	Resource                  string    `json:"resource"`
	Repository                string    `json:"repository"`
	Ref                       string    `json:"ref"`
	Path                      string    `json:"path"`
	Destination               string    `json:"destination"`
	NormalizedArgumentsDigest string    `json:"normalized_arguments_digest"`
	Quantity                  int64     `json:"quantity"`
	BudgetMicros              int64     `json:"budget_micros"`
	CurrentAuthority          string    `json:"current_authority"`
	RequestedAuthority        string    `json:"requested_authority"`
	ConsequenceChange         string    `json:"consequence_change"`
	ReasonCode                string    `json:"reason_code"`
	Reversibility             string    `json:"reversibility"`
	RequestedExpiry           time.Time `json:"requested_expiry"`
	AgentRationale            string    `json:"agent_rationale,omitempty"`
	ExpansionDigest           string    `json:"expansion_digest"`
}

// ExpansionDetail is the authoritative upstream expansion object: the
// canonical delta plus the decision outcome. The digest covers only the
// canonical delta fields, never the outcome.
type ExpansionDetail struct {
	Delta
	Status                string `json:"status"`
	DecidedMissionVersion int64  `json:"decided_mission_version,omitempty"`
}

// strictDecodeDetail strict-decodes one upstream expansion object,
// rejecting unknown fields instead of retaining them.
func strictDecodeDetail(raw json.RawMessage) (ExpansionDetail, error) {
	var detail ExpansionDetail
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&detail); err != nil {
		return ExpansionDetail{}, fmt.Errorf("expansion: decode delta: %w", err)
	}
	if err := detail.Delta.validate(); err != nil {
		return ExpansionDetail{}, err
	}
	return detail, nil
}

func validDigestShape(s string) bool {
	return strings.HasPrefix(s, "sha256:") && len(s) == len("sha256:")+64
}

func (d Delta) validate() error {
	if d.ExpansionID == "" || d.MissionRef == "" {
		return fmt.Errorf("expansion: delta missing expansion or mission identity")
	}
	if d.BlockedOperation == "" || d.Resource == "" {
		return fmt.Errorf("expansion: delta missing blocked operation or resource")
	}
	if d.CurrentAuthority == "" || d.RequestedAuthority == "" {
		return fmt.Errorf("expansion: delta missing current or requested authority")
	}
	if d.ConsequenceChange == "" || d.ReasonCode == "" {
		return fmt.Errorf("expansion: delta missing consequence change or reason code")
	}
	if d.Reversibility != "reversible" && d.Reversibility != "irreversible" {
		return fmt.Errorf("expansion: unknown reversibility %q", d.Reversibility)
	}
	if d.RequestedExpiry.IsZero() {
		return fmt.Errorf("expansion: delta missing requested expiry")
	}
	if !validDigestShape(d.NormalizedArgumentsDigest) {
		return fmt.Errorf("expansion: malformed normalized arguments digest")
	}
	if !validDigestShape(d.ExpansionDigest) {
		return fmt.Errorf("expansion: malformed expansion digest")
	}
	if d.Quantity < 0 || d.BudgetMicros < 0 {
		return fmt.Errorf("expansion: negative quantity or budget")
	}
	return nil
}

// canonicalDeltaJSON renders the canonical delta with fixed field
// order and normalized time formatting, so the stored row carries
// exactly the allowlisted fields.
func canonicalDeltaJSON(d Delta) ([]byte, error) {
	d.RequestedExpiry = d.RequestedExpiry.UTC().Truncate(time.Second)
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("expansion: encode canonical delta: %w", err)
	}
	return raw, nil
}

// CanonicalExpansionDigest is the sha256 digest over the canonical
// delta bytes: every canonical field except the agent-authored
// rationale and the digest itself, in fixed field order.
func CanonicalExpansionDigest(d Delta) string {
	// The digest input excludes AgentRationale (agent-authored, never
	// bound) and ExpansionDigest (the digest itself).
	type digestInput Delta
	in := digestInput(d)
	in.AgentRationale = ""
	in.ExpansionDigest = ""
	in.RequestedExpiry = in.RequestedExpiry.UTC().Truncate(time.Second)
	raw, err := json.Marshal(in)
	if err != nil {
		panic(fmt.Sprintf("expansion: encode digest input: %v", err))
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// verifyDigest checks that the embedded expansion digest covers the
// canonical delta. A widened or tampered delta fails closed here,
// before anything is shown or bound.
func (d Delta) verifyDigest() error {
	if got := CanonicalExpansionDigest(d); got != d.ExpansionDigest {
		return fmt.Errorf("expansion: digest mismatch: delta fields do not match the signed expansion digest")
	}
	return nil
}

// ExpansionBinding is the exact server-side binding for one expansion
// decision challenge: workspace, pass, mission reference, expected
// upstream mission version, expansion identity and digest, decision,
// effective expiry, purpose, and audience. Every field is attested.
type ExpansionBinding struct {
	WorkspaceID              string
	PassID                   string
	MissionRef               string
	ExpectedAuthScopeVersion int64
	ExpansionID              string
	ExpansionDigest          string
	Decision                 Decision
	EffectiveExpiry          time.Time
	Purpose                  string
	Audience                 string
}

// canonicalExpansionJSON is the fixed-order canonical form of the
// binding. Times render as UTC RFC3339 so the digest is deterministic.
type canonicalExpansionJSON struct {
	WorkspaceID              string `json:"workspace_id"`
	PassID                   string `json:"pass_id"`
	MissionRef               string `json:"mission_ref"`
	ExpectedAuthScopeVersion int64  `json:"expected_authscope_version"`
	ExpansionID              string `json:"expansion_id"`
	ExpansionDigest          string `json:"expansion_digest"`
	Decision                 string `json:"decision"`
	EffectiveExpiry          string `json:"effective_expiry"`
	Purpose                  string `json:"purpose"`
	Audience                 string `json:"audience"`
}

// CanonicalExpansionBytes renders the binding in fixed field order.
func CanonicalExpansionBytes(b ExpansionBinding) []byte {
	raw, err := json.Marshal(canonicalExpansionJSON{
		WorkspaceID:              b.WorkspaceID,
		PassID:                   b.PassID,
		MissionRef:               b.MissionRef,
		ExpectedAuthScopeVersion: b.ExpectedAuthScopeVersion,
		ExpansionID:              b.ExpansionID,
		ExpansionDigest:          b.ExpansionDigest,
		Decision:                 string(b.Decision),
		EffectiveExpiry:          b.EffectiveExpiry.UTC().Format(time.RFC3339),
		Purpose:                  b.Purpose,
		Audience:                 b.Audience,
	})
	if err != nil {
		panic(fmt.Sprintf("expansion: encode binding: %v", err))
	}
	return raw
}

// bindingDigest is the hex SHA-256 of the canonical binding bytes, the
// value attested in the decision digest claim.
func bindingDigest(b ExpansionBinding) string {
	sum := sha256.Sum256(CanonicalExpansionBytes(b))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// effectiveExpiry computes the bound for an approve_once decision: the
// lesser of the requested expiry and the mission expiry. A denial
// carries the zero expiry because no grant is issued.
func effectiveExpiry(decision Decision, requestedExpiry, missionExpiry time.Time) time.Time {
	if decision != ApproveOnce {
		return time.Time{}
	}
	if missionExpiry.IsZero() || !missionExpiry.Before(requestedExpiry) {
		return requestedExpiry.UTC()
	}
	return missionExpiry.UTC()
}
