// Package telemetry defines the privacy-limited OPE product telemetry.
//
// Telemetry is an allowlisted funnel log: every event is one of the fixed
// funnel step names and carries only opaque identifiers, a duration, a
// fixed error code, the enforcement level, an intervention count, and a
// fixed outcome class. Repository names, issue titles and bodies, prompts,
// patches, source code, acceptance criteria, transcripts, tokens,
// credentials, receipt payloads, email addresses, URLs, and free-form
// messages are structurally excluded: the Event struct has no field that
// can hold them, and Validate rejects anything outside the fixed enums.
//
// Telemetry is off by default in development and stays off until the
// operator explicitly sets OPE_TELEMETRY=enabled. The installation ID is
// pseudonymized with an instance-local salt before it is stored or sent.
package telemetry

import (
	"fmt"
	"regexp"
	"strings"
)

// Fixed funnel event names. No other name may be recorded.
const (
	EventConnect          = "connect"
	EventIssueSelected    = "issue_selected"
	EventProposalReady    = "proposal_ready"
	EventApproved         = "approved"
	EventCLIAuthorized    = "cli_authorized"
	EventRunPrepared      = "run_prepared"
	EventExpansionDecided = "expansion_decided"
	EventReceiptVerified  = "receipt_verified"
	EventCheckPublished   = "check_published"
)

// validEventNames is the allowlist of recordable event names.
var validEventNames = map[string]bool{
	EventConnect:          true,
	EventIssueSelected:    true,
	EventProposalReady:    true,
	EventApproved:         true,
	EventCLIAuthorized:    true,
	EventRunPrepared:      true,
	EventExpansionDecided: true,
	EventReceiptVerified:  true,
	EventCheckPublished:   true,
}

// Fixed error codes. Error detail, upstream response bodies, and
// free-form messages never leave the process as telemetry.
const (
	ErrorNone                   = "none"
	ErrorUpstreamUnreachable    = "upstream_unreachable"
	ErrorUpstreamRejected       = "upstream_rejected"
	ErrorConfig                 = "config_error"
	ErrorAuthFailed             = "auth_failed"
	ErrorProjectionIncompatible = "projection_incompatible"
	ErrorReceiptUnverifiable    = "receipt_unverifiable"
	ErrorCheckPublishFailed     = "check_publish_failed"
	ErrorInternal               = "internal_error"
)

// validErrorCodes is the allowlist of recordable error codes.
var validErrorCodes = map[string]bool{
	ErrorNone:                   true,
	ErrorUpstreamUnreachable:    true,
	ErrorUpstreamRejected:       true,
	ErrorConfig:                 true,
	ErrorAuthFailed:             true,
	ErrorProjectionIncompatible: true,
	ErrorReceiptUnverifiable:    true,
	ErrorCheckPublishFailed:     true,
	ErrorInternal:               true,
}

// Fixed outcome classes.
const (
	OutcomeSuccess   = "success"
	OutcomeDenied    = "denied"
	OutcomeFailed    = "failed"
	OutcomeCancelled = "cancelled"
	OutcomePending   = "pending"
)

// validOutcomeClasses is the allowlist of recordable outcome classes.
var validOutcomeClasses = map[string]bool{
	OutcomeSuccess:   true,
	OutcomeDenied:    true,
	OutcomeFailed:    true,
	OutcomeCancelled: true,
	OutcomePending:   true,
}

// Enforcement levels record the instance mode the event ran under.
const (
	EnforcementDevelopment = "development"
	EnforcementRelease     = "release"
)

// validEnforcementLevels is the allowlist of recordable enforcement levels.
var validEnforcementLevels = map[string]bool{
	EnforcementDevelopment: true,
	EnforcementRelease:     true,
}

// opaqueIDPattern constrains identifier fields to opaque tokens: no URLs,
// emails, paths, or free-form text can match.
var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Event is the single telemetry record shape. Every field is fixed;
// there is intentionally no payload, message, or detail field.
type Event struct {
	Name              string
	DurationMillis    int64
	InstallationID    string
	PassID            string
	RunID             string
	ErrorCode         string
	EnforcementLevel  string
	InterventionCount int
	OutcomeClass      string
}

// Validate rejects any event outside the allowlisted schema: unknown
// names, error codes, outcomes, or enforcement levels; negative
// durations or counts; and identifier values that are not opaque
// tokens.
func (e Event) Validate() error {
	if !validEventNames[e.Name] {
		return fmt.Errorf("telemetry: unknown event name %q", e.Name)
	}
	if !validErrorCodes[e.ErrorCode] {
		return fmt.Errorf("telemetry: unknown error code %q", e.ErrorCode)
	}
	if !validOutcomeClasses[e.OutcomeClass] {
		return fmt.Errorf("telemetry: unknown outcome class %q", e.OutcomeClass)
	}
	if !validEnforcementLevels[e.EnforcementLevel] {
		return fmt.Errorf("telemetry: unknown enforcement level %q", e.EnforcementLevel)
	}
	if e.DurationMillis < 0 {
		return fmt.Errorf("telemetry: negative duration %d", e.DurationMillis)
	}
	if e.InterventionCount < 0 {
		return fmt.Errorf("telemetry: negative intervention count %d", e.InterventionCount)
	}
	for _, id := range []struct {
		label string
		value string
	}{
		{"installation_id", e.InstallationID},
		{"pass_id", e.PassID},
		{"run_id", e.RunID},
	} {
		if id.value == "" {
			continue
		}
		if !opaqueIDPattern.MatchString(id.value) {
			return fmt.Errorf("telemetry: %s %q is not an opaque identifier", id.label, id.value)
		}
	}
	return nil
}

// forbiddenFieldTokens are substrings that no telemetry field name may
// contain. The schema test reflects over the Event struct and rejects
// any field whose name suggests it could carry private content.
var forbiddenFieldTokens = []string{
	"repository", "issue", "branch", "objective", "criteria",
	"prompt", "source", "patch", "transcript", "token", "secret",
	"credential", "email", "url", "receipt", "payload", "message",
	"body", "title", "content", "key",
}

// SchemaFieldNames returns the lowercase field names of the Event
// struct for schema auditing.
func SchemaFieldNames() []string {
	return []string{
		"name", "duration_millis", "installation_id", "pass_id",
		"run_id", "error_code", "enforcement_level",
		"intervention_count", "outcome_class",
	}
}

// CheckSchemaFieldName reports whether a field name is acceptable in the
// telemetry schema: it must be one of the fixed names and contain none
// of the forbidden tokens. Comparison is case- and
// underscore-insensitive so both Go and JSON spellings are covered.
func CheckSchemaFieldName(field string) error {
	norm := strings.ReplaceAll(strings.ToLower(field), "_", "")
	allowed := false
	for _, n := range SchemaFieldNames() {
		if norm == strings.ReplaceAll(n, "_", "") {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("telemetry: field %q is not in the allowlisted schema", field)
	}
	lower := strings.ToLower(field)
	for _, tok := range forbiddenFieldTokens {
		if strings.Contains(lower, tok) {
			return fmt.Errorf("telemetry: field %q contains forbidden token %q", field, tok)
		}
	}
	return nil
}
