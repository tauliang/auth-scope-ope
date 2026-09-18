package telemetry

import (
	"reflect"
	"strings"
	"testing"
)

// TestSchemaAllowsOnlyFixedFields reflects over every field of the Event
// struct and rejects repository, issue, branch, PR, objective, criteria,
// prompt, source, patch, transcript, token, secret, credential, email,
// URL, receipt payload, or free-form message fields.
func TestSchemaAllowsOnlyFixedFields(t *testing.T) {
	typ := reflect.TypeOf(Event{})
	if typ.Kind() != reflect.Struct {
		t.Fatalf("Event is %s, want struct", typ.Kind())
	}
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		names = append(names, f.Name)
		if err := CheckSchemaFieldName(f.Name); err != nil {
			t.Errorf("field %q rejected: %v", f.Name, err)
		}
		// No field may be a free-form string bag: every field is a
		// scalar with a fixed meaning.
		switch f.Type.Kind() {
		case reflect.String, reflect.Int64, reflect.Int:
		default:
			t.Errorf("field %q has kind %s, want string/int64/int", f.Name, f.Type.Kind())
		}
	}
	// The schema is exactly the nine allowlisted fields: adding a tenth
	// field fails here even if it passes the token check.
	if len(names) != 9 {
		t.Fatalf("Event has %d fields %v, want exactly 9", len(names), names)
	}
	want := map[string]bool{
		"Name": true, "DurationMillis": true, "InstallationID": true,
		"PassID": true, "RunID": true, "ErrorCode": true,
		"EnforcementLevel": true, "InterventionCount": true,
		"OutcomeClass": true,
	}
	for _, n := range names {
		if !want[n] {
			t.Errorf("unexpected field %q", n)
		}
	}
}

// TestSchemaRejectsPrivateFieldNames guards the token list itself: each
// forbidden concept must trip CheckSchemaFieldName.
func TestSchemaRejectsPrivateFieldNames(t *testing.T) {
	bad := []string{
		"RepositoryName", "IssueTitle", "IssueBody", "Branch", "PullRequestNumber",
		"Objective", "AcceptanceCriteria", "Prompt", "SourceCode", "Patch",
		"Transcript", "Token", "Secret", "Credential", "Email", "URL",
		"ReceiptPayload", "Message", "ErrorDetail", "PrivateKey",
	}
	for _, name := range bad {
		if err := CheckSchemaFieldName(name); err == nil {
			t.Errorf("CheckSchemaFieldName(%q) = nil, want rejection", name)
		}
	}
}

func validEvent() Event {
	return Event{
		Name:              EventConnect,
		DurationMillis:    120,
		InstallationID:    "inst-01HZY",
		PassID:            "pass-abc123",
		RunID:             "run-xyz",
		ErrorCode:         ErrorNone,
		EnforcementLevel:  EnforcementDevelopment,
		InterventionCount: 0,
		OutcomeClass:      OutcomeSuccess,
	}
}

// TestValidateAcceptsAllowlistedEvent checks the happy path.
func TestValidateAcceptsAllowlistedEvent(t *testing.T) {
	if err := validEvent().Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// TestValidateRejectsUnknownEnums checks that names, error codes,
// outcome classes, and enforcement levels outside the fixed enums are
// rejected.
func TestValidateRejectsUnknownEnums(t *testing.T) {
	cases := []func(*Event){
		func(e *Event) { e.Name = "prompt_sent" },
		func(e *Event) { e.Name = "" },
		func(e *Event) { e.ErrorCode = "upstream 500: boom" },
		func(e *Event) { e.ErrorCode = "" },
		func(e *Event) { e.OutcomeClass = "succeeded with warnings" },
		func(e *Event) { e.EnforcementLevel = "strict" },
		func(e *Event) { e.DurationMillis = -1 },
		func(e *Event) { e.InterventionCount = -2 },
		func(e *Event) { e.PassID = "pass with spaces" },
		func(e *Event) { e.RunID = "https://example.com/run" },
		func(e *Event) { e.InstallationID = "user@example.com" },
		func(e *Event) { e.PassID = "../etc/passwd" },
	}
	for i, mutate := range cases {
		e := validEvent()
		mutate(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("case %d: Validate() = nil, want rejection (event=%+v)", i, e)
		}
	}
}

// TestValidateAllowsEmptyOptionalIDs: pass and run IDs are optional;
// empty is valid.
func TestValidateAllowsEmptyOptionalIDs(t *testing.T) {
	e := validEvent()
	e.PassID, e.RunID = "", ""
	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

// TestEventNamesAreFixedEnum asserts the funnel vocabulary is exactly
// the nine steps from the design.
func TestEventNamesAreFixedEnum(t *testing.T) {
	want := []string{
		"connect", "issue_selected", "proposal_ready", "approved",
		"cli_authorized", "run_prepared", "expansion_decided",
		"receipt_verified", "check_published",
	}
	if len(validEventNames) != len(want) {
		t.Fatalf("validEventNames has %d entries, want %d", len(validEventNames), len(want))
	}
	for _, n := range want {
		if !validEventNames[n] {
			t.Errorf("funnel step %q missing from the allowlist", n)
		}
		if strings.ContainsAny(n, " /") {
			t.Errorf("event name %q contains separator characters", n)
		}
	}
}
