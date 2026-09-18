package telemetry

import (
	"context"
	"testing"

	"github.com/tauliang/authscope-ope/internal/store"
)

// TestTelemetryOffByDefault asserts the consent rule: without an
// explicit OPE_TELEMETRY=enabled, telemetry stays off in development
// and before explicit release-mode configuration.
func TestTelemetryOffByDefault(t *testing.T) {
	t.Setenv(telemetryEnvVar, "")
	if EnabledFromEnv() {
		t.Fatal("EnabledFromEnv() = true with OPE_TELEMETRY unset, want false")
	}
	for _, v := range []string{"1", "true", "yes", "on", "ENABLED", " enabled "} {
		t.Setenv(telemetryEnvVar, v)
		if v == " enabled " {
			// Whitespace-trimmed "enabled" is still explicit opt-in.
			if !EnabledFromEnv() {
				t.Errorf("EnabledFromEnv() = false with OPE_TELEMETRY=%q, want true", v)
			}
			continue
		}
		if EnabledFromEnv() {
			t.Errorf("EnabledFromEnv() = true with OPE_TELEMETRY=%q, want false", v)
		}
	}
	t.Setenv(telemetryEnvVar, "enabled")
	if !EnabledFromEnv() {
		t.Fatal("EnabledFromEnv() = false with OPE_TELEMETRY=enabled, want true")
	}
}

// TestDisabledSinkDropsEvents: the default sink records nothing.
func TestDisabledSinkDropsEvents(t *testing.T) {
	var s Sink = DisabledSink{}
	if s.Enabled() {
		t.Fatal("DisabledSink.Enabled() = true, want false")
	}
	if err := s.Record(context.Background(), Event{Name: "bogus"}); err != nil {
		t.Fatalf("DisabledSink.Record() = %v, want nil", err)
	}
}

// TestNewSinkFailsClosed: anything but an explicitly enabled
// configuration with a store yields the disabled sink.
func TestNewSinkFailsClosed(t *testing.T) {
	st := openTestStore(t)
	cases := []SinkConfig{
		{},
		{Enabled: true},
		{Enabled: true, Store: st},
		{Enabled: true, Store: st, WorkspaceID: "ws-1"},
		{Enabled: false, Store: st, WorkspaceID: "ws-1", InstanceID: "inst-1"},
	}
	for i, cfg := range cases {
		s := NewSink(cfg)
		if s.Enabled() {
			t.Errorf("case %d: NewSink(%+v).Enabled() = true, want false", i, cfg)
		}
	}
	s := NewSink(SinkConfig{Enabled: true, Store: st, WorkspaceID: "ws-1", InstanceID: "inst-1"})
	if !s.Enabled() {
		t.Fatal("NewSink(enabled config).Enabled() = false, want true")
	}
}

// TestMemorySinkValidates: the in-memory sink validates and records.
func TestMemorySinkValidates(t *testing.T) {
	m := &MemorySink{}
	e := Event{
		Name: EventCheckPublished, ErrorCode: ErrorNone,
		EnforcementLevel: EnforcementRelease, OutcomeClass: OutcomeSuccess,
		PassID: "pass-1",
	}
	if err := m.Record(context.Background(), e); err != nil {
		t.Fatalf("Record() = %v, want nil", err)
	}
	if len(m.Events) != 1 || m.Events[0].Name != EventCheckPublished {
		t.Fatalf("Events = %+v, want one check_published event", m.Events)
	}
	bad := e
	bad.Name = "transcript_uploaded"
	if err := m.Record(context.Background(), bad); err == nil {
		t.Fatal("Record(bad name) = nil, want validation error")
	}
	if len(m.Events) != 1 {
		t.Fatalf("Events = %d after rejected record, want 1", len(m.Events))
	}
}

// TestStoreSinkPseudonymizesInstallationID: the stored installation ID
// is the salted pseudonym, stable across records, and differs per
// instance and per salt.
func TestStoreSinkPseudonymizesInstallationID(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	s := NewSink(SinkConfig{Enabled: true, Store: st, WorkspaceID: "ws-1", InstanceID: "inst-1"}).(*StoreSink)

	e := Event{
		Name: EventConnect, ErrorCode: ErrorNone,
		EnforcementLevel: EnforcementDevelopment, OutcomeClass: OutcomeSuccess,
	}
	if err := s.Record(ctx, e); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	if err := s.Record(ctx, e); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	rows, err := st.ListTelemetryEvents(ctx, "ws-1", 10)
	if err != nil {
		t.Fatalf("ListTelemetryEvents() = %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	got := rows[0].InstallationID
	if got == "" || got == "inst-1" {
		t.Fatalf("InstallationID = %q, want pseudonymized value", got)
	}
	if rows[1].InstallationID != got {
		t.Fatal("pseudonymized installation ID is not stable across records")
	}
	salt, err := st.GetOrCreateTelemetrySalt(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateTelemetrySalt() = %v", err)
	}
	if want := PseudonymizeInstallationID(salt, "inst-1"); got != want {
		t.Fatalf("InstallationID = %q, want %q", got, want)
	}
	if other := PseudonymizeInstallationID(salt, "inst-2"); other == got {
		t.Fatal("different instance IDs pseudonymize identically")
	}
}

// TestStoreSinkRejectsCallerInstallationID: callers must not smuggle an
// installation ID into the event.
func TestStoreSinkRejectsCallerInstallationID(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	s := NewSink(SinkConfig{Enabled: true, Store: st, WorkspaceID: "ws-1", InstanceID: "inst-1"})
	e := Event{
		Name: EventConnect, ErrorCode: ErrorNone,
		EnforcementLevel: EnforcementDevelopment, OutcomeClass: OutcomeSuccess,
		InstallationID: "attacker-chosen-id",
	}
	if err := s.Record(ctx, e); err == nil {
		t.Fatal("Record() with caller InstallationID = nil, want error")
	}
}

// TestStoreSinkSaltIsInstanceLocal: the salt persists in the store and
// is reused across sink instances.
func TestStoreSinkSaltIsInstanceLocal(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	salt1, err := st.GetOrCreateTelemetrySalt(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateTelemetrySalt() = %v", err)
	}
	if len(salt1) != 32 {
		t.Fatalf("salt length = %d, want 32", len(salt1))
	}
	salt2, err := st.GetOrCreateTelemetrySalt(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateTelemetrySalt() = %v", err)
	}
	if string(salt1) != string(salt2) {
		t.Fatal("salt changed between calls")
	}
}

// openTestStore opens an isolated SQLite store for telemetry tests.
func openTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("store.Open() = %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}
