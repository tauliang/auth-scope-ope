// Telemetry sinks: consent-gated, allowlisted event recording.
//
// A Sink records validated telemetry events. Production uses the
// StoreSink, which pseudonymizes the installation ID with the
// instance-local salt and persists only the fixed event fields. Tests
// use the MemorySink. When telemetry is not explicitly enabled the
// DisabledSink drops every event.
//
// Consent: telemetry is off by default in development and stays off
// until the operator explicitly sets OPE_TELEMETRY=enabled. There is no
// other way to enable it.
package telemetry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/store"
)

// Sink records privacy-limited telemetry events.
type Sink interface {
	// Record validates the event and records it. A disabled sink
	// returns nil without recording.
	Record(ctx context.Context, e Event) error
	// Enabled reports whether the sink records events.
	Enabled() bool
}

// telemetryEnvVar is the single explicit opt-in switch.
const telemetryEnvVar = "OPE_TELEMETRY"

// EnabledFromEnv reports whether telemetry was explicitly enabled. Only
// OPE_TELEMETRY=enabled turns it on; every other value, including
// unset, leaves it off. Development therefore defaults to off, and
// release mode requires explicit configuration.
func EnabledFromEnv() bool {
	return strings.TrimSpace(os.Getenv(telemetryEnvVar)) == "enabled"
}

// SinkConfig wires a sink.
type SinkConfig struct {
	// Enabled is the explicit operator opt-in (OPE_TELEMETRY=enabled).
	Enabled bool
	// Store persists events. Required when Enabled.
	Store store.Store
	// WorkspaceID qualifies recorded events.
	WorkspaceID string
	// InstanceID is pseudonymized with the instance-local salt before
	// it is recorded.
	InstanceID string
	// Clock overrides time.Now for tests.
	Clock func() time.Time
}

// NewSink builds the sink for the configuration. Anything but an
// explicitly enabled configuration with a store yields the disabled
// sink: telemetry fails closed to off.
func NewSink(cfg SinkConfig) Sink {
	if !cfg.Enabled || cfg.Store == nil || cfg.WorkspaceID == "" || cfg.InstanceID == "" {
		return DisabledSink{}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &StoreSink{
		store:       cfg.Store,
		workspaceID: cfg.WorkspaceID,
		instanceID:  cfg.InstanceID,
		clock:       clock,
	}
}

// MaybeRecord records the event when the sink is non-nil and enabled.
// Validation failures are returned; a nil or disabled sink is a no-op.
func MaybeRecord(s Sink, ctx context.Context, e Event) error {
	if s == nil || !s.Enabled() {
		return nil
	}
	return s.Record(ctx, e)
}

// EnforcementForMode maps the instance mode to the telemetry
// enforcement level.
func EnforcementForMode(mode string) string {
	if mode == "release" {
		return EnforcementRelease
	}
	return EnforcementDevelopment
}

// DisabledSink drops every event. It is the default.
type DisabledSink struct{}

// Record implements Sink.
func (DisabledSink) Record(_ context.Context, _ Event) error { return nil }

// Enabled implements Sink.
func (DisabledSink) Enabled() bool { return false }

// MemorySink records events in memory for tests. It validates every
// event but never pseudonymizes: test assertions inspect the raw IDs.
type MemorySink struct {
	Events []Event
}

// Record implements Sink.
func (m *MemorySink) Record(_ context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	m.Events = append(m.Events, e)
	return nil
}

// Enabled implements Sink.
func (m *MemorySink) Enabled() bool { return true }

// StoreSink persists validated events with a pseudonymized
// installation ID.
type StoreSink struct {
	store       store.Store
	workspaceID string
	instanceID  string
	clock       func() time.Time
}

// PseudonymizeInstallationID derives the stable pseudonymous
// installation ID from the instance-local salt: the first 32 hex
// characters of SHA-256(salt || 0x00 || instanceID). The raw instance
// ID never leaves the store.
func PseudonymizeInstallationID(salt []byte, instanceID string) string {
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte{0})
	h.Write([]byte(instanceID))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// Record implements Sink. The event is validated first; validation
// failures are returned and nothing is persisted. The installation ID
// is pseudonymized with the instance-local salt on every record so a
// rotated salt cannot be correlated with an old one through stored
// events.
func (s *StoreSink) Record(ctx context.Context, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	salt, err := s.store.GetOrCreateTelemetrySalt(ctx)
	if err != nil {
		return fmt.Errorf("telemetry: salt: %w", err)
	}
	rec := store.TelemetryEventRecord{
		WorkspaceID:       s.workspaceID,
		Name:              e.Name,
		DurationMillis:    e.DurationMillis,
		InstallationID:    PseudonymizeInstallationID(salt, s.instanceID),
		PassID:            e.PassID,
		RunID:             e.RunID,
		ErrorCode:         e.ErrorCode,
		EnforcementLevel:  e.EnforcementLevel,
		InterventionCount: int64(e.InterventionCount),
		OutcomeClass:      e.OutcomeClass,
		OccurredAt:        s.clock().UTC(),
	}
	// The caller-supplied InstallationID is never trusted: the sink
	// always derives it from the instance binding. A caller value that
	// differs from the derived one is a programming error.
	if e.InstallationID != "" && e.InstallationID != rec.InstallationID {
		return fmt.Errorf("telemetry: caller must not set InstallationID")
	}
	if err := s.store.InsertTelemetryEvent(ctx, rec); err != nil {
		return fmt.Errorf("telemetry: record: %w", err)
	}
	return nil
}

// Enabled implements Sink.
func (s *StoreSink) Enabled() bool { return true }
