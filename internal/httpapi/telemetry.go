// Funnel telemetry helpers for the HTTP layer.
//
// Every product funnel step records one allowlisted telemetry event:
// step name, duration, opaque identifiers, a fixed error code, the
// enforcement level, an intervention count, and a fixed outcome class.
// A nil or disabled sink records nothing, so tests that do not wire
// telemetry are unaffected.
package httpapi

import (
	"context"
	"time"

	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/telemetry"
)

// telemetryState renders the configured telemetry state for the
// bootstrap response: "enabled" only under the explicit
// OPE_TELEMETRY=enabled opt-in, "disabled" otherwise.
func telemetryState(cfg config.Config) string {
	if cfg.TelemetryEnabled {
		return "enabled"
	}
	return "disabled"
}

// recordFunnel records one funnel step event. The sink is nil-safe: a
// nil or disabled sink records nothing.
func recordFunnel(sink telemetry.Sink, mode string, ctx context.Context, name string, start time.Time, passID, runID, errCode, outcome string, interventions int) {
	_ = telemetry.MaybeRecord(sink, ctx, telemetry.Event{
		Name:              name,
		DurationMillis:    time.Since(start).Milliseconds(),
		PassID:            passID,
		RunID:             runID,
		ErrorCode:         errCode,
		EnforcementLevel:  telemetry.EnforcementForMode(mode),
		InterventionCount: interventions,
		OutcomeClass:      outcome,
	})
}

// funnelErrorCode maps a funnel-step failure to the fixed error-code
// enum. Detail stays out of telemetry by construction.
func funnelErrorCode(err error) string {
	if err == nil {
		return telemetry.ErrorNone
	}
	return telemetry.ErrorInternal
}
