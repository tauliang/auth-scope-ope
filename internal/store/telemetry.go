// Privacy-limited telemetry persistence.
//
// The telemetry salt is an instance-local 32-byte secret stored in the
// singleton telemetry_settings table. It pseudonymizes the installation
// ID before any telemetry event is recorded, so the raw instance ID
// never leaves the store. Telemetry events carry only the fixed
// allowlisted fields; there is no content column by construction.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// telemetrySaltKey is the singleton key of the instance-local salt.
const telemetrySaltKey = "telemetry_salt"

// telemetrySaltBytes is the salt length.
const telemetrySaltBytes = 32

// GetOrCreateTelemetrySalt implements Store.
func (s *sqliteStore) GetOrCreateTelemetrySalt(ctx context.Context) ([]byte, error) {
	var value []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM telemetry_settings WHERE key = ?`, telemetrySaltKey).Scan(&value)
	switch {
	case err == nil:
		if len(value) != telemetrySaltBytes {
			return nil, fmt.Errorf("store: telemetry salt has unexpected length %d", len(value))
		}
		return value, nil
	case errors.Is(err, sql.ErrNoRows):
		salt := make([]byte, telemetrySaltBytes)
		if _, err := rand.Read(salt); err != nil {
			return nil, fmt.Errorf("store: generate telemetry salt: %w", err)
		}
		// Insert-or-ignore keeps the first writer's salt when two
		// processes race at first boot; the single-writer lock makes
		// the race unlikely, but the read-back stays correct either
		// way.
		if _, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO telemetry_settings (key, value) VALUES (?, ?)`, telemetrySaltKey, salt); err != nil {
			return nil, fmt.Errorf("store: store telemetry salt: %w", err)
		}
		var stored []byte
		if err := s.db.QueryRowContext(ctx, `SELECT value FROM telemetry_settings WHERE key = ?`, telemetrySaltKey).Scan(&stored); err != nil {
			return nil, fmt.Errorf("store: read telemetry salt: %w", err)
		}
		if len(stored) != telemetrySaltBytes {
			return nil, fmt.Errorf("store: telemetry salt has unexpected length %d", len(stored))
		}
		return stored, nil
	default:
		return nil, fmt.Errorf("store: read telemetry salt: %w", err)
	}
}

// InsertTelemetryEvent implements Store.
func (s *sqliteStore) InsertTelemetryEvent(ctx context.Context, rec TelemetryEventRecord) error {
	if rec.WorkspaceID == "" || rec.Name == "" {
		return fmt.Errorf("store: telemetry event requires workspace and name")
	}
	occurred := rec.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO telemetry_events
		(workspace_id, name, occurred_at, duration_millis, installation_id,
		 pass_id, run_id, error_code, enforcement_level, intervention_count,
		 outcome_class)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.Name, formatTime(occurred), rec.DurationMillis,
		rec.InstallationID, rec.PassID, rec.RunID, rec.ErrorCode,
		rec.EnforcementLevel, rec.InterventionCount, rec.OutcomeClass)
	if err != nil {
		return fmt.Errorf("store: insert telemetry event: %w", err)
	}
	return nil
}

// ListTelemetryEvents implements Store.
func (s *sqliteStore) ListTelemetryEvents(ctx context.Context, workspaceID string, limit int) ([]TelemetryEventRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT workspace_id, name, occurred_at,
		duration_millis, installation_id, pass_id, run_id, error_code,
		enforcement_level, intervention_count, outcome_class
		FROM telemetry_events WHERE workspace_id = ?
		ORDER BY id DESC LIMIT ?`, workspaceID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list telemetry events: %w", err)
	}
	defer rows.Close()
	var out []TelemetryEventRecord
	for rows.Next() {
		var rec TelemetryEventRecord
		var occurred string
		if err := rows.Scan(&rec.WorkspaceID, &rec.Name, &occurred,
			&rec.DurationMillis, &rec.InstallationID, &rec.PassID, &rec.RunID,
			&rec.ErrorCode, &rec.EnforcementLevel, &rec.InterventionCount,
			&rec.OutcomeClass); err != nil {
			return nil, fmt.Errorf("store: scan telemetry event: %w", err)
		}
		rec.OccurredAt, err = parseTime(occurred)
		if err != nil {
			return nil, fmt.Errorf("store: parse telemetry event time: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list telemetry events: %w", err)
	}
	return out, nil
}
