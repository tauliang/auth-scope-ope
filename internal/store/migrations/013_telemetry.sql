-- Task 15: privacy-limited telemetry. Extend the telemetry_events table
-- with the fixed allowlisted event columns and add the singleton
-- telemetry_settings table holding the instance-local telemetry salt.
-- No content fields exist: step name, duration, pseudonymized
-- installation ID, opaque pass/run identifiers, fixed error code,
-- enforcement level, intervention count, and fixed outcome class only.
ALTER TABLE telemetry_events ADD COLUMN duration_millis INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_events ADD COLUMN installation_id TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN pass_id TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN run_id TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN error_code TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN enforcement_level TEXT NOT NULL DEFAULT '';
ALTER TABLE telemetry_events ADD COLUMN intervention_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE telemetry_events ADD COLUMN outcome_class TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS telemetry_settings (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
