// Local expansion projections and durable expansion decision intents.
// Task 11 adds these rows alongside the existing projection tables. The
// expansions table is the single source of truth the browser reads: it
// holds only allowlisted canonical delta fields, never raw upstream
// payloads, prompts, or credentials.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (t *sqliteTx) PutExpansion(ctx context.Context, rec ExpansionRecord) error {
	return putExpansion(ctx, t.tx, rec)
}

func (t *sqliteTx) GetExpansion(ctx context.Context, workspaceID, expansionID string) (ExpansionRecord, error) {
	return getExpansion(ctx, t.tx, workspaceID, expansionID)
}

func (t *sqliteTx) ListExpansions(ctx context.Context, workspaceID, passID, status string) ([]ExpansionRecord, error) {
	return listExpansions(ctx, t.tx, workspaceID, passID, status)
}

func (t *sqliteTx) ResolveExpansion(ctx context.Context, workspaceID, expansionID, status string) error {
	return resolveExpansion(ctx, t.tx, workspaceID, expansionID, status)
}

func (t *sqliteTx) PutExpansionIntent(ctx context.Context, rec ExpansionIntentRecord) error {
	return putExpansionIntent(ctx, t.tx, rec)
}

func (t *sqliteTx) GetExpansionIntent(ctx context.Context, workspaceID, expansionID string) (ExpansionIntentRecord, error) {
	return getExpansionIntent(ctx, t.tx, workspaceID, expansionID)
}

func (t *sqliteTx) CompleteExpansionIntent(ctx context.Context, workspaceID, expansionID, decisionRef string, resultMissionVersion int64) error {
	return completeExpansionIntent(ctx, t.tx, workspaceID, expansionID, decisionRef, resultMissionVersion)
}

func (s *sqliteStore) ListExpansionIntents(ctx context.Context, workspaceID, state string) ([]ExpansionIntentRecord, error) {
	return listExpansionIntents(ctx, s.db, workspaceID, state)
}

// putExpansion upserts the locally projected expansion delta. The delta
// JSON must already be verified against the expansion digest by the
// caller; the store keeps only the allowlisted canonical fields.
func putExpansion(ctx context.Context, c dbConn, rec ExpansionRecord) error {
	if rec.WorkspaceID == "" || rec.ExpansionID == "" || rec.PassID == "" || rec.DeltaJSON == "" {
		return fmt.Errorf("store: put expansion: workspace, expansion, pass, and delta are required")
	}
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE expansions
		SET pass_id = ?, mission_ref = ?, status = ?, delta_json = ?,
		    expansion_digest = ?, updated_at = ?
		WHERE workspace_id = ? AND expansion_id = ? AND status = ?`,
		rec.PassID, rec.MissionRef, expansionStatus(rec.Status), rec.DeltaJSON,
		rec.ExpansionDigest, now, rec.WorkspaceID, rec.ExpansionID, ExpansionPending)
	if err != nil {
		return fmt.Errorf("store: put expansion: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: put expansion: %w", err)
	} else if n == 1 {
		return nil
	}
	_, err = c.ExecContext(ctx, `INSERT INTO expansions
		(workspace_id, expansion_id, pass_id, mission_ref, status, delta_json,
		 expansion_digest, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.ExpansionID, rec.PassID, rec.MissionRef,
		expansionStatus(rec.Status), rec.DeltaJSON, rec.ExpansionDigest, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: expansion already exists", ErrConflict)
		}
		return fmt.Errorf("store: put expansion: %w", err)
	}
	return nil
}

func expansionStatus(status string) string {
	if status == "" {
		return ExpansionPending
	}
	return status
}

const expansionColumns = `workspace_id, expansion_id, pass_id, mission_ref, status,
	delta_json, expansion_digest, created_at, updated_at`

func scanExpansion(row *sql.Row, rows *sql.Rows) (ExpansionRecord, error) {
	var rec ExpansionRecord
	var created, updated string
	var err error
	if rows != nil {
		err = rows.Scan(&rec.WorkspaceID, &rec.ExpansionID, &rec.PassID, &rec.MissionRef,
			&rec.Status, &rec.DeltaJSON, &rec.ExpansionDigest, &created, &updated)
	} else {
		err = row.Scan(&rec.WorkspaceID, &rec.ExpansionID, &rec.PassID, &rec.MissionRef,
			&rec.Status, &rec.DeltaJSON, &rec.ExpansionDigest, &created, &updated)
	}
	if err != nil {
		return ExpansionRecord{}, err
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return ExpansionRecord{}, fmt.Errorf("store: scan expansion: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return ExpansionRecord{}, fmt.Errorf("store: scan expansion: %w", err)
	}
	return rec, nil
}

func getExpansion(ctx context.Context, c dbConn, workspaceID, expansionID string) (ExpansionRecord, error) {
	rec, err := scanExpansion(c.QueryRowContext(ctx, `SELECT `+expansionColumns+`
		FROM expansions WHERE workspace_id = ? AND expansion_id = ?`,
		workspaceID, expansionID), nil)
	if err == sql.ErrNoRows {
		return ExpansionRecord{}, fmt.Errorf("%w: expansion %q", ErrNotFound, expansionID)
	}
	if err != nil {
		return ExpansionRecord{}, fmt.Errorf("store: get expansion: %w", err)
	}
	return rec, nil
}

// listExpansions returns the expansions of a pass in the given status,
// oldest first.
func listExpansions(ctx context.Context, c dbConn, workspaceID, passID, status string) ([]ExpansionRecord, error) {
	rows, err := c.QueryContext(ctx, `SELECT `+expansionColumns+`
		FROM expansions WHERE workspace_id = ? AND pass_id = ? AND status = ?
		ORDER BY created_at ASC`,
		workspaceID, passID, status)
	if err != nil {
		return nil, fmt.Errorf("store: list expansions: %w", err)
	}
	defer rows.Close()
	var out []ExpansionRecord
	for rows.Next() {
		rec, err := scanExpansion(nil, rows)
		if err != nil {
			return nil, fmt.Errorf("store: list expansions: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list expansions: %w", err)
	}
	return out, nil
}

// resolveExpansion marks a projected expansion with a final status. It
// affects exactly one pending row, so resolving an already-resolved
// expansion is a conflict.
func resolveExpansion(ctx context.Context, c dbConn, workspaceID, expansionID, status string) error {
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE expansions
		SET status = ?, updated_at = ?
		WHERE workspace_id = ? AND expansion_id = ? AND status = ?`,
		status, now, workspaceID, expansionID, ExpansionPending)
	if err != nil {
		return fmt.Errorf("store: resolve expansion: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: resolve expansion: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: expansion %q already resolved or missing", ErrConflict, expansionID)
	}
	return nil
}

func putExpansionIntent(ctx context.Context, c dbConn, rec ExpansionIntentRecord) error {
	if rec.WorkspaceID == "" || rec.ExpansionID == "" || rec.PassID == "" || rec.IdempotencyKey == "" {
		return fmt.Errorf("store: put expansion intent: workspace, expansion, pass, and idempotency key are required")
	}
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE expansion_intents
		SET pass_id = ?, idempotency_key = ?, decision = ?, canonical_digest = ?,
		    state = ?, attestation_digest = ?, attestation_json = ?,
		    upstream_ref = ?, result_mission_version = ?, updated_at = ?
		WHERE workspace_id = ? AND expansion_id = ? AND state <> ?`,
		rec.PassID, rec.IdempotencyKey, rec.Decision, rec.CanonicalDigest,
		expansionIntentState(rec.State), rec.AttestationDigest, rec.AttestationJSON,
		rec.UpstreamRef, rec.ResultMissionVersion, now,
		rec.WorkspaceID, rec.ExpansionID, ExpansionIntentCompleted)
	if err != nil {
		return fmt.Errorf("store: put expansion intent: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: put expansion intent: %w", err)
	} else if n == 1 {
		return nil
	}
	_, err = c.ExecContext(ctx, `INSERT INTO expansion_intents
		(workspace_id, expansion_id, pass_id, idempotency_key, decision, canonical_digest,
		 state, attestation_digest, attestation_json, upstream_ref, result_mission_version,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.ExpansionID, rec.PassID, rec.IdempotencyKey, rec.Decision,
		rec.CanonicalDigest, expansionIntentState(rec.State), rec.AttestationDigest,
		rec.AttestationJSON, rec.UpstreamRef, rec.ResultMissionVersion, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: expansion intent already exists", ErrConflict)
		}
		return fmt.Errorf("store: put expansion intent: %w", err)
	}
	return nil
}

func expansionIntentState(state string) string {
	if state == "" {
		return ExpansionIntentInFlight
	}
	return state
}

const expansionIntentColumns = `workspace_id, expansion_id, pass_id, idempotency_key,
	decision, canonical_digest, state, attestation_digest, attestation_json,
	upstream_ref, result_mission_version, created_at, updated_at`

func getExpansionIntent(ctx context.Context, c dbConn, workspaceID, expansionID string) (ExpansionIntentRecord, error) {
	var rec ExpansionIntentRecord
	var created, updated string
	err := c.QueryRowContext(ctx, `SELECT `+expansionIntentColumns+`
		FROM expansion_intents WHERE workspace_id = ? AND expansion_id = ?`,
		workspaceID, expansionID).Scan(&rec.WorkspaceID, &rec.ExpansionID, &rec.PassID,
		&rec.IdempotencyKey, &rec.Decision, &rec.CanonicalDigest, &rec.State,
		&rec.AttestationDigest, &rec.AttestationJSON, &rec.UpstreamRef,
		&rec.ResultMissionVersion, &created, &updated)
	if err == sql.ErrNoRows {
		return ExpansionIntentRecord{}, fmt.Errorf("%w: expansion intent %q", ErrNotFound, expansionID)
	}
	if err != nil {
		return ExpansionIntentRecord{}, fmt.Errorf("store: get expansion intent: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return ExpansionIntentRecord{}, fmt.Errorf("store: get expansion intent: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return ExpansionIntentRecord{}, fmt.Errorf("store: get expansion intent: %w", err)
	}
	return rec, nil
}

// listExpansionIntents returns the intents of a workspace in the given
// state, oldest first.
func listExpansionIntents(ctx context.Context, c dbConn, workspaceID, state string) ([]ExpansionIntentRecord, error) {
	rows, err := c.QueryContext(ctx, `SELECT `+expansionIntentColumns+`
		FROM expansion_intents WHERE workspace_id = ? AND state = ?
		ORDER BY created_at ASC`,
		workspaceID, state)
	if err != nil {
		return nil, fmt.Errorf("store: list expansion intents: %w", err)
	}
	defer rows.Close()
	var out []ExpansionIntentRecord
	for rows.Next() {
		var rec ExpansionIntentRecord
		var created, updated string
		if err := rows.Scan(&rec.WorkspaceID, &rec.ExpansionID, &rec.PassID,
			&rec.IdempotencyKey, &rec.Decision, &rec.CanonicalDigest, &rec.State,
			&rec.AttestationDigest, &rec.AttestationJSON, &rec.UpstreamRef,
			&rec.ResultMissionVersion, &created, &updated); err != nil {
			return nil, fmt.Errorf("store: list expansion intents: %w", err)
		}
		if rec.CreatedAt, err = parseTime(created); err != nil {
			return nil, fmt.Errorf("store: list expansion intents: %w", err)
		}
		if rec.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, fmt.Errorf("store: list expansion intents: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list expansion intents: %w", err)
	}
	return out, nil
}

// completeExpansionIntent marks the intent completed with the decision
// reference and the resulting upstream mission version. It never
// rewrites a completed intent.
func completeExpansionIntent(ctx context.Context, c dbConn, workspaceID, expansionID, decisionRef string, resultMissionVersion int64) error {
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE expansion_intents
		SET state = ?, upstream_ref = ?, result_mission_version = ?, updated_at = ?
		WHERE workspace_id = ? AND expansion_id = ? AND state <> ?`,
		ExpansionIntentCompleted, decisionRef, resultMissionVersion, now,
		workspaceID, expansionID, ExpansionIntentCompleted)
	if err != nil {
		return fmt.Errorf("store: complete expansion intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: complete expansion intent: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: expansion intent %q already completed or missing", ErrConflict, expansionID)
	}
	return nil
}
