// Offline recovery storage: recovery intents, recovery events, bulk
// session revocation, handoff invalidation, passkey removal, and
// one-use recovery-key consumption. Raw recovery keys are never
// persisted; only their SHA-256 hashes reach the database, and the
// recovery event carries no key material at all.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *sqliteStore) GetRecoveryIntent(ctx context.Context, workspaceID, idempotencyKey string) (RecoveryIntentRecord, error) {
	return getRecoveryIntent(ctx, s.db, workspaceID, idempotencyKey)
}

func (s *sqliteStore) GetRecoveryEvent(ctx context.Context, workspaceID, eventID string) (RecoveryEventRecord, error) {
	return getRecoveryEvent(ctx, s.db, workspaceID, eventID)
}

func (s *sqliteStore) ListRecoveryEvents(ctx context.Context, workspaceID string, limit int) ([]RecoveryEventRecord, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, `SELECT workspace_id, event_id, founder_id, idempotency_key,
		contained_mission_count, containment_generation,
		attestation_digest, recovery_proof_digest, bootstrap_code_hash, occurred_at
		FROM recovery_events WHERE workspace_id = ?
		ORDER BY occurred_at DESC LIMIT ?`, workspaceID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list recovery events: %w", err)
	}
	defer rows.Close()
	var out []RecoveryEventRecord
	for rows.Next() {
		var rec RecoveryEventRecord
		var occurred string
		var generation int64
		if err := rows.Scan(&rec.WorkspaceID, &rec.EventID, &rec.FounderID, &rec.IdempotencyKey,
			&rec.ContainedMissionCount, &generation,
			&rec.AttestationDigest, &rec.RecoveryProofDigest, &rec.BootstrapCodeHash, &occurred); err != nil {
			return nil, fmt.Errorf("store: list recovery events: %w", err)
		}
		rec.ContainmentGeneration = generation
		if rec.OccurredAt, err = parseTime(occurred); err != nil {
			return nil, fmt.Errorf("store: list recovery events: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list recovery events: %w", err)
	}
	return out, nil
}

func (s *sqliteStore) GetWorkerLease(ctx context.Context, instanceID string) (WorkerLeaseRecord, error) {
	return getWorkerLease(ctx, s.db, instanceID)
}

func (t *sqliteTx) PutRecoveryIntent(ctx context.Context, rec RecoveryIntentRecord) error {
	return putRecoveryIntent(ctx, t.tx, rec)
}

func (t *sqliteTx) GetRecoveryIntent(ctx context.Context, workspaceID, idempotencyKey string) (RecoveryIntentRecord, error) {
	return getRecoveryIntent(ctx, t.tx, workspaceID, idempotencyKey)
}

func (t *sqliteTx) SetRecoveryIntentAttestation(ctx context.Context, workspaceID, idempotencyKey, attestationDigest string, at time.Time) error {
	return transitionRecoveryIntent(ctx, t.tx, workspaceID, idempotencyKey, RecoveryIntentPending, RecoveryIntentPending,
		map[string]any{"attestation_digest": attestationDigest}, at)
}

func (t *sqliteTx) SetRecoveryIntentContained(ctx context.Context, workspaceID, idempotencyKey string, generation int64, at time.Time) error {
	return transitionRecoveryIntent(ctx, t.tx, workspaceID, idempotencyKey, RecoveryIntentPending, RecoveryIntentContained,
		map[string]any{"containment_generation": generation}, at)
}

func (t *sqliteTx) SetRecoveryIntentVerifiedEmpty(ctx context.Context, workspaceID, idempotencyKey string, at time.Time) error {
	return transitionRecoveryIntent(ctx, t.tx, workspaceID, idempotencyKey, RecoveryIntentContained, RecoveryIntentVerifiedEmpty,
		nil, at)
}

func (t *sqliteTx) SetRecoveryIntentCompleted(ctx context.Context, workspaceID, idempotencyKey, eventID string, revokedSessions, containedMissions int, bootstrapExpiresAt, at time.Time) error {
	return transitionRecoveryIntent(ctx, t.tx, workspaceID, idempotencyKey, RecoveryIntentVerifiedEmpty, RecoveryIntentCompleted,
		map[string]any{
			"recovery_event_id":       eventID,
			"revoked_session_count":   revokedSessions,
			"contained_mission_count": containedMissions,
			"bootstrap_expires_at":    formatTime(bootstrapExpiresAt),
		}, at)
}

func (t *sqliteTx) PutRecoveryEvent(ctx context.Context, rec RecoveryEventRecord) error {
	return putRecoveryEvent(ctx, t.tx, rec)
}

func (t *sqliteTx) GetRecoveryEvent(ctx context.Context, workspaceID, eventID string) (RecoveryEventRecord, error) {
	return getRecoveryEvent(ctx, t.tx, workspaceID, eventID)
}

func (t *sqliteTx) GetWorkerLease(ctx context.Context, instanceID string) (WorkerLeaseRecord, error) {
	return getWorkerLease(ctx, t.tx, instanceID)
}

func (t *sqliteTx) RevokeAllSessions(ctx context.Context, workspaceID string) (int, error) {
	return revokeAllSessions(ctx, t.tx, workspaceID)
}

func (t *sqliteTx) ResetLaunchHandoffs(ctx context.Context, workspaceID string) error {
	return resetLaunchHandoffs(ctx, t.tx, workspaceID)
}

func (t *sqliteTx) DeleteAllWebAuthnCredentials(ctx context.Context, workspaceID string) (int, error) {
	return deleteAllWebAuthnCredentials(ctx, t.tx, workspaceID)
}

func (t *sqliteTx) ConsumeOfflineRecoveryKey(ctx context.Context, workspaceID, founderID string) error {
	return consumeOfflineRecoveryKey(ctx, t.tx, workspaceID, founderID)
}

func (t *sqliteTx) DeleteFounder(ctx context.Context, workspaceID, founderID string) error {
	return deleteFounder(ctx, t.tx, workspaceID, founderID)
}

func putRecoveryIntent(ctx context.Context, c dbConn, rec RecoveryIntentRecord) error {
	if rec.WorkspaceID == "" || rec.IdempotencyKey == "" || rec.IntentID == "" {
		return fmt.Errorf("store: put recovery intent: workspace, idempotency key, and intent IDs are required")
	}
	if rec.CanonicalDigest == "" || rec.Nonce == "" {
		return fmt.Errorf("store: put recovery intent: canonical digest and nonce are required")
	}
	if rec.State != RecoveryIntentPending {
		return fmt.Errorf("store: put recovery intent: new intents must be %q", RecoveryIntentPending)
	}
	_, err := c.ExecContext(ctx, `INSERT INTO recovery_intents
		(workspace_id, idempotency_key, intent_id, canonical_digest, attestation_digest,
		 nonce, state, containment_generation, recovery_event_id,
		 revoked_session_count, contained_mission_count, bootstrap_expires_at,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', 0, 0, '', ?, ?)`,
		rec.WorkspaceID, rec.IdempotencyKey, rec.IntentID, rec.CanonicalDigest,
		rec.AttestationDigest, rec.Nonce, rec.State,
		formatTime(rec.CreatedAt), formatTime(rec.UpdatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: recovery intent already exists", ErrConflict)
		}
		return fmt.Errorf("store: put recovery intent: %w", err)
	}
	return nil
}

func scanRecoveryIntent(row *sql.Row) (RecoveryIntentRecord, error) {
	var rec RecoveryIntentRecord
	var created, updated, bootstrapExpires string
	var generation int64
	var revoked, contained int64
	err := row.Scan(&rec.WorkspaceID, &rec.IdempotencyKey, &rec.IntentID,
		&rec.CanonicalDigest, &rec.AttestationDigest, &rec.Nonce, &rec.State,
		&generation, &rec.RecoveryEventID, &revoked, &contained,
		&bootstrapExpires, &created, &updated)
	if err != nil {
		return RecoveryIntentRecord{}, err
	}
	rec.ContainmentGeneration = generation
	rec.RevokedSessionCount = int(revoked)
	rec.ContainedMissionCount = int(contained)
	if bootstrapExpires != "" {
		if rec.BootstrapExpiresAt, err = parseTime(bootstrapExpires); err != nil {
			return RecoveryIntentRecord{}, fmt.Errorf("store: get recovery intent: %w", err)
		}
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return RecoveryIntentRecord{}, fmt.Errorf("store: get recovery intent: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return RecoveryIntentRecord{}, fmt.Errorf("store: get recovery intent: %w", err)
	}
	return rec, nil
}

func getRecoveryIntent(ctx context.Context, c dbConn, workspaceID, idempotencyKey string) (RecoveryIntentRecord, error) {
	rec, err := scanRecoveryIntent(c.QueryRowContext(ctx, `SELECT workspace_id, idempotency_key, intent_id,
		canonical_digest, attestation_digest, nonce, state, containment_generation,
		recovery_event_id, revoked_session_count, contained_mission_count,
		bootstrap_expires_at, created_at, updated_at
		FROM recovery_intents WHERE workspace_id = ? AND idempotency_key = ?`,
		workspaceID, idempotencyKey))
	if err == sql.ErrNoRows {
		return RecoveryIntentRecord{}, fmt.Errorf("%w: recovery intent", ErrNotFound)
	}
	if err != nil {
		return RecoveryIntentRecord{}, fmt.Errorf("store: get recovery intent: %w", err)
	}
	return rec, nil
}

// transitionRecoveryIntent moves an intent from exactly one expected state
// to the next, applying extra column updates. It affects exactly one row;
// any other current state returns ErrConflict, so concurrent or replayed
// transitions fail closed instead of skipping a step.
func transitionRecoveryIntent(ctx context.Context, c dbConn, workspaceID, idempotencyKey, fromState, toState string, extra map[string]any, at time.Time) error {
	setClauses := []string{"state = ?", "updated_at = ?"}
	args := []any{toState, formatTime(at)}
	for _, col := range []string{"attestation_digest", "containment_generation", "recovery_event_id", "revoked_session_count", "contained_mission_count", "bootstrap_expires_at"} {
		if v, ok := extra[col]; ok {
			setClauses = append(setClauses, col+" = ?")
			args = append(args, v)
		}
	}
	args = append(args, workspaceID, idempotencyKey, fromState)
	query := `UPDATE recovery_intents SET ` + joinClauses(setClauses) + ` WHERE workspace_id = ? AND idempotency_key = ? AND state = ?`
	res, err := c.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("store: transition recovery intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: transition recovery intent: %w", err)
	}
	if n == 1 {
		return nil
	}
	_, gerr := getRecoveryIntent(ctx, c, workspaceID, idempotencyKey)
	if gerr != nil {
		return gerr
	}
	return fmt.Errorf("%w: recovery intent is not %q", ErrConflict, fromState)
}

func joinClauses(clauses []string) string {
	out := ""
	for i, cl := range clauses {
		if i > 0 {
			out += ", "
		}
		out += cl
	}
	return out
}

func putRecoveryEvent(ctx context.Context, c dbConn, rec RecoveryEventRecord) error {
	if rec.WorkspaceID == "" || rec.EventID == "" || rec.FounderID == "" {
		return fmt.Errorf("store: put recovery event: workspace, event, and founder IDs are required")
	}
	if rec.AttestationDigest == "" || rec.RecoveryProofDigest == "" || rec.BootstrapCodeHash == "" {
		return fmt.Errorf("store: put recovery event: attestation, proof, and bootstrap digests are required")
	}
	_, err := c.ExecContext(ctx, `INSERT INTO recovery_events
		(workspace_id, event_id, founder_id, idempotency_key,
		 contained_mission_count, containment_generation,
		 attestation_digest, recovery_proof_digest, bootstrap_code_hash, occurred_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.EventID, rec.FounderID, rec.IdempotencyKey,
		rec.ContainedMissionCount, rec.ContainmentGeneration,
		rec.AttestationDigest, rec.RecoveryProofDigest, rec.BootstrapCodeHash,
		formatTime(rec.OccurredAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: recovery event already recorded", ErrConflict)
		}
		return fmt.Errorf("store: put recovery event: %w", err)
	}
	return nil
}

func getRecoveryEvent(ctx context.Context, c dbConn, workspaceID, eventID string) (RecoveryEventRecord, error) {
	var rec RecoveryEventRecord
	var occurred string
	var generation int64
	err := c.QueryRowContext(ctx, `SELECT workspace_id, event_id, founder_id, idempotency_key,
		contained_mission_count, containment_generation,
		attestation_digest, recovery_proof_digest, bootstrap_code_hash, occurred_at
		FROM recovery_events WHERE workspace_id = ? AND event_id = ?`,
		workspaceID, eventID).
		Scan(&rec.WorkspaceID, &rec.EventID, &rec.FounderID, &rec.IdempotencyKey,
			&rec.ContainedMissionCount, &generation,
			&rec.AttestationDigest, &rec.RecoveryProofDigest, &rec.BootstrapCodeHash, &occurred)
	if err == sql.ErrNoRows {
		return RecoveryEventRecord{}, fmt.Errorf("%w: recovery event", ErrNotFound)
	}
	if err != nil {
		return RecoveryEventRecord{}, fmt.Errorf("store: get recovery event: %w", err)
	}
	rec.ContainmentGeneration = generation
	if rec.OccurredAt, err = parseTime(occurred); err != nil {
		return RecoveryEventRecord{}, fmt.Errorf("store: get recovery event: %w", err)
	}
	return rec, nil
}

func getWorkerLease(ctx context.Context, c dbConn, instanceID string) (WorkerLeaseRecord, error) {
	var rec WorkerLeaseRecord
	var heartbeat, expires string
	err := c.QueryRowContext(ctx, `SELECT instance_id, owner, heartbeat_at, expires_at
		FROM worker_leases WHERE instance_id = ?`, instanceID).
		Scan(&rec.InstanceID, &rec.Owner, &heartbeat, &expires)
	if err == sql.ErrNoRows {
		return WorkerLeaseRecord{}, fmt.Errorf("%w: worker lease", ErrNotFound)
	}
	if err != nil {
		return WorkerLeaseRecord{}, fmt.Errorf("store: get worker lease: %w", err)
	}
	if rec.HeartbeatAt, err = parseTime(heartbeat); err != nil {
		return WorkerLeaseRecord{}, fmt.Errorf("store: get worker lease: %w", err)
	}
	if rec.ExpiresAt, err = parseTime(expires); err != nil {
		return WorkerLeaseRecord{}, fmt.Errorf("store: get worker lease: %w", err)
	}
	return rec, nil
}

// revokeAllSessions marks every unrevoked web session of a workspace
// revoked and returns the revoked count.
func revokeAllSessions(ctx context.Context, c dbConn, workspaceID string) (int, error) {
	res, err := c.ExecContext(ctx, `UPDATE sessions SET revoked = 1
		WHERE workspace_id = ? AND revoked = 0`, workspaceID)
	if err != nil {
		return 0, fmt.Errorf("store: revoke all sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: revoke all sessions: %w", err)
	}
	return int(n), nil
}

// resetLaunchHandoffs deletes every one-use CLI authorization, CLI
// revocation, and launch-exchange intent row of a workspace. After an
// offline recovery these handoffs are invalid and never resume.
func resetLaunchHandoffs(ctx context.Context, c dbConn, workspaceID string) error {
	for _, table := range []string{"cli_authorizations", "cli_revocations", "launch_exchange_intents"} {
		if _, err := c.ExecContext(ctx, `DELETE FROM `+table+` WHERE workspace_id = ?`, workspaceID); err != nil {
			return fmt.Errorf("store: reset launch handoffs: %w", err)
		}
	}
	return nil
}

// deleteAllWebAuthnCredentials deletes every passkey public credential of
// a workspace and returns the deleted count.
func deleteAllWebAuthnCredentials(ctx context.Context, c dbConn, workspaceID string) (int, error) {
	res, err := c.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE workspace_id = ?`, workspaceID)
	if err != nil {
		return 0, fmt.Errorf("store: delete passkey credentials: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete passkey credentials: %w", err)
	}
	return int(n), nil
}

// deleteFounder removes a founder row. Offline recovery calls it after
// revoking the founder's sessions and deleting their credentials, so
// the fresh bootstrap code can re-enroll the workspace.
func deleteFounder(ctx context.Context, c dbConn, workspaceID, founderID string) error {
	res, err := c.ExecContext(ctx, `DELETE FROM founders WHERE workspace_id = ? AND founder_id = ?`,
		workspaceID, founderID)
	if err != nil {
		return fmt.Errorf("store: delete founder: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete founder: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: founder", ErrNotFound)
	}
	return nil
}

// The key is one-use: recovery consumes it in the same transaction that
// resets authentication state, and enrollment of a replacement recovery
// method happens through the fresh bootstrap code.
// consumeOfflineRecoveryKey deletes a founder's offline recovery key
// hash. The key is one-use: recovery consumes it in the same
// transaction that resets authentication state.
func consumeOfflineRecoveryKey(ctx context.Context, c dbConn, workspaceID, founderID string) error {
	res, err := c.ExecContext(ctx, `DELETE FROM offline_recovery_keys
		WHERE workspace_id = ? AND founder_id = ?`, workspaceID, founderID)
	if err != nil {
		return fmt.Errorf("store: consume recovery key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: consume recovery key: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: offline recovery key", ErrNotFound)
	}
	return nil
}
