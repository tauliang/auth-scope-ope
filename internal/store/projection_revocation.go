// Durable event-projection state, worker leases, revocation intents, and
// CLI revocation handoffs. Task 10 adds these rows alongside the existing
// mission pass and event tables; the store intentionally only ever holds
// allowlisted SafeEvent fields, never prompts, patches, issue bodies,
// transcripts, URLs, email addresses, or credentials.
package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"
)

func (t *sqliteTx) AdvanceProjection(ctx context.Context, workspaceID, passID, pageCursor string, eventSeq, missionVersion int64) error {
	return advanceProjection(ctx, t.tx, workspaceID, passID, pageCursor, eventSeq, missionVersion)
}

func (t *sqliteTx) AdvanceProjectionCursor(ctx context.Context, workspaceID, passID, pageCursor string) error {
	return advanceProjectionCursor(ctx, t.tx, workspaceID, passID, pageCursor)
}

func (t *sqliteTx) GetMissionProjection(ctx context.Context, workspaceID, passID string) (MissionProjection, error) {
	return getMissionProjection(ctx, t.tx, workspaceID, passID)
}

func (t *sqliteTx) ListMissionEvents(ctx context.Context, workspaceID, passID, afterCursor string, limit int) ([]MissionEventRecord, error) {
	return listMissionEvents(ctx, t.tx, workspaceID, passID, afterCursor, limit)
}

func (t *sqliteTx) MarkProjectionIncompatible(ctx context.Context, workspaceID, passID, reason string) error {
	return markProjectionIncompatible(ctx, t.tx, workspaceID, passID, reason)
}

func (t *sqliteTx) MarkProjectionCompatible(ctx context.Context, workspaceID, passID string) error {
	return markProjectionCompatible(ctx, t.tx, workspaceID, passID)
}

func (s *sqliteStore) GetMissionProjection(ctx context.Context, workspaceID, passID string) (MissionProjection, error) {
	return getMissionProjection(ctx, s.db, workspaceID, passID)
}

func (s *sqliteStore) ListMissionPasses(ctx context.Context, workspaceID string) ([]MissionPassRecord, error) {
	return listMissionPasses(ctx, s.db, workspaceID)
}

func (t *sqliteTx) AcquireWorkerLease(ctx context.Context, instanceID, owner string, ttl time.Duration) (bool, error) {
	return acquireWorkerLease(ctx, t.tx, instanceID, owner, ttl)
}

func (t *sqliteTx) HeartbeatWorkerLease(ctx context.Context, instanceID, owner string, ttl time.Duration) (bool, error) {
	return heartbeatWorkerLease(ctx, t.tx, instanceID, owner, ttl)
}

func (t *sqliteTx) ReleaseWorkerLease(ctx context.Context, instanceID, owner string) error {
	return releaseWorkerLease(ctx, t.tx, instanceID, owner)
}

func (t *sqliteTx) PutRevocationIntent(ctx context.Context, rec RevocationIntentRecord) error {
	return putRevocationIntent(ctx, t.tx, rec)
}

func (t *sqliteTx) GetRevocationIntent(ctx context.Context, workspaceID, passID string) (RevocationIntentRecord, error) {
	return getRevocationIntent(ctx, t.tx, workspaceID, passID)
}

func (t *sqliteTx) CompleteRevocationIntent(ctx context.Context, workspaceID, passID, containment, upstreamRef string) error {
	return completeRevocationIntent(ctx, t.tx, workspaceID, passID, containment, upstreamRef)
}

func (s *sqliteStore) ListRevocationIntents(ctx context.Context, workspaceID, state string) ([]RevocationIntentRecord, error) {
	return listRevocationIntents(ctx, s.db, workspaceID, state)
}

func (t *sqliteTx) PutCLIRevocation(ctx context.Context, rec CLIRevocation) error {
	return putCLIRevocation(ctx, t.tx, rec)
}

func (t *sqliteTx) MintCLIRevocationResult(ctx context.Context, workspaceID, requestID, resultRef, containment string, codeHash [32]byte, now time.Time) error {
	return mintCLIRevocationResult(ctx, t.tx, workspaceID, requestID, resultRef, containment, codeHash, now)
}

func (t *sqliteTx) ConsumeCLIRevocationResult(ctx context.Context, workspaceID string, codeHash [32]byte, now time.Time) (string, string, error) {
	return consumeCLIRevocationResult(ctx, t.tx, workspaceID, codeHash, now)
}

func (s *sqliteStore) GetCLIRevocation(ctx context.Context, workspaceID, requestID string) (CLIRevocation, error) {
	return getCLIRevocation(ctx, s.db, workspaceID, requestID)
}

func (s *sqliteStore) GetCLIRevocationByState(ctx context.Context, workspaceID, passID, state string) (CLIRevocation, error) {
	return getCLIRevocationByState(ctx, s.db, workspaceID, passID, state)
}

func (s *sqliteStore) GetCLIRevocationByCodeHash(ctx context.Context, workspaceID string, codeHash [32]byte) (CLIRevocation, error) {
	return getCLIRevocationByCodeHash(ctx, s.db, workspaceID, codeHash)
}

// advanceProjection records projection progress after a page: the
// authority page cursor moves forward only, the local event sequence and
// projected mission version move upward only, and the projection stays
// marked compatible. It upserts the projection row.
func advanceProjection(ctx context.Context, c dbConn, workspaceID, passID, pageCursor string, eventSeq, missionVersion int64) error {
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE mission_projections
		SET cursor = CASE WHEN cursor < ? THEN ? ELSE cursor END,
		    event_seq = CASE WHEN event_seq < ? THEN ? ELSE event_seq END,
		    mission_version = CASE WHEN mission_version < ? THEN ? ELSE mission_version END,
		    compatible = 1, stale = 0, updated_at = ?
		WHERE workspace_id = ? AND pass_id = ?`,
		pageCursor, pageCursor, eventSeq, eventSeq, missionVersion, missionVersion, now,
		workspaceID, passID)
	if err != nil {
		return fmt.Errorf("store: advance projection: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: advance projection: %w", err)
	} else if n == 1 {
		return nil
	}
	_, err = c.ExecContext(ctx, `INSERT INTO mission_projections
		(workspace_id, pass_id, cursor, event_seq, mission_version, compatible, stale,
		 incompatibility_reason, updated_at)
		VALUES (?, ?, ?, ?, ?, 1, 0, '', ?)`,
		workspaceID, passID, pageCursor, eventSeq, missionVersion, now)
	if err != nil {
		if isUniqueViolation(err) {
			// A concurrent page won the insert; retry the update once.
			return advanceProjection(ctx, c, workspaceID, passID, pageCursor, eventSeq, missionVersion)
		}
		return fmt.Errorf("store: insert projection: %w", err)
	}
	return nil
}

// advanceProjectionCursor moves the authority page cursor forward without
// storing an event, for pages that carry no new events.
func advanceProjectionCursor(ctx context.Context, c dbConn, workspaceID, passID, pageCursor string) error {
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE mission_projections
		SET cursor = ?, compatible = 1, stale = 0, updated_at = ?
		WHERE workspace_id = ? AND pass_id = ? AND cursor < ?`,
		pageCursor, now, workspaceID, passID, pageCursor)
	if err != nil {
		return fmt.Errorf("store: advance projection cursor: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: advance projection cursor: %w", err)
	} else if n == 1 {
		return nil
	}
	var existing string
	err = c.QueryRowContext(ctx, `SELECT cursor FROM mission_projections
		WHERE workspace_id = ? AND pass_id = ?`, workspaceID, passID).Scan(&existing)
	switch {
	case err == sql.ErrNoRows:
		_, err = c.ExecContext(ctx, `INSERT INTO mission_projections
			(workspace_id, pass_id, cursor, event_seq, mission_version, compatible, stale,
			 incompatibility_reason, updated_at)
			VALUES (?, ?, ?, 0, 0, 1, 0, '', ?)`, workspaceID, passID, pageCursor, now)
		if err != nil {
			return fmt.Errorf("store: insert projection cursor: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("store: read projection cursor: %w", err)
	default:
		return nil
	}
}

// markProjectionIncompatible records the fixed local reason for an
// unknown authenticated event type. The payload is never stored, the
// cursor stays unchanged, and the projection is marked incompatible and
// stale so business mutations fail closed until a parser and
// pinned-contract upgrade replays from the unchanged cursor.
func markProjectionIncompatible(ctx context.Context, c dbConn, workspaceID, passID, reason string) error {
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE mission_projections
		SET compatible = 0, stale = 1, incompatibility_reason = ?, updated_at = ?
		WHERE workspace_id = ? AND pass_id = ?`, reason, now, workspaceID, passID)
	if err != nil {
		return fmt.Errorf("store: mark projection incompatible: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: mark projection incompatible: %w", err)
	} else if n == 1 {
		return nil
	}
	_, err = c.ExecContext(ctx, `INSERT INTO mission_projections
		(workspace_id, pass_id, cursor, compatible, stale, incompatibility_reason, updated_at)
		VALUES (?, ?, '', 0, 1, ?, ?)`, workspaceID, passID, reason, now)
	if err != nil {
		if isUniqueViolation(err) {
			// A concurrent mark won; keep the row it wrote.
			return nil
		}
		return fmt.Errorf("store: mark projection incompatible: %w", err)
	}
	return nil
}

// markProjectionCompatible clears the incompatibility gate after a
// parser and pinned-contract upgrade, leaving the cursor exactly where
// the unknown event stopped it so replay resumes from that point.
func markProjectionCompatible(ctx context.Context, c dbConn, workspaceID, passID string) error {
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE mission_projections
		SET compatible = 1, stale = 0, incompatibility_reason = '', updated_at = ?
		WHERE workspace_id = ? AND pass_id = ?`, now, workspaceID, passID)
	if err != nil {
		return fmt.Errorf("store: mark projection compatible: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: mark projection compatible: %w", err)
	} else if n == 1 {
		return nil
	}
	return fmt.Errorf("%w: mission projection %q", ErrNotFound, passID)
}

func getMissionProjection(ctx context.Context, c dbConn, workspaceID, passID string) (MissionProjection, error) {
	var rec MissionProjection
	var compatible, stale int
	var updated string
	err := c.QueryRowContext(ctx, `SELECT workspace_id, pass_id, cursor, event_seq, mission_version,
			compatible, stale, incompatibility_reason, updated_at
		FROM mission_projections WHERE workspace_id = ? AND pass_id = ?`,
		workspaceID, passID).Scan(&rec.WorkspaceID, &rec.PassID, &rec.Cursor,
		&rec.EventSeq, &rec.MissionVersion,
		&compatible, &stale, &rec.IncompatibilityReason, &updated)
	if err == sql.ErrNoRows {
		return MissionProjection{}, fmt.Errorf("%w: mission projection %q", ErrNotFound, passID)
	}
	if err != nil {
		return MissionProjection{}, fmt.Errorf("store: get mission projection: %w", err)
	}
	rec.Compatible = compatible != 0
	rec.Stale = stale != 0
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return MissionProjection{}, fmt.Errorf("store: get mission projection: %w", err)
	}
	return rec, nil
}

func listMissionPasses(ctx context.Context, c dbConn, workspaceID string) ([]MissionPassRecord, error) {
	rows, err := c.QueryContext(ctx, `SELECT `+missionPassColumns+`
		FROM mission_passes WHERE workspace_id = ? ORDER BY created_at ASC, pass_id ASC`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("store: list mission passes: %w", err)
	}
	defer rows.Close()
	var out []MissionPassRecord
	for rows.Next() {
		var rec MissionPassRecord
		var runnerArgs, criteria, expires, receiptPending, created, updated string
		if err := rows.Scan(&rec.WorkspaceID, &rec.PassID, &rec.StoreRevision, &rec.DraftVersion,
			&rec.AuthScopeMissionVersion, &rec.ConnectionID, &rec.IssueNumber, &rec.RepositoryName,
			&rec.ProposalID, &rec.ProposalDigest, &rec.ApprovedProposalDigest,
			&rec.SourceRevision, &rec.SourceDigest, &rec.BaseSHA, &rec.MissionBranch,
			&rec.AgentKitID, &rec.AgentKitVersion, &runnerArgs, &rec.InvocationDigest,
			&expires, &rec.MaxAggregateCostMicros, &rec.Objective, &criteria,
			&rec.ShapedDraftJSON, &rec.State, &rec.Reconciliation,
			&rec.MissionRef, &rec.MissionHash, &rec.ApprovalDecisionRef,
			&rec.AttestationDigest, &rec.RunID, &rec.Containment, &receiptPending, &created, &updated); err != nil {
			return nil, fmt.Errorf("store: list mission passes: %w", err)
		}
		if rec.RunnerArguments, err = decodeStringSlice(runnerArgs); err != nil {
			return nil, fmt.Errorf("store: list mission passes: %w", err)
		}
		if rec.AcceptanceCriteria, err = decodeStringSlice(criteria); err != nil {
			return nil, fmt.Errorf("store: list mission passes: %w", err)
		}
		if rec.ExpiresAt, err = parseOptionalTime(expires); err != nil {
			return nil, fmt.Errorf("store: list mission passes: %w", err)
		}
		if rec.ReceiptPendingAt, err = parseOptionalTime(receiptPending); err != nil {
			return nil, fmt.Errorf("store: list mission passes: %w", err)
		}
		if rec.CreatedAt, err = parseTime(created); err != nil {
			return nil, fmt.Errorf("store: list mission passes: %w", err)
		}
		if rec.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, fmt.Errorf("store: list mission passes: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list mission passes: %w", err)
	}
	return out, nil
}

// acquireWorkerLease takes the instance worker lease for owner when no
// live lease exists. A second process cannot own the lease while the
// first heartbeats.
func acquireWorkerLease(ctx context.Context, c dbConn, instanceID, owner string, ttl time.Duration) (bool, error) {
	now := time.Now()
	res, err := c.ExecContext(ctx, `UPDATE worker_leases
		SET owner = ?, heartbeat_at = ?, expires_at = ?
		WHERE instance_id = ? AND (owner = ? OR expires_at <= ?)`,
		owner, formatTime(now), formatTime(now.Add(ttl)), instanceID, owner, formatTime(now))
	if err != nil {
		return false, fmt.Errorf("store: acquire worker lease: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return false, fmt.Errorf("store: acquire worker lease: %w", err)
	} else if n == 1 {
		return true, nil
	}
	_, err = c.ExecContext(ctx, `INSERT INTO worker_leases
		(instance_id, owner, heartbeat_at, expires_at)
		VALUES (?, ?, ?, ?)`, instanceID, owner, formatTime(now), formatTime(now.Add(ttl)))
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil
		}
		return false, fmt.Errorf("store: acquire worker lease: %w", err)
	}
	return true, nil
}

// heartbeatWorkerLease renews the lease only when owner still holds it.
func heartbeatWorkerLease(ctx context.Context, c dbConn, instanceID, owner string, ttl time.Duration) (bool, error) {
	now := time.Now()
	res, err := c.ExecContext(ctx, `UPDATE worker_leases
		SET heartbeat_at = ?, expires_at = ?
		WHERE instance_id = ? AND owner = ? AND expires_at > ?`,
		formatTime(now), formatTime(now.Add(ttl)), instanceID, owner, formatTime(now))
	if err != nil {
		return false, fmt.Errorf("store: heartbeat worker lease: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: heartbeat worker lease: %w", err)
	}
	return n == 1, nil
}

// releaseWorkerLease drops the lease only when owner still holds it.
func releaseWorkerLease(ctx context.Context, c dbConn, instanceID, owner string) error {
	_, err := c.ExecContext(ctx, `DELETE FROM worker_leases
		WHERE instance_id = ? AND owner = ?`, instanceID, owner)
	if err != nil {
		return fmt.Errorf("store: release worker lease: %w", err)
	}
	return nil
}

func putRevocationIntent(ctx context.Context, c dbConn, rec RevocationIntentRecord) error {
	if rec.WorkspaceID == "" || rec.PassID == "" || rec.IdempotencyKey == "" {
		return fmt.Errorf("store: put revocation intent: workspace, pass, and idempotency key are required")
	}
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE revocation_intents
		SET idempotency_key = ?, reason_code = ?, canonical_digest = ?,
		    state = ?, containment = ?, attestation_digest = ?, attestation_json = ?,
		    upstream_ref = ?, updated_at = ?
		WHERE workspace_id = ? AND pass_id = ? AND state <> ?`,
		rec.IdempotencyKey, rec.ReasonCode, rec.CanonicalDigest,
		revocationIntentState(rec.State), rec.Containment, rec.AttestationDigest, rec.AttestationJSON,
		rec.UpstreamRef, now, rec.WorkspaceID, rec.PassID, RevocationIntentCompleted)
	if err != nil {
		return fmt.Errorf("store: put revocation intent: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: put revocation intent: %w", err)
	} else if n == 1 {
		return nil
	}
	_, err = c.ExecContext(ctx, `INSERT INTO revocation_intents
		(workspace_id, pass_id, idempotency_key, reason_code, canonical_digest,
		 state, containment, attestation_digest, attestation_json, upstream_ref,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.PassID, rec.IdempotencyKey, rec.ReasonCode, rec.CanonicalDigest,
		revocationIntentState(rec.State), rec.Containment, rec.AttestationDigest, rec.AttestationJSON,
		rec.UpstreamRef, now, now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: revocation intent already exists", ErrConflict)
		}
		return fmt.Errorf("store: put revocation intent: %w", err)
	}
	return nil
}

func revocationIntentState(state string) string {
	if state == "" {
		return RevocationIntentInFlight
	}
	return state
}

func getRevocationIntent(ctx context.Context, c dbConn, workspaceID, passID string) (RevocationIntentRecord, error) {
	var rec RevocationIntentRecord
	var created, updated string
	err := c.QueryRowContext(ctx, `SELECT workspace_id, pass_id, idempotency_key, reason_code,
			canonical_digest, state, containment, attestation_digest, attestation_json,
			upstream_ref, created_at, updated_at
		FROM revocation_intents WHERE workspace_id = ? AND pass_id = ?`,
		workspaceID, passID).Scan(&rec.WorkspaceID, &rec.PassID, &rec.IdempotencyKey,
		&rec.ReasonCode, &rec.CanonicalDigest, &rec.State, &rec.Containment,
		&rec.AttestationDigest, &rec.AttestationJSON, &rec.UpstreamRef, &created, &updated)
	if err == sql.ErrNoRows {
		return RevocationIntentRecord{}, fmt.Errorf("%w: revocation intent %q", ErrNotFound, passID)
	}
	if err != nil {
		return RevocationIntentRecord{}, fmt.Errorf("store: get revocation intent: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return RevocationIntentRecord{}, fmt.Errorf("store: get revocation intent: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return RevocationIntentRecord{}, fmt.Errorf("store: get revocation intent: %w", err)
	}
	return rec, nil
}

// listRevocationIntents returns the intents of a workspace in the given
// state, oldest first.
func listRevocationIntents(ctx context.Context, c dbConn, workspaceID, state string) ([]RevocationIntentRecord, error) {
	rows, err := c.QueryContext(ctx, `SELECT workspace_id, pass_id, idempotency_key, reason_code,
			canonical_digest, state, containment, attestation_digest, attestation_json,
			upstream_ref, created_at, updated_at
		FROM revocation_intents WHERE workspace_id = ? AND state = ?
		ORDER BY created_at ASC`,
		workspaceID, state)
	if err != nil {
		return nil, fmt.Errorf("store: list revocation intents: %w", err)
	}
	defer rows.Close()
	var out []RevocationIntentRecord
	for rows.Next() {
		var rec RevocationIntentRecord
		var created, updated string
		if err := rows.Scan(&rec.WorkspaceID, &rec.PassID, &rec.IdempotencyKey,
			&rec.ReasonCode, &rec.CanonicalDigest, &rec.State, &rec.Containment,
			&rec.AttestationDigest, &rec.AttestationJSON, &rec.UpstreamRef, &created, &updated); err != nil {
			return nil, fmt.Errorf("store: list revocation intents: %w", err)
		}
		if rec.CreatedAt, err = parseTime(created); err != nil {
			return nil, fmt.Errorf("store: list revocation intents: %w", err)
		}
		if rec.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, fmt.Errorf("store: list revocation intents: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list revocation intents: %w", err)
	}
	return out, nil
}

// completeRevocationIntent moves the intent to completed with the
// containment state and upstream reference. It never rewrites a
// completed intent.
func completeRevocationIntent(ctx context.Context, c dbConn, workspaceID, passID, containment, upstreamRef string) error {
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE revocation_intents
		SET state = ?, containment = ?, upstream_ref = ?, updated_at = ?
		WHERE workspace_id = ? AND pass_id = ? AND state <> ?`,
		RevocationIntentCompleted, containment, upstreamRef, now, workspaceID, passID, RevocationIntentCompleted)
	if err != nil {
		return fmt.Errorf("store: complete revocation intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: complete revocation intent: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: revocation intent %q already completed or missing", ErrConflict, passID)
	}
	return nil
}

func putCLIRevocation(ctx context.Context, c dbConn, rec CLIRevocation) error {
	if rec.WorkspaceID == "" || rec.RequestID == "" || rec.PassID == "" {
		return fmt.Errorf("store: put CLI revocation: workspace, request, and pass IDs are required")
	}
	now := formatTime(time.Now())
	_, err := c.ExecContext(ctx, `INSERT INTO cli_revocations
		(workspace_id, request_id, pass_id, state, code_challenge, redirect_uri,
		 canonical_digest, reason_code, result_ref, result_containment, code_hash,
		 result_consumed_at, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', ?, ?)`,
		rec.WorkspaceID, rec.RequestID, rec.PassID, rec.State, rec.CodeChallenge, rec.RedirectURI,
		rec.CanonicalDigest, rec.ReasonCode, formatTime(rec.ExpiresAt), now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: CLI revocation request already exists", ErrConflict)
		}
		return fmt.Errorf("store: put CLI revocation: %w", err)
	}
	return nil
}

// mintCLIRevocationResult records the one-use result code hash, the
// opaque result reference, and the fixed containment state. It affects
// exactly one unminted row, so a duplicate mint is a conflict.
func mintCLIRevocationResult(ctx context.Context, c dbConn, workspaceID, requestID, resultRef, containment string, codeHash [32]byte, now time.Time) error {
	res, err := c.ExecContext(ctx, `UPDATE cli_revocations
		SET result_ref = ?, result_containment = ?, code_hash = ?
		WHERE workspace_id = ? AND request_id = ? AND result_ref = ''`,
		resultRef, containment, hex.EncodeToString(codeHash[:]), workspaceID, requestID)
	if err != nil {
		return fmt.Errorf("store: mint CLI revocation result: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: mint CLI revocation result: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: CLI revocation request missing or already minted", ErrConflict)
	}
	return nil
}

// consumeCLIRevocationResult atomically marks a minted result consumed
// and returns the original opaque reference. An identical retry after a
// lost response returns only the original reference; it never mints a
// second result.
func consumeCLIRevocationResult(ctx context.Context, c dbConn, workspaceID string, codeHash [32]byte, now time.Time) (string, string, error) {
	var rec CLIRevocation
	var err error
	runner, err := asTxRunner(c)
	if err != nil {
		return "", "", err
	}
	err = runner(ctx, func(tx dbConn) error {
		rec, err = getCLIRevocationByCodeHash(ctx, tx, workspaceID, codeHash)
		if err != nil {
			return err
		}
		if rec.ResultRef == "" {
			return fmt.Errorf("%w: CLI revocation result not minted", ErrNotFound)
		}
		if rec.ExpiresAt.Before(now) {
			return fmt.Errorf("%w: CLI revocation result expired", ErrConflict)
		}
		_, err = tx.ExecContext(ctx, `UPDATE cli_revocations
			SET result_consumed_at = ?
			WHERE workspace_id = ? AND request_id = ? AND code_hash = ?`,
			formatTime(now), workspaceID, rec.RequestID, hex.EncodeToString(codeHash[:]))
		if err != nil {
			return fmt.Errorf("store: consume CLI revocation result: %w", err)
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	return rec.ResultRef, rec.ResultContainment, nil
}

const cliRevocationColumns = `workspace_id, request_id, pass_id, state, code_challenge,
	redirect_uri, canonical_digest, reason_code, result_ref, result_containment, code_hash,
	result_consumed_at, expires_at, created_at`

func getCLIRevocation(ctx context.Context, c dbConn, workspaceID, requestID string) (CLIRevocation, error) {
	var rec CLIRevocation
	var codeHash, consumedAt, expires, created string
	err := c.QueryRowContext(ctx, `SELECT `+cliRevocationColumns+`
		FROM cli_revocations WHERE workspace_id = ? AND request_id = ?`,
		workspaceID, requestID).Scan(&rec.WorkspaceID, &rec.RequestID, &rec.PassID,
		&rec.State, &rec.CodeChallenge, &rec.RedirectURI, &rec.CanonicalDigest, &rec.ReasonCode,
		&rec.ResultRef, &rec.ResultContainment, &codeHash, &consumedAt, &expires, &created)
	if err == sql.ErrNoRows {
		return CLIRevocation{}, fmt.Errorf("%w: CLI revocation request %q", ErrNotFound, requestID)
	}
	if err != nil {
		return CLIRevocation{}, fmt.Errorf("store: get CLI revocation: %w", err)
	}
	if err := scanCLIRevocation(&rec, codeHash, consumedAt, expires, created); err != nil {
		return CLIRevocation{}, err
	}
	return rec, nil
}

func getCLIRevocationByState(ctx context.Context, c dbConn, workspaceID, passID, state string) (CLIRevocation, error) {
	var rec CLIRevocation
	var codeHash, consumedAt, expires, created string
	err := c.QueryRowContext(ctx, `SELECT `+cliRevocationColumns+`
		FROM cli_revocations WHERE workspace_id = ? AND pass_id = ? AND state = ?
		ORDER BY created_at DESC LIMIT 1`,
		workspaceID, passID, state).Scan(&rec.WorkspaceID, &rec.RequestID, &rec.PassID,
		&rec.State, &rec.CodeChallenge, &rec.RedirectURI, &rec.CanonicalDigest, &rec.ReasonCode,
		&rec.ResultRef, &rec.ResultContainment, &codeHash, &consumedAt, &expires, &created)
	if err == sql.ErrNoRows {
		return CLIRevocation{}, fmt.Errorf("%w: CLI revocation request", ErrNotFound)
	}
	if err != nil {
		return CLIRevocation{}, fmt.Errorf("store: get CLI revocation by state: %w", err)
	}
	if err := scanCLIRevocation(&rec, codeHash, consumedAt, expires, created); err != nil {
		return CLIRevocation{}, err
	}
	return rec, nil
}

func getCLIRevocationByCodeHash(ctx context.Context, c dbConn, workspaceID string, codeHash [32]byte) (CLIRevocation, error) {
	var rec CLIRevocation
	var storedHash, consumedAt, expires, created string
	err := c.QueryRowContext(ctx, `SELECT `+cliRevocationColumns+`
		FROM cli_revocations WHERE workspace_id = ? AND code_hash = ?`,
		workspaceID, hex.EncodeToString(codeHash[:])).Scan(&rec.WorkspaceID, &rec.RequestID,
		&rec.PassID, &rec.State, &rec.CodeChallenge, &rec.RedirectURI, &rec.CanonicalDigest, &rec.ReasonCode,
		&rec.ResultRef, &rec.ResultContainment, &storedHash, &consumedAt, &expires, &created)
	if err == sql.ErrNoRows {
		return CLIRevocation{}, fmt.Errorf("%w: CLI revocation result", ErrNotFound)
	}
	if err != nil {
		return CLIRevocation{}, fmt.Errorf("store: get CLI revocation by code hash: %w", err)
	}
	if err := scanCLIRevocation(&rec, storedHash, consumedAt, expires, created); err != nil {
		return CLIRevocation{}, err
	}
	return rec, nil
}

func scanCLIRevocation(rec *CLIRevocation, codeHashHex, consumedAt, expires, created string) error {
	if codeHashHex != "" {
		raw, err := hex.DecodeString(codeHashHex)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("store: scan CLI revocation: corrupt code hash")
		}
		copy(rec.CodeHash[:], raw)
	}
	if consumedAt != "" {
		t, err := parseTime(consumedAt)
		if err != nil {
			return fmt.Errorf("store: scan CLI revocation: %w", err)
		}
		rec.ResultConsumedAt = &t
	}
	var err error
	if rec.ExpiresAt, err = parseTime(expires); err != nil {
		return fmt.Errorf("store: scan CLI revocation: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return fmt.Errorf("store: scan CLI revocation: %w", err)
	}
	return nil
}

// asTxRunner runs fn in a transaction when c is not already inside one.
// The event-cursor transaction needs atomicity for an idempotent event
// insert plus the projection advance.
func asTxRunner(c dbConn) (func(context.Context, func(dbConn) error) error, error) {
	switch conn := c.(type) {
	case *sql.Tx:
		return func(ctx context.Context, fn func(dbConn) error) error {
			return fn(conn)
		}, nil
	case *sql.DB:
		return func(ctx context.Context, fn func(dbConn) error) error {
			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				return fmt.Errorf("store: begin transaction: %w", err)
			}
			defer func() {
				_ = tx.Rollback()
			}()
			if err := fn(tx); err != nil {
				return err
			}
			if err := tx.Commit(); err != nil {
				return fmt.Errorf("store: commit transaction: %w", err)
			}
			return nil
		}, nil
	default:
		return nil, fmt.Errorf("store: transaction runner: unsupported connection %T", c)
	}
}
