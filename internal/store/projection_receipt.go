// Local receipt projections and durable check-publication intents.
// Task 12 adds these rows alongside the existing projection tables. The
// receipt_views table is the single source of truth the private receipt
// view reads: it holds the receipt digest and the fixed verified fields,
// never the raw signed envelope, issue bodies, logs, patches,
// transcripts, private detail URLs, or secrets. The
// check_publications table is the durable intent behind one GitHub
// check publication idempotency key.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (t *sqliteTx) PutReceiptView(ctx context.Context, rec ReceiptViewRecord) error {
	return putReceiptView(ctx, t.tx, rec)
}

func (t *sqliteTx) GetReceiptView(ctx context.Context, workspaceID, passID string) (ReceiptViewRecord, error) {
	return getReceiptView(ctx, t.tx, workspaceID, passID)
}

func (t *sqliteTx) PutCheckPublicationIfAbsent(ctx context.Context, rec CheckPublicationRecord) (bool, error) {
	return putCheckPublicationIfAbsent(ctx, t.tx, rec)
}

func (t *sqliteTx) GetCheckPublication(ctx context.Context, workspaceID, idempotencyKey string) (CheckPublicationRecord, error) {
	return getCheckPublication(ctx, t.tx, workspaceID, idempotencyKey)
}

func (t *sqliteTx) GetLatestCheckPublicationForPass(ctx context.Context, workspaceID, passID string) (CheckPublicationRecord, error) {
	return getLatestCheckPublicationForPass(ctx, t.tx, workspaceID, passID)
}

func (t *sqliteTx) ListCheckPublications(ctx context.Context, workspaceID, state string) ([]CheckPublicationRecord, error) {
	return listCheckPublications(ctx, t.tx, workspaceID, state)
}

func (t *sqliteTx) SetCheckPublicationState(ctx context.Context, workspaceID, idempotencyKey, state, checkRunID string, at time.Time) error {
	return setCheckPublicationState(ctx, t.tx, workspaceID, idempotencyKey, state, checkRunID, at)
}

func (t *sqliteTx) MarkCheckPublicationsDisputedExcept(ctx context.Context, workspaceID, passID, exceptKey string, at time.Time) error {
	return markCheckPublicationsDisputedExcept(ctx, t.tx, workspaceID, passID, exceptKey, at)
}

func (s *sqliteStore) GetReceiptView(ctx context.Context, workspaceID, passID string) (ReceiptViewRecord, error) {
	return getReceiptView(ctx, s.db, workspaceID, passID)
}

func (s *sqliteStore) GetLatestCheckPublicationForPass(ctx context.Context, workspaceID, passID string) (CheckPublicationRecord, error) {
	return getLatestCheckPublicationForPass(ctx, s.db, workspaceID, passID)
}

func (s *sqliteStore) ListCheckPublications(ctx context.Context, workspaceID, state string) ([]CheckPublicationRecord, error) {
	return listCheckPublications(ctx, s.db, workspaceID, state)
}

const receiptViewColumns = `workspace_id, pass_id, verification, reason_code,
	receipt_id, grant_id, mission_ref, key_id, signed_at, receipt_digest,
	settlement_digest, outcome,
	mission_versions_json, expansion_decision_refs_json,
	repository_id, issue_number, branch, pull_request_number, head_sha,
	checks_json, started_at, finished_at, aggregate_cost_micros,
	budget_micros, historical_enforcement_json, verified_at`

// putReceiptView upserts the verified receipt projection for a pass. A
// verified view never overwrites an unverifiable verdict recorded for a
// different receipt digest: that case is a dispute and must be
// surfaced, not silently replaced.
func putReceiptView(ctx context.Context, c dbConn, rec ReceiptViewRecord) error {
	if rec.WorkspaceID == "" || rec.PassID == "" || rec.Verification == "" {
		return fmt.Errorf("store: put receipt view: workspace, pass, and verification are required")
	}
	if rec.Verification != ReceiptVerified && rec.Verification != ReceiptUnverifiable {
		return fmt.Errorf("store: put receipt view: unknown verification %q", rec.Verification)
	}
	now := formatTime(rec.VerifiedAt)
	if rec.VerifiedAt.IsZero() {
		now = formatTime(time.Now())
	}
	res, err := c.ExecContext(ctx, `UPDATE receipt_views
		SET verification = ?, reason_code = ?, receipt_id = ?, grant_id = ?,
		    mission_ref = ?, key_id = ?, signed_at = ?, receipt_digest = ?,
		    settlement_digest = ?, outcome = ?,
		    mission_versions_json = ?, expansion_decision_refs_json = ?,
		    repository_id = ?, issue_number = ?, branch = ?, pull_request_number = ?, head_sha = ?,
		    checks_json = ?, started_at = ?, finished_at = ?, aggregate_cost_micros = ?,
		    budget_micros = ?, historical_enforcement_json = ?, verified_at = ?
		WHERE workspace_id = ? AND pass_id = ?
		  AND NOT (verification = ? AND receipt_digest <> ?)`,
		rec.Verification, rec.ReasonCode, rec.ReceiptID, rec.GrantID,
		rec.MissionRef, rec.KeyID, formatOptionalTime(rec.SignedAt), rec.ReceiptDigest,
		rec.SettlementDigest, rec.Outcome,
		rec.MissionVersionsJSON, rec.ExpansionDecisionRefsJSON,
		rec.RepositoryID, rec.IssueNumber, rec.Branch, rec.PullRequestNumber, rec.HeadSHA,
		rec.ChecksJSON, formatOptionalTime(rec.StartedAt), formatOptionalTime(rec.FinishedAt), rec.AggregateCostMicros,
		rec.BudgetMicros, rec.HistoricalEnforcementJSON, now,
		rec.WorkspaceID, rec.PassID,
		ReceiptUnverifiable, rec.ReceiptDigest)
	if err != nil {
		return fmt.Errorf("store: put receipt view: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: put receipt view: %w", err)
	}
	if n == 1 {
		return nil
	}
	_, err = c.ExecContext(ctx, `INSERT OR IGNORE INTO receipt_views (`+receiptViewColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.PassID, rec.Verification, rec.ReasonCode,
		rec.ReceiptID, rec.GrantID, rec.MissionRef, rec.KeyID, formatOptionalTime(rec.SignedAt), rec.ReceiptDigest,
		rec.SettlementDigest, rec.Outcome,
		rec.MissionVersionsJSON, rec.ExpansionDecisionRefsJSON,
		rec.RepositoryID, rec.IssueNumber, rec.Branch, rec.PullRequestNumber, rec.HeadSHA,
		rec.ChecksJSON, formatOptionalTime(rec.StartedAt), formatOptionalTime(rec.FinishedAt), rec.AggregateCostMicros,
		rec.BudgetMicros, rec.HistoricalEnforcementJSON, now)
	if err != nil {
		return fmt.Errorf("store: put receipt view: %w", err)
	}
	return nil
}

func scanReceiptView(row *sql.Row, rows *sql.Rows) (ReceiptViewRecord, error) {
	var rec ReceiptViewRecord
	var signedAt, startedAt, finishedAt, verifiedAt string
	var err error
	if rows != nil {
		err = rows.Scan(
			&rec.WorkspaceID, &rec.PassID, &rec.Verification, &rec.ReasonCode,
			&rec.ReceiptID, &rec.GrantID, &rec.MissionRef, &rec.KeyID, &signedAt, &rec.ReceiptDigest,
			&rec.SettlementDigest, &rec.Outcome,
			&rec.MissionVersionsJSON, &rec.ExpansionDecisionRefsJSON,
			&rec.RepositoryID, &rec.IssueNumber, &rec.Branch, &rec.PullRequestNumber, &rec.HeadSHA,
			&rec.ChecksJSON, &startedAt, &finishedAt, &rec.AggregateCostMicros,
			&rec.BudgetMicros, &rec.HistoricalEnforcementJSON, &verifiedAt)
	} else {
		err = row.Scan(
			&rec.WorkspaceID, &rec.PassID, &rec.Verification, &rec.ReasonCode,
			&rec.ReceiptID, &rec.GrantID, &rec.MissionRef, &rec.KeyID, &signedAt, &rec.ReceiptDigest,
			&rec.SettlementDigest, &rec.Outcome,
			&rec.MissionVersionsJSON, &rec.ExpansionDecisionRefsJSON,
			&rec.RepositoryID, &rec.IssueNumber, &rec.Branch, &rec.PullRequestNumber, &rec.HeadSHA,
			&rec.ChecksJSON, &startedAt, &finishedAt, &rec.AggregateCostMicros,
			&rec.BudgetMicros, &rec.HistoricalEnforcementJSON, &verifiedAt)
	}
	if err != nil {
		return ReceiptViewRecord{}, err
	}
	if rec.SignedAt, err = parseOptionalTime(signedAt); err != nil {
		return ReceiptViewRecord{}, fmt.Errorf("store: scan receipt view: %w", err)
	}
	if rec.StartedAt, err = parseOptionalTime(startedAt); err != nil {
		return ReceiptViewRecord{}, fmt.Errorf("store: scan receipt view: %w", err)
	}
	if rec.FinishedAt, err = parseOptionalTime(finishedAt); err != nil {
		return ReceiptViewRecord{}, fmt.Errorf("store: scan receipt view: %w", err)
	}
	if rec.VerifiedAt, err = parseTime(verifiedAt); err != nil {
		return ReceiptViewRecord{}, fmt.Errorf("store: scan receipt view: %w", err)
	}
	return rec, nil
}

func getReceiptView(ctx context.Context, c dbConn, workspaceID, passID string) (ReceiptViewRecord, error) {
	rec, err := scanReceiptView(c.QueryRowContext(ctx, `SELECT `+receiptViewColumns+`
		FROM receipt_views WHERE workspace_id = ? AND pass_id = ?`, workspaceID, passID), nil)
	if err == sql.ErrNoRows {
		return ReceiptViewRecord{}, fmt.Errorf("%w: receipt view for pass %q", ErrNotFound, passID)
	}
	if err != nil {
		return ReceiptViewRecord{}, fmt.Errorf("store: get receipt view: %w", err)
	}
	return rec, nil
}

const checkPublicationColumns = `workspace_id, pass_id, idempotency_key,
	receipt_digest, repository_id, pull_request_number, head_sha, binding_id,
	state, check_run_id, created_at, updated_at`

func scanCheckPublication(row *sql.Row, rows *sql.Rows) (CheckPublicationRecord, error) {
	var rec CheckPublicationRecord
	var created, updated string
	var err error
	if rows != nil {
		err = rows.Scan(&rec.WorkspaceID, &rec.PassID, &rec.IdempotencyKey,
			&rec.ReceiptDigest, &rec.RepositoryID, &rec.PullRequestNumber, &rec.HeadSHA, &rec.BindingID,
			&rec.State, &rec.CheckRunID, &created, &updated)
	} else {
		err = row.Scan(&rec.WorkspaceID, &rec.PassID, &rec.IdempotencyKey,
			&rec.ReceiptDigest, &rec.RepositoryID, &rec.PullRequestNumber, &rec.HeadSHA, &rec.BindingID,
			&rec.State, &rec.CheckRunID, &created, &updated)
	}
	if err != nil {
		return CheckPublicationRecord{}, err
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return CheckPublicationRecord{}, fmt.Errorf("store: scan check publication: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return CheckPublicationRecord{}, fmt.Errorf("store: scan check publication: %w", err)
	}
	return rec, nil
}

func validCheckPublicationState(state string) bool {
	switch state {
	case CheckPublicationInFlight, CheckPublicationSettled, CheckPublicationDisputed:
		return true
	}
	return false
}

// putCheckPublicationIfAbsent inserts the publication intent. The
// idempotency key is the primary key, so a duplicate insert is a
// no-op returning false.
func putCheckPublicationIfAbsent(ctx context.Context, c dbConn, rec CheckPublicationRecord) (bool, error) {
	if rec.WorkspaceID == "" || rec.PassID == "" || rec.IdempotencyKey == "" {
		return false, fmt.Errorf("store: put check publication: workspace, pass, and idempotency key are required")
	}
	if !validCheckPublicationState(rec.State) {
		return false, fmt.Errorf("store: put check publication: unknown state %q", rec.State)
	}
	now := formatTime(time.Now())
	if !rec.CreatedAt.IsZero() {
		now = formatTime(rec.CreatedAt)
	}
	updated := formatTime(time.Now())
	if !rec.UpdatedAt.IsZero() {
		updated = formatTime(rec.UpdatedAt)
	}
	res, err := c.ExecContext(ctx, `INSERT OR IGNORE INTO check_publications (`+checkPublicationColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.PassID, rec.IdempotencyKey,
		rec.ReceiptDigest, rec.RepositoryID, rec.PullRequestNumber, rec.HeadSHA, rec.BindingID,
		rec.State, rec.CheckRunID, now, updated)
	if err != nil {
		return false, fmt.Errorf("store: put check publication: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: put check publication: %w", err)
	}
	return n == 1, nil
}

func getCheckPublication(ctx context.Context, c dbConn, workspaceID, idempotencyKey string) (CheckPublicationRecord, error) {
	rec, err := scanCheckPublication(c.QueryRowContext(ctx, `SELECT `+checkPublicationColumns+`
		FROM check_publications WHERE workspace_id = ? AND idempotency_key = ?`,
		workspaceID, idempotencyKey), nil)
	if err == sql.ErrNoRows {
		return CheckPublicationRecord{}, fmt.Errorf("%w: check publication %q", ErrNotFound, idempotencyKey)
	}
	if err != nil {
		return CheckPublicationRecord{}, fmt.Errorf("store: get check publication: %w", err)
	}
	return rec, nil
}

func getLatestCheckPublicationForPass(ctx context.Context, c dbConn, workspaceID, passID string) (CheckPublicationRecord, error) {
	rec, err := scanCheckPublication(c.QueryRowContext(ctx, `SELECT `+checkPublicationColumns+`
		FROM check_publications WHERE workspace_id = ? AND pass_id = ?
		ORDER BY updated_at DESC LIMIT 1`, workspaceID, passID), nil)
	if err == sql.ErrNoRows {
		return CheckPublicationRecord{}, fmt.Errorf("%w: check publication for pass %q", ErrNotFound, passID)
	}
	if err != nil {
		return CheckPublicationRecord{}, fmt.Errorf("store: get latest check publication: %w", err)
	}
	return rec, nil
}

func listCheckPublications(ctx context.Context, c dbConn, workspaceID, state string) ([]CheckPublicationRecord, error) {
	var rows *sql.Rows
	var err error
	if state == "" {
		rows, err = c.QueryContext(ctx, `SELECT `+checkPublicationColumns+`
			FROM check_publications WHERE workspace_id = ? ORDER BY updated_at ASC`, workspaceID)
	} else {
		if !validCheckPublicationState(state) {
			return nil, fmt.Errorf("store: list check publications: unknown state %q", state)
		}
		rows, err = c.QueryContext(ctx, `SELECT `+checkPublicationColumns+`
			FROM check_publications WHERE workspace_id = ? AND state = ? ORDER BY updated_at ASC`,
			workspaceID, state)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list check publications: %w", err)
	}
	defer rows.Close()
	var out []CheckPublicationRecord
	for rows.Next() {
		rec, err := scanCheckPublication(nil, rows)
		if err != nil {
			return nil, fmt.Errorf("store: list check publications: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list check publications: %w", err)
	}
	return out, nil
}

func setCheckPublicationState(ctx context.Context, c dbConn, workspaceID, idempotencyKey, state, checkRunID string, at time.Time) error {
	if !validCheckPublicationState(state) {
		return fmt.Errorf("store: set check publication state: unknown state %q", state)
	}
	if at.IsZero() {
		at = time.Now()
	}
	res, err := c.ExecContext(ctx, `UPDATE check_publications
		SET state = ?, check_run_id = ?, updated_at = ?
		WHERE workspace_id = ? AND idempotency_key = ?`,
		state, checkRunID, formatTime(at), workspaceID, idempotencyKey)
	if err != nil {
		return fmt.Errorf("store: set check publication state: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set check publication state: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: check publication %q", ErrNotFound, idempotencyKey)
	}
	return nil
}

func markCheckPublicationsDisputedExcept(ctx context.Context, c dbConn, workspaceID, passID, exceptKey string, at time.Time) error {
	if at.IsZero() {
		at = time.Now()
	}
	_, err := c.ExecContext(ctx, `UPDATE check_publications
		SET state = ?, updated_at = ?
		WHERE workspace_id = ? AND pass_id = ? AND idempotency_key <> ? AND state <> ?`,
		CheckPublicationDisputed, formatTime(at), workspaceID, passID, exceptKey, CheckPublicationSettled)
	if err != nil {
		return fmt.Errorf("store: mark check publications disputed: %w", err)
	}
	return nil
}
