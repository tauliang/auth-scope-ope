// Launch exchange intent storage: durable exactly-once reservations for
// authorization code exchanges. Only digests and run metadata reach the
// database: the sealed signed envelope and the signed decision
// attestation never do.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func (t *sqliteTx) ClaimLaunchExchangeIntent(ctx context.Context, intent LaunchExchangeIntent, now time.Time) (bool, error) {
	return claimLaunchExchangeIntent(ctx, t.tx, intent, now)
}

func (t *sqliteTx) GetLaunchExchangeIntent(ctx context.Context, workspaceID, codeHash string) (LaunchExchangeIntent, error) {
	return getLaunchExchangeIntent(ctx, t.tx, workspaceID, codeHash)
}

func (t *sqliteTx) SettleLaunchExchangeIntent(ctx context.Context, workspaceID, codeHash, status, runID, envelopeDigest, failure string, now time.Time) error {
	return settleLaunchExchangeIntent(ctx, t.tx, workspaceID, codeHash, status, runID, envelopeDigest, failure, now)
}

// Launch intent statuses.
const (
	LaunchExchangeInFlight  = "in_flight"
	LaunchExchangeCompleted = "completed"
	LaunchExchangeFailed    = "failed"
	LaunchExchangeExpired   = "expired"
)

func claimLaunchExchangeIntent(ctx context.Context, c dbConn, intent LaunchExchangeIntent, now time.Time) (bool, error) {
	if intent.WorkspaceID == "" || intent.CodeHash == "" || intent.AuthorizationID == "" || intent.PassID == "" {
		return false, fmt.Errorf("store: claim launch exchange intent: workspace, code hash, authorization, and pass IDs are required")
	}
	if intent.AttestationDigest == "" {
		return false, fmt.Errorf("store: claim launch exchange intent: attestation digest is required")
	}
	ts := formatTime(now)
	res, err := c.ExecContext(ctx, `INSERT INTO launch_exchange_intents
		(workspace_id, code_hash, authorization_id, pass_id, run_id, status,
		 attestation_digest, envelope_digest, error, created_at, updated_at)
		VALUES (?, ?, ?, ?, '', ?, ?, '', '', ?, ?)
		ON CONFLICT(workspace_id, code_hash) DO NOTHING`,
		intent.WorkspaceID, strings.ToLower(intent.CodeHash), intent.AuthorizationID,
		intent.PassID, LaunchExchangeInFlight, intent.AttestationDigest, ts, ts)
	if err != nil {
		return false, fmt.Errorf("store: claim launch exchange intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: claim launch exchange intent: %w", err)
	}
	return n == 1, nil
}

const launchExchangeColumns = `workspace_id, code_hash, authorization_id, pass_id,
	run_id, status, attestation_digest, envelope_digest, error, created_at, updated_at`

func getLaunchExchangeIntent(ctx context.Context, c dbConn, workspaceID, codeHash string) (LaunchExchangeIntent, error) {
	var rec LaunchExchangeIntent
	var created, updated string
	err := c.QueryRowContext(ctx, `SELECT `+launchExchangeColumns+`
		FROM launch_exchange_intents WHERE workspace_id = ? AND code_hash = ?`,
		workspaceID, strings.ToLower(codeHash)).Scan(
		&rec.WorkspaceID, &rec.CodeHash, &rec.AuthorizationID, &rec.PassID,
		&rec.RunID, &rec.Status, &rec.AttestationDigest, &rec.EnvelopeDigest,
		&rec.Failure, &created, &updated)
	if err == sql.ErrNoRows {
		return LaunchExchangeIntent{}, ErrNotFound
	}
	if err != nil {
		return LaunchExchangeIntent{}, fmt.Errorf("store: get launch exchange intent: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return LaunchExchangeIntent{}, fmt.Errorf("store: get launch exchange intent: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return LaunchExchangeIntent{}, fmt.Errorf("store: get launch exchange intent: %w", err)
	}
	return rec, nil
}

func settleLaunchExchangeIntent(ctx context.Context, c dbConn, workspaceID, codeHash, status, runID, envelopeDigest, failure string, now time.Time) error {
	switch status {
	case LaunchExchangeCompleted, LaunchExchangeFailed, LaunchExchangeExpired:
	default:
		return fmt.Errorf("store: settle launch exchange intent: bad status %q", status)
	}
	res, err := c.ExecContext(ctx, `UPDATE launch_exchange_intents
		SET status = ?, run_id = ?, envelope_digest = ?, error = ?, updated_at = ?
		WHERE workspace_id = ? AND code_hash = ? AND status = ?`,
		status, runID, envelopeDigest, failure, formatTime(now),
		workspaceID, strings.ToLower(codeHash), LaunchExchangeInFlight)
	if err != nil {
		return fmt.Errorf("store: settle launch exchange intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: settle launch exchange intent: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: launch exchange intent is not in flight", ErrConflict)
	}
	return nil
}
