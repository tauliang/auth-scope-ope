// Founder authentication storage: founders, passkey public credentials,
// hashed sessions, one-use bootstrap codes, and offline recovery key
// hashes. Raw session tokens, bootstrap codes, and recovery keys are never
// persisted; only their SHA-256 hashes reach the database.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *sqliteStore) CountFounders(ctx context.Context, workspaceID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM founders WHERE workspace_id = ?`, workspaceID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count founders: %w", err)
	}
	return n, nil
}

func (s *sqliteStore) ListFounders(ctx context.Context, workspaceID string) ([]FounderRecord, error) {
	return listFounders(ctx, s.db, workspaceID)
}

func (s *sqliteStore) ListWebAuthnCredentials(ctx context.Context, workspaceID, founderID string) ([]WebAuthnCredentialRecord, error) {
	return listWebAuthnCredentials(ctx, s.db, workspaceID, founderID)
}

func (s *sqliteStore) GetSessionByHash(ctx context.Context, workspaceID, sessionHash string) (SessionRecord, error) {
	return getSessionByHash(ctx, s.db, workspaceID, sessionHash)
}

func (s *sqliteStore) GetBootstrapCode(ctx context.Context, workspaceID string) (BootstrapCodeRecord, error) {
	return getBootstrapCode(ctx, s.db, workspaceID)
}

func (s *sqliteStore) GetOfflineRecoveryKey(ctx context.Context, workspaceID, founderID string) (OfflineRecoveryKeyRecord, error) {
	return getOfflineRecoveryKey(ctx, s.db, workspaceID, founderID)
}

func (t *sqliteTx) CreateFounder(ctx context.Context, rec FounderRecord) error {
	return createFounder(ctx, t.tx, rec)
}

func (t *sqliteTx) PutWebAuthnCredential(ctx context.Context, rec WebAuthnCredentialRecord) error {
	return putWebAuthnCredential(ctx, t.tx, rec)
}

func (t *sqliteTx) UpdateWebAuthnCredentialSignCount(ctx context.Context, workspaceID, credentialID string, signCount uint32) error {
	return updateWebAuthnCredentialSignCount(ctx, t.tx, workspaceID, credentialID, signCount)
}

func (t *sqliteTx) CreateSession(ctx context.Context, rec SessionRecord) error {
	return createSession(ctx, t.tx, rec)
}

func (t *sqliteTx) RevokeSession(ctx context.Context, workspaceID, sessionID string) error {
	return revokeSession(ctx, t.tx, workspaceID, sessionID)
}

func (t *sqliteTx) PutBootstrapCode(ctx context.Context, rec BootstrapCodeRecord) error {
	return putBootstrapCode(ctx, t.tx, rec)
}

func (t *sqliteTx) ConsumeBootstrapCode(ctx context.Context, workspaceID, codeHash string, now time.Time) error {
	return consumeBootstrapCode(ctx, t.tx, workspaceID, codeHash, now)
}

func (t *sqliteTx) PutOfflineRecoveryKey(ctx context.Context, rec OfflineRecoveryKeyRecord) error {
	return putOfflineRecoveryKey(ctx, t.tx, rec)
}

func createFounder(ctx context.Context, c dbConn, rec FounderRecord) error {
	if rec.WorkspaceID == "" || rec.FounderID == "" {
		return fmt.Errorf("store: create founder: workspace and founder IDs are required")
	}
	_, err := c.ExecContext(ctx, `INSERT INTO founders
		(workspace_id, founder_id, display_name, created_at)
		VALUES (?, ?, ?, ?)`,
		rec.WorkspaceID, rec.FounderID, rec.DisplayName, formatTime(rec.CreatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: founder already enrolled", ErrConflict)
		}
		return fmt.Errorf("store: create founder: %w", err)
	}
	return nil
}

func listFounders(ctx context.Context, c dbConn, workspaceID string) ([]FounderRecord, error) {
	rows, err := c.QueryContext(ctx, `SELECT workspace_id, founder_id, display_name, created_at
		FROM founders WHERE workspace_id = ? ORDER BY created_at ASC`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("store: list founders: %w", err)
	}
	defer rows.Close()
	var out []FounderRecord
	for rows.Next() {
		var rec FounderRecord
		var created string
		if err := rows.Scan(&rec.WorkspaceID, &rec.FounderID, &rec.DisplayName, &created); err != nil {
			return nil, fmt.Errorf("store: list founders: %w", err)
		}
		if rec.CreatedAt, err = parseTime(created); err != nil {
			return nil, fmt.Errorf("store: list founders: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list founders: %w", err)
	}
	return out, nil
}

func putWebAuthnCredential(ctx context.Context, c dbConn, rec WebAuthnCredentialRecord) error {
	if rec.WorkspaceID == "" || rec.CredentialID == "" || rec.FounderID == "" {
		return fmt.Errorf("store: put credential: workspace, credential, and founder IDs are required")
	}
	if len(rec.PublicKey) == 0 {
		return fmt.Errorf("store: put credential: public key is required")
	}
	_, err := c.ExecContext(ctx, `INSERT INTO webauthn_credentials
		(workspace_id, credential_id, founder_id, public_key, sign_count, transports, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.CredentialID, rec.FounderID, rec.PublicKey,
		rec.SignCount, rec.Transports, formatTime(rec.CreatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: credential already registered", ErrConflict)
		}
		return fmt.Errorf("store: put credential: %w", err)
	}
	return nil
}

func listWebAuthnCredentials(ctx context.Context, c dbConn, workspaceID, founderID string) ([]WebAuthnCredentialRecord, error) {
	rows, err := c.QueryContext(ctx, `SELECT workspace_id, credential_id, founder_id, public_key,
		sign_count, transports, created_at FROM webauthn_credentials
		WHERE workspace_id = ? AND founder_id = ? ORDER BY created_at ASC`, workspaceID, founderID)
	if err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	defer rows.Close()
	var out []WebAuthnCredentialRecord
	for rows.Next() {
		var rec WebAuthnCredentialRecord
		var created string
		var signCount int64
		if err := rows.Scan(&rec.WorkspaceID, &rec.CredentialID, &rec.FounderID,
			&rec.PublicKey, &signCount, &rec.Transports, &created); err != nil {
			return nil, fmt.Errorf("store: list credentials: %w", err)
		}
		rec.SignCount = uint32(signCount)
		if rec.CreatedAt, err = parseTime(created); err != nil {
			return nil, fmt.Errorf("store: list credentials: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	return out, nil
}

// updateWebAuthnCredentialSignCount advances the stored sign count after a
// verified assertion. The count must move forward; a stagnant or backward
// count reports a possible cloned authenticator.
func updateWebAuthnCredentialSignCount(ctx context.Context, c dbConn, workspaceID, credentialID string, signCount uint32) error {
	res, err := c.ExecContext(ctx, `UPDATE webauthn_credentials
		SET sign_count = ? WHERE workspace_id = ? AND credential_id = ? AND sign_count < ?`,
		signCount, workspaceID, credentialID, signCount)
	if err != nil {
		return fmt.Errorf("store: update sign count: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update sign count: %w", err)
	}
	if n == 1 {
		return nil
	}
	var stored int64
	err = c.QueryRowContext(ctx, `SELECT sign_count FROM webauthn_credentials
		WHERE workspace_id = ? AND credential_id = ?`, workspaceID, credentialID).Scan(&stored)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: credential %q", ErrNotFound, credentialID)
	}
	if err != nil {
		return fmt.Errorf("store: update sign count: %w", err)
	}
	return fmt.Errorf("%w: sign count did not advance (stored %d, got %d)", ErrConflict, stored, signCount)
}

func createSession(ctx context.Context, c dbConn, rec SessionRecord) error {
	if rec.WorkspaceID == "" || rec.SessionID == "" || rec.SessionHash == "" || rec.FounderID == "" {
		return fmt.Errorf("store: create session: workspace, session, and founder IDs and the token hash are required")
	}
	if rec.CSRFTokenHash == "" {
		return fmt.Errorf("store: create session: CSRF token hash is required")
	}
	_, err := c.ExecContext(ctx, `INSERT INTO sessions
		(workspace_id, session_id, session_hash, founder_id, csrf_token_hash, created_at, expires_at, revoked)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		rec.WorkspaceID, rec.SessionID, rec.SessionHash, rec.FounderID,
		rec.CSRFTokenHash, formatTime(rec.CreatedAt), formatTime(rec.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: session token already exists", ErrConflict)
		}
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

func getSessionByHash(ctx context.Context, c dbConn, workspaceID, sessionHash string) (SessionRecord, error) {
	var rec SessionRecord
	var created, expires string
	var revoked int
	err := c.QueryRowContext(ctx, `SELECT workspace_id, session_id, session_hash, founder_id,
		csrf_token_hash, created_at, expires_at, revoked FROM sessions
		WHERE workspace_id = ? AND session_hash = ?`, workspaceID, sessionHash).
		Scan(&rec.WorkspaceID, &rec.SessionID, &rec.SessionHash, &rec.FounderID,
			&rec.CSRFTokenHash, &created, &expires, &revoked)
	if err == sql.ErrNoRows {
		return SessionRecord{}, fmt.Errorf("%w: session", ErrNotFound)
	}
	if err != nil {
		return SessionRecord{}, fmt.Errorf("store: get session: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return SessionRecord{}, fmt.Errorf("store: get session: %w", err)
	}
	if rec.ExpiresAt, err = parseTime(expires); err != nil {
		return SessionRecord{}, fmt.Errorf("store: get session: %w", err)
	}
	rec.Revoked = revoked != 0
	return rec, nil
}

func revokeSession(ctx context.Context, c dbConn, workspaceID, sessionID string) error {
	res, err := c.ExecContext(ctx, `UPDATE sessions SET revoked = 1
		WHERE workspace_id = ? AND session_id = ? AND revoked = 0`, workspaceID, sessionID)
	if err != nil {
		return fmt.Errorf("store: revoke session: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: revoke session: %w", err)
	}
	if n == 1 {
		return nil
	}
	var exists int
	if err := c.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions
		WHERE workspace_id = ? AND session_id = ?`, workspaceID, sessionID).Scan(&exists); err != nil {
		return fmt.Errorf("store: revoke session: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("%w: session %q", ErrNotFound, sessionID)
	}
	return fmt.Errorf("%w: session %q already revoked", ErrConflict, sessionID)
}

// putBootstrapCode replaces the active bootstrap code of a workspace. Serve
// start calls this when no founder is enrolled yet; the raw code is printed
// once to the controlling terminal and never stored.
func putBootstrapCode(ctx context.Context, c dbConn, rec BootstrapCodeRecord) error {
	if rec.WorkspaceID == "" || rec.CodeHash == "" {
		return fmt.Errorf("store: put bootstrap code: workspace ID and code hash are required")
	}
	if _, err := c.ExecContext(ctx, `DELETE FROM bootstrap_codes
		WHERE workspace_id = ? AND consumed_at IS NULL`, rec.WorkspaceID); err != nil {
		return fmt.Errorf("store: put bootstrap code: %w", err)
	}
	_, err := c.ExecContext(ctx, `INSERT INTO bootstrap_codes
		(workspace_id, code_hash, created_at, expires_at, consumed_at)
		VALUES (?, ?, ?, ?, NULL)`,
		rec.WorkspaceID, rec.CodeHash, formatTime(rec.CreatedAt), formatTime(rec.ExpiresAt))
	if err != nil {
		return fmt.Errorf("store: put bootstrap code: %w", err)
	}
	return nil
}

func getBootstrapCode(ctx context.Context, c dbConn, workspaceID string) (BootstrapCodeRecord, error) {
	var rec BootstrapCodeRecord
	var created, expires string
	var consumed sql.NullString
	err := c.QueryRowContext(ctx, `SELECT workspace_id, code_hash, created_at, expires_at, consumed_at
		FROM bootstrap_codes WHERE workspace_id = ? AND consumed_at IS NULL
		ORDER BY created_at DESC LIMIT 1`, workspaceID).
		Scan(&rec.WorkspaceID, &rec.CodeHash, &created, &expires, &consumed)
	if err == sql.ErrNoRows {
		return BootstrapCodeRecord{}, fmt.Errorf("%w: bootstrap code", ErrNotFound)
	}
	if err != nil {
		return BootstrapCodeRecord{}, fmt.Errorf("store: get bootstrap code: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return BootstrapCodeRecord{}, fmt.Errorf("store: get bootstrap code: %w", err)
	}
	if rec.ExpiresAt, err = parseTime(expires); err != nil {
		return BootstrapCodeRecord{}, fmt.Errorf("store: get bootstrap code: %w", err)
	}
	if consumed.Valid {
		t, err := parseTime(consumed.String)
		if err != nil {
			return BootstrapCodeRecord{}, fmt.Errorf("store: get bootstrap code: %w", err)
		}
		rec.ConsumedAt = &t
	}
	return rec, nil
}

// consumeBootstrapCode atomically marks the active code consumed. It fails
// when no active code matches or when the code already expired.
func consumeBootstrapCode(ctx context.Context, c dbConn, workspaceID, codeHash string, now time.Time) error {
	res, err := c.ExecContext(ctx, `UPDATE bootstrap_codes SET consumed_at = ?
		WHERE workspace_id = ? AND code_hash = ? AND consumed_at IS NULL AND expires_at > ?`,
		formatTime(now), workspaceID, codeHash, formatTime(now))
	if err != nil {
		return fmt.Errorf("store: consume bootstrap code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: consume bootstrap code: %w", err)
	}
	if n == 1 {
		return nil
	}
	rec, err := getBootstrapCode(ctx, c, workspaceID)
	if err != nil {
		return err
	}
	if rec.CodeHash != codeHash {
		return fmt.Errorf("%w: bootstrap code mismatch", ErrNotFound)
	}
	return fmt.Errorf("%w: bootstrap code expired", ErrConflict)
}

func putOfflineRecoveryKey(ctx context.Context, c dbConn, rec OfflineRecoveryKeyRecord) error {
	if rec.WorkspaceID == "" || rec.FounderID == "" || rec.KeyHash == "" {
		return fmt.Errorf("store: put recovery key: workspace and founder IDs and the key hash are required")
	}
	_, err := c.ExecContext(ctx, `INSERT INTO offline_recovery_keys
		(workspace_id, founder_id, key_hash, created_at)
		VALUES (?, ?, ?, ?)`,
		rec.WorkspaceID, rec.FounderID, rec.KeyHash, formatTime(rec.CreatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: recovery key already stored", ErrConflict)
		}
		return fmt.Errorf("store: put recovery key: %w", err)
	}
	return nil
}

func getOfflineRecoveryKey(ctx context.Context, c dbConn, workspaceID, founderID string) (OfflineRecoveryKeyRecord, error) {
	var rec OfflineRecoveryKeyRecord
	var created string
	err := c.QueryRowContext(ctx, `SELECT workspace_id, founder_id, key_hash, created_at
		FROM offline_recovery_keys WHERE workspace_id = ? AND founder_id = ?`,
		workspaceID, founderID).
		Scan(&rec.WorkspaceID, &rec.FounderID, &rec.KeyHash, &created)
	if err == sql.ErrNoRows {
		return OfflineRecoveryKeyRecord{}, fmt.Errorf("%w: offline recovery key", ErrNotFound)
	}
	if err != nil {
		return OfflineRecoveryKeyRecord{}, fmt.Errorf("store: get recovery key: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return OfflineRecoveryKeyRecord{}, fmt.Errorf("store: get recovery key: %w", err)
	}
	return rec, nil
}
