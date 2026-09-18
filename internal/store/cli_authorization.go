// CLI launch authorization storage: pending one-use browser PKCE handoffs.
// Only hashes of secret values reach the database: the SHA-256 of the
// authorization code, never the raw code or verifier. The signed decision
// attestation lives only in process memory.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (s *sqliteStore) GetCLIAuthorization(ctx context.Context, workspaceID, authorizationID string) (CLIAuthorization, error) {
	return getCLIAuthorization(ctx, s.db, workspaceID, authorizationID)
}

func (s *sqliteStore) GetCLIAuthorizationByState(ctx context.Context, workspaceID, passID, state string) (CLIAuthorization, error) {
	return getCLIAuthorizationByState(ctx, s.db, workspaceID, passID, state)
}

func (s *sqliteStore) GetCLIAuthorizationByCodeHash(ctx context.Context, workspaceID string, codeHash [32]byte) (CLIAuthorization, error) {
	return getCLIAuthorizationByCodeHash(ctx, s.db, workspaceID, codeHash)
}

func (t *sqliteTx) PutCLIAuthorization(ctx context.Context, rec CLIAuthorization) error {
	return putCLIAuthorization(ctx, t.tx, rec)
}

func (t *sqliteTx) ApproveCLIAuthorization(ctx context.Context, workspaceID, authorizationID, decisionChallengeID, attestationDigest string, codeHash [32]byte, approvedAt time.Time) error {
	return approveCLIAuthorization(ctx, t.tx, workspaceID, authorizationID, decisionChallengeID, attestationDigest, codeHash, approvedAt)
}

const cliAuthorizationColumns = `workspace_id, authorization_id, pass_id, state,
	code_challenge, redirect_uri, ephemeral_public_key, proposal_digest,
	invocation_digest, agent_kit_id, agent_kit_version, runner_arguments_json,
	mission_ref, mission_version, canonical_request_digest,
	decision_challenge_id, decision_attestation_digest, code_hash,
	approved_at, expires_at, created_at`

func scanCLIAuthorization(row *sql.Row) (CLIAuthorization, error) {
	var rec CLIAuthorization
	var argsJSON, expiresAt, createdAt string
	var approvedAt sql.NullString
	var codeHash, canonicalDigest []byte
	err := row.Scan(
		&rec.WorkspaceID, &rec.AuthorizationID, &rec.PassID, &rec.State,
		&rec.CodeChallenge, &rec.RedirectURI, &rec.EphemeralPublicKey,
		&rec.ProposalDigest, &rec.InvocationDigest, &rec.AgentKitID,
		&rec.AgentKitVersion, &argsJSON,
		&rec.MissionRef, &rec.MissionVersion, &canonicalDigest,
		&rec.DecisionChallengeID,
		&rec.DecisionAttestationDigest, &codeHash,
		&approvedAt, &expiresAt, &createdAt,
	)
	if err != nil {
		return CLIAuthorization{}, err
	}
	if rec.RunnerArguments, err = decodeStringSlice(argsJSON); err != nil {
		return CLIAuthorization{}, fmt.Errorf("store: decode CLI authorization arguments: %w", err)
	}
	if len(canonicalDigest) != 32 {
		return CLIAuthorization{}, fmt.Errorf("store: CLI authorization canonical digest has %d bytes, want 32", len(canonicalDigest))
	}
	copy(rec.CanonicalRequestDigest[:], canonicalDigest)
	if len(codeHash) > 0 {
		if len(codeHash) != 32 {
			return CLIAuthorization{}, fmt.Errorf("store: CLI authorization code hash has %d bytes, want 32", len(codeHash))
		}
		copy(rec.CodeHash[:], codeHash)
	}
	if approvedAt.Valid && approvedAt.String != "" {
		t, err := parseTime(approvedAt.String)
		if err != nil {
			return CLIAuthorization{}, fmt.Errorf("store: parse CLI authorization approved_at: %w", err)
		}
		rec.ApprovedAt = &t
	}
	if rec.ExpiresAt, err = parseTime(expiresAt); err != nil {
		return CLIAuthorization{}, fmt.Errorf("store: parse CLI authorization expires_at: %w", err)
	}
	if rec.CreatedAt, err = parseTime(createdAt); err != nil {
		return CLIAuthorization{}, fmt.Errorf("store: parse CLI authorization created_at: %w", err)
	}
	return rec, nil
}

func getCLIAuthorization(ctx context.Context, c dbConn, workspaceID, authorizationID string) (CLIAuthorization, error) {
	rec, err := scanCLIAuthorization(c.QueryRowContext(ctx,
		`SELECT `+cliAuthorizationColumns+`
		FROM cli_authorizations WHERE workspace_id = ? AND authorization_id = ?`,
		workspaceID, authorizationID))
	if err != nil {
		if err == sql.ErrNoRows {
			return CLIAuthorization{}, fmt.Errorf("%w: CLI authorization %q", ErrNotFound, authorizationID)
		}
		return CLIAuthorization{}, fmt.Errorf("store: get CLI authorization: %w", err)
	}
	return rec, nil
}

func getCLIAuthorizationByCodeHash(ctx context.Context, c dbConn, workspaceID string, codeHash [32]byte) (CLIAuthorization, error) {
	rec, err := scanCLIAuthorization(c.QueryRowContext(ctx,
		`SELECT `+cliAuthorizationColumns+`
		FROM cli_authorizations WHERE workspace_id = ? AND code_hash = ?`,
		workspaceID, codeHash[:]))
	if err != nil {
		if err == sql.ErrNoRows {
			return CLIAuthorization{}, fmt.Errorf("%w: CLI authorization for code", ErrNotFound)
		}
		return CLIAuthorization{}, fmt.Errorf("store: get CLI authorization by code hash: %w", err)
	}
	return rec, nil
}

func getCLIAuthorizationByState(ctx context.Context, c dbConn, workspaceID, passID, state string) (CLIAuthorization, error) {
	rec, err := scanCLIAuthorization(c.QueryRowContext(ctx,
		`SELECT `+cliAuthorizationColumns+`
		FROM cli_authorizations WHERE workspace_id = ? AND pass_id = ? AND state = ?`,
		workspaceID, passID, state))
	if err != nil {
		if err == sql.ErrNoRows {
			return CLIAuthorization{}, fmt.Errorf("%w: CLI authorization for pass %q", ErrNotFound, passID)
		}
		return CLIAuthorization{}, fmt.Errorf("store: get CLI authorization by state: %w", err)
	}
	return rec, nil
}

func putCLIAuthorization(ctx context.Context, c dbConn, rec CLIAuthorization) error {
	if rec.WorkspaceID == "" || rec.AuthorizationID == "" || rec.PassID == "" {
		return fmt.Errorf("store: put CLI authorization: workspace, authorization, and pass IDs are required")
	}
	if rec.State == "" || rec.CodeChallenge == "" || rec.RedirectURI == "" || rec.EphemeralPublicKey == "" {
		return fmt.Errorf("store: put CLI authorization: state, code challenge, redirect URI, and ephemeral key are required")
	}
	if rec.ProposalDigest == "" || rec.InvocationDigest == "" || rec.AgentKitID == "" {
		return fmt.Errorf("store: put CLI authorization: launch binding is required")
	}
	if rec.MissionRef == "" || rec.MissionVersion <= 0 {
		return fmt.Errorf("store: put CLI authorization: mission reference and version are required")
	}
	argsJSON, err := encodeStringSlice(rec.RunnerArguments)
	if err != nil {
		return fmt.Errorf("store: put CLI authorization: %w", err)
	}
	_, err = c.ExecContext(ctx, `INSERT INTO cli_authorizations
		(workspace_id, authorization_id, pass_id, state, code_challenge,
		redirect_uri, ephemeral_public_key, proposal_digest, invocation_digest,
		agent_kit_id, agent_kit_version, runner_arguments_json,
		mission_ref, mission_version, canonical_request_digest,
		decision_challenge_id, decision_attestation_digest, code_hash,
		approved_at, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', NULL, NULL, ?, ?)`,
		rec.WorkspaceID, rec.AuthorizationID, rec.PassID, rec.State,
		rec.CodeChallenge, rec.RedirectURI, rec.EphemeralPublicKey,
		rec.ProposalDigest, rec.InvocationDigest, rec.AgentKitID,
		rec.AgentKitVersion, argsJSON,
		rec.MissionRef, rec.MissionVersion, rec.CanonicalRequestDigest[:],
		formatTime(rec.ExpiresAt), formatTime(rec.CreatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: CLI authorization %q", ErrConflict, rec.AuthorizationID)
		}
		return fmt.Errorf("store: put CLI authorization: %w", err)
	}
	return nil
}

// approveCLIAuthorization atomically marks an authorization approved. The
// conditional update affects exactly one row: an unknown ID or an
// already-approved authorization reports ErrConflict, which rejects
// duplicate and concurrent finishes.
func approveCLIAuthorization(ctx context.Context, c dbConn, workspaceID, authorizationID, decisionChallengeID, attestationDigest string, codeHash [32]byte, approvedAt time.Time) error {
	if decisionChallengeID == "" || attestationDigest == "" {
		return fmt.Errorf("store: approve CLI authorization: challenge ID and attestation digest are required")
	}
	var zero [32]byte
	if codeHash == zero {
		return fmt.Errorf("store: approve CLI authorization: code hash is required")
	}
	res, err := c.ExecContext(ctx, `UPDATE cli_authorizations
		SET decision_challenge_id = ?, decision_attestation_digest = ?,
		code_hash = ?, approved_at = ?
		WHERE workspace_id = ? AND authorization_id = ? AND approved_at IS NULL`,
		decisionChallengeID, attestationDigest, codeHash[:], formatTime(approvedAt),
		workspaceID, authorizationID)
	if err != nil {
		return fmt.Errorf("store: approve CLI authorization: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: approve CLI authorization: %w", err)
	}
	if n == 1 {
		return nil
	}
	if _, err := getCLIAuthorization(ctx, c, workspaceID, authorizationID); err != nil {
		return err
	}
	return fmt.Errorf("%w: CLI authorization %q already approved", ErrConflict, authorizationID)
}
