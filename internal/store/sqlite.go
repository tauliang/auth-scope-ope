// SQLite adapter for the presentation store.
//
// The database opens with WAL journaling, foreign keys, a five-second busy
// timeout, and a single writer connection. The data directory and database
// file are created with owner-only permissions; in release mode existing
// paths that are symlinks or carry group/world permission bits are rejected.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/001_initial.sql migrations/002_authn.sql migrations/003_github.sql migrations/004_mission_pass_proposal.sql migrations/005_mission_pass_request_keys.sql migrations/006_mission_pass_approval.sql migrations/007_cli_authorizations.sql migrations/008_launch_exchange.sql migrations/009_event_projections.sql migrations/010_expansions.sql migrations/011_receipts.sql migrations/012_recovery.sql migrations/013_telemetry.sql
var migrationFS embed.FS

// migrations lists the schema migrations in apply order. Each version is
// recorded in schema_migrations exactly once.
var migrations = []struct {
	version string
	file    string
}{
	{"001_initial", "migrations/001_initial.sql"},
	{"002_authn", "migrations/002_authn.sql"},
	{"003_github", "migrations/003_github.sql"},
	{"004_mission_pass_proposal", "migrations/004_mission_pass_proposal.sql"},
	{"005_mission_pass_request_keys", "migrations/005_mission_pass_request_keys.sql"},
	{"006_mission_pass_approval", "migrations/006_mission_pass_approval.sql"},
	{"007_cli_authorizations", "migrations/007_cli_authorizations.sql"},
	{"008_launch_exchange", "migrations/008_launch_exchange.sql"},
	{"009_event_projections", "migrations/009_event_projections.sql"},
	{"010_expansions", "migrations/010_expansions.sql"},
	{"011_receipts", "migrations/011_receipts.sql"},
	{"012_recovery", "migrations/012_recovery.sql"},
	{"013_telemetry", "migrations/013_telemetry.sql"},
}

// loadMigration reads one embedded migration file.
func loadMigration(file string) (string, error) {
	b, err := migrationFS.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("store: read embedded migration %s: %w", file, err)
	}
	return string(b), nil
}

const (
	dbFileName        = "ope.db"
	busyTimeoutMillis = 5000
)

// dbConn abstracts *sql.DB and *sql.Tx so the same statements serve direct
// reads and transactional writes.
type dbConn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type sqliteStore struct {
	db   *sql.DB
	mode string
	// lockFile holds the exclusive data-directory lock taken by
	// OpenExclusive. It is nil for stores opened with Open. Closing the
	// file releases the lock.
	lockFile *os.File
}

type sqliteTx struct {
	tx   *sql.Tx
	mode string
}

// Open opens (creating if needed) the presentation store in dataDir. The
// database file is <dataDir>/ope.db. mode is "development" or "release" and
// controls the data-path hardening checks.
func Open(dataDir, mode string) (Store, error) {
	return open(dataDir, mode, false)
}

// lockFileName is the data-directory lock file. The server and the
// offline recovery command each take an exclusive advisory lock on it
// for their whole lifetime, so recovery refuses to run while the server
// owns the database.
const lockFileName = ".ope.lock"

// OpenExclusive opens the presentation store like Open and additionally
// holds an exclusive advisory lock on the data directory until Close.
// A second OpenExclusive on the same data directory fails with
// ErrDatabaseLocked while the first store is alive. The server opens
// this way at startup; the offline recovery command opens this way and
// refuses to run while the server holds the lock. The lock is acquired
// before the database file is opened or any migration runs, so a second
// process can never observe or mutate the database while the first owns
// it.
func OpenExclusive(dataDir, mode string) (Store, error) {
	return open(dataDir, mode, true)
}

func open(dataDir, mode string, exclusive bool) (Store, error) {
	if mode != "development" && mode != "release" {
		return nil, fmt.Errorf("store: invalid mode %q", mode)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	var lockFile *os.File
	if exclusive {
		f, err := os.OpenFile(filepath.Join(dataDir, lockFileName), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("store: open lock file: %w", err)
		}
		if err := lockExclusiveNonblock(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("%w: stop the running server first", ErrDatabaseLocked)
		}
		lockFile = f
	}
	st, err := openDatabase(dataDir, mode)
	if err != nil {
		if lockFile != nil {
			lockFile.Close()
		}
		return nil, err
	}
	s := st.(*sqliteStore)
	s.lockFile = lockFile
	return s, nil
}

func openDatabase(dataDir, mode string) (Store, error) {
	dbPath := filepath.Join(dataDir, dbFileName)
	if mode == "release" {
		if err := checkPathHardened(dataDir); err != nil {
			return nil, err
		}
		if _, err := os.Lstat(dbPath); err == nil {
			if err := checkPathHardened(dbPath); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("store: stat database: %w", err)
		}
	}
	// Create the file with owner-only permissions when it does not exist.
	f, err := os.OpenFile(dbPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: create database file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: create database file: %w", err)
	}

	dsn := (&url.URL{
		Scheme:   "file",
		Path:     dbPath,
		RawQuery: fmt.Sprintf("_pragma=journal_mode(WAL)&_pragma=busy_timeout(%d)&_pragma=foreign_keys(ON)", busyTimeoutMillis),
	}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	// One writer connection: every mutation serializes through it.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: ping database: %w", err)
	}
	if err := runMigrations(db); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteStore{db: db, mode: mode}, nil
}

// checkPathHardened rejects symlinks and paths with group or world
// permission bits, without following symlinks.
func checkPathHardened(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("store: stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrUnsafeDataPath, path)
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a regular file or directory", ErrUnsafeDataPath, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s has group/world permission bits (%o)", ErrUnsafeDataPath, path, fi.Mode().Perm())
	}
	return nil
}

func runMigrations(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: create migrations table: %w", err)
	}
	for _, m := range migrations {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&count); err != nil {
			return fmt.Errorf("store: check migrations: %w", err)
		}
		if count > 0 {
			continue
		}
		migration, err := loadMigration(m.file)
		if err != nil {
			return err
		}
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("store: apply %s: %w", m.version, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, m.version, formatTime(time.Now())); err != nil {
			return fmt.Errorf("store: record migration: %w", err)
		}
	}
	return nil
}

func (s *sqliteStore) Close() error {
	// Closing the lock file releases the exclusive data-directory lock.
	var lockErr error
	if s.lockFile != nil {
		lockErr = s.lockFile.Close()
		s.lockFile = nil
	}
	if err := s.db.Close(); err != nil {
		return err
	}
	return lockErr
}

func (s *sqliteStore) WithTx(ctx context.Context, fn func(Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin transaction: %w", err)
	}
	// A panic inside fn must not leak the single writer connection.
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()
	stx := &sqliteTx{tx: tx, mode: s.mode}
	if err := fn(stx); err != nil {
		// When the context is canceled mid-transaction the driver may
		// already have rolled the transaction back, in which case the
		// explicit rollback reports sql.ErrTxDone. That is not a new
		// failure: return the original error so its chain (for example
		// context.DeadlineExceeded) stays intact for errors.Is callers.
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			return fmt.Errorf("store: rollback after %w: %w", err, rbErr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetInstance(ctx context.Context) (InstanceRecord, error) {
	return getInstance(ctx, s.db)
}

func (s *sqliteStore) GetMissionPass(ctx context.Context, workspaceID, passID string) (MissionPassRecord, error) {
	return getMissionPass(ctx, s.db, workspaceID, passID)
}

func (s *sqliteStore) ClaimMissionPassRequestKey(ctx context.Context, workspaceID, idempotencyKey, passID string) (string, error) {
	if workspaceID == "" || idempotencyKey == "" || passID == "" {
		return "", fmt.Errorf("store: claim mission pass request key: workspace, key, and pass are required")
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO mission_pass_request_keys
		(workspace_id, idempotency_key, pass_id, created_at) VALUES (?, ?, ?, ?)`,
		workspaceID, idempotencyKey, passID, formatTime(time.Now()))
	if err != nil {
		return "", fmt.Errorf("store: claim mission pass request key: %w", err)
	}
	var winner string
	err = s.db.QueryRowContext(ctx, `SELECT pass_id FROM mission_pass_request_keys
		WHERE workspace_id = ? AND idempotency_key = ?`, workspaceID, idempotencyKey).Scan(&winner)
	if err != nil {
		return "", fmt.Errorf("store: claim mission pass request key: %w", err)
	}
	return winner, nil
}

func (s *sqliteStore) GetMissionPassIDByRequestKey(ctx context.Context, workspaceID, idempotencyKey string) (string, error) {
	var passID string
	err := s.db.QueryRowContext(ctx, `SELECT pass_id FROM mission_pass_request_keys
		WHERE workspace_id = ? AND idempotency_key = ?`, workspaceID, idempotencyKey).Scan(&passID)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: get mission pass request key: %w", err)
	}
	return passID, nil
}

func (s *sqliteStore) DeleteMissionPassRequestKey(ctx context.Context, workspaceID, idempotencyKey string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mission_pass_request_keys
		WHERE workspace_id = ? AND idempotency_key = ?`, workspaceID, idempotencyKey)
	if err != nil {
		return fmt.Errorf("store: delete mission pass request key: %w", err)
	}
	return nil
}

func (s *sqliteStore) GetMissionPassRequestKeyClaimedAt(ctx context.Context, workspaceID, idempotencyKey string) (time.Time, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT created_at FROM mission_pass_request_keys
		WHERE workspace_id = ? AND idempotency_key = ?`, workspaceID, idempotencyKey).Scan(&raw)
	if err == sql.ErrNoRows {
		return time.Time{}, fmt.Errorf("%w: request key %q", ErrNotFound, idempotencyKey)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("store: get mission pass request key claimed at: %w", err)
	}
	claimedAt, err := parseTime(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("store: get mission pass request key claimed at: %w", err)
	}
	return claimedAt, nil
}

func (s *sqliteStore) ListMissionEvents(ctx context.Context, workspaceID, passID, afterCursor string, limit int) ([]MissionEventRecord, error) {
	return listMissionEvents(ctx, s.db, workspaceID, passID, afterCursor, limit)
}

func (t *sqliteTx) BindInstance(ctx context.Context, rec InstanceRecord) error {
	return bindInstance(ctx, t.tx, t.mode, rec)
}

func (t *sqliteTx) AttachWorkloadIdentity(ctx context.Context, expected, digest string) error {
	return attachWorkloadIdentity(ctx, t.tx, expected, digest)
}

func (t *sqliteTx) PutConnection(ctx context.Context, rec ConnectionRecord) error {
	return putConnection(ctx, t.tx, rec)
}

func (t *sqliteTx) GetConnection(ctx context.Context, workspaceID, connectionID string) (ConnectionRecord, error) {
	return getConnection(ctx, t.tx, workspaceID, connectionID)
}

func (s *sqliteStore) GetGitHubHandoff(ctx context.Context, workspaceID, handoffID string) (GitHubHandoffRecord, error) {
	return getGitHubHandoff(ctx, s.db, workspaceID, handoffID)
}

func (s *sqliteStore) GetGitHubHandoffByID(ctx context.Context, handoffID string) (GitHubHandoffRecord, error) {
	return getGitHubHandoffByID(ctx, s.db, handoffID)
}

func (s *sqliteStore) GetConnection(ctx context.Context, workspaceID, connectionID string) (ConnectionRecord, error) {
	return getConnection(ctx, s.db, workspaceID, connectionID)
}

func (s *sqliteStore) ListConnections(ctx context.Context, workspaceID string) ([]ConnectionRecord, error) {
	return listConnections(ctx, s.db, workspaceID)
}

func (s *sqliteStore) GetWorkflowPosture(ctx context.Context, workspaceID, connectionID, ref string) (WorkflowPostureRecord, error) {
	return getWorkflowPosture(ctx, s.db, workspaceID, connectionID, ref)
}

func (s *sqliteStore) LatestWorkflowPosture(ctx context.Context, workspaceID, connectionID string) (WorkflowPostureRecord, error) {
	return latestWorkflowPosture(ctx, s.db, workspaceID, connectionID)
}

func (t *sqliteTx) PutGitHubHandoff(ctx context.Context, rec GitHubHandoffRecord) error {
	return putGitHubHandoff(ctx, t.tx, rec)
}

func (t *sqliteTx) SetGitHubHandoffUpstream(ctx context.Context, workspaceID, handoffID, upstreamHandoffID string) error {
	return setGitHubHandoffUpstream(ctx, t.tx, workspaceID, handoffID, upstreamHandoffID)
}

func (t *sqliteTx) RecordGitHubHandoffCallback(ctx context.Context, workspaceID, handoffID, codeDigest string, at time.Time) error {
	return recordGitHubHandoffCallback(ctx, t.tx, workspaceID, handoffID, codeDigest, at)
}

func (t *sqliteTx) ConsumeGitHubHandoff(ctx context.Context, workspaceID, handoffID string, at time.Time) error {
	return consumeGitHubHandoff(ctx, t.tx, workspaceID, handoffID, at)
}

func (t *sqliteTx) PutWorkflowPosture(ctx context.Context, rec WorkflowPostureRecord) error {
	return putWorkflowPosture(ctx, t.tx, rec)
}

func (t *sqliteTx) DeleteConnection(ctx context.Context, workspaceID, connectionID string) error {
	return deleteConnection(ctx, t.tx, workspaceID, connectionID)
}

func (t *sqliteTx) PutMissionPass(ctx context.Context, rec MissionPassRecord, expectedStoreRevision int64) error {
	return putMissionPass(ctx, t.tx, rec, expectedStoreRevision)
}

func (t *sqliteTx) GetMissionPass(ctx context.Context, workspaceID, passID string) (MissionPassRecord, error) {
	return getMissionPass(ctx, t.tx, workspaceID, passID)
}

func (t *sqliteTx) PutEventIfAbsent(ctx context.Context, rec MissionEventRecord) (bool, error) {
	return putEventIfAbsent(ctx, t.tx, rec)
}

func (t *sqliteTx) BeginIdempotency(ctx context.Context, rec IdempotencyRecord) (IdempotencyResult, error) {
	return beginIdempotency(ctx, t.tx, rec)
}

func (t *sqliteTx) CompleteIdempotency(ctx context.Context, workspaceID, key string, result []byte) error {
	return completeIdempotency(ctx, t.tx, workspaceID, key, result)
}

func (t *sqliteTx) PutApprovalIntent(ctx context.Context, rec ApprovalIntentRecord) error {
	return putApprovalIntent(ctx, t.tx, rec)
}

func (t *sqliteTx) GetApprovalIntent(ctx context.Context, workspaceID, passID string) (ApprovalIntentRecord, error) {
	return getApprovalIntent(ctx, t.tx, workspaceID, passID)
}

func (t *sqliteTx) CompleteApprovalIntent(ctx context.Context, workspaceID, passID string, operationRef string) error {
	return completeApprovalIntent(ctx, t.tx, workspaceID, passID, operationRef)
}

// putApprovalIntent upserts the durable local intent for one approval
// idempotency key. A retry with the same challenge and attestation is a
// no-op; a retry with a different challenge refreshes the in-flight
// intent. Completed intents are never rewritten.
func putApprovalIntent(ctx context.Context, c dbConn, rec ApprovalIntentRecord) error {
	if rec.WorkspaceID == "" || rec.PassID == "" || rec.IdempotencyKey == "" {
		return fmt.Errorf("store: put approval intent: workspace, pass, and idempotency key are required")
	}
	if rec.State == "" {
		rec.State = ApprovalIntentInFlight
	}
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `INSERT INTO approval_intents
		(workspace_id, pass_id, idempotency_key, operation_ref, state,
		 challenge_id, attestation_digest, attestation_json, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, pass_id) DO UPDATE SET
			operation_ref = CASE WHEN approval_intents.state = 'completed' THEN approval_intents.operation_ref ELSE excluded.operation_ref END,
			state = CASE WHEN approval_intents.state = 'completed' THEN approval_intents.state ELSE excluded.state END,
			challenge_id = CASE WHEN approval_intents.state = 'completed' THEN approval_intents.challenge_id ELSE excluded.challenge_id END,
			attestation_digest = CASE WHEN approval_intents.state = 'completed' THEN approval_intents.attestation_digest ELSE excluded.attestation_digest END,
			attestation_json = CASE WHEN approval_intents.state = 'completed' THEN approval_intents.attestation_json ELSE excluded.attestation_json END,
			updated_at = excluded.updated_at`,
		rec.WorkspaceID, rec.PassID, rec.IdempotencyKey, rec.OperationRef, rec.State,
		rec.ChallengeID, rec.AttestationDigest, rec.AttestationJSON, now, now)
	if err != nil {
		return fmt.Errorf("store: put approval intent: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("store: put approval intent: unexpected rows affected: %v", err)
	}
	return nil
}

func getApprovalIntent(ctx context.Context, c dbConn, workspaceID, passID string) (ApprovalIntentRecord, error) {
	var rec ApprovalIntentRecord
	var created, updated string
	err := c.QueryRowContext(ctx, `SELECT workspace_id, pass_id, idempotency_key,
		operation_ref, state, challenge_id, attestation_digest, attestation_json, created_at, updated_at
		FROM approval_intents WHERE workspace_id = ? AND pass_id = ?`, workspaceID, passID).
		Scan(&rec.WorkspaceID, &rec.PassID, &rec.IdempotencyKey,
			&rec.OperationRef, &rec.State, &rec.ChallengeID, &rec.AttestationDigest,
			&rec.AttestationJSON, &created, &updated)
	if err == sql.ErrNoRows {
		return ApprovalIntentRecord{}, fmt.Errorf("%w: approval intent for pass %q", ErrNotFound, passID)
	}
	if err != nil {
		return ApprovalIntentRecord{}, fmt.Errorf("store: get approval intent: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return ApprovalIntentRecord{}, fmt.Errorf("store: get approval intent: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return ApprovalIntentRecord{}, fmt.Errorf("store: get approval intent: %w", err)
	}
	return rec, nil
}

func completeApprovalIntent(ctx context.Context, c dbConn, workspaceID, passID string, operationRef string) error {
	res, err := c.ExecContext(ctx, `UPDATE approval_intents
		SET state = 'completed', operation_ref = ?, updated_at = ?
		WHERE workspace_id = ? AND pass_id = ? AND state = 'in_flight'`,
		operationRef, formatTime(time.Now()), workspaceID, passID)
	if err != nil {
		return fmt.Errorf("store: complete approval intent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: complete approval intent: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: approval intent for pass %q", ErrNotFound, passID)
	}
	return nil
}

func bindInstance(ctx context.Context, c dbConn, mode string, rec InstanceRecord) error {
	if err := ValidateInstance(rec, mode); err != nil {
		return err
	}
	res, err := c.ExecContext(ctx, `INSERT INTO instance
		(id, instance_id, workspace_id, hostname, origin, rp_id, session_cookie_name, workload_identity_digest, created_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, '', ?) ON CONFLICT(id) DO NOTHING`,
		rec.InstanceID, rec.WorkspaceID, rec.Hostname, rec.Origin, rec.RPID,
		rec.SessionCookieName, formatTime(rec.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: bind instance: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: bind instance: %w", err)
	}
	if n == 1 {
		return nil
	}
	existing, err := getInstance(ctx, c)
	if err != nil {
		return fmt.Errorf("store: bind instance: %w", err)
	}
	if existing.InstanceID != rec.InstanceID ||
		existing.WorkspaceID != rec.WorkspaceID ||
		existing.Hostname != rec.Hostname ||
		existing.Origin != rec.Origin ||
		existing.RPID != rec.RPID ||
		existing.SessionCookieName != rec.SessionCookieName {
		return fmt.Errorf("%w: stored binding for workspace %q, hostname %q differs",
			ErrInstanceRebind, existing.WorkspaceID, existing.Hostname)
	}
	return nil
}

func getInstance(ctx context.Context, c dbConn) (InstanceRecord, error) {
	var rec InstanceRecord
	var created string
	err := c.QueryRowContext(ctx, `SELECT instance_id, workspace_id, hostname, origin, rp_id,
		session_cookie_name, workload_identity_digest, created_at FROM instance WHERE id = 1`).
		Scan(&rec.InstanceID, &rec.WorkspaceID, &rec.Hostname, &rec.Origin,
			&rec.RPID, &rec.SessionCookieName, &rec.WorkloadIdentityDigest, &created)
	if err == sql.ErrNoRows {
		return InstanceRecord{}, ErrNotFound
	}
	if err != nil {
		return InstanceRecord{}, fmt.Errorf("store: get instance: %w", err)
	}
	rec.CreatedAt, err = parseTime(created)
	if err != nil {
		return InstanceRecord{}, fmt.Errorf("store: get instance: %w", err)
	}
	return rec, nil
}

func attachWorkloadIdentity(ctx context.Context, c dbConn, expected, digest string) error {
	if expected != "" {
		return fmt.Errorf("store: attach workload identity: expected must be empty, got %q", expected)
	}
	// Fail closed on a malformed digest before touching the singleton row.
	if err := ValidateWorkloadIdentityDigest(digest); err != nil {
		return fmt.Errorf("store: attach workload identity: %w", err)
	}
	res, err := c.ExecContext(ctx,
		`UPDATE instance SET workload_identity_digest = ? WHERE id = 1 AND workload_identity_digest = ''`, digest)
	if err != nil {
		return fmt.Errorf("store: attach workload identity: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: attach workload identity: %w", err)
	}
	if n == 1 {
		return nil
	}
	if _, err := getInstance(ctx, c); err != nil {
		return err
	}
	return fmt.Errorf("%w: workload identity already attached", ErrConflict)
}

func putConnection(ctx context.Context, c dbConn, rec ConnectionRecord) error {
	if rec.WorkspaceID == "" || rec.ConnectionID == "" {
		return fmt.Errorf("store: put connection: workspace and connection IDs are required")
	}
	if rec.RepositoryBindingRef == "" {
		return fmt.Errorf("store: put connection: repository binding reference is required")
	}
	_, err := c.ExecContext(ctx, `INSERT INTO github_connections
		(workspace_id, connection_id, repository_binding_ref, installation_id, repository_id,
		 repository_name, permission_status, verified_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, connection_id) DO UPDATE SET
			repository_binding_ref = excluded.repository_binding_ref,
			installation_id = excluded.installation_id,
			repository_id = excluded.repository_id,
			repository_name = excluded.repository_name,
			permission_status = excluded.permission_status,
			verified_at = excluded.verified_at,
			created_at = excluded.created_at`,
		rec.WorkspaceID, rec.ConnectionID, rec.RepositoryBindingRef, rec.InstallationID,
		rec.RepositoryID, rec.RepositoryName, rec.PermissionStatus,
		formatTime(rec.VerifiedAt), formatTime(rec.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: put connection: %w", err)
	}
	return nil
}

func scanConnection(row *sql.Row) (ConnectionRecord, error) {
	var rec ConnectionRecord
	var verified, created string
	err := row.Scan(&rec.WorkspaceID, &rec.ConnectionID, &rec.RepositoryBindingRef,
		&rec.InstallationID, &rec.RepositoryID, &rec.RepositoryName,
		&rec.PermissionStatus, &verified, &created)
	if err == sql.ErrNoRows {
		return ConnectionRecord{}, ErrNotFound
	}
	if err != nil {
		return ConnectionRecord{}, fmt.Errorf("store: get connection: %w", err)
	}
	if rec.VerifiedAt, err = parseTime(verified); err != nil {
		return ConnectionRecord{}, fmt.Errorf("store: get connection: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return ConnectionRecord{}, fmt.Errorf("store: get connection: %w", err)
	}
	return rec, nil
}

const connectionColumns = `workspace_id, connection_id, repository_binding_ref, installation_id,
	repository_id, repository_name, permission_status, verified_at, created_at`

func getConnection(ctx context.Context, c dbConn, workspaceID, connectionID string) (ConnectionRecord, error) {
	return scanConnection(c.QueryRowContext(ctx, `SELECT `+connectionColumns+`
		FROM github_connections WHERE workspace_id = ? AND connection_id = ?`, workspaceID, connectionID))
}

func listConnections(ctx context.Context, c dbConn, workspaceID string) ([]ConnectionRecord, error) {
	rows, err := c.QueryContext(ctx, `SELECT `+connectionColumns+`
		FROM github_connections WHERE workspace_id = ? ORDER BY created_at ASC`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("store: list connections: %w", err)
	}
	defer rows.Close()
	var out []ConnectionRecord
	for rows.Next() {
		var rec ConnectionRecord
		var verified, created string
		if err := rows.Scan(&rec.WorkspaceID, &rec.ConnectionID, &rec.RepositoryBindingRef,
			&rec.InstallationID, &rec.RepositoryID, &rec.RepositoryName,
			&rec.PermissionStatus, &verified, &created); err != nil {
			return nil, fmt.Errorf("store: list connections: %w", err)
		}
		if rec.VerifiedAt, err = parseTime(verified); err != nil {
			return nil, fmt.Errorf("store: list connections: %w", err)
		}
		if rec.CreatedAt, err = parseTime(created); err != nil {
			return nil, fmt.Errorf("store: list connections: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list connections: %w", err)
	}
	return out, nil
}

func putGitHubHandoff(ctx context.Context, c dbConn, rec GitHubHandoffRecord) error {
	if rec.WorkspaceID == "" || rec.HandoffID == "" || rec.SessionID == "" {
		return fmt.Errorf("store: put github handoff: workspace, handoff, and session IDs are required")
	}
	if rec.StateHash == "" || rec.AuthScopeOrigin == "" {
		return fmt.Errorf("store: put github handoff: state hash and AuthScope origin are required")
	}
	_, err := c.ExecContext(ctx, `INSERT INTO github_handoffs
		(workspace_id, handoff_id, session_id, state_hash, upstream_handoff_id,
		 binding_code_digest, authscope_origin, expires_at, callback_at, consumed_at)
		VALUES (?, ?, ?, ?, ?, '', ?, ?, NULL, NULL)`,
		rec.WorkspaceID, rec.HandoffID, rec.SessionID, rec.StateHash,
		rec.UpstreamHandoffID, rec.AuthScopeOrigin, formatTime(rec.ExpiresAt))
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: github handoff %q", ErrConflict, rec.HandoffID)
		}
		return fmt.Errorf("store: put github handoff: %w", err)
	}
	return nil
}

func scanGitHubHandoff(row *sql.Row) (GitHubHandoffRecord, error) {
	var rec GitHubHandoffRecord
	var expires string
	var callbackAt, consumedAt sql.NullString
	err := row.Scan(&rec.WorkspaceID, &rec.HandoffID, &rec.SessionID, &rec.StateHash,
		&rec.UpstreamHandoffID, &rec.BindingCodeDigest, &rec.AuthScopeOrigin,
		&expires, &callbackAt, &consumedAt)
	if err == sql.ErrNoRows {
		return GitHubHandoffRecord{}, ErrNotFound
	}
	if err != nil {
		return GitHubHandoffRecord{}, fmt.Errorf("store: get github handoff: %w", err)
	}
	if rec.ExpiresAt, err = parseTime(expires); err != nil {
		return GitHubHandoffRecord{}, fmt.Errorf("store: get github handoff: %w", err)
	}
	if callbackAt.Valid {
		t, err := parseTime(callbackAt.String)
		if err != nil {
			return GitHubHandoffRecord{}, fmt.Errorf("store: get github handoff: %w", err)
		}
		rec.CallbackAt = &t
	}
	if consumedAt.Valid {
		t, err := parseTime(consumedAt.String)
		if err != nil {
			return GitHubHandoffRecord{}, fmt.Errorf("store: get github handoff: %w", err)
		}
		rec.ConsumedAt = &t
	}
	return rec, nil
}

const handoffColumns = `workspace_id, handoff_id, session_id, state_hash, upstream_handoff_id,
	binding_code_digest, authscope_origin, expires_at, callback_at, consumed_at`

func getGitHubHandoff(ctx context.Context, c dbConn, workspaceID, handoffID string) (GitHubHandoffRecord, error) {
	return scanGitHubHandoff(c.QueryRowContext(ctx, `SELECT `+handoffColumns+`
		FROM github_handoffs WHERE workspace_id = ? AND handoff_id = ?`, workspaceID, handoffID))
}

func getGitHubHandoffByID(ctx context.Context, c dbConn, handoffID string) (GitHubHandoffRecord, error) {
	return scanGitHubHandoff(c.QueryRowContext(ctx, `SELECT `+handoffColumns+`
		FROM github_handoffs WHERE handoff_id = ?`, handoffID))
}

func setGitHubHandoffUpstream(ctx context.Context, c dbConn, workspaceID, handoffID, upstreamHandoffID string) error {
	if upstreamHandoffID == "" {
		return fmt.Errorf("store: set github handoff upstream: upstream handoff ID is required")
	}
	res, err := c.ExecContext(ctx, `UPDATE github_handoffs SET upstream_handoff_id = ?
		WHERE workspace_id = ? AND handoff_id = ? AND upstream_handoff_id = ''`,
		upstreamHandoffID, workspaceID, handoffID)
	if err != nil {
		return fmt.Errorf("store: set github handoff upstream: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: set github handoff upstream: %w", err)
	}
	if n == 1 {
		return nil
	}
	if _, err := getGitHubHandoff(ctx, c, workspaceID, handoffID); err != nil {
		return err
	}
	return fmt.Errorf("%w: github handoff %q already has an upstream handoff", ErrConflict, handoffID)
}

func recordGitHubHandoffCallback(ctx context.Context, c dbConn, workspaceID, handoffID, codeDigest string, at time.Time) error {
	if codeDigest == "" {
		return fmt.Errorf("store: record github handoff callback: code digest is required")
	}
	res, err := c.ExecContext(ctx, `UPDATE github_handoffs
		SET binding_code_digest = ?, callback_at = ?
		WHERE workspace_id = ? AND handoff_id = ? AND callback_at IS NULL`,
		codeDigest, formatTime(at), workspaceID, handoffID)
	if err != nil {
		return fmt.Errorf("store: record github handoff callback: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: record github handoff callback: %w", err)
	}
	if n == 1 {
		return nil
	}
	if _, err := getGitHubHandoff(ctx, c, workspaceID, handoffID); err != nil {
		return err
	}
	return fmt.Errorf("%w: github handoff %q callback already recorded", ErrConflict, handoffID)
}

func consumeGitHubHandoff(ctx context.Context, c dbConn, workspaceID, handoffID string, at time.Time) error {
	res, err := c.ExecContext(ctx, `UPDATE github_handoffs SET consumed_at = ?
		WHERE workspace_id = ? AND handoff_id = ? AND consumed_at IS NULL`,
		formatTime(at), workspaceID, handoffID)
	if err != nil {
		return fmt.Errorf("store: consume github handoff: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: consume github handoff: %w", err)
	}
	if n == 1 {
		return nil
	}
	if _, err := getGitHubHandoff(ctx, c, workspaceID, handoffID); err != nil {
		return err
	}
	return fmt.Errorf("%w: github handoff %q already consumed", ErrConflict, handoffID)
}

func deleteConnection(ctx context.Context, c dbConn, workspaceID, connectionID string) error {
	res, err := c.ExecContext(ctx, `DELETE FROM github_connections
		WHERE workspace_id = ? AND connection_id = ?`, workspaceID, connectionID)
	if err != nil {
		return fmt.Errorf("store: delete connection: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete connection: %w", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: connection %q", ErrNotFound, connectionID)
	}
	return nil
}

func putWorkflowPosture(ctx context.Context, c dbConn, rec WorkflowPostureRecord) error {
	if rec.WorkspaceID == "" || rec.ConnectionID == "" || rec.Ref == "" {
		return fmt.Errorf("store: put workflow posture: workspace, connection, and ref are required")
	}
	if rec.PostureDigest == "" || rec.HeadSHA == "" || rec.Outcome == "" {
		return fmt.Errorf("store: put workflow posture: digest, head SHA, and outcome are required")
	}
	reasons, err := encodeReasonCodes(rec.ReasonCodes)
	if err != nil {
		return err
	}
	_, err = c.ExecContext(ctx, `INSERT INTO github_posture_checks
		(workspace_id, connection_id, ref, posture_digest, head_sha, outcome, reason_codes, expires_at, checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, connection_id, ref) DO UPDATE SET
			posture_digest = excluded.posture_digest,
			head_sha = excluded.head_sha,
			outcome = excluded.outcome,
			reason_codes = excluded.reason_codes,
			expires_at = excluded.expires_at,
			checked_at = excluded.checked_at`,
		rec.WorkspaceID, rec.ConnectionID, rec.Ref, rec.PostureDigest, rec.HeadSHA,
		rec.Outcome, reasons, formatTime(rec.ExpiresAt), formatTime(rec.CheckedAt))
	if err != nil {
		return fmt.Errorf("store: put workflow posture: %w", err)
	}
	return nil
}

func scanWorkflowPosture(row *sql.Row) (WorkflowPostureRecord, error) {
	var rec WorkflowPostureRecord
	var reasons, expires, checked string
	err := row.Scan(&rec.WorkspaceID, &rec.ConnectionID, &rec.Ref, &rec.PostureDigest,
		&rec.HeadSHA, &rec.Outcome, &reasons, &expires, &checked)
	if err == sql.ErrNoRows {
		return WorkflowPostureRecord{}, ErrNotFound
	}
	if err != nil {
		return WorkflowPostureRecord{}, fmt.Errorf("store: get workflow posture: %w", err)
	}
	if rec.ReasonCodes, err = decodeReasonCodes(reasons); err != nil {
		return WorkflowPostureRecord{}, fmt.Errorf("store: get workflow posture: %w", err)
	}
	if rec.ExpiresAt, err = parseTime(expires); err != nil {
		return WorkflowPostureRecord{}, fmt.Errorf("store: get workflow posture: %w", err)
	}
	if rec.CheckedAt, err = parseTime(checked); err != nil {
		return WorkflowPostureRecord{}, fmt.Errorf("store: get workflow posture: %w", err)
	}
	return rec, nil
}

const postureColumns = `workspace_id, connection_id, ref, posture_digest, head_sha, outcome, reason_codes, expires_at, checked_at`

func getWorkflowPosture(ctx context.Context, c dbConn, workspaceID, connectionID, ref string) (WorkflowPostureRecord, error) {
	return scanWorkflowPosture(c.QueryRowContext(ctx, `SELECT `+postureColumns+`
		FROM github_posture_checks WHERE workspace_id = ? AND connection_id = ? AND ref = ?`,
		workspaceID, connectionID, ref))
}

func latestWorkflowPosture(ctx context.Context, c dbConn, workspaceID, connectionID string) (WorkflowPostureRecord, error) {
	return scanWorkflowPosture(c.QueryRowContext(ctx, `SELECT `+postureColumns+`
		FROM github_posture_checks WHERE workspace_id = ? AND connection_id = ?
		ORDER BY checked_at DESC LIMIT 1`, workspaceID, connectionID))
}

func putMissionPass(ctx context.Context, c dbConn, rec MissionPassRecord, expectedStoreRevision int64) error {
	if rec.WorkspaceID == "" || rec.PassID == "" {
		return fmt.Errorf("store: put mission pass: workspace and pass IDs are required")
	}
	if expectedStoreRevision < 0 {
		return fmt.Errorf("store: put mission pass: negative expected revision")
	}
	runnerArgs, err := encodeStringSlice(rec.RunnerArguments)
	if err != nil {
		return fmt.Errorf("store: put mission pass: %w", err)
	}
	criteria, err := encodeStringSlice(rec.AcceptanceCriteria)
	if err != nil {
		return fmt.Errorf("store: put mission pass: %w", err)
	}
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE mission_passes
		SET store_revision = store_revision + 1,
		    draft_version = ?,
		    authscope_mission_version = ?,
		    connection_id = ?,
		    issue_number = ?,
		    repository_name = ?,
		    proposal_id = ?,
		    proposal_digest = ?,
		    approved_proposal_digest = ?,
		    source_revision = ?,
		    source_digest = ?,
		    base_sha = ?,
		    mission_branch = ?,
		    agent_kit_id = ?,
		    agent_kit_version = ?,
		    runner_arguments = ?,
		    invocation_digest = ?,
		    expires_at = ?,
		    max_aggregate_cost_micros = ?,
		    objective = ?,
		    acceptance_criteria = ?,
		    shaped_draft_json = ?,
		    state = ?,
		    reconciliation = ?,
		    mission_ref = ?,
		    mission_hash = ?,
		    approval_decision_ref = ?,
		    attestation_digest = ?,
		    run_id = ?,
		    containment = ?,
		    receipt_pending_at = ?,
		    updated_at = ?
		WHERE workspace_id = ? AND pass_id = ? AND store_revision = ?`,
		rec.DraftVersion, rec.AuthScopeMissionVersion,
		rec.ConnectionID, rec.IssueNumber, rec.RepositoryName,
		rec.ProposalID, rec.ProposalDigest, rec.ApprovedProposalDigest,
		rec.SourceRevision, rec.SourceDigest, rec.BaseSHA, rec.MissionBranch,
		rec.AgentKitID, rec.AgentKitVersion, runnerArgs, rec.InvocationDigest,
		formatOptionalTime(rec.ExpiresAt), rec.MaxAggregateCostMicros,
		rec.Objective, criteria, rec.ShapedDraftJSON,
		rec.State, rec.Reconciliation,
		rec.MissionRef, rec.MissionHash, rec.ApprovalDecisionRef,
		rec.AttestationDigest, rec.RunID, rec.Containment, formatOptionalTime(rec.ReceiptPendingAt), now,
		rec.WorkspaceID, rec.PassID, expectedStoreRevision)
	if err != nil {
		return fmt.Errorf("store: put mission pass: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: put mission pass: %w", err)
	}
	if n == 1 {
		return nil
	}
	if expectedStoreRevision != 0 {
		return fmt.Errorf("%w: expected store revision %d", ErrConflict, expectedStoreRevision)
	}
	_, err = c.ExecContext(ctx, `INSERT INTO mission_passes
		(workspace_id, pass_id, store_revision, draft_version, authscope_mission_version,
		 connection_id, issue_number, repository_name,
		 proposal_id, proposal_digest, approved_proposal_digest,
		 source_revision, source_digest, base_sha, mission_branch,
		 agent_kit_id, agent_kit_version, runner_arguments, invocation_digest,
		 expires_at, max_aggregate_cost_micros, objective, acceptance_criteria,
		 shaped_draft_json, state, reconciliation,
		 mission_ref, mission_hash, approval_decision_ref, attestation_digest, run_id,
		 containment, receipt_pending_at,
		 created_at, updated_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.PassID, rec.DraftVersion, rec.AuthScopeMissionVersion,
		rec.ConnectionID, rec.IssueNumber, rec.RepositoryName,
		rec.ProposalID, rec.ProposalDigest, rec.ApprovedProposalDigest,
		rec.SourceRevision, rec.SourceDigest, rec.BaseSHA, rec.MissionBranch,
		rec.AgentKitID, rec.AgentKitVersion, runnerArgs, rec.InvocationDigest,
		formatOptionalTime(rec.ExpiresAt), rec.MaxAggregateCostMicros, rec.Objective, criteria,
		rec.ShapedDraftJSON, rec.State, rec.Reconciliation,
		rec.MissionRef, rec.MissionHash, rec.ApprovalDecisionRef, rec.AttestationDigest, rec.RunID,
		rec.Containment, formatOptionalTime(rec.ReceiptPendingAt),
		formatTime(rec.CreatedAt), now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: pass already exists", ErrConflict)
		}
		return fmt.Errorf("store: put mission pass: %w", err)
	}
	return nil
}

const missionPassColumns = `workspace_id, pass_id, store_revision, draft_version,
	authscope_mission_version, connection_id, issue_number, repository_name,
	proposal_id, proposal_digest, approved_proposal_digest,
	source_revision, source_digest, base_sha, mission_branch,
	agent_kit_id, agent_kit_version, runner_arguments, invocation_digest,
	expires_at, max_aggregate_cost_micros, objective, acceptance_criteria,
	shaped_draft_json, state, reconciliation,
	mission_ref, mission_hash, approval_decision_ref, attestation_digest, run_id,
	containment, receipt_pending_at,
	created_at, updated_at`

func getMissionPass(ctx context.Context, c dbConn, workspaceID, passID string) (MissionPassRecord, error) {
	var rec MissionPassRecord
	var runnerArgs, criteria, expires, receiptPending, created, updated string
	err := c.QueryRowContext(ctx, `SELECT `+missionPassColumns+`
		FROM mission_passes WHERE workspace_id = ? AND pass_id = ?`, workspaceID, passID).
		Scan(&rec.WorkspaceID, &rec.PassID, &rec.StoreRevision, &rec.DraftVersion,
			&rec.AuthScopeMissionVersion, &rec.ConnectionID, &rec.IssueNumber, &rec.RepositoryName,
			&rec.ProposalID, &rec.ProposalDigest, &rec.ApprovedProposalDigest,
			&rec.SourceRevision, &rec.SourceDigest, &rec.BaseSHA, &rec.MissionBranch,
			&rec.AgentKitID, &rec.AgentKitVersion, &runnerArgs, &rec.InvocationDigest,
			&expires, &rec.MaxAggregateCostMicros, &rec.Objective, &criteria,
			&rec.ShapedDraftJSON, &rec.State, &rec.Reconciliation,
			&rec.MissionRef, &rec.MissionHash, &rec.ApprovalDecisionRef,
			&rec.AttestationDigest, &rec.RunID, &rec.Containment, &receiptPending, &created, &updated)
	if err == sql.ErrNoRows {
		return MissionPassRecord{}, fmt.Errorf("%w: mission pass %q", ErrNotFound, passID)
	}
	if err != nil {
		return MissionPassRecord{}, fmt.Errorf("store: get mission pass: %w", err)
	}
	if rec.RunnerArguments, err = decodeStringSlice(runnerArgs); err != nil {
		return MissionPassRecord{}, fmt.Errorf("store: get mission pass: %w", err)
	}
	if rec.AcceptanceCriteria, err = decodeStringSlice(criteria); err != nil {
		return MissionPassRecord{}, fmt.Errorf("store: get mission pass: %w", err)
	}
	if rec.ExpiresAt, err = parseOptionalTime(expires); err != nil {
		return MissionPassRecord{}, fmt.Errorf("store: get mission pass: %w", err)
	}
	if rec.ReceiptPendingAt, err = parseOptionalTime(receiptPending); err != nil {
		return MissionPassRecord{}, fmt.Errorf("store: get mission pass: %w", err)
	}
	if rec.CreatedAt, err = parseTime(created); err != nil {
		return MissionPassRecord{}, fmt.Errorf("store: get mission pass: %w", err)
	}
	if rec.UpdatedAt, err = parseTime(updated); err != nil {
		return MissionPassRecord{}, fmt.Errorf("store: get mission pass: %w", err)
	}
	return rec, nil
}

// encodeStringSlice stores a string slice as a JSON array. A corrupt value
// fails closed on read instead of silently yielding no entries.
func encodeStringSlice(vals []string) (string, error) {
	if vals == nil {
		vals = []string{}
	}
	raw, err := json.Marshal(vals)
	if err != nil {
		return "", fmt.Errorf("store: encode string slice: %w", err)
	}
	return string(raw), nil
}

func decodeStringSlice(raw string) ([]string, error) {
	var vals []string
	if err := json.Unmarshal([]byte(raw), &vals); err != nil {
		return nil, fmt.Errorf("store: decode string slice: %w", err)
	}
	if vals == nil {
		vals = []string{}
	}
	return vals, nil
}

// formatOptionalTime renders a possibly-zero time for a nullable column.
func formatOptionalTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return formatTime(t)
}

// parseOptionalTime parses a nullable time column; empty means zero.
func parseOptionalTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return parseTime(s)
}

func putEventIfAbsent(ctx context.Context, c dbConn, rec MissionEventRecord) (bool, error) {
	if rec.WorkspaceID == "" || rec.PassID == "" || rec.EventID == "" {
		return false, fmt.Errorf("store: put event: workspace, pass, and event IDs are required")
	}
	res, err := c.ExecContext(ctx, `INSERT INTO mission_events
		(workspace_id, pass_id, event_id, event_type, cursor, payload, occurred_at, ingested_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, pass_id, event_id) DO NOTHING`,
		rec.WorkspaceID, rec.PassID, rec.EventID, rec.EventType, rec.Cursor,
		rec.Payload, formatTime(rec.OccurredAt), formatTime(time.Now()))
	if err != nil {
		return false, fmt.Errorf("store: put event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: put event: %w", err)
	}
	return n == 1, nil
}

func listMissionEvents(ctx context.Context, c dbConn, workspaceID, passID, afterCursor string, limit int) ([]MissionEventRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := c.QueryContext(ctx, `SELECT workspace_id, pass_id, event_id, event_type, cursor, payload, occurred_at
		FROM mission_events
		WHERE workspace_id = ? AND pass_id = ? AND cursor > ?
		ORDER BY cursor ASC, event_id ASC LIMIT ?`, workspaceID, passID, afterCursor, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list mission events: %w", err)
	}
	defer rows.Close()
	var out []MissionEventRecord
	for rows.Next() {
		var rec MissionEventRecord
		var occurred string
		if err := rows.Scan(&rec.WorkspaceID, &rec.PassID, &rec.EventID, &rec.EventType,
			&rec.Cursor, &rec.Payload, &occurred); err != nil {
			return nil, fmt.Errorf("store: list mission events: %w", err)
		}
		if rec.OccurredAt, err = parseTime(occurred); err != nil {
			return nil, fmt.Errorf("store: list mission events: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list mission events: %w", err)
	}
	return out, nil
}

func beginIdempotency(ctx context.Context, c dbConn, rec IdempotencyRecord) (IdempotencyResult, error) {
	if rec.WorkspaceID == "" || rec.Key == "" || rec.CanonicalDigest == "" {
		return IdempotencyResult{}, fmt.Errorf("store: begin idempotency: workspace, key, and digest are required")
	}
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `INSERT INTO idempotency_records
		(workspace_id, idempotency_key, canonical_digest, status, created_at, updated_at)
		VALUES (?, ?, ?, 'inflight', ?, ?)
		ON CONFLICT(workspace_id, idempotency_key) DO NOTHING`,
		rec.WorkspaceID, rec.Key, rec.CanonicalDigest, now, now)
	if err != nil {
		return IdempotencyResult{}, fmt.Errorf("store: begin idempotency: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return IdempotencyResult{}, fmt.Errorf("store: begin idempotency: %w", err)
	}
	if n == 1 {
		return IdempotencyResult{}, nil
	}
	var digest, status string
	var result []byte
	err = c.QueryRowContext(ctx, `SELECT canonical_digest, status, result FROM idempotency_records
		WHERE workspace_id = ? AND idempotency_key = ?`, rec.WorkspaceID, rec.Key).
		Scan(&digest, &status, &result)
	if err != nil {
		return IdempotencyResult{}, fmt.Errorf("store: begin idempotency: %w", err)
	}
	if digest != rec.CanonicalDigest {
		return IdempotencyResult{}, fmt.Errorf("%w: key %q", ErrIdempotencyMismatch, rec.Key)
	}
	return IdempotencyResult{Replay: true, Completed: status == "completed", Result: result}, nil
}

func completeIdempotency(ctx context.Context, c dbConn, workspaceID, key string, result []byte) error {
	res, err := c.ExecContext(ctx, `UPDATE idempotency_records
		SET status = 'completed', result = ?, updated_at = ?
		WHERE workspace_id = ? AND idempotency_key = ? AND status = 'inflight'`,
		result, formatTime(time.Now()), workspaceID, key)
	if err != nil {
		return fmt.Errorf("store: complete idempotency: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: complete idempotency: %w", err)
	}
	if n == 1 {
		return nil
	}
	var status string
	err = c.QueryRowContext(ctx, `SELECT status FROM idempotency_records
		WHERE workspace_id = ? AND idempotency_key = ?`, workspaceID, key).Scan(&status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: idempotency key %q", ErrNotFound, key)
	}
	if err != nil {
		return fmt.Errorf("store: complete idempotency: %w", err)
	}
	return fmt.Errorf("%w: idempotency key %q already %s", ErrConflict, key, status)
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// encodeReasonCodes renders reason codes as a JSON array for storage.
// The codes are a fixed allowlist; encoding never fails on valid input,
// but the error is surfaced rather than silently dropped.
func encodeReasonCodes(codes []string) (string, error) {
	if codes == nil {
		codes = []string{}
	}
	raw, err := json.Marshal(codes)
	if err != nil {
		return "", fmt.Errorf("store: encode reason codes: %w", err)
	}
	return string(raw), nil
}

// decodeReasonCodes parses the stored JSON reason-code array. A corrupt
// value fails closed instead of silently yielding no reasons.
func decodeReasonCodes(raw string) ([]string, error) {
	var codes []string
	if err := json.Unmarshal([]byte(raw), &codes); err != nil {
		return nil, fmt.Errorf("store: decode reason codes: %w", err)
	}
	if codes == nil {
		codes = []string{}
	}
	return codes, nil
}

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
