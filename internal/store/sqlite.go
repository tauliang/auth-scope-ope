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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/001_initial.sql
var migrationFS embed.FS

// initialMigration is the DDL for the presentation store, kept as a .sql
// migration file and embedded at compile time.
func loadInitialMigration() (string, error) {
	b, err := migrationFS.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return "", fmt.Errorf("store: read embedded migration: %w", err)
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
}

type sqliteTx struct {
	tx   *sql.Tx
	mode string
}

// Open opens (creating if needed) the presentation store in dataDir. The
// database file is <dataDir>/ope.db. mode is "development" or "release" and
// controls the data-path hardening checks.
func Open(dataDir, mode string) (Store, error) {
	if mode != "development" && mode != "release" {
		return nil, fmt.Errorf("store: invalid mode %q", mode)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
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
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = '001_initial'`).Scan(&count); err != nil {
		return fmt.Errorf("store: check migrations: %w", err)
	}
	if count > 0 {
		return nil
	}
	migration, err := loadInitialMigration()
	if err != nil {
		return err
	}
	if _, err := db.Exec(migration); err != nil {
		return fmt.Errorf("store: apply 001_initial: %w", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES ('001_initial', ?)`, formatTime(time.Now())); err != nil {
		return fmt.Errorf("store: record migration: %w", err)
	}
	return nil
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
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
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("store: rollback after %v: %w", err, rbErr)
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

func (t *sqliteTx) PutMissionPass(ctx context.Context, rec MissionPassRecord, expectedStoreRevision int64) error {
	return putMissionPass(ctx, t.tx, rec, expectedStoreRevision)
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
	if digest == "" {
		return fmt.Errorf("store: attach workload identity: digest is required")
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
	_, err := c.ExecContext(ctx, `INSERT INTO github_connections
		(workspace_id, connection_id, repository_binding_ref, repository_id, repository_name, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(workspace_id, connection_id) DO UPDATE SET
			repository_binding_ref = excluded.repository_binding_ref,
			repository_id = excluded.repository_id,
			repository_name = excluded.repository_name,
			created_at = excluded.created_at`,
		rec.WorkspaceID, rec.ConnectionID, rec.RepositoryBindingRef,
		rec.RepositoryID, rec.RepositoryName, formatTime(rec.CreatedAt))
	if err != nil {
		return fmt.Errorf("store: put connection: %w", err)
	}
	return nil
}

func putMissionPass(ctx context.Context, c dbConn, rec MissionPassRecord, expectedStoreRevision int64) error {
	if rec.WorkspaceID == "" || rec.PassID == "" {
		return fmt.Errorf("store: put mission pass: workspace and pass IDs are required")
	}
	if expectedStoreRevision < 0 {
		return fmt.Errorf("store: put mission pass: negative expected revision")
	}
	now := formatTime(time.Now())
	res, err := c.ExecContext(ctx, `UPDATE mission_passes
		SET store_revision = store_revision + 1,
		    draft_version = ?,
		    authscope_mission_version = ?,
		    state = ?,
		    updated_at = ?
		WHERE workspace_id = ? AND pass_id = ? AND store_revision = ?`,
		rec.DraftVersion, rec.AuthScopeMissionVersion, rec.State, now,
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
		(workspace_id, pass_id, store_revision, draft_version, authscope_mission_version, state, created_at, updated_at)
		VALUES (?, ?, 1, ?, ?, ?, ?, ?)`,
		rec.WorkspaceID, rec.PassID, rec.DraftVersion, rec.AuthScopeMissionVersion,
		rec.State, formatTime(rec.CreatedAt), now)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: pass already exists", ErrConflict)
		}
		return fmt.Errorf("store: put mission pass: %w", err)
	}
	return nil
}

func getMissionPass(ctx context.Context, c dbConn, workspaceID, passID string) (MissionPassRecord, error) {
	var rec MissionPassRecord
	var created, updated string
	err := c.QueryRowContext(ctx, `SELECT workspace_id, pass_id, store_revision, draft_version,
		authscope_mission_version, state, created_at, updated_at
		FROM mission_passes WHERE workspace_id = ? AND pass_id = ?`, workspaceID, passID).
		Scan(&rec.WorkspaceID, &rec.PassID, &rec.StoreRevision, &rec.DraftVersion,
			&rec.AuthScopeMissionVersion, &rec.State, &created, &updated)
	if err == sql.ErrNoRows {
		return MissionPassRecord{}, fmt.Errorf("%w: mission pass %q", ErrNotFound, passID)
	}
	if err != nil {
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

func formatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
