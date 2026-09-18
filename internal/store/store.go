// Package store is the local, non-authoritative presentation store for one
// OPE instance. Every business key begins with workspace_id, so records from
// one workspace can never be read or written through another workspace's
// key. The store holds workspace-qualified references, passkey public
// credentials, hashed sessions, event cursors, and idempotency results. It
// never holds GitHub tokens, AuthScope refresh tokens, private keys, raw
// issue bodies, patches, agent transcripts, or receipt secrets.
package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound reports a missing record.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict reports a failed compare-and-swap: the local revision moved
	// under the caller, a create raced an existing row, or a singleton was
	// already attached.
	ErrConflict = errors.New("store: conflict")
	// ErrInstanceRebind reports an attempt to change the immutable instance
	// binding (workspace, hostname, origin, RP ID, instance ID, or cookie
	// name) after it was established.
	ErrInstanceRebind = errors.New("store: instance rebind rejected")
	// ErrIdempotencyMismatch reports an idempotency key reused with a
	// different canonical digest, meaning a different operation.
	ErrIdempotencyMismatch = errors.New("store: idempotency key reused with different digest")
	// ErrUnsafeDataPath reports a data directory or database file that fails
	// the release-mode hardening checks (symlink, or group/world permission
	// bits).
	ErrUnsafeDataPath = errors.New("store: unsafe data path")
)

// Store is the read side of the presentation store plus transaction entry.
// The immutable instance binding is established once via Tx.BindInstance
// before HTTP serving starts; later tasks only read it through GetInstance.
type Store interface {
	// WithTx runs fn inside a single transaction. The transaction commits
	// when fn returns nil and rolls back otherwise.
	WithTx(context.Context, func(Tx) error) error
	// GetInstance returns the immutable instance binding, or ErrNotFound
	// before BindInstance has run.
	GetInstance(context.Context) (InstanceRecord, error)
	// GetMissionPass returns one workspace-qualified mission pass.
	GetMissionPass(ctx context.Context, workspaceID, passID string) (MissionPassRecord, error)
	// ListMissionEvents returns up to limit events for a pass, ordered by
	// cursor, strictly after afterCursor (empty means from the start).
	ListMissionEvents(ctx context.Context, workspaceID, passID, afterCursor string, limit int) ([]MissionEventRecord, error)
	// Close releases the database connection.
	Close() error
}

// Tx is the write side of the presentation store. Every method is
// workspace-qualified; callers pass the workspace explicitly so a missing or
// wrong workspace fails closed instead of defaulting.
type Tx interface {
	// BindInstance inserts the singleton instance binding exactly once.
	// Rebinding with identical values is a no-op; any change to the binding
	// fields returns ErrInstanceRebind.
	BindInstance(context.Context, InstanceRecord) error
	// AttachWorkloadIdentity attaches the workload-identity digest exactly
	// once, only while it is empty. expected must be the empty string; any
	// later attempt returns ErrConflict and no path replaces the digest.
	AttachWorkloadIdentity(ctx context.Context, expected string, digest string) error
	// PutConnection upserts a workspace-qualified GitHub connection holding
	// only the AuthScope repository-binding reference and immutable
	// repository identity. No GitHub token or App private key is stored.
	PutConnection(context.Context, ConnectionRecord) error
	// PutMissionPass creates or compare-and-swap updates a mission pass.
	// expectedStoreRevision is the local CAS token: 0 creates the row with
	// store_revision 1, any other value must match the stored revision. The
	// update increments store_revision by one and requires exactly one
	// affected row, otherwise ErrConflict.
	PutMissionPass(ctx context.Context, rec MissionPassRecord, expectedStoreRevision int64) error
	// PutEventIfAbsent appends a mission event idempotently. It returns true
	// when the event was inserted and false when an event with the same
	// workspace-qualified event ID already exists.
	PutEventIfAbsent(context.Context, MissionEventRecord) (bool, error)
	// BeginIdempotency starts or replays an idempotent operation. A new key
	// returns Replay=false; a known key with the same canonical digest
	// returns Replay=true with the stored result when completed; a known key
	// with a different digest returns ErrIdempotencyMismatch.
	BeginIdempotency(context.Context, IdempotencyRecord) (IdempotencyResult, error)
	// CompleteIdempotency records the result of an in-flight operation.
	CompleteIdempotency(ctx context.Context, workspaceID, key string, result []byte) error
}

// InstanceRecord is the immutable binding of one OPE instance. It is
// written once at startup before HTTP serving and never updated, except for
// the workload-identity digest which Task 4 attaches exactly once.
type InstanceRecord struct {
	InstanceID             string
	WorkspaceID            string
	Hostname               string
	Origin                 string
	RPID                   string
	SessionCookieName      string
	WorkloadIdentityDigest string // empty until Task 4 attaches it exactly once
	CreatedAt              time.Time
}

// MissionPassRecord is the local presentation state of one mission pass.
// StoreRevision is the local compare-and-swap token and increments on every
// mutation; DraftVersion is the founder-visible proposal revision;
// AuthScopeMissionVersion is the upstream authority version and changes only
// from authenticated upstream results.
type MissionPassRecord struct {
	WorkspaceID             string
	PassID                  string
	StoreRevision           int64
	DraftVersion            int64
	AuthScopeMissionVersion int64
	State                   string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}

// MissionEventRecord is one projected, allowlisted event for a pass.
type MissionEventRecord struct {
	WorkspaceID string
	PassID      string
	EventID     string
	EventType   string
	Cursor      string
	Payload     string // JSON with allowlisted safe fields only
	OccurredAt  time.Time
}

// ConnectionRecord is a workspace-qualified GitHub repository connection. It
// stores only the AuthScope repository-binding reference and immutable
// repository identity, never tokens or keys.
type ConnectionRecord struct {
	WorkspaceID          string
	ConnectionID         string
	RepositoryBindingRef string
	RepositoryID         int64
	RepositoryName       string
	CreatedAt            time.Time
}

// IdempotencyRecord starts an idempotent operation. CanonicalDigest is the
// canonical digest of the operation's inputs; reusing a key with a different
// digest is a programmer error and fails with ErrIdempotencyMismatch.
type IdempotencyRecord struct {
	WorkspaceID     string
	Key             string
	CanonicalDigest string
}

// IdempotencyResult is the outcome of BeginIdempotency.
type IdempotencyResult struct {
	// Replay is true when the key was seen before with the same digest.
	Replay bool
	// Completed is true when a previous attempt finished and Result holds
	// its stored result.
	Completed bool
	Result    []byte
}
