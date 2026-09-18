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
	// CountFounders returns the number of enrolled founders in a workspace.
	CountFounders(ctx context.Context, workspaceID string) (int, error)
	// ListFounders returns every enrolled founder in a workspace.
	ListFounders(ctx context.Context, workspaceID string) ([]FounderRecord, error)
	// ListWebAuthnCredentials returns the registered passkey public
	// credentials of one founder.
	ListWebAuthnCredentials(ctx context.Context, workspaceID, founderID string) ([]WebAuthnCredentialRecord, error)
	// GetSessionByHash returns the session holding the given hex SHA-256
	// token hash, or ErrNotFound. Raw session tokens are never stored.
	GetSessionByHash(ctx context.Context, workspaceID, sessionHash string) (SessionRecord, error)
	// GetBootstrapCode returns the active (unconsumed) bootstrap code for a
	// workspace, or ErrNotFound when none is active.
	GetBootstrapCode(ctx context.Context, workspaceID string) (BootstrapCodeRecord, error)
	// GetOfflineRecoveryKey returns the stored offline recovery key hash of
	// one founder, or ErrNotFound.
	GetOfflineRecoveryKey(ctx context.Context, workspaceID, founderID string) (OfflineRecoveryKeyRecord, error)
	// GetConnection returns one workspace-qualified GitHub connection, or
	// ErrNotFound.
	GetConnection(ctx context.Context, workspaceID, connectionID string) (ConnectionRecord, error)
	// ListConnections returns every GitHub connection of a workspace.
	ListConnections(ctx context.Context, workspaceID string) ([]ConnectionRecord, error)
	// GetGitHubHandoff returns one workspace-qualified handoff record, or
	// ErrNotFound.
	GetGitHubHandoff(ctx context.Context, workspaceID, handoffID string) (GitHubHandoffRecord, error)
	// GetGitHubHandoffByID returns a handoff by its unguessable ID without
	// a workspace qualifier. Only the unauthenticated AuthScope callback
	// may use it; every later step re-verifies the workspace against the
	// founder session.
	GetGitHubHandoffByID(ctx context.Context, handoffID string) (GitHubHandoffRecord, error)
	// GetWorkflowPosture returns the persisted posture check for a
	// connection and ref, or ErrNotFound.
	GetWorkflowPosture(ctx context.Context, workspaceID, connectionID, ref string) (WorkflowPostureRecord, error)
	// LatestWorkflowPosture returns the most recently checked posture for a
	// connection, or ErrNotFound when none was ever inspected.
	LatestWorkflowPosture(ctx context.Context, workspaceID, connectionID string) (WorkflowPostureRecord, error)
	// ClaimMissionPassRequestKey records (workspace, idempotency key) ->
	// pass for a draft-open request. It is insert-or-ignore: it returns
	// the pass ID that owns the key, which may belong to an earlier
	// racing request with the same key.
	ClaimMissionPassRequestKey(ctx context.Context, workspaceID, idempotencyKey, passID string) (string, error)
	// GetMissionPassIDByRequestKey returns the pass ID owning a
	// draft-open idempotency key, or "" when the key was never claimed.
	GetMissionPassIDByRequestKey(ctx context.Context, workspaceID, idempotencyKey string) (string, error)
	// DeleteMissionPassRequestKey removes a key mapping. It is only
	// called when no pass row exists for the mapped pass: releasing a
	// failed draft-open attempt's key, or reclaiming a mapping whose
	// owner died without persisting. It never removes a mapping that a
	// live attempt might still persist under.
	DeleteMissionPassRequestKey(ctx context.Context, workspaceID, idempotencyKey string) error
	// GetMissionPassRequestKeyClaimedAt returns when a draft-open
	// idempotency key was claimed, or ErrNotFound when the key was never
	// claimed. It lets the service tell a still-running owner apart from
	// a mapping whose owner died without persisting.
	GetMissionPassRequestKeyClaimedAt(ctx context.Context, workspaceID, idempotencyKey string) (time.Time, error)
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
	// Reconnection replaces a revoked binding transactionally: the row is
	// overwritten in full, never merged with the revoked binding's state.
	PutConnection(context.Context, ConnectionRecord) error
	// PutGitHubHandoff inserts one handoff record. A duplicate handoff ID
	// returns ErrConflict.
	PutGitHubHandoff(context.Context, GitHubHandoffRecord) error
	// SetGitHubHandoffUpstream records the upstream handoff ID once the
	// begin call settles. It fails with ErrNotFound for an unknown
	// handoff.
	SetGitHubHandoffUpstream(ctx context.Context, workspaceID, handoffID, upstreamHandoffID string) error
	// RecordGitHubHandoffCallback records the binding-code digest and the
	// callback time exactly once. A second callback for the same handoff
	// returns ErrConflict and never replaces the recorded digest.
	RecordGitHubHandoffCallback(ctx context.Context, workspaceID, handoffID, codeDigest string, at time.Time) error
	// ConsumeGitHubHandoff marks a handoff consumed after finish settles.
	// A second consumption returns ErrConflict.
	ConsumeGitHubHandoff(ctx context.Context, workspaceID, handoffID string, at time.Time) error
	// PutWorkflowPosture upserts the posture check for a connection and
	// ref, storing only the digest, head SHA, outcome, reason codes, and
	// expiry.
	PutWorkflowPosture(context.Context, WorkflowPostureRecord) error
	// DeleteConnection removes one workspace-qualified GitHub connection.
	// Reconnection uses it to replace a revoked binding transactionally.
	DeleteConnection(ctx context.Context, workspaceID, connectionID string) error
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
	// CreateFounder enrolls a founder. A second founder in the same
	// workspace returns ErrConflict: v1 serves exactly one founder per
	// instance.
	CreateFounder(ctx context.Context, rec FounderRecord) error
	// PutWebAuthnCredential stores a passkey public credential. Reusing a
	// credential ID returns ErrConflict; private key material must never
	// reach the store.
	PutWebAuthnCredential(ctx context.Context, rec WebAuthnCredentialRecord) error
	// UpdateWebAuthnCredentialSignCount advances the stored sign count. The
	// new count must be greater than the stored one; otherwise ErrConflict
	// reports a possible cloned authenticator.
	UpdateWebAuthnCredentialSignCount(ctx context.Context, workspaceID, credentialID string, signCount uint32) error
	// CreateSession stores a session record holding only the SHA-256 hashes
	// of the session token and CSRF token. A duplicate token hash returns
	// ErrConflict.
	CreateSession(ctx context.Context, rec SessionRecord) error
	// RevokeSession marks one session revoked. Revoking an unknown session
	// returns ErrNotFound.
	RevokeSession(ctx context.Context, workspaceID, sessionID string) error
	// PutBootstrapCode replaces the active bootstrap code of a workspace.
	// Only the SHA-256 hash of the code is stored.
	PutBootstrapCode(ctx context.Context, rec BootstrapCodeRecord) error
	// ConsumeBootstrapCode marks the active code consumed. It fails with
	// ErrNotFound when no active code matches and ErrConflict when the code
	// is already consumed or expired.
	ConsumeBootstrapCode(ctx context.Context, workspaceID, codeHash string, now time.Time) error
	// PutOfflineRecoveryKey stores the hash of a founder's offline recovery
	// key. A second key for the same founder returns ErrConflict.
	PutOfflineRecoveryKey(ctx context.Context, rec OfflineRecoveryKeyRecord) error
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

// HasWorkloadIdentity reports whether the stable workload-identity digest
// has been attached to the instance record.
func (r InstanceRecord) HasWorkloadIdentity() bool {
	return r.WorkloadIdentityDigest != ""
}

// MissionPassRecord is the local presentation state of one mission pass.
// StoreRevision is the local compare-and-swap token and increments on every
// mutation; DraftVersion is the founder-visible proposal revision;
// AuthScopeMissionVersion is the upstream authority version and changes only
// from authenticated upstream results. Task 6 adds the exact upstream
// proposal fields: AuthScope's returned proposal ID, algorithm-tagged
// proposal and invocation digests, fixed agent-kit identity, ordered runner
// arguments, pinned source identifiers, the generated mission branch, and
// the two editable limits. ApprovedProposalDigest stays empty until
// approval copies the approved value. Reconciliation tracks whether the
// last upstream proposal mutation has a known outcome.
type MissionPassRecord struct {
	WorkspaceID             string
	PassID                  string
	StoreRevision           int64
	DraftVersion            int64
	AuthScopeMissionVersion int64
	ConnectionID            string
	IssueNumber             int64
	RepositoryName          string
	ProposalID              string
	ProposalDigest          string
	ApprovedProposalDigest  string
	SourceRevision          string
	SourceDigest            string
	BaseSHA                 string
	MissionBranch           string
	AgentKitID              string
	AgentKitVersion         string
	RunnerArguments         []string
	InvocationDigest        string
	ExpiresAt               time.Time
	MaxAggregateCostMicros  int64
	Objective               string
	AcceptanceCriteria      []string
	ShapedDraftJSON         string
	State                   string
	Reconciliation          string
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
// repository identity, never tokens or keys. PermissionStatus is the last
// verified permission state ("ok", "insufficient", "revoked", or
// "unknown"); VerifiedAt is when AuthScope last confirmed the binding.
type ConnectionRecord struct {
	WorkspaceID          string
	ConnectionID         string
	RepositoryBindingRef string
	InstallationID       int64
	RepositoryID         int64
	RepositoryName       string
	PermissionStatus     string
	VerifiedAt           time.Time
	CreatedAt            time.Time
}

// GitHubHandoffRecord is the durable half of an AuthScope-hosted GitHub
// App installation handoff. StateHash is the hex SHA-256 of the 256-bit
// state; BindingCodeDigest is the hex SHA-256 of the one-use binding
// code, empty until the callback. The raw binding code is never stored:
// it lives only in a bounded in-memory cache until finish, restart, or
// expiry.
type GitHubHandoffRecord struct {
	WorkspaceID       string
	HandoffID         string
	SessionID         string
	StateHash         string
	UpstreamHandoffID string
	BindingCodeDigest string
	AuthScopeOrigin   string
	ExpiresAt         time.Time
	CallbackAt        *time.Time
	ConsumedAt        *time.Time
}

// WorkflowPostureRecord is one persisted workflow-posture inspection. Only
// the posture digest, the inspected head SHA, the outcome, reason codes,
// and expiry are stored; workflow file contents never reach the store.
type WorkflowPostureRecord struct {
	WorkspaceID   string
	ConnectionID  string
	Ref           string
	PostureDigest string
	HeadSHA       string
	Outcome       string // "clean" or "risky"
	ReasonCodes   []string
	ExpiresAt     time.Time
	CheckedAt     time.Time
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

// FounderRecord is one enrolled founder of a workspace. V1 serves exactly
// one founder per instance.
type FounderRecord struct {
	WorkspaceID string
	FounderID   string
	DisplayName string
	CreatedAt   time.Time
}

// WebAuthnCredentialRecord is one registered passkey public credential. It
// stores public key material only; private key material never reaches the
// store. CredentialID is the base64url-encoded credential ID.
type WebAuthnCredentialRecord struct {
	WorkspaceID  string
	CredentialID string
	FounderID    string
	PublicKey    []byte
	SignCount    uint32
	Transports   string // comma-joined transport names
	CreatedAt    time.Time
}

// SessionRecord is one local founder session. Only the SHA-256 hashes of
// the opaque session token and the session-bound CSRF token are stored;
// the raw values exist only in the founder's cookie and memory.
type SessionRecord struct {
	WorkspaceID   string
	SessionID     string
	SessionHash   string // hex SHA-256 of the opaque session token
	FounderID     string
	CSRFTokenHash string // hex SHA-256 of the session-bound CSRF token
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Revoked       bool
}

// BootstrapCodeRecord is a one-use terminal bootstrap code. Only the
// SHA-256 hash of the code is stored; the raw code is printed once to the
// controlling terminal at serve start.
type BootstrapCodeRecord struct {
	WorkspaceID string
	CodeHash    string // hex SHA-256 of the 128-bit code
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
}

// OfflineRecoveryKeyRecord is the stored hash of a founder's offline
// recovery key. The raw key is displayed once during enrollment and
// confirmed by proof of possession; the browser never sees it again.
type OfflineRecoveryKeyRecord struct {
	WorkspaceID string
	FounderID   string
	KeyHash     string // hex SHA-256 of the 256-bit recovery key
	CreatedAt   time.Time
}
