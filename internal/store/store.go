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
	// ErrDatabaseLocked reports an exclusive open refused because another
	// process holds the data-directory lock. The offline recovery command
	// fails with this error while the server owns the database.
	ErrDatabaseLocked = errors.New("store: database is locked by another process")
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
	// GetOrCreateTelemetrySalt returns the instance-local telemetry
	// salt, generating and persisting 32 random bytes on first use. The
	// salt pseudonymizes the installation ID in telemetry events so the
	// raw instance ID never leaves the store.
	GetOrCreateTelemetrySalt(context.Context) ([]byte, error)
	// InsertTelemetryEvent records one validated telemetry event. The
	// record carries only the fixed allowlisted fields.
	InsertTelemetryEvent(ctx context.Context, rec TelemetryEventRecord) error
	// ListTelemetryEvents returns telemetry events of a workspace,
	// newest first, up to limit. Test and audit support.
	ListTelemetryEvents(ctx context.Context, workspaceID string, limit int) ([]TelemetryEventRecord, error)
	// GetMissionPass returns one workspace-qualified mission pass.
	GetMissionPass(ctx context.Context, workspaceID, passID string) (MissionPassRecord, error)
	// ListMissionPasses returns every mission pass of a workspace, oldest
	// first. The reconciliation worker uses it to resume each nonterminal
	// mission from its durable cursor.
	ListMissionPasses(ctx context.Context, workspaceID string) ([]MissionPassRecord, error)
	// ListMissionEvents returns up to limit events for a pass, ordered by
	// cursor, strictly after afterCursor (empty means from the start).
	ListMissionEvents(ctx context.Context, workspaceID, passID, afterCursor string, limit int) ([]MissionEventRecord, error)
	// GetMissionProjection returns the durable event-projection state of a
	// pass, or ErrNotFound when no event was ever projected.
	GetMissionProjection(ctx context.Context, workspaceID, passID string) (MissionProjection, error)
	// GetReceiptView returns the stored receipt view for a pass, or
	// ErrNotFound when no receipt was verified yet.
	GetReceiptView(ctx context.Context, workspaceID, passID string) (ReceiptViewRecord, error)
	// GetLatestCheckPublicationForPass returns the newest publication
	// intent for a pass, or ErrNotFound when nothing was published yet.
	GetLatestCheckPublicationForPass(ctx context.Context, workspaceID, passID string) (CheckPublicationRecord, error)
	// ListCheckPublications returns the publication intents of a
	// workspace in the given state, oldest first. An empty state lists
	// every intent.
	ListCheckPublications(ctx context.Context, workspaceID, state string) ([]CheckPublicationRecord, error)
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
	// GetCLIAuthorization returns one workspace-qualified CLI
	// authorization, or ErrNotFound.
	GetCLIAuthorization(ctx context.Context, workspaceID, authorizationID string) (CLIAuthorization, error)
	// GetCLIAuthorizationByState returns the pending authorization opened
	// with the given pass and state, or ErrNotFound. Create uses it for
	// idempotent replay: the same canonical request replays, changed
	// content conflicts.
	GetCLIAuthorizationByState(ctx context.Context, workspaceID, passID, state string) (CLIAuthorization, error)
	// GetCLIAuthorizationByCodeHash returns the approved authorization
	// holding the given code hash, or ErrNotFound. The launch exchange
	// uses it to resolve an authorization code without ever storing the
	// code itself.
	GetCLIAuthorizationByCodeHash(ctx context.Context, workspaceID string, codeHash [32]byte) (CLIAuthorization, error)
	// GetCLIRevocation returns one workspace-qualified CLI revocation
	// request, or ErrNotFound.
	GetCLIRevocation(ctx context.Context, workspaceID, requestID string) (CLIRevocation, error)
	// GetCLIRevocationByState returns the pending revocation request opened
	// with the given pass and state, or ErrNotFound. Create uses it for
	// idempotent replay: the same canonical request replays, changed
	// content conflicts.
	GetCLIRevocationByState(ctx context.Context, workspaceID, passID, state string) (CLIRevocation, error)
	// GetCLIRevocationByCodeHash returns the revocation request holding
	// the given result code hash, or ErrNotFound. The token exchange uses
	// it to resolve a result code without ever storing the code itself.
	GetCLIRevocationByCodeHash(ctx context.Context, workspaceID string, codeHash [32]byte) (CLIRevocation, error)
	// ListRevocationIntents returns the revocation intents of a workspace
	// in the given state, oldest first. The reconciliation worker uses it
	// to resume ambiguous revocations without re-issuing them.
	ListRevocationIntents(ctx context.Context, workspaceID, state string) ([]RevocationIntentRecord, error)
	// GetRecoveryIntent returns the durable offline recovery intent for
	// an idempotency key, or ErrNotFound.
	GetRecoveryIntent(ctx context.Context, workspaceID, idempotencyKey string) (RecoveryIntentRecord, error)
	// GetRecoveryEvent returns one workspace-qualified recovery event,
	// or ErrNotFound.
	GetRecoveryEvent(ctx context.Context, workspaceID, eventID string) (RecoveryEventRecord, error)
	// ListRecoveryEvents returns the non-secret recovery events of a
	// workspace, newest first, capped at limit (zero means ten).
	ListRecoveryEvents(ctx context.Context, workspaceID string, limit int) ([]RecoveryEventRecord, error)
	// GetWorkerLease returns the server-owned reconciliation worker
	// lease for an instance, or ErrNotFound when no lease row exists.
	GetWorkerLease(ctx context.Context, instanceID string) (WorkerLeaseRecord, error)
	// ListExpansionIntents returns the expansion decision intents of a
	// workspace in the given state, oldest first. The reconciliation
	// worker uses it to resume ambiguous decisions without re-issuing
	// them.
	ListExpansionIntents(ctx context.Context, workspaceID, state string) ([]ExpansionIntentRecord, error)
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
	// GetConnection returns one workspace-qualified GitHub connection
	// inside the transaction, or ErrNotFound.
	GetConnection(ctx context.Context, workspaceID, connectionID string) (ConnectionRecord, error)
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
	// GetMissionPass returns one workspace-qualified mission pass inside
	// the transaction, or ErrNotFound.
	GetMissionPass(ctx context.Context, workspaceID, passID string) (MissionPassRecord, error)
	// GetMissionProjection returns the durable event-projection state of a
	// pass inside the transaction, or ErrNotFound when no event was ever
	// projected.
	GetMissionProjection(ctx context.Context, workspaceID, passID string) (MissionProjection, error)
	// ListMissionEvents returns up to limit events for a pass inside the
	// transaction, ordered by cursor, strictly after afterCursor.
	ListMissionEvents(ctx context.Context, workspaceID, passID, afterCursor string, limit int) ([]MissionEventRecord, error)
	// BeginIdempotency starts or replays an idempotent operation. A new key
	// returns Replay=false; a known key with the same canonical digest
	// returns Replay=true with the stored result when completed; a known key
	// with a different digest returns ErrIdempotencyMismatch.
	BeginIdempotency(context.Context, IdempotencyRecord) (IdempotencyResult, error)
	// CompleteIdempotency records the result of an in-flight operation.
	CompleteIdempotency(ctx context.Context, workspaceID, key string, result []byte) error
	// PutApprovalIntent upserts the durable local intent for an approval
	// idempotency key. It is written before the upstream approval call so
	// an ambiguous outcome can be reconciled without re-issuing approval.
	PutApprovalIntent(ctx context.Context, rec ApprovalIntentRecord) error
	// GetApprovalIntent returns the durable approval intent for a pass.
	GetApprovalIntent(ctx context.Context, workspaceID, passID string) (ApprovalIntentRecord, error)
	// CompleteApprovalIntent marks the approval intent completed with the
	// upstream operation reference.
	CompleteApprovalIntent(ctx context.Context, workspaceID, passID string, operationRef string) error
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
	// PutCLIAuthorization inserts one pending CLI authorization. A
	// duplicate authorization ID returns ErrConflict. Only hashes of
	// secret values are stored: the raw verifier and code never reach the
	// store.
	PutCLIAuthorization(ctx context.Context, rec CLIAuthorization) error
	// ApproveCLIAuthorization atomically marks an authorization approved,
	// recording the consumed decision challenge, the attestation digest,
	// and the code hash. It affects exactly one row: an unknown ID or an
	// already-approved authorization returns ErrConflict, which rejects
	// duplicate and concurrent finishes.
	ApproveCLIAuthorization(ctx context.Context, workspaceID, authorizationID, decisionChallengeID, attestationDigest string, codeHash [32]byte, approvedAt time.Time) error
	// ClaimLaunchExchangeIntent atomically inserts one exchange intent row
	// keyed by the code hash. It reports false (without error) when the
	// code hash is already claimed. Only digests and run metadata are
	// stored: the sealed envelope and the attestation never reach the
	// store.
	ClaimLaunchExchangeIntent(ctx context.Context, intent LaunchExchangeIntent, now time.Time) (bool, error)
	// GetLaunchExchangeIntent returns one workspace-qualified exchange
	// intent by code hash, or ErrNotFound.
	GetLaunchExchangeIntent(ctx context.Context, workspaceID, codeHash string) (LaunchExchangeIntent, error)
	// SettleLaunchExchangeIntent moves an in-flight intent to completed or
	// failed exactly once, recording the run id and envelope digest on
	// success. A second settle returns ErrConflict.
	SettleLaunchExchangeIntent(ctx context.Context, workspaceID, codeHash, status, runID, envelopeDigest, failure string, now time.Time) error
	// AdvanceProjection records projection progress after a page: the
	// authority page cursor moves forward only, the local event sequence
	// and projected mission version move upward only, and the projection
	// stays marked compatible. It upserts the projection row.
	AdvanceProjection(ctx context.Context, workspaceID, passID, pageCursor string, eventSeq, missionVersion int64) error
	// AdvanceProjectionCursor moves the authority page cursor forward
	// without storing an event, for pages that carry no new events.
	AdvanceProjectionCursor(ctx context.Context, workspaceID, passID, pageCursor string) error
	// MarkProjectionIncompatible discards forward progress for an unknown
	// authenticated event type: the payload is never stored, the cursor
	// stays unchanged, and the projection is marked incompatible and
	// stale with the fixed local reason. Business mutations fail closed
	// until a parser and pinned-contract upgrade replays from the
	// unchanged cursor.
	MarkProjectionIncompatible(ctx context.Context, workspaceID, passID, reason string) error
	// MarkProjectionCompatible clears the incompatibility gate after a
	// parser and pinned-contract upgrade, so replay from the unchanged
	// cursor can resume.
	MarkProjectionCompatible(ctx context.Context, workspaceID, passID string) error
	// AcquireWorkerLease takes the instance worker lease for owner when
	// no live lease exists. It returns false when another live owner
	// holds the lease.
	AcquireWorkerLease(ctx context.Context, instanceID, owner string, ttl time.Duration) (bool, error)
	// HeartbeatWorkerLease renews the lease the owner holds. It returns
	// false when the owner no longer holds the lease.
	HeartbeatWorkerLease(ctx context.Context, instanceID, owner string, ttl time.Duration) (bool, error)
	// ReleaseWorkerLease drops the lease the owner holds. It is a no-op
	// when the owner does not hold it.
	ReleaseWorkerLease(ctx context.Context, instanceID, owner string) error
	// PutRevocationIntent upserts the durable local intent for one
	// revocation idempotency key. It is written before the upstream
	// RevokeMission call so an ambiguous outcome reconciles by the same
	// key. Completed intents are never rewritten.
	PutRevocationIntent(ctx context.Context, rec RevocationIntentRecord) error
	// GetRevocationIntent returns the durable revocation intent for a
	// pass, or ErrNotFound.
	GetRevocationIntent(ctx context.Context, workspaceID, passID string) (RevocationIntentRecord, error)
	// CompleteRevocationIntent marks the revocation intent completed with
	// the containment state and the upstream revocation reference.
	CompleteRevocationIntent(ctx context.Context, workspaceID, passID, containment, upstreamRef string) error
	// PutExpansion upserts the locally projected expansion delta for one
	// upstream expansion request. Only allowlisted canonical fields are
	// stored; the delta JSON must already be verified against the
	// expansion digest by the caller.
	PutExpansion(ctx context.Context, rec ExpansionRecord) error
	// GetExpansion returns the locally projected expansion, or
	// ErrNotFound.
	GetExpansion(ctx context.Context, workspaceID, expansionID string) (ExpansionRecord, error)
	// ListExpansions returns the locally projected expansions of a pass
	// in the given status, oldest first.
	ListExpansions(ctx context.Context, workspaceID, passID, status string) ([]ExpansionRecord, error)
	// ResolveExpansion marks a locally projected expansion with a final
	// status such as approved, denied, or expired.
	ResolveExpansion(ctx context.Context, workspaceID, expansionID, status string) error
	// PutExpansionIntent upserts the durable local intent for one
	// expansion decision idempotency key. It is written before the
	// upstream DecideExpansion call so an ambiguous outcome reconciles by
	// the same key. Completed intents are never rewritten.
	PutExpansionIntent(ctx context.Context, rec ExpansionIntentRecord) error
	// GetExpansionIntent returns the durable expansion decision intent
	// for an expansion, or ErrNotFound.
	GetExpansionIntent(ctx context.Context, workspaceID, expansionID string) (ExpansionIntentRecord, error)
	// CompleteExpansionIntent marks the expansion decision intent
	// completed with the decision reference and the resulting upstream
	// mission version.
	CompleteExpansionIntent(ctx context.Context, workspaceID, expansionID, decisionRef string, resultMissionVersion int64) error
	// ListExpansionIntents returns the expansion decision intents of a
	// workspace in the given state, oldest first.
	ListExpansionIntents(ctx context.Context, workspaceID, state string) ([]ExpansionIntentRecord, error)
	// PutReceiptView upserts the verified receipt projection (or the
	// unverifiable verdict) for a pass. The raw signed envelope is never
	// persisted: only the receipt digest and the fixed verified fields.
	// A verified view never overwrites an unverifiable verdict for a
	// different receipt digest; that case is a dispute and is surfaced,
	// not silently replaced.
	PutReceiptView(context.Context, ReceiptViewRecord) error
	// GetReceiptView returns the stored receipt view for a pass, or
	// ErrNotFound when no receipt was verified yet.
	GetReceiptView(ctx context.Context, workspaceID, passID string) (ReceiptViewRecord, error)
	// PutCheckPublicationIfAbsent inserts the durable intent behind one
	// GitHub check publication idempotency key. It returns true when the
	// intent was inserted and false when the key already exists.
	PutCheckPublicationIfAbsent(context.Context, CheckPublicationRecord) (bool, error)
	// GetCheckPublication returns the publication intent for an
	// idempotency key, or ErrNotFound.
	GetCheckPublication(ctx context.Context, workspaceID, idempotencyKey string) (CheckPublicationRecord, error)
	// GetLatestCheckPublicationForPass returns the newest publication
	// intent for a pass, or ErrNotFound when nothing was published yet.
	GetLatestCheckPublicationForPass(ctx context.Context, workspaceID, passID string) (CheckPublicationRecord, error)
	// ListCheckPublications returns the publication intents of a
	// workspace in the given state, oldest first. An empty state lists
	// every intent.
	ListCheckPublications(ctx context.Context, workspaceID, state string) ([]CheckPublicationRecord, error)
	// SetCheckPublicationState moves a publication intent to a new state
	// and records the upstream check run ID when known.
	SetCheckPublicationState(ctx context.Context, workspaceID, idempotencyKey, state, checkRunID string, at time.Time) error
	// MarkCheckPublicationsDisputedExcept marks every non-settled
	// publication intent of a pass disputed except the given key. It is
	// used when a newer receipt digest supersedes the published one.
	MarkCheckPublicationsDisputedExcept(ctx context.Context, workspaceID, passID, exceptKey string, at time.Time) error
	// PutCLIRevocation inserts one pending CLI revocation request. A
	// duplicate request ID returns ErrConflict. Only hashes of secret
	// values are stored: the raw result code and verifier never reach the
	// store.
	PutCLIRevocation(ctx context.Context, rec CLIRevocation) error
	// MintCLIRevocationResult records the one-use result code hash, the
	// opaque result reference, and the fixed containment state for a
	// revocation request whose upstream result settled or became pending
	// reconciliation. It affects exactly one unminted row; an unknown ID
	// or an already-minted request returns ErrConflict.
	MintCLIRevocationResult(ctx context.Context, workspaceID, requestID, resultRef, containment string, codeHash [32]byte, now time.Time) error
	// ConsumeCLIRevocationResult atomically marks a minted result consumed
	// and returns its opaque reference. An identical retry after a lost
	// response returns only the original reference; it never mints a
	// second result.
	ConsumeCLIRevocationResult(ctx context.Context, workspaceID string, codeHash [32]byte, now time.Time) (string, string, error)
	// PutRecoveryIntent inserts the durable local intent behind one
	// offline recovery idempotency key. It is written before the upstream
	// ContainWorkspace call so an ambiguous outcome reconciles by the
	// same key. A duplicate idempotency key returns ErrConflict.
	PutRecoveryIntent(ctx context.Context, rec RecoveryIntentRecord) error
	// GetRecoveryIntent returns the durable recovery intent for an
	// idempotency key, or ErrNotFound.
	GetRecoveryIntent(ctx context.Context, workspaceID, idempotencyKey string) (RecoveryIntentRecord, error)
	// SetRecoveryIntentAttestation records the digest of the signed
	// containment attestation on a pending intent. It affects exactly
	// one pending row; any other state returns ErrConflict.
	SetRecoveryIntentAttestation(ctx context.Context, workspaceID, idempotencyKey, attestationDigest string, at time.Time) error
	// SetRecoveryIntentContained moves a pending intent to contained
	// after AuthScope acknowledged the workspace containment, recording
	// the containment generation. It affects exactly one pending row.
	SetRecoveryIntentContained(ctx context.Context, workspaceID, idempotencyKey string, generation int64, at time.Time) error
	// SetRecoveryIntentVerifiedEmpty moves a contained intent to
	// verified_empty after the authoritative ListActiveMissions view
	// returned an empty list. It affects exactly one contained row.
	SetRecoveryIntentVerifiedEmpty(ctx context.Context, workspaceID, idempotencyKey string, at time.Time) error
	// SetRecoveryIntentCompleted moves a verified_empty intent to
	// completed, recording the recovery event and the reset outcome. It
	// affects exactly one verified_empty row.
	SetRecoveryIntentCompleted(ctx context.Context, workspaceID, idempotencyKey, eventID string, revokedSessions, containedMissions int, bootstrapExpiresAt, at time.Time) error
	// PutRecoveryEvent records the non-secret durable recovery event. A
	// duplicate event ID returns ErrConflict. No recovery-key material
	// is stored here.
	PutRecoveryEvent(ctx context.Context, rec RecoveryEventRecord) error
	// GetRecoveryEvent returns one workspace-qualified recovery event,
	// or ErrNotFound.
	GetRecoveryEvent(ctx context.Context, workspaceID, eventID string) (RecoveryEventRecord, error)
	// GetWorkerLease returns the server-owned reconciliation worker
	// lease for an instance, or ErrNotFound when no lease row exists.
	GetWorkerLease(ctx context.Context, instanceID string) (WorkerLeaseRecord, error)
	// RevokeAllSessions marks every unrevoked web session of a
	// workspace revoked and returns the revoked count. It is the local
	// half of offline recovery: every founder session dies at once.
	RevokeAllSessions(ctx context.Context, workspaceID string) (int, error)
	// ResetLaunchHandoffs deletes every CLI authorization, CLI
	// revocation, and launch-exchange intent row of a workspace. These
	// are one-use handoff records; after an offline recovery they are
	// invalid and never resume.
	ResetLaunchHandoffs(ctx context.Context, workspaceID string) error
	// DeleteAllWebAuthnCredentials deletes every passkey public
	// credential of a workspace and returns the deleted count. The
	// founder re-enrolls credentials through the recovery bootstrap
	// code.
	DeleteAllWebAuthnCredentials(ctx context.Context, workspaceID string) (int, error)
	// ConsumeOfflineRecoveryKey deletes a founder's offline recovery key
	// hash. The key is one-use: recovery consumes it in the same
	// transaction that resets authentication state. A missing key
	// returns ErrNotFound.
	ConsumeOfflineRecoveryKey(ctx context.Context, workspaceID, founderID string) error
	// DeleteFounder removes a founder row. Offline recovery deletes the
	// founder whose credentials were all revoked and deleted, so the
	// fresh bootstrap code can re-enroll the workspace. Pass-scoped
	// presentation state is untouched.
	DeleteFounder(ctx context.Context, workspaceID, founderID string) error
}

// LaunchExchangeIntent is the durable reservation for one authorization
// code exchange. Status is one of "in_flight", "completed", or "failed".
// The row carries only digests and run metadata.
type LaunchExchangeIntent struct {
	WorkspaceID       string
	CodeHash          string // hex SHA-256 of the decoded authorization code
	AuthorizationID   string
	PassID            string
	RunID             string
	Status            string
	AttestationDigest string
	EnvelopeDigest    string // "sha256:..." of the sealed signed envelope
	Failure           string
	CreatedAt         time.Time
	UpdatedAt         time.Time
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

// TelemetryEventRecord is one persisted telemetry event. It mirrors the
// allowlisted telemetry.Event: step name, duration, pseudonymized
// installation ID, opaque pass/run identifiers, fixed error code,
// enforcement level, intervention count, and fixed outcome class. No
// content fields exist by construction.
type TelemetryEventRecord struct {
	WorkspaceID       string
	Name              string
	DurationMillis    int64
	InstallationID    string // pseudonymized with the instance-local salt
	PassID            string
	RunID             string
	ErrorCode         string
	EnforcementLevel  string
	InterventionCount int64
	OutcomeClass      string
	OccurredAt        time.Time
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
	// MissionRef is the upstream AuthScope mission reference created by
	// approval. It is empty until the pass is approved.
	MissionRef string
	// MissionHash is the algorithm-tagged digest of the created mission.
	MissionHash string
	// ApprovalDecisionRef is the local reference for the signed approval
	// decision attestation.
	ApprovalDecisionRef string
	// AttestationDigest is the sha256 digest of the signed decision
	// attestation produced at approval time.
	AttestationDigest string
	// RunID stays empty on approval: approval creates only the mission, and
	// a launch run is created later.
	RunID string
	// Containment is the last known upstream revocation containment:
	// "acknowledged", "pending", or "partial". Empty until the first
	// revocation. A pending containment is reconciled by the
	// server-owned worker.
	Containment string
	// ReceiptPendingAt records when the upstream receipt-ready signal was
	// projected. It is zero until then. The worker verifies the receipt
	// locally and only the verified receipt moves the pass terminal.
	ReceiptPendingAt time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// ApprovalIntentState values for ApprovalIntentRecord.
const (
	// ApprovalIntentInFlight means an approval upstream call is in progress
	// or its outcome is unknown; reconciliation may settle it.
	ApprovalIntentInFlight = "in_flight"
	// ApprovalIntentCompleted means the approval settled and the pass was
	// persisted as approved.
	ApprovalIntentCompleted = "completed"
)

// ApprovalIntentRecord is the durable local intent behind one approval
// idempotency key. It is written before the upstream ApproveProposal call
// so an ambiguous upstream outcome (timeout, dropped response, crash) can
// be reconciled later without ever re-issuing the approval.
type ApprovalIntentRecord struct {
	WorkspaceID       string
	PassID            string
	IdempotencyKey    string
	OperationRef      string
	State             string
	ChallengeID       string
	AttestationDigest string
	// AttestationJSON is the original signed decision attestation, so an
	// idempotent replay carries the exact original call.
	AttestationJSON string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// MissionProjection is the durable event-projection state of one pass:
// the cursor the reconciliation worker resumes from, and the
// compatibility gate. An unknown authenticated event type marks the
// projection incompatible and stale with a fixed local reason, leaves the
// cursor unchanged, and blocks business mutations until a parser and
// pinned-contract upgrade replays from that cursor.
type MissionProjection struct {
	WorkspaceID           string
	PassID                string
	Cursor                string
	EventSeq              int64
	MissionVersion        int64
	Compatible            bool
	Stale                 bool
	IncompatibilityReason string
	UpdatedAt             time.Time
}

// IncompatibleProjectionReason is the fixed local reason recorded when an
// unknown authenticated event type arrives. It names no payload content.
const IncompatibleProjectionReason = "unknown event type: parser and pinned contract upgrade required"

// RevocationIntentState values for RevocationIntentRecord.
const (
	// RevocationIntentInFlight means a revocation upstream call is in
	// progress or its outcome is unknown; reconciliation may settle it.
	RevocationIntentInFlight = "in_flight"
	// RevocationIntentCompleted means the revocation settled and the pass
	// was persisted with its containment state.
	RevocationIntentCompleted = "completed"
)

// Revocation containment states recorded on the pass and the intent.
const (
	// ContainmentAcknowledged means the upstream acknowledged gateway
	// containment for the revocation.
	ContainmentAcknowledged = "acknowledged"
	// ContainmentPending means the revocation outcome is ambiguous; the
	// worker reconciles it by the original idempotency key.
	ContainmentPending = "pending"
	// ContainmentPartial means the upstream recorded the revocation but
	// did not acknowledge full gateway containment.
	ContainmentPartial = "partial"
)

// RevocationIntentRecord is the durable local intent behind one
// revocation idempotency key. It is written before the upstream
// RevokeMission call so an ambiguous upstream outcome (timeout, dropped
// response, crash) reconciles later without ever re-issuing the
// revocation.
type RevocationIntentRecord struct {
	WorkspaceID       string
	PassID            string
	IdempotencyKey    string
	ReasonCode        string
	CanonicalDigest   string // hex SHA-256 of the canonical revocation bytes
	State             string
	Containment       string
	AttestationDigest string
	// AttestationJSON is the original signed decision attestation, so an
	// idempotent replay carries the exact original call.
	AttestationJSON string
	UpstreamRef     string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Expansion statuses for locally projected expansions.
const (
	ExpansionPending  = "pending"
	ExpansionApproved = "approved"
	ExpansionDenied   = "denied"
	ExpansionExpired  = "expired"
)

// ExpansionRecord is one locally projected expansion delta: the exact
// canonical upstream delta under review. It is the single source of
// truth the browser reads; only allowlisted canonical fields are
// stored in DeltaJSON, never raw upstream payloads.
type ExpansionRecord struct {
	WorkspaceID     string
	ExpansionID     string
	PassID          string
	MissionRef      string
	Status          string
	DeltaJSON       string
	ExpansionDigest string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Expansion intent states mirror the revocation intent lifecycle.
const (
	ExpansionIntentInFlight  = "in_flight"
	ExpansionIntentCompleted = "completed"
)

// ExpansionIntentRecord is the durable local intent behind one
// expansion decision idempotency key. Decision is approve_once or deny;
// CanonicalDigest is the hex SHA-256 of the canonical expansion
// binding the founder signed.
type ExpansionIntentRecord struct {
	WorkspaceID          string
	ExpansionID          string
	PassID               string
	IdempotencyKey       string
	Decision             string
	CanonicalDigest      string
	State                string
	AttestationDigest    string
	AttestationJSON      string
	UpstreamRef          string
	ResultMissionVersion int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// Receipt verification states persisted for a pass. ReceiptStatePending
// is the implicit state of a pass with no receipt view row yet.
const (
	ReceiptStatePending = "pending"
	ReceiptVerified     = "verified"
	ReceiptUnverifiable = "unverifiable"
)

// ReceiptViewRecord is the persisted verified receipt projection for a
// pass, or the latched unverifiable verdict. The raw signed envelope
// is never stored: only the receipt digest and the fixed verified
// fields. JSON columns carry the structured sub-documents; private
// detail URLs and secret material are stripped before the row is
// written.
type ReceiptViewRecord struct {
	WorkspaceID               string
	PassID                    string
	Verification              string
	ReasonCode                string
	ReceiptID                 string
	GrantID                   string
	MissionRef                string
	KeyID                     string
	SignedAt                  time.Time
	ReceiptDigest             string
	SettlementDigest          string
	Outcome                   string
	MissionVersionsJSON       string
	ExpansionDecisionRefsJSON string
	RepositoryID              int64
	IssueNumber               int64
	Branch                    string
	PullRequestNumber         int64
	HeadSHA                   string
	ChecksJSON                string
	StartedAt                 time.Time
	FinishedAt                time.Time
	AggregateCostMicros       int64
	BudgetMicros              int64
	HistoricalEnforcementJSON string
	VerifiedAt                time.Time
}

// Check publication intent states mirror the revocation intent
// lifecycle, plus disputed for a superseded or conflicting upstream
// check.
const (
	CheckPublicationInFlight = "in_flight"
	CheckPublicationSettled  = "settled"
	CheckPublicationDisputed = "disputed"
)

// CheckPublicationRecord is the durable intent behind one GitHub check
// publication idempotency key. The key is derived from the workspace,
// the receipt digest, and the repository binding triple, so retries
// and duplicate deliveries never create a second check run. Only the
// minimal public check content is ever published; the row carries no
// receipt payload.
type CheckPublicationRecord struct {
	WorkspaceID       string
	PassID            string
	IdempotencyKey    string
	ReceiptDigest     string
	RepositoryID      int64
	PullRequestNumber int64
	HeadSHA           string
	BindingID         string
	State             string
	CheckRunID        string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// CLIRevocation is the durable record for a result-only loopback PKCE
// revocation handoff. Only hashes of secret values are stored: the
// SHA-256 of the one-use result code, never the raw code or verifier.
// The token exchange returns only the opaque result reference plus the
// fixed containment state; no CLI credential or session is issued or
// stored.
type CLIRevocation struct {
	WorkspaceID       string
	RequestID         string
	PassID            string
	State             string // original state, for the loopback redirect
	CodeChallenge     string // S256 only
	RedirectURI       string // exact loopback callback
	CanonicalDigest   string // hex SHA-256 of the server-canonical revocation binding
	ReasonCode        string // unused: the founder picks the reason in the browser
	ResultRef         string // opaque revocation-result reference
	ResultContainment string // fixed containment state for the result
	CodeHash          [32]byte
	ResultConsumedAt  *time.Time
	ExpiresAt         time.Time
	CreatedAt         time.Time
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

// CLIAuthorization is the durable record for a one-use browser PKCE
// handoff. Only hashes of secret values are stored: the SHA-256 of the
// authorization code, never the raw code or verifier. The signed decision
// attestation lives only in process memory, never here.
type CLIAuthorization struct {
	WorkspaceID               string
	AuthorizationID           string
	PassID                    string
	State                     string // original state, for the loopback redirect
	CodeChallenge             string // S256 only
	RedirectURI               string // exact loopback callback
	EphemeralPublicKey        string // base64url X25519 public key
	ProposalDigest            string
	InvocationDigest          string
	AgentKitID                string
	AgentKitVersion           string
	RunnerArguments           []string
	MissionRef                string
	MissionVersion            int64
	CanonicalRequestDigest    [32]byte
	DecisionChallengeID       string
	DecisionAttestationDigest string
	CodeHash                  [32]byte
	ApprovedAt                *time.Time
	ExpiresAt                 time.Time
	CreatedAt                 time.Time
}

// Recovery intent states for RecoveryIntentRecord. The offline recovery
// flow moves one step at a time: pending (intent persisted, containment
// not yet acknowledged), contained (AuthScope acknowledged the bulk
// containment), verified_empty (the authoritative active-mission list
// came back empty), completed (local authentication state reset and the
// recovery event recorded). A crash resumes from the recorded state.
const (
	RecoveryIntentPending       = "pending"
	RecoveryIntentContained     = "contained"
	RecoveryIntentVerifiedEmpty = "verified_empty"
	RecoveryIntentCompleted     = "completed"
)

// RecoveryIntentRecord is the durable local intent behind one offline
// recovery idempotency key. It is written before the upstream
// ContainWorkspace call so an ambiguous outcome (timeout, dropped
// response, crash) reconciles by the same key without ever re-containing
// the workspace. Nonce is the hex of the 32-byte attestation nonce.
type RecoveryIntentRecord struct {
	WorkspaceID           string
	IdempotencyKey        string
	IntentID              string
	CanonicalDigest       string
	AttestationDigest     string
	Nonce                 string
	State                 string
	ContainmentGeneration int64
	RecoveryEventID       string
	RevokedSessionCount   int
	ContainedMissionCount int
	BootstrapExpiresAt    time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// RecoveryEventRecord is the durable, non-secret record of one completed
// offline recovery. It names the workspace, the founder, how many active
// missions the bulk containment covered, and the digests binding the
// event to the signed containment attestation and the fresh bootstrap
// code. No recovery-key material is stored here.
type RecoveryEventRecord struct {
	WorkspaceID           string
	EventID               string
	FounderID             string
	IdempotencyKey        string
	ContainedMissionCount int
	ContainmentGeneration int64
	AttestationDigest     string
	RecoveryProofDigest   string
	BootstrapCodeHash     string
	OccurredAt            time.Time
}

// WorkerLeaseRecord is the server-owned reconciliation worker lease for
// one instance. The worker holds it while running so a second process
// cannot own the same instance cursor.
type WorkerLeaseRecord struct {
	InstanceID  string
	Owner       string
	HeartbeatAt time.Time
	ExpiresAt   time.Time
}
