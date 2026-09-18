// Package recovery implements the offline recovery flow: after the
// founder loses every authentication method, the operator runs
// "authscope-ope recover" on the instance host with the one-time offline
// recovery key. The service verifies the key locally, attests the fixed
// workspace-wide containment decision with the workload signer, asks
// AuthScope to bulk-contain the workspace, waits for the authoritative
// active-mission list to come back empty, and only then resets local
// authentication state in a single transaction: sessions revoked,
// one-use handoffs invalidated, passkey credentials deleted, the
// recovery key consumed, a recovery event recorded, and one ten-minute
// bootstrap code issued for re-enrollment.
//
// Any failure before the authoritative empty list leaves authentication
// and recovery state unchanged and the intent pending, so a crash or a
// retry resumes from the durable intent instead of re-containing the
// workspace.
package recovery

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

var (
	// ErrInvalidRecoveryKey reports a wrong or already-consumed offline
	// recovery key. The comparison is constant time.
	ErrInvalidRecoveryKey = errors.New("recovery: invalid offline recovery key")
	// ErrWorkspaceConfirmationMismatch reports a typed workspace
	// confirmation that does not exactly match the bound workspace.
	ErrWorkspaceConfirmationMismatch = errors.New("recovery: workspace confirmation does not match the bound workspace")
	// ErrRecoveryInProgress reports a concurrent reset racing the same
	// recovery key. Exactly one reset owns the intent.
	ErrRecoveryInProgress = errors.New("recovery: another reset is already in progress for this recovery key")
	// ErrNotEnrolled reports recovery on a workspace with no founder and
	// therefore no recovery key.
	ErrNotEnrolled = errors.New("recovery: no founder enrolled")
	// ErrNoWorkloadIdentity reports a missing workload-identity digest on
	// the instance record. Recovery needs the attached identity to sign
	// the containment attestation.
	ErrNoWorkloadIdentity = errors.New("recovery: workload identity not attached to the instance record")
	// ErrIdentityNotVerified reports a transport-authenticated workload
	// identity that is not bound to this workspace, lacks the
	// decision_attestor role, or carries a different digest than the
	// attached one.
	ErrIdentityNotVerified = errors.New("recovery: workload identity verification failed")
	// ErrContainmentNotAcknowledged reports an upstream containment that
	// did not acknowledge.
	ErrContainmentNotAcknowledged = errors.New("recovery: workspace containment not acknowledged")
	// ErrActiveMissionsRemain reports that the authoritative
	// active-mission list never came back empty before the deadline.
	ErrActiveMissionsRemain = errors.New("recovery: active missions remain; authentication state unchanged")
	// ErrUnverifiableUpstream reports an upstream result that cannot be
	// authenticated: a mission bound to another workspace, a containment
	// for another workspace, or an unavailable authority.
	ErrUnverifiableUpstream = errors.New("recovery: upstream result is not verifiable")
	// ErrRecoveryStateCorrupt reports a durable recovery intent whose
	// canonical decision digest does not match the decision recomputed
	// from the current recovery key. The intent cannot be resumed; the
	// operator must investigate the data directory.
	ErrRecoveryStateCorrupt = errors.New("recovery: durable intent does not match the recovery decision")
)

// RecoveryRequest is one offline recovery attempt. The recovery key
// comes from the controlling terminal with echo disabled, never from
// argv, environment, or configuration. ConfirmWorkspace is the
// operator-typed workspace ID, which must exactly match the bound
// workspace.
type RecoveryRequest struct {
	WorkspaceID      string
	RecoveryKey      []byte
	ConfirmWorkspace string
}

// RecoveryResult is the outcome of a completed offline recovery.
type RecoveryResult struct {
	RecoveryEventID       string
	RevokedSessionCount   int
	ContainedMissionCount int
	BootstrapExpiresAt    time.Time
}

// Config wires the recovery service.
type Config struct {
	Store     store.Store
	Authority coreapi.Authority
	Attestor  *identity.DecisionAttestor
	// Clock returns the current time; defaults to time.Now.
	Clock func() time.Time
	// Rand supplies random bytes; defaults to crypto/rand.
	Rand io.Reader
	// PollInterval spaces ListActiveMissions polls; defaults to 5s.
	PollInterval time.Duration
	// ContainmentTimeout bounds one ContainWorkspace call; defaults to 60s.
	ContainmentTimeout time.Duration
	// EmptyListTimeout bounds the wait for the authoritative empty
	// active-mission list; defaults to 5m.
	EmptyListTimeout time.Duration
	// BootstrapCodeSink receives the raw one-time bootstrap code after
	// it is issued, so the caller can print it to the controlling
	// terminal. The raw code is never stored.
	BootstrapCodeSink func(code string, expiresAt time.Time)
}

// Service runs offline recovery against the local store and AuthScope.
type Service struct {
	store              store.Store
	authority          coreapi.Authority
	attestor           *identity.DecisionAttestor
	clock              func() time.Time
	rand               io.Reader
	pollInterval       time.Duration
	containmentTimeout time.Duration
	emptyListTimeout   time.Duration
	bootstrapCodeSink  func(code string, expiresAt time.Time)
}

// NewService builds the recovery service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("recovery: store is required")
	}
	if cfg.Authority == nil {
		return nil, errors.New("recovery: authority is required")
	}
	if cfg.Attestor == nil {
		return nil, errors.New("recovery: decision attestor is required")
	}
	s := &Service{
		store:              cfg.Store,
		authority:          cfg.Authority,
		attestor:           cfg.Attestor,
		clock:              cfg.Clock,
		rand:               cfg.Rand,
		pollInterval:       cfg.PollInterval,
		containmentTimeout: cfg.ContainmentTimeout,
		emptyListTimeout:   cfg.EmptyListTimeout,
		bootstrapCodeSink:  cfg.BootstrapCodeSink,
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.rand == nil {
		s.rand = rand.Reader
	}
	if s.pollInterval <= 0 {
		s.pollInterval = 5 * time.Second
	}
	if s.containmentTimeout <= 0 {
		s.containmentTimeout = 60 * time.Second
	}
	if s.emptyListTimeout <= 0 {
		s.emptyListTimeout = 5 * time.Minute
	}
	return s, nil
}

// canonicalJSON marshals v deterministically: fixed struct field order
// and no HTML escaping.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// taggedDigest returns "sha256:"+hex(sha256(canonical JSON of v)).
func taggedDigest(v any) (string, error) {
	raw, err := canonicalJSON(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s *Service) randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(s.rand, b); err != nil {
		return "", fmt.Errorf("recovery: random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// recoveryRecord is the verified local recovery record covered by the
// recovery proof digest. It carries the stored key hash, never the key.
type recoveryRecord struct {
	WorkspaceID string `json:"workspace_id"`
	FounderID   string `json:"founder_id"`
	KeyHash     string `json:"key_hash"`
	CreatedAt   string `json:"created_at"`
}

// containmentDecision is the fixed workspace-wide containment decision
// the recovery attestation binds.
type containmentDecision struct {
	Decision            string `json:"decision"`
	WorkspaceID         string `json:"workspace_id"`
	RecoveryProofDigest string `json:"recovery_proof_digest"`
}

// idempotencyKey derives the stable containment idempotency key from the
// workspace and the stored recovery-key hash. Retries of the same
// recovery key reconcile by this key; a different key gets its own.
func idempotencyKey(workspaceID, keyHash string) string {
	h := keyHash
	if len(h) > 16 {
		h = h[:16]
	}
	return "offline-recovery-contain/" + workspaceID + "/" + h
}

// ResetOffline performs the offline recovery. It is safe to retry after
// a crash: the durable intent records each step, and the stable
// idempotency key reconciles an ambiguous containment instead of
// re-containing the workspace.
func (s *Service) ResetOffline(ctx context.Context, req RecoveryRequest) (RecoveryResult, error) {
	if req.WorkspaceID == "" {
		return RecoveryResult{}, fmt.Errorf("%w: workspace ID is required", ErrWorkspaceConfirmationMismatch)
	}
	inst, err := s.store.GetInstance(ctx)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("recovery: load instance record: %w", err)
	}
	// No workspace picker, no switch: the request must name exactly the
	// bound workspace, and the typed confirmation must match it exactly.
	if req.WorkspaceID != inst.WorkspaceID {
		return RecoveryResult{}, fmt.Errorf("%w: request names %q, instance is bound to %q",
			ErrWorkspaceConfirmationMismatch, req.WorkspaceID, inst.WorkspaceID)
	}
	if req.ConfirmWorkspace != inst.WorkspaceID {
		return RecoveryResult{}, ErrWorkspaceConfirmationMismatch
	}
	if !inst.HasWorkloadIdentity() {
		return RecoveryResult{}, ErrNoWorkloadIdentity
	}
	founders, err := s.store.ListFounders(ctx, inst.WorkspaceID)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("recovery: list founders: %w", err)
	}
	if len(founders) == 0 {
		return RecoveryResult{}, ErrNotEnrolled
	}
	founderID := founders[0].FounderID

	// The transport-authenticated workload identity must be bound to
	// this workspace, carry the decision_attestor role, and match the
	// digest attached to the instance record. A signing identity
	// without the role fails here, before any state changes.
	wid, err := s.authority.VerifyWorkspaceIdentity(ctx, inst.WorkspaceID)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("%w: %v", ErrIdentityNotVerified, err)
	}
	if wid.WorkspaceID != inst.WorkspaceID {
		return RecoveryResult{}, fmt.Errorf("%w: identity bound to workspace %q",
			ErrIdentityNotVerified, wid.WorkspaceID)
	}
	if !wid.HasRole(coreapi.DecisionAttestorRole) {
		return RecoveryResult{}, fmt.Errorf("%w: identity lacks %q",
			ErrIdentityNotVerified, coreapi.DecisionAttestorRole)
	}
	if wid.IdentityDigest != inst.WorkloadIdentityDigest {
		return RecoveryResult{}, fmt.Errorf("%w: identity digest mismatch", ErrIdentityNotVerified)
	}

	// Verify the offline recovery proof in constant time against the
	// stored key hash. A wrong or already-consumed key fails here; the
	// key is consumed only in the final reset transaction.
	stored, err := s.store.GetOfflineRecoveryKey(ctx, inst.WorkspaceID, founderID)
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("%w: %v", ErrInvalidRecoveryKey, err)
	}
	providedSum := sha256.Sum256(req.RecoveryKey)
	providedHex := hex.EncodeToString(providedSum[:])
	if subtle.ConstantTimeCompare([]byte(providedHex), []byte(stored.KeyHash)) != 1 {
		return RecoveryResult{}, ErrInvalidRecoveryKey
	}
	// The proof digest covers the verified local recovery record: the
	// stored key hash, never the key itself.
	proofDigest, err := taggedDigest(recoveryRecord{
		WorkspaceID: stored.WorkspaceID,
		FounderID:   stored.FounderID,
		KeyHash:     stored.KeyHash,
		CreatedAt:   stored.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("recovery: proof digest: %w", err)
	}
	decisionDigest, err := taggedDigest(containmentDecision{
		Decision:            "contain_workspace",
		WorkspaceID:         inst.WorkspaceID,
		RecoveryProofDigest: proofDigest,
	})
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("recovery: decision digest: %w", err)
	}

	key := idempotencyKey(inst.WorkspaceID, stored.KeyHash)
	intent, err := s.store.GetRecoveryIntent(ctx, inst.WorkspaceID, key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return RecoveryResult{}, fmt.Errorf("recovery: load intent: %w", err)
	}
	if err == nil {
		// The canonical digest is deterministic in the recovery key. A
		// preexisting intent with a different digest means the durable
		// state was tampered with or corrupted; fail closed rather than
		// resume a decision the key did not authorize.
		if intent.CanonicalDigest != "" && intent.CanonicalDigest != decisionDigest {
			return RecoveryResult{}, ErrRecoveryStateCorrupt
		}
		if intent.State == store.RecoveryIntentCompleted {
			// A completed intent replays its recorded result. The key
			// was consumed at completion, so reaching here means the
			// stored hash above could not have matched; this path
			// exists only for races inside the consumption window.
			return RecoveryResult{
				RecoveryEventID:       intent.RecoveryEventID,
				RevokedSessionCount:   intent.RevokedSessionCount,
				ContainedMissionCount: intent.ContainedMissionCount,
				BootstrapExpiresAt:    intent.BootstrapExpiresAt,
			}, nil
		}
	} else {
		// Persist the recovery intent before signing or calling
		// upstream, so a crash resumes instead of re-containing. A
		// concurrent reset racing the same key loses here.
		nonceHex, err := s.randHex(32)
		if err != nil {
			return RecoveryResult{}, err
		}
		intentID, err := s.randHex(16)
		if err != nil {
			return RecoveryResult{}, err
		}
		now := s.clock().UTC()
		intent = store.RecoveryIntentRecord{
			WorkspaceID:     inst.WorkspaceID,
			IdempotencyKey:  key,
			IntentID:        intentID,
			CanonicalDigest: decisionDigest,
			Nonce:           nonceHex,
			State:           store.RecoveryIntentPending,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.PutRecoveryIntent(ctx, intent)
		}); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return RecoveryResult{}, ErrRecoveryInProgress
			}
			return RecoveryResult{}, fmt.Errorf("recovery: persist intent: %w", err)
		}
	}

	// Sign the short-lived one-use containment attestation: fixed
	// purpose, audience, method, and the proof digest that reveals no
	// key material.
	attestation, err := s.signContainmentAttestation(ctx, inst, founderID, decisionDigest, proofDigest)
	if err != nil {
		return RecoveryResult{}, err
	}
	attestationDigest, err := s.attestationDigest(attestation)
	if err != nil {
		return RecoveryResult{}, err
	}
	if intent.State == store.RecoveryIntentPending && intent.AttestationDigest == "" {
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.SetRecoveryIntentAttestation(ctx, inst.WorkspaceID, key, attestationDigest, s.clock().UTC())
		}); err != nil {
			if errors.Is(err, store.ErrConflict) {
				// A concurrent reset drove this intent out of pending
				// while we worked: report in-progress so the caller
				// retries into the completed replay instead of
				// surfacing a store conflict.
				return RecoveryResult{}, ErrRecoveryInProgress
			}
			return RecoveryResult{}, fmt.Errorf("recovery: record attestation: %w", err)
		}
		intent.AttestationDigest = attestationDigest
	}

	if intent.State == store.RecoveryIntentPending {
		// Baseline: the authoritative active-mission list before
		// containment. Bulk containment must cover every mission
		// here, including missions known only to AuthScope.
		contained, err := s.authoritativeActiveMissions(ctx, inst.WorkspaceID)
		if err != nil {
			return RecoveryResult{}, err
		}
		intent.ContainedMissionCount = len(contained)

		// Contain first, with the stable idempotency key. An ambiguous
		// outcome reconciles by that key with a freshly signed
		// attestation; it never re-contains.
		generation, err := s.contain(ctx, inst, founderID, key, decisionDigest, proofDigest, attestation)
		if err != nil {
			return RecoveryResult{}, err
		}
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.SetRecoveryIntentContained(ctx, inst.WorkspaceID, key, generation, s.clock().UTC())
		}); err != nil {
			if errors.Is(err, store.ErrConflict) {
				// A concurrent reset completed the containment step
				// first: this reset is the loser of the race.
				return RecoveryResult{}, ErrRecoveryInProgress
			}
			return RecoveryResult{}, fmt.Errorf("recovery: record containment: %w", err)
		}
		intent.State = store.RecoveryIntentContained
		intent.ContainmentGeneration = generation
	}

	if intent.State == store.RecoveryIntentContained {
		// Only after acknowledged containment, poll the authoritative
		// view until it returns an authenticated empty list. Any
		// nonempty, unavailable, or unverifiable result leaves
		// authentication and recovery state unchanged.
		if err := s.awaitEmptyActiveMissions(ctx, inst.WorkspaceID); err != nil {
			return RecoveryResult{}, err
		}
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.SetRecoveryIntentVerifiedEmpty(ctx, inst.WorkspaceID, key, s.clock().UTC())
		}); err != nil {
			return RecoveryResult{}, fmt.Errorf("recovery: record empty list: %w", err)
		}
		intent.State = store.RecoveryIntentVerifiedEmpty
	}

	if intent.State != store.RecoveryIntentVerifiedEmpty {
		return RecoveryResult{}, fmt.Errorf("recovery: unexpected intent state %q", intent.State)
	}

	return s.resetLocalState(ctx, inst, founderID, key, intent, proofDigest, attestationDigest)
}

// signContainmentAttestation signs the fixed workspace-wide containment
// decision with a fresh nonce and a short TTL.
func (s *Service) signContainmentAttestation(ctx context.Context, inst store.InstanceRecord, founderID, decisionDigest, proofDigest string) (identity.SignedDecisionAttestation, error) {
	nonceBytes := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, nonceBytes); err != nil {
		return identity.SignedDecisionAttestation{}, fmt.Errorf("recovery: nonce: %w", err)
	}
	var nonce [32]byte
	copy(nonce[:], nonceBytes)
	now := s.clock().UTC()
	att, err := s.attestor.Attest(ctx, identity.DecisionClaims{
		WorkspaceID:               inst.WorkspaceID,
		FounderID:                 founderID,
		Audience:                  identity.AudienceWorkspaceContain,
		Purpose:                   identity.PurposeOfflineRecoveryContain,
		SubjectID:                 inst.WorkspaceID,
		DecisionDigest:            decisionDigest,
		AuthenticationMethod:      identity.AuthMethodOfflineRecovery,
		AuthenticationProofDigest: proofDigest,
		Nonce:                     nonce,
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(15 * time.Minute),
	})
	if err != nil {
		return identity.SignedDecisionAttestation{}, fmt.Errorf("recovery: sign containment attestation: %w", err)
	}
	return att, nil
}

// attestationDigest is the algorithm-tagged digest of the canonical
// attestation claims, recorded on the intent and the recovery event.
func (s *Service) attestationDigest(att identity.SignedDecisionAttestation) (string, error) {
	raw, err := identity.CanonicalClaimsJSON(att.Claims, att.KeyID, att.IdentityDigest)
	if err != nil {
		return "", fmt.Errorf("recovery: attestation digest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// authoritativeActiveMissions returns the authenticated workspace-scoped
// active-mission list. Every mission must belong to this workspace;
// anything else is unverifiable and fails closed.
func (s *Service) authoritativeActiveMissions(ctx context.Context, workspaceID string) ([]coreapi.ActiveMission, error) {
	missions, err := s.authority.ListActiveMissions(ctx, coreapi.RequestOptions{
		WorkspaceID: workspaceID,
		Timeout:     s.containmentTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: list active missions: %v", ErrUnverifiableUpstream, err)
	}
	for _, m := range missions {
		if m.WorkspaceID != workspaceID {
			return nil, fmt.Errorf("%w: mission %q bound to workspace %q",
				ErrUnverifiableUpstream, m.MissionRef, m.WorkspaceID)
		}
	}
	return missions, nil
}

// contain calls ContainWorkspace with the stable idempotency key. An
// ambiguous outcome (timeout, 5xx, transport failure) reconciles once by
// the same key with a freshly signed attestation; a definitive denial
// fails without changing local state.
func (s *Service) contain(ctx context.Context, inst store.InstanceRecord, founderID, key, decisionDigest, proofDigest string, attestation identity.SignedDecisionAttestation) (int64, error) {
	out, err := s.authority.ContainWorkspace(ctx,
		coreapi.WorkspaceContainmentRequest{Founder: founderID, IdempotencyKey: key},
		attestation,
		coreapi.RequestOptions{WorkspaceID: inst.WorkspaceID, Timeout: s.containmentTimeout})
	if err == nil {
		return checkContainment(inst.WorkspaceID, out)
	}
	if !isAmbiguous(err) {
		return 0, fmt.Errorf("recovery: contain workspace: %w", err)
	}
	// Ambiguous: reconcile by the idempotency key. The upstream
	// deduplicates on the key, so this cannot re-contain; the fresh
	// attestation keeps the one-use nonce invariant. A second ambiguous
	// outcome leaves the intent pending for a later retry.
	retryAttestation, rerr := s.signContainmentAttestation(ctx, inst, founderID, decisionDigest, proofDigest)
	if rerr != nil {
		return 0, rerr
	}
	out, rerr = s.authority.ContainWorkspace(ctx,
		coreapi.WorkspaceContainmentRequest{Founder: founderID, IdempotencyKey: key},
		retryAttestation,
		coreapi.RequestOptions{WorkspaceID: inst.WorkspaceID, Timeout: s.containmentTimeout})
	if rerr != nil {
		return 0, fmt.Errorf("recovery: contain workspace: %w", rerr)
	}
	return checkContainment(inst.WorkspaceID, out)
}

// checkContainment verifies the acknowledged containment names this
// workspace and was acknowledged.
func checkContainment(workspaceID string, out coreapi.WorkspaceContainment) (int64, error) {
	if out.WorkspaceID != workspaceID {
		return 0, fmt.Errorf("%w: containment for workspace %q",
			ErrUnverifiableUpstream, out.WorkspaceID)
	}
	if !out.Contained {
		return 0, ErrContainmentNotAcknowledged
	}
	return out.Generation, nil
}

// isAmbiguous reports whether an upstream error leaves the containment
// outcome unknown: timeouts, transport failures, and 5xx/429 statuses.
// A 4xx denial is definitive.
func isAmbiguous(err error) bool {
	var up *coreapi.UpstreamError
	if errors.As(err, &up) {
		return up.StatusCode == 429 || up.StatusCode >= 500
	}
	return true
}

// awaitEmptyActiveMissions polls the authoritative view until it returns
// an authenticated empty list or the deadline passes. Nonempty results
// keep the intent pending; unavailable or unverifiable results fail.
func (s *Service) awaitEmptyActiveMissions(ctx context.Context, workspaceID string) error {
	deadline := s.clock().Add(s.emptyListTimeout)
	for {
		missions, err := s.authoritativeActiveMissions(ctx, workspaceID)
		if err != nil {
			return err
		}
		if len(missions) == 0 {
			return nil
		}
		if !s.clock().Before(deadline) {
			return fmt.Errorf("%w: %d mission(s) still active",
				ErrActiveMissionsRemain, len(missions))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.pollInterval):
		}
	}
}

// resetLocalState performs the local reset in a single transaction after
// the authoritative empty list was durably recorded: revoke every web
// session, invalidate one-use CLI handoffs, delete passkey credentials,
// consume the one-use recovery key, record the non-secret recovery
// event, and issue one ten-minute bootstrap code for re-enrollment. The
// founder row is removed so the bootstrap ceremony can re-enroll the
// workspace; pass-scoped presentation state is untouched.
func (s *Service) resetLocalState(ctx context.Context, inst store.InstanceRecord, founderID, key string, intent store.RecoveryIntentRecord, proofDigest, attestationDigest string) (RecoveryResult, error) {
	eventID, err := s.randHex(16)
	if err != nil {
		return RecoveryResult{}, err
	}
	now := s.clock().UTC()
	var revoked int
	var code []byte
	var codeSum [32]byte
	var bootstrapExpiresAt time.Time
	err = s.store.WithTx(ctx, func(tx store.Tx) error {
		// The bootstrap code is issued inside the same transaction as
		// the resets: a crash can never leave resets without a code or
		// a code without resets.
		var err error
		code, bootstrapExpiresAt, err = authn.IssueRecoveryBootstrapCodeTx(ctx, tx, inst.WorkspaceID, now)
		if err != nil {
			return err
		}
		codeSum = sha256.Sum256(code)
		revoked, err = tx.RevokeAllSessions(ctx, inst.WorkspaceID)
		if err != nil {
			return err
		}
		if err := tx.ResetLaunchHandoffs(ctx, inst.WorkspaceID); err != nil {
			return err
		}
		if _, err := tx.DeleteAllWebAuthnCredentials(ctx, inst.WorkspaceID); err != nil {
			return err
		}
		if err := tx.ConsumeOfflineRecoveryKey(ctx, inst.WorkspaceID, founderID); err != nil {
			return err
		}
		if err := tx.DeleteFounder(ctx, inst.WorkspaceID, founderID); err != nil {
			return err
		}
		if err := tx.PutRecoveryEvent(ctx, store.RecoveryEventRecord{
			WorkspaceID:           inst.WorkspaceID,
			EventID:               eventID,
			FounderID:             founderID,
			IdempotencyKey:        key,
			ContainedMissionCount: intent.ContainedMissionCount,
			ContainmentGeneration: intent.ContainmentGeneration,
			AttestationDigest:     attestationDigest,
			RecoveryProofDigest:   proofDigest,
			BootstrapCodeHash:     hex.EncodeToString(codeSum[:]),
			OccurredAt:            now,
		}); err != nil {
			return err
		}
		return tx.SetRecoveryIntentCompleted(ctx, inst.WorkspaceID, key, eventID,
			revoked, intent.ContainedMissionCount, bootstrapExpiresAt, now)
	})
	if err != nil {
		zeroBytes(code)
		return RecoveryResult{}, fmt.Errorf("recovery: local reset: %w", err)
	}
	// The raw code is delivered to the caller exactly once and never
	// stored; it is zeroed immediately afterwards.
	codeDisplay := base64.RawURLEncoding.EncodeToString(code)
	if s.bootstrapCodeSink != nil {
		s.bootstrapCodeSink(codeDisplay, bootstrapExpiresAt)
	}
	zeroBytes(code)
	return RecoveryResult{
		RecoveryEventID:       eventID,
		RevokedSessionCount:   revoked,
		ContainedMissionCount: intent.ContainedMissionCount,
		BootstrapExpiresAt:    bootstrapExpiresAt,
	}, nil
}

// zeroBytes clears a secret byte slice.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
