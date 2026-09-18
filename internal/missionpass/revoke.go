// Mission revocation: the founder-bound begin/finish decision ceremony
// that revokes a governed mission, plus the result-only CLI revocation
// handoff. It mirrors the approval flow: the finish consumes the
// challenge atomically, signs the exact decision attestation, persists
// the local intent before the upstream call, and invokes RevokeMission
// exactly once per pass. Containment is persisted as acknowledged,
// pending, or partial; enforcement is never claimed until the gateway
// containment is acknowledged. An ambiguous upstream outcome stays
// in-flight and reconciles by the original idempotency key via
// ReconcileOperation; settling replays the original idempotent call to
// recover its result, never a fresh revocation.
package missionpass

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

// Fixed normalized revocation reason enum.
const (
	RevocationReasonFounderRequested   = "founder_requested"
	RevocationReasonSafetyConcern      = "safety_concern"
	RevocationReasonMissionSuperseded  = "mission_superseded"
)

var validRevocationReasons = map[string]bool{
	RevocationReasonFounderRequested:  true,
	RevocationReasonSafetyConcern:     true,
	RevocationReasonMissionSuperseded: true,
}

var (
	// ErrInvalidRevocationReason reports a reason outside the fixed enum.
	ErrInvalidRevocationReason = errors.New("missionpass: invalid revocation reason")
	// ErrPassNotRevocable reports a pass whose state cannot move to revoked.
	ErrPassNotRevocable = errors.New("missionpass: pass cannot be revoked from its state")
	// ErrRevokeBindingChanged reports a pass that changed after the
	// revocation challenge began.
	ErrRevokeBindingChanged = errors.New("missionpass: revocation binding changed after begin")
	// ErrRevokePending reports an ambiguous upstream revoke: the outcome
	// is unknown and the intent stays in-flight for reconciliation.
	ErrRevokePending = errors.New("missionpass: revocation outcome unknown; reconciling")
	// ErrRevokeConflict reports a second revocation attempt whose binding
	// differs from the in-flight intent.
	ErrRevokeConflict = errors.New("missionpass: revocation already in flight with a different binding")
)

// NormalizeRevocationReason trims and lowercases the reason and rejects
// anything outside the fixed enum.
func NormalizeRevocationReason(reason string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(reason))
	if !validRevocationReasons[normalized] {
		return "", fmt.Errorf("%w: %q", ErrInvalidRevocationReason, reason)
	}
	return normalized, nil
}

// RevokeBinding is the exact server-side binding for one revocation
// challenge: workspace, founder/session, pass, mission reference and
// version, descendants=true, the normalized reason, the mission_revoke
// purpose, the authscope:mission-revoke audience, and a fresh nonce.
type RevokeBinding struct {
	WorkspaceID    string
	FounderID      string
	SessionID      string
	PassID         string
	MissionRef     string
	MissionVersion int64
	Descendants    bool
	ReasonCode     string
	Purpose        string
	Audience       string
	Nonce          string
}

type revokeCanonical struct {
	WorkspaceID    string `json:"workspace_id"`
	FounderID      string `json:"founder_id"`
	SessionID      string `json:"session_id"`
	PassID         string `json:"pass_id"`
	MissionRef     string `json:"mission_ref"`
	MissionVersion int64  `json:"mission_version"`
	Descendants    bool   `json:"descendants"`
	ReasonCode     string `json:"reason_code"`
	Purpose        string `json:"purpose"`
	Audience       string `json:"audience"`
	Nonce          string `json:"nonce"`
}

// CanonicalRevokeBytes renders the binding in fixed field order. The
// authn challenge digests these bytes; Finish rebuilds them byte for
// byte and fails closed on any difference.
func CanonicalRevokeBytes(binding RevokeBinding) []byte {
	raw, err := json.Marshal(revokeCanonical{
		WorkspaceID:    binding.WorkspaceID,
		FounderID:      binding.FounderID,
		SessionID:      binding.SessionID,
		PassID:         binding.PassID,
		MissionRef:     binding.MissionRef,
		MissionVersion: binding.MissionVersion,
		Descendants:    binding.Descendants,
		ReasonCode:     binding.ReasonCode,
		Purpose:        binding.Purpose,
		Audience:       binding.Audience,
		Nonce:          binding.Nonce,
	})
	if err != nil {
		panic(fmt.Sprintf("missionpass: encode revoke binding: %v", err))
	}
	return raw
}

// RevocationDigestInput is the server-known subset of the revocation
// binding: everything the CLI handoff can name before the browser
// ceremony binds founder, session, and nonce.
type RevocationDigestInput struct {
	WorkspaceID    string
	PassID         string
	MissionRef     string
	MissionVersion int64
	ReasonCode     string
}

type revocationDigestCanonical struct {
	WorkspaceID    string `json:"workspace_id"`
	PassID         string `json:"pass_id"`
	MissionRef     string `json:"mission_ref"`
	MissionVersion int64  `json:"mission_version"`
	Descendants    bool   `json:"descendants"`
	ReasonCode     string `json:"reason_code"`
	Purpose        string `json:"purpose"`
	Audience       string `json:"audience"`
}

// CanonicalRevocationDigest is the exact server-canonical revocation
// digest: sha256 hex over the fixed binding subset. The CLI handoff
// registers with this digest, and the browser finish recomputes it from
// the live pass; a differently bound request fails.
func CanonicalRevocationDigest(in RevocationDigestInput) string {
	raw, err := json.Marshal(revocationDigestCanonical{
		WorkspaceID:    in.WorkspaceID,
		PassID:         in.PassID,
		MissionRef:     in.MissionRef,
		MissionVersion: in.MissionVersion,
		Descendants:    true,
		ReasonCode:     in.ReasonCode,
		Purpose:        string(authn.DecisionMissionRevoke),
		Audience:       identity.AudienceMissionRevoke,
	})
	if err != nil {
		panic(fmt.Sprintf("missionpass: encode revocation digest: %v", err))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// revocationDecisionRef is the non-empty local reference for the signed
// revocation decision.
func revocationDecisionRef(binding RevokeBinding) string {
	return fmt.Sprintf("revocation-decision:%s:%s:%s", binding.WorkspaceID, binding.PassID, binding.ReasonCode)
}

// RevocationResult is the settled revocation outcome.
type RevocationResult struct {
	PassID      string    `json:"pass_id"`
	MissionRef  string    `json:"mission_ref"`
	Revoked     bool      `json:"revoked"`
	Containment string    `json:"containment"`
	ReasonCode  string    `json:"reason_code"`
	RevokedAt   time.Time `json:"revoked_at"`
}

// RevocationConfig wires the revocation service.
type RevocationConfig struct {
	Store           store.Store
	Authn           *authn.Service
	Authority       coreapi.Authority
	Attestor        *identity.DecisionAttestor
	Clock           func() time.Time
	UpstreamTimeout time.Duration
	NewNonce        func() ([32]byte, error)
}

type begunRevocation struct {
	challengeID string
	digest      [32]byte
	binding     RevokeBinding
	canonical   []byte
	principal   authn.Principal
	expiresAt   time.Time
}

// RevocationService performs the founder-bound mission revocation
// ceremony.
type RevocationService struct {
	store           store.Store
	authn           *authn.Service
	authority       coreapi.Authority
	attestor        *identity.DecisionAttestor
	clock           func() time.Time
	upstreamTimeout time.Duration
	newNonce        func() ([32]byte, error)

	mu    sync.Mutex
	begun map[string]*begunRevocation
	// revokeLocks serializes concurrent finishes for one pass so two
	// ceremonies cannot issue two upstream revokes.
	revokeLocks map[string]*sync.Mutex
}

// revokeAttestationTTL bounds the signed revocation decision.
const revokeAttestationTTL = 5 * time.Minute

// NewRevocationService builds the service.
func NewRevocationService(cfg RevocationConfig) (*RevocationService, error) {
	if cfg.Store == nil || cfg.Authn == nil || cfg.Authority == nil || cfg.Attestor == nil {
		return nil, fmt.Errorf("missionpass: revocation service requires store, authn, authority, and attestor")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	newNonce := cfg.NewNonce
	if newNonce == nil {
		newNonce = func() ([32]byte, error) {
			var n [32]byte
			_, err := rand.Read(n[:])
			return n, err
		}
	}
	return &RevocationService{
		store:           cfg.Store,
		authn:           cfg.Authn,
		authority:       cfg.Authority,
		attestor:        cfg.Attestor,
		clock:           clock,
		upstreamTimeout: timeout,
		newNonce:        newNonce,
		begun:           map[string]*begunRevocation{},
		revokeLocks:     map[string]*sync.Mutex{},
	}, nil
}

func (s *RevocationService) now() time.Time { return s.clock().UTC() }

// RevokeBeginResult carries the challenge for the browser ceremony.
type RevokeBeginResult struct {
	ChallengeID string
	OptionsJSON json.RawMessage
}

// Begin starts the revocation ceremony: it validates the normalized
// reason, checks the pass is in a revocable state, and binds the
// challenge to workspace, founder/session, pass, mission
// reference/version, descendants=true, the reason, the mission_revoke
// purpose, the authscope:mission-revoke audience, and a fresh nonce.
func (s *RevocationService) Begin(ctx context.Context, p authn.Principal, passID, reason string) (*RevokeBeginResult, error) {
	reasonCode, err := NormalizeRevocationReason(reason)
	if err != nil {
		return nil, err
	}
	rec, err := s.store.GetMissionPass(ctx, p.WorkspaceID, passID)
	if err != nil {
		return nil, err
	}
	if !Revocable(PassState(rec.State)) {
		return nil, fmt.Errorf("%w: state %q", ErrPassNotRevocable, rec.State)
	}
	if rec.MissionRef == "" {
		return nil, fmt.Errorf("%w: pass has no mission", ErrPassNotRevocable)
	}
	nonce, err := s.newNonce()
	if err != nil {
		return nil, fmt.Errorf("missionpass: revoke nonce: %w", err)
	}
	binding := RevokeBinding{
		WorkspaceID:    p.WorkspaceID,
		FounderID:      p.FounderID,
		SessionID:      p.SessionID,
		PassID:         passID,
		MissionRef:     rec.MissionRef,
		MissionVersion: rec.AuthScopeMissionVersion,
		Descendants:    true,
		ReasonCode:     reasonCode,
		Purpose:        string(authn.DecisionMissionRevoke),
		Audience:       identity.AudienceMissionRevoke,
		Nonce:          hex.EncodeToString(nonce[:]),
	}
	canonical := CanonicalRevokeBytes(binding)
	challenge, optionsJSON, err := s.authn.BeginDecision(ctx, p, authn.DecisionMissionRevoke, passID, canonical)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.begun[challenge.ChallengeID] = &begunRevocation{
		challengeID: challenge.ChallengeID,
		digest:      challenge.Digest,
		binding:     binding,
		canonical:   canonical,
		principal:   p,
		expiresAt:   challenge.ExpiresAt,
	}
	s.mu.Unlock()
	return &RevokeBeginResult{ChallengeID: challenge.ChallengeID, OptionsJSON: optionsJSON}, nil
}

// begunForTest exposes begun revocation state to in-package tests.
func (s *RevocationService) begunForTest(challengeID string) *begunRevocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.begun[challengeID]
}

func (s *RevocationService) dropBegun(challengeID string) {
	s.mu.Lock()
	delete(s.begun, challengeID)
	s.mu.Unlock()
}

func (s *RevocationService) lockFor(passID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.revokeLocks[passID]; ok {
		return l
	}
	l := &sync.Mutex{}
	s.revokeLocks[passID] = l
	return l
}

// Finish completes the revocation ceremony: it consumes the challenge
// atomically, rebuilds the exact binding and fails closed when the pass
// changed, verifies the passkey assertion, signs the exact decision
// attestation, persists the intent before the upstream call, and invokes
// RevokeMission exactly once per pass.
func (s *RevocationService) Finish(ctx context.Context, p authn.Principal, passID, challengeID string, assertion []byte) (*RevocationResult, error) {
	s.mu.Lock()
	begun, ok := s.begun[challengeID]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown revocation challenge", authn.ErrCeremonyNotFound)
	}
	if begun.principal.WorkspaceID != p.WorkspaceID || begun.principal.FounderID != p.FounderID ||
		begun.principal.SessionID != p.SessionID {
		return nil, fmt.Errorf("%w: challenge bound to a different principal", ErrRevokeBindingChanged)
	}
	rec, err := s.store.GetMissionPass(ctx, p.WorkspaceID, passID)
	if err != nil {
		return nil, err
	}
	// The pass must still match the challenge binding: the mission
	// reference and version are pinned at begin. A pass that is already
	// revoked still carries its binding, so a concurrent finish replays
	// the completed revocation below instead of failing. These checks run
	// before the challenge is consumed so a changed pass fails closed
	// without burning the ceremony; FinishDecision rechecks the digest as
	// the second line of defense.
	if rec.MissionRef != begun.binding.MissionRef ||
		rec.AuthScopeMissionVersion != begun.binding.MissionVersion {
		return nil, fmt.Errorf("%w: mission changed after begin", ErrRevokeBindingChanged)
	}
	if rec.State != string(PassRevoked) {
		if !Revocable(PassState(rec.State)) {
			return nil, fmt.Errorf("%w: state %q", ErrPassNotRevocable, rec.State)
		}
	}
	// The binding held: consume the one-use challenge before the
	// assertion is verified. FinishDecision consumes the authn ceremony
	// atomically, so a concurrent finish loses the race there.
	s.dropBegun(challengeID)
	verified, err := s.authn.FinishDecision(ctx, p, challengeID, authn.DecisionMissionRevoke, passID, begun.canonical, assertion)
	if err != nil {
		return nil, err
	}
	proofDigest, err := ceremonyProofDigest(ceremonyProof{
		Method:       verified.Method,
		ChallengeID:  verified.ChallengeID,
		Nonce:        hex.EncodeToString(verified.Nonce[:]),
		WorkspaceID:  verified.WorkspaceID,
		SessionID:    verified.SessionID,
		FounderID:    verified.FounderID,
		SubjectID:    verified.SubjectID,
		Purpose:      string(verified.Purpose),
		UserVerified: verified.UserVerified,
	})
	if err != nil {
		return nil, err
	}
	issuedAt := s.now()
	att, err := s.attestor.Attest(ctx, identity.DecisionClaims{
		WorkspaceID:               begun.binding.WorkspaceID,
		FounderID:                 begun.binding.FounderID,
		Audience:                  identity.AudienceMissionRevoke,
		Purpose:                   identity.PurposeMissionRevoke,
		SubjectID:                 begun.binding.MissionRef,
		DecisionDigest:            "sha256:" + hex.EncodeToString(mustDigest(begun.canonical)),
		AuthenticationMethod:      verified.Method,
		AuthenticationProofDigest: proofDigest,
		Nonce:                     verified.Nonce,
		IssuedAt:                  issuedAt,
		ExpiresAt:                 issuedAt.Add(revokeAttestationTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("missionpass: sign revocation decision: %w", err)
	}
	attDigest, err := attestationDigest(att)
	if err != nil {
		return nil, err
	}
	attJSON, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("missionpass: encode revocation attestation: %w", err)
	}
	return s.revokeOnce(ctx, p, begun.binding, att, attDigest, string(attJSON))
}

// revocationKey is the deterministic idempotency key for one pass: a
// pass is revoked at most once, so concurrent web and CLI finishes share
// it and cause exactly one upstream revoke.
func revocationKey(workspaceID, passID string) string {
	return "revoke:" + workspaceID + ":" + passID
}

// mapContainment maps the upstream containment to the local fixed enum.
// Anything but an explicit acknowledgement stays pending: enforcement is
// never claimed until the gateway containment is acknowledged.
func mapContainment(upstream string) string {
	switch upstream {
	case store.ContainmentAcknowledged:
		return store.ContainmentAcknowledged
	case store.ContainmentPartial:
		return store.ContainmentPartial
	default:
		return store.ContainmentPending
	}
}

// revokeOnce persists the local intent before the upstream call so an
// ambiguous outcome reconciles by the original idempotency key without
// ever re-issuing the revocation. Concurrent finishes for one pass are
// serialized: the first issues the call, the rest replay or reconcile.
func (s *RevocationService) revokeOnce(ctx context.Context, p authn.Principal, binding RevokeBinding, att identity.SignedDecisionAttestation, attDigest, attJSON string) (*RevocationResult, error) {
	unlock := s.lockFor(binding.PassID)
	unlock.Lock()
	defer unlock.Unlock()

	key := revocationKey(binding.WorkspaceID, binding.PassID)
	canonicalDigest := CanonicalRevocationDigest(RevocationDigestInput{
		WorkspaceID:    binding.WorkspaceID,
		PassID:         binding.PassID,
		MissionRef:     binding.MissionRef,
		MissionVersion: binding.MissionVersion,
		ReasonCode:     binding.ReasonCode,
	})
	var intent store.RevocationIntentRecord
	haveIntent := true
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetRevocationIntent(ctx, binding.WorkspaceID, binding.PassID)
		return err
	}); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		haveIntent = false
	}
	if haveIntent {
		switch intent.State {
		case store.RevocationIntentCompleted:
			return s.replayCompleted(ctx, binding)
		default:
			if intent.CanonicalDigest != canonicalDigest {
				return nil, fmt.Errorf("%w: canonical digest mismatch", ErrRevokeConflict)
			}
			if intent.IdempotencyKey != key {
				return nil, fmt.Errorf("%w: idempotency key mismatch", ErrRevokeConflict)
			}
			// An in-flight intent with the same binding reconciles
			// instead of re-issuing the revocation.
			return s.ReconcileRevocation(ctx, binding.WorkspaceID, binding.PassID)
		}
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutRevocationIntent(ctx, store.RevocationIntentRecord{
			WorkspaceID:       binding.WorkspaceID,
			PassID:            binding.PassID,
			IdempotencyKey:    key,
			ReasonCode:        binding.ReasonCode,
			CanonicalDigest:   canonicalDigest,
			State:             store.RevocationIntentInFlight,
			AttestationDigest: attDigest,
			AttestationJSON:   attJSON,
		})
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// A concurrent finish won the intent: reconcile with it.
			return s.ReconcileRevocation(ctx, binding.WorkspaceID, binding.PassID)
		}
		return nil, err
	}
	upstreamCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	revocation, err := s.authority.RevokeMission(upstreamCtx, binding.MissionRef,
		coreapi.RevokeRequest{Reason: binding.ReasonCode}, att, coreapi.RequestOptions{
			WorkspaceID:    binding.WorkspaceID,
			ActorID:        "founder:" + binding.FounderID,
			IdempotencyKey: key,
		})
	if err != nil {
		if isAmbiguousUpstream(err) {
			// The outcome is unknown: the intent stays in-flight and the
			// pass records pending reconciliation. The worker reconciles
			// by the original idempotency key; never retry blindly.
			_ = s.markRevokePending(ctx, binding)
			return nil, fmt.Errorf("%w: revoke mission", ErrRevokePending)
		}
		return nil, err
	}
	return s.settleRevocation(ctx, binding, revocation)
}

// replayCompleted returns the stored result for an already-completed
// revocation instead of re-issuing it.
func (s *RevocationService) replayCompleted(ctx context.Context, binding RevokeBinding) (*RevocationResult, error) {
	var intent store.RevocationIntentRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetRevocationIntent(ctx, binding.WorkspaceID, binding.PassID)
		return err
	}); err != nil {
		return nil, err
	}
	return &RevocationResult{
		PassID:      binding.PassID,
		MissionRef:  binding.MissionRef,
		Revoked:     true,
		Containment: intent.Containment,
		ReasonCode:  intent.ReasonCode,
		RevokedAt:   intent.UpdatedAt,
	}, nil
}

// markRevokePending records the ambiguous outcome on the pass: the pass
// keeps its state with pending reconciliation and pending containment.
func (s *RevocationService) markRevokePending(ctx context.Context, binding RevokeBinding) error {
	return s.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, binding.WorkspaceID, binding.PassID)
		if err != nil {
			return err
		}
		rec.Reconciliation = string(ReconciliationPending)
		if rec.Containment == "" {
			rec.Containment = store.ContainmentPending
		}
		return tx.PutMissionPass(ctx, rec, rec.StoreRevision)
	})
}

// settleRevocation persists the revoked pass atomically: the pass moves
// to revoked with its containment state, and the intent completes. It
// never claims enforcement until the gateway containment is
// acknowledged.
func (s *RevocationService) settleRevocation(ctx context.Context, binding RevokeBinding, revocation coreapi.Revocation) (*RevocationResult, error) {
	containment := mapContainment(revocation.Containment)
	revokedAt := s.now()
	if revocation.RevokedAt > 0 {
		revokedAt = time.UnixMilli(revocation.RevokedAt).UTC()
	}
	res := &RevocationResult{
		PassID:      binding.PassID,
		MissionRef:  binding.MissionRef,
		Revoked:     true,
		Containment: containment,
		ReasonCode:  binding.ReasonCode,
		RevokedAt:   revokedAt,
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, binding.WorkspaceID, binding.PassID)
		if err != nil {
			return err
		}
		if rec.State != string(PassRevoked) {
			if !Revocable(PassState(rec.State)) {
				return fmt.Errorf("missionpass: settle revocation: state %q not revocable", rec.State)
			}
			rec.State = string(PassRevoked)
		}
		rec.Containment = containment
		rec.Reconciliation = string(ReconciliationSettled)
		if err := tx.PutMissionPass(ctx, rec, rec.StoreRevision); err != nil {
			return err
		}
		upstreamRef := revocation.MissionRef
		if upstreamRef == "" {
			upstreamRef = binding.MissionRef
		}
		return tx.CompleteRevocationIntent(ctx, binding.WorkspaceID, binding.PassID, containment, upstreamRef)
	}); err != nil {
		return nil, err
	}
	return res, nil
}

// ReconcileRevocation settles an ambiguous revocation by the original
// idempotency key. It is a no-op when nothing is pending: it returns nil
// when the revocation already settled or while the operation is still in
// flight. On a completed upstream operation it records the revocation
// locally without repeating the RevokeMission mutation; the containment
// is recorded as pending because the explicit upstream acknowledgment
// was not observed, and the worker continues to reconcile it through
// events. It never starts a new revocation with a fresh key.
func (s *RevocationService) ReconcileRevocation(ctx context.Context, workspaceID, passID string) (*RevocationResult, error) {
	rec, err := s.store.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return nil, err
	}
	if rec.State == string(PassRevoked) && rec.Reconciliation == string(ReconciliationSettled) {
		return nil, nil
	}
	var intent store.RevocationIntentRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetRevocationIntent(ctx, workspaceID, passID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if intent.State == store.RevocationIntentCompleted {
		return nil, nil
	}
	reconCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	outcome, err := s.authority.ReconcileOperation(reconCtx, intent.IdempotencyKey, rec.MissionRef, coreapi.RequestOptions{
		WorkspaceID: workspaceID,
		ActorID:     "founder:reconcile",
	})
	if err != nil {
		return nil, err
	}
	if outcome.Status != "completed" {
		return nil, nil
	}
	// The operation completed upstream. Record the revocation locally
	// without repeating the mutation. Containment stays pending until
	// the upstream acknowledgment is observed through events; the
	// worker owns the intent until it settles.
	revocation := coreapi.Revocation{
		MissionRef:  rec.MissionRef,
		Revoked:     true,
		RevokedAt:   time.Now().UTC().UnixMilli(),
		Containment: "pending",
	}
	binding := RevokeBinding{
		WorkspaceID:    workspaceID,
		PassID:         passID,
		MissionRef:     rec.MissionRef,
		MissionVersion: rec.AuthScopeMissionVersion,
		Descendants:    true,
		ReasonCode:     intent.ReasonCode,
		Purpose:        string(authn.DecisionMissionRevoke),
		Audience:       identity.AudienceMissionRevoke,
	}
	return s.settleRevocation(ctx, binding, revocation)
}

// CLIRevocationConfig wires the result-only CLI revocation handoff.
type CLIRevocationConfig struct {
	Store        store.Store
	Revocation   *RevocationService
	WorkspaceID  string
	BrowserURL   string
	Clock        func() time.Time
	RequestTTL   time.Duration
	NewRequestID func() (string, error)
	NewCode      func() (string, error)
	NewResultRef func() (string, error)
}

// validateRevocationChallenge checks the S256 code challenge shape: a
// base64url SHA-256 like the PKCE challenges the authn package accepts.
func validateRevocationChallenge(challenge string) error {
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("%w: code challenge must be base64url SHA-256", authn.ErrInvalidPKCE)
	}
	return nil
}

// CLIRevocationService implements the server side of the result-only
// loopback PKCE revocation handoff. The CLI registers a two-minute
// pass-bound request carrying the exact server-canonical revocation
// digest; the founder completes the normal mission revoke begin/finish
// decision in the browser; the finish mints a one-use result code and
// redirects to the loopback callback with the original state; the CLI
// exchanges the code plus verifier for only the opaque
// revocation-result reference and the fixed containment state. No CLI
// credential or session is issued or stored.
type CLIRevocationService struct {
	store       store.Store
	revocation  *RevocationService
	workspaceID string
	browserURL  string
	clock       func() time.Time
	requestTTL  time.Duration
	newID       func() (string, error)
	newCode     func() (string, error)
	newResultRef func() (string, error)
}

// NewCLIRevocationService builds the handoff service.
func NewCLIRevocationService(cfg CLIRevocationConfig) (*CLIRevocationService, error) {
	if cfg.Store == nil || cfg.Revocation == nil || cfg.WorkspaceID == "" || cfg.BrowserURL == "" {
		return nil, fmt.Errorf("missionpass: CLI revocation service requires store, revocation service, workspace, and browser URL")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	ttl := cfg.RequestTTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	newID := cfg.NewRequestID
	if newID == nil {
		newID = func() (string, error) {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			return "clr-" + hex.EncodeToString(b[:]), nil
		}
	}
	newCode := cfg.NewCode
	if newCode == nil {
		newCode = func() (string, error) {
			var b [32]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			return hex.EncodeToString(b[:]), nil
		}
	}
	newResultRef := cfg.NewResultRef
	if newResultRef == nil {
		newResultRef = func() (string, error) {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				return "", err
			}
			return "revres-" + hex.EncodeToString(b[:]), nil
		}
	}
	return &CLIRevocationService{
		store:        cfg.Store,
		revocation:   cfg.Revocation,
		workspaceID:  cfg.WorkspaceID,
		browserURL:   strings.TrimSuffix(cfg.BrowserURL, "/"),
		clock:        clock,
		requestTTL:   ttl,
		newID:        newID,
		newCode:      newCode,
		newResultRef: newResultRef,
	}, nil
}

// CLIRevocationRegisterRequest is the result-only registration the CLI
// sends. The CLI supplies no authority fields beyond the pass; the
// founder picks the revocation reason in the browser, and the server
// binds the exact server-canonical revocation digest over the pass and
// its mission reference and version.
type CLIRevocationRegisterRequest struct {
	PassID        string
	State         string
	CodeChallenge string
	RedirectURI   string
}

// CLIRevocationStart is the registration response.
type CLIRevocationStart struct {
	RequestID       string
	BrowserURL      string
	CanonicalDigest string
	ExpiresAt       time.Time
}

var (
	// ErrCLIRevocationNotFound reports an unknown or expired request.
	ErrCLIRevocationNotFound = errors.New("missionpass: CLI revocation request not found")
	// ErrCLIRevocationConflict reports a replay-altered or differently
	// bound request.
	ErrCLIRevocationConflict = errors.New("missionpass: CLI revocation request conflict")
	// ErrCLIRevocationExpired reports an expired request or result.
	ErrCLIRevocationExpired = errors.New("missionpass: CLI revocation request expired")
)

// Register creates the two-minute pass-bound request. An identical
// replay (same pass, state, challenge, and redirect) returns the existing
// request; a changed, expired, or differently bound request fails. The
// founder chooses the revocation reason later in the browser, so the
// canonical digest covers only the pass and its mission reference and
// version: a mission that changed since registration fails the digest
// check at finish time.
func (s *CLIRevocationService) Register(ctx context.Context, req CLIRevocationRegisterRequest) (*CLIRevocationStart, error) {
	if req.PassID == "" {
		return nil, fmt.Errorf("%w: pass ID is required", ErrCLIRevocationConflict)
	}
	if req.State == "" || len(req.State) > 128 {
		return nil, fmt.Errorf("%w: invalid state", ErrCLIRevocationConflict)
	}
	if err := validateRevocationChallenge(req.CodeChallenge); err != nil {
		return nil, err
	}
	redirectURI, err := authn.ValidateLoopbackRedirectURI(req.RedirectURI)
	if err != nil {
		return nil, err
	}
	rec, err := s.store.GetMissionPass(ctx, s.workspaceID, req.PassID)
	if err != nil {
		return nil, err
	}
	if !Revocable(PassState(rec.State)) {
		return nil, fmt.Errorf("%w: state %q", ErrPassNotRevocable, rec.State)
	}
	if rec.MissionRef == "" {
		return nil, fmt.Errorf("%w: pass has no mission", ErrPassNotRevocable)
	}
	digest := CanonicalRevocationDigest(RevocationDigestInput{
		WorkspaceID:    s.workspaceID,
		PassID:         req.PassID,
		MissionRef:     rec.MissionRef,
		MissionVersion: rec.AuthScopeMissionVersion,
	})
	now := s.clock().UTC()
	if existing, err := s.store.GetCLIRevocationByState(ctx, s.workspaceID, req.PassID, req.State); err == nil {
		if existing.ExpiresAt.After(now) && existing.CanonicalDigest == digest &&
			existing.CodeChallenge == req.CodeChallenge && existing.RedirectURI == redirectURI {
			return &CLIRevocationStart{
				RequestID:       existing.RequestID,
				BrowserURL:        s.browserURLFor(existing.RequestID, req.PassID),
				CanonicalDigest:   existing.CanonicalDigest,
				ExpiresAt:         existing.ExpiresAt,
			}, nil
		}
		return nil, fmt.Errorf("%w: request changed since registration", ErrCLIRevocationConflict)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	requestID, err := s.newID()
	if err != nil {
		return nil, fmt.Errorf("missionpass: CLI revocation request ID: %w", err)
	}
	expiresAt := now.Add(s.requestTTL)
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutCLIRevocation(ctx, store.CLIRevocation{
			WorkspaceID:     s.workspaceID,
			RequestID:       requestID,
			PassID:          req.PassID,
			State:           req.State,
			CodeChallenge:   req.CodeChallenge,
			RedirectURI:     redirectURI,
			CanonicalDigest: digest,
			ExpiresAt:       expiresAt,
		})
	}); err != nil {
		return nil, err
	}
	return &CLIRevocationStart{
		RequestID:       requestID,
		BrowserURL:      s.browserURLFor(requestID, req.PassID),
		CanonicalDigest: digest,
		ExpiresAt:       expiresAt,
	}, nil
}

func (s *CLIRevocationService) browserURLFor(requestID, passID string) string {
	return fmt.Sprintf("%s/mission/%s?cli_revocation=%s", s.browserURL, passID, requestID)
}

// MintResult records the one-use result code after the browser finish
// ran the revocation for this request, and returns the raw code for the
// loopback redirect. The code hash alone is stored; the raw code never
// reaches the store. The revocation that ran must be the one that was
// registered: the canonical digest over pass and mission
// reference/version must match, so a mission that changed since
// registration fails. The founder's reason is bound by the normal
// revoke begin/finish ceremony, not by this digest.
func (s *CLIRevocationService) MintResult(ctx context.Context, requestID string, in RevocationDigestInput, containment string) (code string, err error) {
	now := s.clock().UTC()
	rec, err := s.store.GetCLIRevocation(ctx, s.workspaceID, requestID)
	if err != nil {
		return "", err
	}
	if rec.WorkspaceID != s.workspaceID {
		return "", fmt.Errorf("%w: foreign workspace", ErrCLIRevocationNotFound)
	}
	if !rec.ExpiresAt.After(now) {
		return "", fmt.Errorf("%w: request expired", ErrCLIRevocationExpired)
	}
	if rec.PassID != in.PassID {
		return "", fmt.Errorf("%w: result bound to a different pass", ErrCLIRevocationConflict)
	}
	if want := CanonicalRevocationDigest(in); want != rec.CanonicalDigest {
		return "", fmt.Errorf("%w: revocation binding changed since registration", ErrCLIRevocationConflict)
	}
	code, err = s.newCode()
	if err != nil {
		return "", fmt.Errorf("missionpass: CLI revocation code: %w", err)
	}
	sum := sha256.Sum256([]byte(code))
	var codeHash [32]byte
	copy(codeHash[:], sum[:])
	resultRef, err := s.newResultRef()
	if err != nil {
		return "", fmt.Errorf("missionpass: CLI revocation result ref: %w", err)
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.MintCLIRevocationResult(ctx, s.workspaceID, requestID, resultRef, containment, codeHash, now)
	}); err != nil {
		return "", err
	}
	return code, nil
}

// ExchangeResult is the token response: only the opaque
// revocation-result reference and the fixed containment state.
type ExchangeResult struct {
	ResultRef   string
	Containment string
}

// Exchange verifies the state, consumes the one-use result code, checks
// the PKCE verifier against the bound S256 challenge, and returns only
// the opaque result reference plus the fixed containment state. No CLI
// credential or session is issued or stored. An identical retry after a
// lost response recovers only the original reference until expiry;
// changed, expired, foreign-workspace, replay-altered, or differently
// bound requests fail.
func (s *CLIRevocationService) Exchange(ctx context.Context, code, verifier, redirectURI, state string) (*ExchangeResult, error) {
	now := s.clock().UTC()
	if code == "" || verifier == "" {
		return nil, fmt.Errorf("%w: code and verifier are required", ErrCLIRevocationConflict)
	}
	sum := sha256.Sum256([]byte(code))
	var codeHash [32]byte
	copy(codeHash[:], sum[:])
	rec, err := s.store.GetCLIRevocationByCodeHash(ctx, s.workspaceID, codeHash)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCLIRevocationNotFound, err)
	}
	if rec.WorkspaceID != s.workspaceID {
		return nil, fmt.Errorf("%w: foreign workspace", ErrCLIRevocationNotFound)
	}
	if subtle.ConstantTimeCompare([]byte(rec.State), []byte(state)) != 1 {
		return nil, fmt.Errorf("%w: state mismatch", ErrCLIRevocationConflict)
	}
	if rec.RedirectURI != redirectURI {
		return nil, fmt.Errorf("%w: redirect URI mismatch", ErrCLIRevocationConflict)
	}
	if !authn.VerifyCodeChallenge(rec.CodeChallenge, verifier) {
		return nil, fmt.Errorf("%w: PKCE verification failed", ErrCLIRevocationConflict)
	}
	if !rec.ExpiresAt.After(now) {
		return nil, fmt.Errorf("%w: result expired", ErrCLIRevocationExpired)
	}
	resultRef, containment, err := func() (string, string, error) {
		var ref, cont string
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			var err error
			ref, cont, err = tx.ConsumeCLIRevocationResult(ctx, s.workspaceID, codeHash, now)
			return err
		}); err != nil {
			return "", "", err
		}
		return ref, cont, nil
	}()
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: result not found", ErrCLIRevocationNotFound)
		}
		return nil, err
	}
	return &ExchangeResult{ResultRef: resultRef, Containment: containment}, nil
}

// CLILookupRequest is the registered CLI revocation request the browser
// finish works against. The founder picks the revocation reason in the
// browser; the request carries only the pass binding and the loopback
// handoff fields.
type CLILookupRequest struct {
	RequestID   string
	PassID      string
	RedirectURI string
	State       string
	ExpiresAt   time.Time
}

// Lookup returns the registered CLI revocation request for the browser
// finish. Unknown, expired, or foreign-workspace requests fail closed.
func (s *CLIRevocationService) Lookup(ctx context.Context, workspaceID, requestID string) (*CLILookupRequest, error) {
	if workspaceID == "" || requestID == "" {
		return nil, fmt.Errorf("%w: workspace and request IDs are required", ErrCLIRevocationNotFound)
	}
	if workspaceID != s.workspaceID {
		return nil, fmt.Errorf("%w: foreign workspace", ErrCLIRevocationNotFound)
	}
	rec, err := s.store.GetCLIRevocation(ctx, s.workspaceID, requestID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCLIRevocationNotFound, err)
	}
	if rec.WorkspaceID != s.workspaceID {
		return nil, fmt.Errorf("%w: foreign workspace", ErrCLIRevocationNotFound)
	}
	if !rec.ExpiresAt.After(s.clock().UTC()) {
		return nil, fmt.Errorf("%w: request expired", ErrCLIRevocationExpired)
	}
	return &CLILookupRequest{
		RequestID:   rec.RequestID,
		PassID:      rec.PassID,
		RedirectURI: rec.RedirectURI,
		State:       rec.State,
		ExpiresAt:   rec.ExpiresAt,
	}, nil
}

// PassMissionSummary carries the mission binding the CLI revocation
// digest covers.
type PassMissionSummary struct {
	PassID         string
	MissionRef     string
	MissionVersion int64
}

// PassSummary returns the pass's mission reference and version for the
// result digest. A foreign workspace fails closed.
func (s *CLIRevocationService) PassSummary(ctx context.Context, workspaceID, passID string) (*PassMissionSummary, error) {
	if workspaceID != s.workspaceID {
		return nil, fmt.Errorf("%w: foreign workspace", ErrCLIRevocationNotFound)
	}
	rec, err := s.store.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return nil, err
	}
	return &PassMissionSummary{
		PassID:         rec.PassID,
		MissionRef:     rec.MissionRef,
		MissionVersion: rec.AuthScopeMissionVersion,
	}, nil
}
