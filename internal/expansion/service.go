package expansion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

// Service errors: every failure fails closed without widening the
// delta or re-issuing the upstream mutation.
var (
	ErrInvalidDecision         = errors.New("expansion: invalid decision")
	ErrExpansionNotPending     = errors.New("expansion: expansion is not pending")
	ErrExpansionConflict       = errors.New("expansion: conflicting expansion decision in progress")
	ErrExpansionBindingChanged = errors.New("expansion: expansion binding changed after begin")
	ErrExpansionStale          = errors.New("expansion: expansion delta is stale")
	ErrExpansionPending        = errors.New("expansion: decision outcome unknown; reconciling")
	ErrPassNotDecidable        = errors.New("expansion: pass cannot decide expansions in its state")
)

// decisionAttestationTTL bounds the signed expansion decision.
const decisionAttestationTTL = 5 * time.Minute

// Attestor signs decision attestations. *identity.DecisionAttestor
// implements it; tests wrap it with tampering decorators.
type Attestor interface {
	Attest(ctx context.Context, claims identity.DecisionClaims) (identity.SignedDecisionAttestation, error)
}

// Config wires the expansion decision service.
type Config struct {
	Store           store.Store
	Authn           *authn.Service
	Authority       coreapi.Authority
	Attestor        Attestor
	Clock           func() time.Time
	UpstreamTimeout time.Duration
	NewNonce        func() ([32]byte, error)
}

// Service decides one exact bounded expansion through a passkey
// ceremony. ListPending reads the single source of truth (the local
// expansions table, synced from the authoritative upstream);
// BeginDecision binds the exact canonical delta into a challenge;
// FinishDecision consumes the challenge, attests the exact binding,
// persists the durable intent before the upstream mutation, and calls
// Authority.DecideExpansion exactly once per decision.
type Service struct {
	store           store.Store
	authn           *authn.Service
	authority       coreapi.Authority
	attestor        Attestor
	clock           func() time.Time
	upstreamTimeout time.Duration
	newNonce        func() ([32]byte, error)

	mu    sync.Mutex
	begun map[string]*begunDecision
	// decideLocks serializes concurrent finishes for one expansion so
	// two ceremonies cannot issue two upstream decisions.
	decideLocks map[string]*sync.Mutex
}

type begunDecision struct {
	challengeID string
	principal   authn.Principal
	binding     ExpansionBinding
	digest      string
	begunAt     time.Time
}

// PendingExpansion is one pending expansion for display: the exact
// canonical delta plus staleness signals. The card is disabled when
// stale or expired. It marshals with the delta fields flattened.
type PendingExpansion struct {
	Delta   Delta
	Stale   bool
	Expired bool
}

// MarshalJSON flattens the delta fields with the staleness signals.
func (p PendingExpansion) MarshalJSON() ([]byte, error) {
	type flat Delta
	return json.Marshal(struct {
		flat
		Stale   bool `json:"stale"`
		Expired bool `json:"expired"`
	}{
		flat:    flat(p.Delta),
		Stale:   p.Stale,
		Expired: p.Expired,
	})
}

// BeginResult is the challenge the browser feeds to the passkey.
type BeginResult struct {
	ChallengeID     string          `json:"challenge_id"`
	OptionsJSON     json.RawMessage `json:"options"`
	ExpansionID     string          `json:"expansion_id"`
	Decision        Decision        `json:"decision"`
	EffectiveExpiry time.Time       `json:"effective_expiry"`
}

// DecisionResult is the settled decision.
type DecisionResult struct {
	ExpansionID             string   `json:"expansion_id"`
	PassID                  string   `json:"pass_id"`
	Decision                Decision `json:"decision"`
	DecisionRef             string   `json:"decision_ref"`
	AuthScopeMissionVersion int64    `json:"authscope_mission_version"`
	State                   string   `json:"state"`
}

// NewService builds the expansion decision service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Authn == nil || cfg.Authority == nil || cfg.Attestor == nil {
		return nil, fmt.Errorf("expansion: service requires store, authn, authority, and attestor")
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
		newNonce = newRandomNonce
	}
	return &Service{
		store:           cfg.Store,
		authn:           cfg.Authn,
		authority:       cfg.Authority,
		attestor:        cfg.Attestor,
		clock:           clock,
		upstreamTimeout: timeout,
		newNonce:        newNonce,
		begun:           map[string]*begunDecision{},
		decideLocks:     map[string]*sync.Mutex{},
	}, nil
}

func newRandomNonce() ([32]byte, error) {
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return n, err
	}
	return n, nil
}

func (s *Service) now() time.Time { return s.clock().UTC() }

// ListPending returns the pending expansions for a pass. It syncs the
// local expansions table from the authoritative upstream first, so the
// browser always sees the live delta; the table stays the single source
// of truth.
func (s *Service) ListPending(ctx context.Context, workspaceID, passID string) ([]PendingExpansion, error) {
	var pass store.MissionPassRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		pass, err = tx.GetMissionPass(ctx, workspaceID, passID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A foreign workspace sees nothing, not an error.
			return nil, nil
		}
		return nil, err
	}
	if err := s.syncExpansions(ctx, workspaceID, pass); err != nil {
		return nil, err
	}
	var recs []store.ExpansionRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		recs, err = tx.ListExpansions(ctx, workspaceID, passID, store.ExpansionPending)
		return err
	}); err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]PendingExpansion, 0, len(recs))
	for _, rec := range recs {
		detail, err := strictDecodeDetail(json.RawMessage(rec.DeltaJSON))
		if err != nil {
			return nil, err
		}
		out = append(out, PendingExpansion{
			Delta:   detail.Delta,
			Stale:   detail.Delta.MissionVersion != pass.AuthScopeMissionVersion,
			Expired: !detail.Delta.RequestedExpiry.After(now),
		})
	}
	return out, nil
}

// syncExpansions refreshes the local expansions table from the
// authoritative upstream. Every pending delta is strict-decoded and
// verified against its expansion digest before it is stored; a widened
// or tampered delta fails the whole sync. More than one pending
// expansion for the mission is a conflict.
func (s *Service) syncExpansions(ctx context.Context, workspaceID string, pass store.MissionPassRecord) error {
	if pass.MissionRef == "" {
		return nil
	}
	upstreamCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	opts := coreapi.RequestOptions{WorkspaceID: workspaceID, ActorID: "founder:expansion-sync"}
	listed, err := s.authority.ListExpansions(upstreamCtx, pass.MissionRef, opts)
	if err != nil {
		return fmt.Errorf("expansion: list upstream expansions: %w", err)
	}
	var pending []coreapi.Expansion
	for _, e := range listed {
		if e.Status == store.ExpansionPending {
			pending = append(pending, e)
		}
	}
	if len(pending) > 1 {
		return fmt.Errorf("%w: %d pending expansions for mission %q",
			ErrExpansionConflict, len(pending), pass.MissionRef)
	}
	seen := make(map[string]bool, len(pending))
	for _, e := range pending {
		raw, err := s.authority.GetExpansion(upstreamCtx, e.ExpansionID, opts)
		if err != nil {
			return fmt.Errorf("expansion: get upstream expansion %q: %w", e.ExpansionID, err)
		}
		detail, err := strictDecodeDetail(raw)
		if err != nil {
			return err
		}
		if detail.Delta.ExpansionID != e.ExpansionID {
			return fmt.Errorf("expansion: identity mismatch: listed %q, delta %q",
				e.ExpansionID, detail.Delta.ExpansionID)
		}
		if detail.Delta.MissionRef != pass.MissionRef {
			return fmt.Errorf("expansion: delta mission %q does not match pass mission %q",
				detail.Delta.MissionRef, pass.MissionRef)
		}
		if err := detail.Delta.verifyDigest(); err != nil {
			return err
		}
		deltaJSON, err := canonicalDeltaJSON(detail.Delta)
		if err != nil {
			return err
		}
		rec := store.ExpansionRecord{
			WorkspaceID:     workspaceID,
			ExpansionID:     e.ExpansionID,
			PassID:          pass.PassID,
			MissionRef:      pass.MissionRef,
			Status:          store.ExpansionPending,
			DeltaJSON:       string(deltaJSON),
			ExpansionDigest: detail.Delta.ExpansionDigest,
		}
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.PutExpansion(ctx, rec)
		}); err != nil {
			return err
		}
		seen[e.ExpansionID] = true
	}
	// Resolve local pending rows the upstream no longer lists as
	// pending, using the authoritative status from the same listing.
	// If the upstream does not list the expansion at all, it is no
	// longer pending.
	return s.store.WithTx(ctx, func(tx store.Tx) error {
		local, err := tx.ListExpansions(ctx, workspaceID, pass.PassID, store.ExpansionPending)
		if err != nil {
			return err
		}
		for _, rec := range local {
			if seen[rec.ExpansionID] {
				continue
			}
			status := ""
			for _, e := range listed {
				if e.ExpansionID == rec.ExpansionID {
					status = e.Status
					break
				}
			}
			if status == store.ExpansionPending {
				continue
			}
			if status == "" {
				status = "resolved"
			}
			if err := tx.ResolveExpansion(ctx, workspaceID, rec.ExpansionID, status); err != nil {
				return err
			}
		}
		return nil
	})
}

// expansionDecisionKey is the deterministic idempotency key for one
// expansion decision: an expansion is decided at most once, so
// concurrent finishes share it and cause exactly one upstream decision.
func expansionDecisionKey(workspaceID, expansionID string) string {
	return "expansion:" + workspaceID + ":" + expansionID
}

// decisionRef is the local reference for the signed expansion decision
// attestation, appended to the timeline.
func decisionRef(binding ExpansionBinding) string {
	return "expansion-decision:" + binding.WorkspaceID + ":" + binding.ExpansionID + ":" + string(binding.Decision)
}

// decidableState reports whether a pass can decide expansions: the
// mission is live (running, or running with a projected expansion
// request still in flight) and not terminal.
func decidableState(state string) bool {
	switch missionpass.PassState(state) {
	case missionpass.PassRunning, missionpass.PassAwaitingExpansion:
		return true
	default:
		return false
	}
}

// BeginDecision binds the exact canonical delta into a one-use passkey
// challenge. It reloads the live pending expansion and the current
// mission version; a stale, expired, resolved, or terminal request
// fails closed.
func (s *Service) BeginDecision(ctx context.Context, p authn.Principal, expansionID string, decision Decision) (*BeginResult, error) {
	if decision != ApproveOnce && decision != Deny {
		return nil, fmt.Errorf("%w: %q", ErrInvalidDecision, decision)
	}
	var rec store.ExpansionRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		rec, err = tx.GetExpansion(ctx, p.WorkspaceID, expansionID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: %q", ErrExpansionNotPending, expansionID)
		}
		return nil, err
	}
	var pass store.MissionPassRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		pass, err = tx.GetMissionPass(ctx, p.WorkspaceID, rec.PassID)
		return err
	}); err != nil {
		return nil, err
	}
	if !decidableState(pass.State) {
		return nil, fmt.Errorf("%w: state %q", ErrPassNotDecidable, pass.State)
	}
	// Reload the live pending expansion and the current mission version
	// before binding anything.
	if err := s.syncExpansions(ctx, p.WorkspaceID, pass); err != nil {
		return nil, err
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		pass, err = tx.GetMissionPass(ctx, p.WorkspaceID, rec.PassID)
		if err != nil {
			return err
		}
		rec, err = tx.GetExpansion(ctx, p.WorkspaceID, expansionID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: %q", ErrExpansionNotPending, expansionID)
		}
		return nil, err
	}
	if rec.Status != store.ExpansionPending {
		return nil, fmt.Errorf("%w: %q is %s", ErrExpansionNotPending, expansionID, rec.Status)
	}
	detail, err := strictDecodeDetail(json.RawMessage(rec.DeltaJSON))
	if err != nil {
		return nil, err
	}
	delta := detail.Delta
	now := s.now()
	if !delta.RequestedExpiry.After(now) {
		return nil, fmt.Errorf("%w: %q expired at %v", ErrExpansionNotPending, expansionID, delta.RequestedExpiry)
	}
	if delta.MissionVersion != pass.AuthScopeMissionVersion {
		return nil, fmt.Errorf("%w: delta at version %d, mission at %d",
			ErrExpansionStale, delta.MissionVersion, pass.AuthScopeMissionVersion)
	}
	// Multiple ceremonies may bind the same pending expansion; the
	// decide lock and the durable intent serialize finishes so only
	// one upstream mutation is issued.
	binding := ExpansionBinding{
		WorkspaceID:              p.WorkspaceID,
		PassID:                   pass.PassID,
		MissionRef:               pass.MissionRef,
		ExpectedAuthScopeVersion: pass.AuthScopeMissionVersion,
		ExpansionID:              expansionID,
		ExpansionDigest:          delta.ExpansionDigest,
		Decision:                 decision,
		EffectiveExpiry:          effectiveExpiry(decision, delta.RequestedExpiry, pass.ExpiresAt),
		Purpose:                  identity.PurposeExpansionDecision,
		Audience:                 identity.AudienceExpansionDecision,
	}
	canonical := CanonicalExpansionBytes(binding)
	challenge, options, err := s.authn.BeginDecision(ctx, p, authn.DecisionExpansionDecision, expansionID, canonical)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.begun[challenge.ChallengeID] = &begunDecision{
		challengeID: challenge.ChallengeID,
		principal:   p,
		binding:     binding,
		digest:      bindingDigest(binding),
		begunAt:     s.now(),
	}
	s.mu.Unlock()
	return &BeginResult{
		ChallengeID:     challenge.ChallengeID,
		OptionsJSON:     options,
		ExpansionID:     expansionID,
		Decision:        decision,
		EffectiveExpiry: binding.EffectiveExpiry,
	}, nil
}

// FinishDecision consumes the one-use challenge, attests the exact
// binding, persists the durable intent before the upstream mutation,
// and calls Authority.DecideExpansion exactly once per decision. A
// replayed challenge, a changed binding, or a second decision for an
// already-decided expansion fails closed.
func (s *Service) FinishDecision(ctx context.Context, p authn.Principal, expansionID, challengeID string, assertion []byte) (*DecisionResult, error) {
	s.mu.Lock()
	begun, ok := s.begun[challengeID]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown expansion challenge", authn.ErrCeremonyNotFound)
	}
	if begun.principal.WorkspaceID != p.WorkspaceID || begun.principal.FounderID != p.FounderID ||
		begun.principal.SessionID != p.SessionID {
		return nil, fmt.Errorf("%w: challenge bound to a different principal", ErrExpansionBindingChanged)
	}
	// The durable intent is the arbiter for replays: a completed or
	// in-flight intent with the same canonical digest replays or
	// reconciles without re-checking live state (the pass version
	// advances as a result of the first finish). A changed binding
	// conflicts.
	var intent store.ExpansionIntentRecord
	haveIntent := true
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetExpansionIntent(ctx, p.WorkspaceID, expansionID)
		return err
	}); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		haveIntent = false
	}
	if haveIntent && intent.CanonicalDigest != begun.digest {
		return nil, fmt.Errorf("%w: canonical digest mismatch for expansion %q",
			ErrExpansionConflict, expansionID)
	}
	var detail Delta
	if !haveIntent {
		// No intent yet: the pass and the delta must still match the
		// challenge binding. A changed mission version, a widened
		// delta, or a resolved expansion fails closed without
		// burning the ceremony.
		var pass store.MissionPassRecord
		var rec store.ExpansionRecord
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			var err error
			pass, err = tx.GetMissionPass(ctx, p.WorkspaceID, begun.binding.PassID)
			if err != nil {
				return err
			}
			rec, err = tx.GetExpansion(ctx, p.WorkspaceID, expansionID)
			return err
		}); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, fmt.Errorf("%w: %q", ErrExpansionNotPending, expansionID)
			}
			return nil, err
		}
		decoded, err := strictDecodeDetail(json.RawMessage(rec.DeltaJSON))
		if err != nil {
			return nil, err
		}
		live := ExpansionBinding{
			WorkspaceID:              p.WorkspaceID,
			PassID:                   pass.PassID,
			MissionRef:               pass.MissionRef,
			ExpectedAuthScopeVersion: pass.AuthScopeMissionVersion,
			ExpansionID:              expansionID,
			ExpansionDigest:          decoded.Delta.ExpansionDigest,
			Decision:                 begun.binding.Decision,
			EffectiveExpiry:          effectiveExpiry(begun.binding.Decision, decoded.Delta.RequestedExpiry, pass.ExpiresAt),
			Purpose:                  identity.PurposeExpansionDecision,
			Audience:                 identity.AudienceExpansionDecision,
		}
		if bindingDigest(live) != begun.digest {
			return nil, fmt.Errorf("%w: live binding differs from the begun challenge", ErrExpansionBindingChanged)
		}
		detail = decoded.Delta
	}
	// The binding held: consume the one-use challenge before the
	// assertion is verified.
	s.dropBegun(challengeID)
	verified, err := s.authn.FinishDecision(ctx, p, challengeID, authn.DecisionExpansionDecision, expansionID, CanonicalExpansionBytes(begun.binding), assertion)
	if err != nil {
		return nil, err
	}
	if haveIntent {
		// Replay or reconcile: the intent already carries the
		// attestation; the ceremony above proves the founder's
		// presence for this challenge.
		return s.decideOnce(ctx, p, begun.binding, detail, identity.SignedDecisionAttestation{}, "", "")
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
	issuedAt := time.Now().UTC()
	nonce, err := s.newNonce()
	if err != nil {
		return nil, fmt.Errorf("expansion: mint attestation nonce: %w", err)
	}
	att, err := s.attestor.Attest(ctx, identity.DecisionClaims{
		WorkspaceID:               begun.binding.WorkspaceID,
		FounderID:                 begun.principal.FounderID,
		Audience:                  identity.AudienceExpansionDecision,
		Purpose:                   identity.PurposeExpansionDecision,
		SubjectID:                 expansionID,
		DecisionDigest:            bindingDigest(begun.binding),
		InvocationDigest:          detail.NormalizedArgumentsDigest,
		AuthenticationMethod:      verified.Method,
		AuthenticationProofDigest: proofDigest,
		Nonce:                     nonce,
		IssuedAt:                  issuedAt,
		ExpiresAt:                 issuedAt.Add(decisionAttestationTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("expansion: sign expansion decision: %w", err)
	}
	attDigest, err := attestationDigest(att)
	if err != nil {
		return nil, err
	}
	attJSON, err := json.Marshal(att)
	if err != nil {
		return nil, fmt.Errorf("expansion: encode expansion attestation: %w", err)
	}
	return s.decideOnce(ctx, p, begun.binding, detail, att, attDigest, string(attJSON))
}

func (s *Service) dropBegun(challengeID string) {
	s.mu.Lock()
	delete(s.begun, challengeID)
	s.mu.Unlock()
}

func (s *Service) lockFor(expansionID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.decideLocks[expansionID]; ok {
		return l
	}
	l := &sync.Mutex{}
	s.decideLocks[expansionID] = l
	return l
}

// decideOnce persists the local intent before the upstream call so an
// ambiguous outcome reconciles by the original idempotency key without
// ever re-issuing the decision. Concurrent finishes for one expansion
// are serialized: the first issues the call, the rest replay or
// reconcile. The same idempotency key plus the canonical binding
// replays the original result; a changed binding conflicts.
func (s *Service) decideOnce(ctx context.Context, p authn.Principal, binding ExpansionBinding, delta Delta, att identity.SignedDecisionAttestation, attDigest, attJSON string) (*DecisionResult, error) {
	unlock := s.lockFor(binding.ExpansionID)
	unlock.Lock()
	defer unlock.Unlock()

	key := expansionDecisionKey(binding.WorkspaceID, binding.ExpansionID)
	canonicalDigest := bindingDigest(binding)
	var intent store.ExpansionIntentRecord
	haveIntent := true
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetExpansionIntent(ctx, binding.WorkspaceID, binding.ExpansionID)
		return err
	}); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		haveIntent = false
	}
	if haveIntent {
		switch intent.State {
		case store.ExpansionIntentCompleted:
			if intent.CanonicalDigest != canonicalDigest {
				return nil, fmt.Errorf("%w: canonical digest mismatch for decided expansion %q",
					ErrExpansionConflict, binding.ExpansionID)
			}
			return s.replayCompleted(ctx, binding)
		default:
			if intent.CanonicalDigest != canonicalDigest {
				return nil, fmt.Errorf("%w: canonical digest mismatch", ErrExpansionConflict)
			}
			if intent.IdempotencyKey != key {
				return nil, fmt.Errorf("%w: idempotency key mismatch", ErrExpansionConflict)
			}
			// An in-flight intent with the same binding reconciles
			// instead of re-issuing the decision.
			return s.reconcileLocked(ctx, binding.WorkspaceID, binding.ExpansionID)
		}
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutExpansionIntent(ctx, store.ExpansionIntentRecord{
			WorkspaceID:       binding.WorkspaceID,
			ExpansionID:       binding.ExpansionID,
			PassID:            binding.PassID,
			IdempotencyKey:    key,
			Decision:          string(binding.Decision),
			CanonicalDigest:   canonicalDigest,
			State:             store.ExpansionIntentInFlight,
			AttestationDigest: attDigest,
			AttestationJSON:   attJSON,
		})
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// A concurrent finish won the intent: reconcile with it.
			return s.reconcileLocked(ctx, binding.WorkspaceID, binding.ExpansionID)
		}
		return nil, err
	}
	upstreamCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	approve := binding.Decision == ApproveOnce
	result, err := s.authority.DecideExpansion(upstreamCtx, binding.ExpansionID,
		coreapi.ExpansionDecision{Approve: approve, Reason: delta.ReasonCode}, att, coreapi.RequestOptions{
			WorkspaceID:    binding.WorkspaceID,
			ActorID:        "founder:" + p.FounderID,
			IdempotencyKey: key,
		})
	if err != nil {
		if isAmbiguousUpstream(err) {
			// The outcome is unknown: the intent stays in-flight and
			// the pass records pending reconciliation. The worker
			// reconciles by the original idempotency key; never retry
			// blindly.
			_ = s.markDecisionPending(ctx, binding)
			return nil, fmt.Errorf("%w: decide expansion: %w", ErrExpansionPending, err)
		}
		return nil, err
	}
	return s.settleDecision(ctx, binding, delta, result)
}

// replayCompleted returns the stored result for an already-decided
// expansion instead of re-issuing the decision.
func (s *Service) replayCompleted(ctx context.Context, binding ExpansionBinding) (*DecisionResult, error) {
	var intent store.ExpansionIntentRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetExpansionIntent(ctx, binding.WorkspaceID, binding.ExpansionID)
		return err
	}); err != nil {
		return nil, err
	}
	var pass store.MissionPassRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		pass, err = tx.GetMissionPass(ctx, binding.WorkspaceID, binding.PassID)
		return err
	}); err != nil {
		return nil, err
	}
	return &DecisionResult{
		ExpansionID:             binding.ExpansionID,
		PassID:                  binding.PassID,
		Decision:                Decision(intent.Decision),
		DecisionRef:             intent.UpstreamRef,
		AuthScopeMissionVersion: intent.ResultMissionVersion,
		State:                   pass.State,
	}, nil
}

// markDecisionPending records the ambiguous outcome on the pass: the
// pass keeps its state with pending reconciliation.
func (s *Service) markDecisionPending(ctx context.Context, binding ExpansionBinding) error {
	return s.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, binding.WorkspaceID, binding.PassID)
		if err != nil {
			return err
		}
		rec.Reconciliation = string(missionpass.ReconciliationPending)
		return tx.PutMissionPass(ctx, rec, rec.StoreRevision)
	})
}

// settleDecision persists the decided expansion atomically. Approval
// stores the returned upstream mission version, increments the store
// revision, preserves the draft version, and returns the pass to
// running. Denial leaves the prior authority byte-identical: the pass
// row is untouched and only the intent completes.
func (s *Service) settleDecision(ctx context.Context, binding ExpansionBinding, delta Delta, result coreapi.ExpansionResult) (*DecisionResult, error) {
	ref := decisionRef(binding)
	res := &DecisionResult{
		ExpansionID: binding.ExpansionID,
		PassID:      binding.PassID,
		Decision:    binding.Decision,
		DecisionRef: ref,
		State:       string(missionpass.PassAwaitingExpansion),
	}
	return res, s.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, binding.WorkspaceID, binding.PassID)
		if err != nil {
			return err
		}
		if binding.Decision == ApproveOnce {
			if result.MissionVersion <= binding.ExpectedAuthScopeVersion {
				return fmt.Errorf("expansion: upstream mission version %d did not advance past %d",
					result.MissionVersion, binding.ExpectedAuthScopeVersion)
			}
			// Idempotent settle: a concurrent finish may have settled
			// already; the completed intent below is the arbiter.
			if rec.AuthScopeMissionVersion < result.MissionVersion || rec.State != string(missionpass.PassRunning) {
				rec.AuthScopeMissionVersion = result.MissionVersion
				rec.State = string(missionpass.PassRunning)
				rec.Reconciliation = string(missionpass.ReconciliationSettled)
				if err := tx.PutMissionPass(ctx, rec, rec.StoreRevision); err != nil {
					return err
				}
			}
			res.AuthScopeMissionVersion = result.MissionVersion
			res.State = string(missionpass.PassRunning)
		} else {
			res.AuthScopeMissionVersion = rec.AuthScopeMissionVersion
			res.State = rec.State
		}
		status := store.ExpansionDenied
		if binding.Decision == ApproveOnce {
			status = store.ExpansionApproved
		}
		if err := tx.ResolveExpansion(ctx, binding.WorkspaceID, binding.ExpansionID, status); err != nil {
			return err
		}
		return tx.CompleteExpansionIntent(ctx, binding.WorkspaceID, binding.ExpansionID, ref, res.AuthScopeMissionVersion)
	})
}

// ReconcileExpansion resumes an ambiguous expansion decision by its
// original idempotency key. It uses only ReconcileOperation and
// authoritative reads; it never repeats DecideExpansion.
func (s *Service) ReconcileExpansion(ctx context.Context, workspaceID, expansionID string) (*DecisionResult, error) {
	unlock := s.lockFor(expansionID)
	unlock.Lock()
	defer unlock.Unlock()
	return s.reconcileLocked(ctx, workspaceID, expansionID)
}

// reconcileLocked is ReconcileExpansion with the decide lock held.
func (s *Service) reconcileLocked(ctx context.Context, workspaceID, expansionID string) (*DecisionResult, error) {
	var intent store.ExpansionIntentRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		intent, err = tx.GetExpansionIntent(ctx, workspaceID, expansionID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if intent.State == store.ExpansionIntentCompleted {
		var binding ExpansionBinding
		binding.WorkspaceID = workspaceID
		binding.ExpansionID = expansionID
		binding.PassID = intent.PassID
		return s.replayCompleted(ctx, binding)
	}
	reconCtx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	outcome, err := s.authority.ReconcileOperation(reconCtx, intent.IdempotencyKey, intent.PassID, coreapi.RequestOptions{
		WorkspaceID: workspaceID,
		ActorID:     "founder:reconcile",
	})
	if err != nil {
		return nil, err
	}
	if outcome.Status != "completed" {
		return nil, nil
	}
	// The decision landed upstream. Read the authoritative outcome;
	// never re-issue the mutation.
	raw, err := s.authority.GetExpansion(reconCtx, expansionID, coreapi.RequestOptions{
		WorkspaceID: workspaceID,
		ActorID:     "founder:reconcile",
	})
	if err != nil {
		return nil, fmt.Errorf("expansion: read decided expansion %q: %w", expansionID, err)
	}
	detail, err := strictDecodeDetail(raw)
	if err != nil {
		return nil, err
	}
	if err := detail.Delta.verifyDigest(); err != nil {
		return nil, err
	}
	var delta Delta = detail.Delta
	binding := ExpansionBinding{
		WorkspaceID:              workspaceID,
		PassID:                   intent.PassID,
		ExpectedAuthScopeVersion: 0,
		ExpansionID:              expansionID,
		ExpansionDigest:          delta.ExpansionDigest,
		Decision:                 Decision(intent.Decision),
		Purpose:                  identity.PurposeExpansionDecision,
		Audience:                 identity.AudienceExpansionDecision,
	}
	// The mission reference and expected version come from the live
	// pass; the decision itself comes from the durable intent.
	var pass store.MissionPassRecord
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		pass, err = tx.GetMissionPass(ctx, workspaceID, intent.PassID)
		if err != nil {
			return err
		}
		binding.MissionRef = pass.MissionRef
		binding.ExpectedAuthScopeVersion = pass.AuthScopeMissionVersion
		return nil
	}); err != nil {
		return nil, err
	}
	switch detail.Status {
	case store.ExpansionApproved:
		if detail.DecidedMissionVersion <= 0 {
			return nil, fmt.Errorf("expansion: upstream decided %q without a mission version", expansionID)
		}
		return s.settleDecision(ctx, binding, delta, coreapi.ExpansionResult{
			ExpansionID:    expansionID,
			Decision:       string(ApproveOnce),
			MissionVersion: detail.DecidedMissionVersion,
		})
	case store.ExpansionDenied:
		return s.settleDecision(ctx, binding, delta, coreapi.ExpansionResult{
			ExpansionID:    expansionID,
			Decision:       string(Deny),
			MissionVersion: pass.AuthScopeMissionVersion,
		})
	default:
		// Still pending upstream: keep the intent in flight.
		return nil, nil
	}
}

// ceremonyProof binds the verified local ceremony record into the
// decision attestation without embedding credential material. The
// struct has fixed JSON field order, so the digest is deterministic.
type ceremonyProof struct {
	Method       string `json:"method"`
	ChallengeID  string `json:"challenge_id"`
	Nonce        string `json:"nonce"`
	WorkspaceID  string `json:"workspace_id"`
	SessionID    string `json:"session_id"`
	FounderID    string `json:"founder_id"`
	SubjectID    string `json:"subject_id"`
	Purpose      string `json:"purpose"`
	UserVerified bool   `json:"user_verified"`
}

func ceremonyProofDigest(proof ceremonyProof) (string, error) {
	raw, err := json.Marshal(proof)
	if err != nil {
		return "", fmt.Errorf("expansion: encode ceremony proof: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// attestationDigest covers the signed decision attestation bytes.
func attestationDigest(att identity.SignedDecisionAttestation) (string, error) {
	raw, err := json.Marshal(att)
	if err != nil {
		return "", fmt.Errorf("expansion: encode attestation: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// isAmbiguousUpstream mirrors the revocation ambiguity rule: a timeout
// or a retryable upstream status means the mutation may have landed, so
// the caller must reconcile instead of issuing another mutation.
func isAmbiguousUpstream(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return true
	}
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	var up *coreapi.UpstreamError
	if errors.As(err, &up) {
		switch up.StatusCode {
		case 429, 503, 504:
			return true
		}
	}
	return false
}
