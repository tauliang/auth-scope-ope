// The launch service exchanges one approved authorization code plus the
// PKCE verifier for exactly one upstream launch preparation. The exchange
// is atomic: a durable intent row keyed by the code hash guarantees that
// concurrent double submits and retries after a lost response return only
// the original sealed result with exactly one upstream PrepareLaunch call.
//
// Only digests and run metadata reach durable storage. The sealed signed
// envelope, the signed decision attestation, and any credential bytes
// never do: the envelope digest and the attestation digest are the only
// cryptographic traces kept. Sealed bytes live in a bounded in-memory
// delivery cache for duplicate delivery only.
package launch

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

var (
	// ErrInvalidExchange reports a malformed code or verifier.
	ErrInvalidExchange = errors.New("launch: invalid exchange request")
	// ErrExchangeNotFound reports an unknown authorization code.
	ErrExchangeNotFound = errors.New("launch: authorization code not found")
	// ErrCodeExpired reports an authorization code past its TTL.
	ErrCodeExpired = errors.New("launch: authorization code expired")
	// ErrExchangeConflict reports an exchange whose canonical content
	// (code plus verifier) moved after the code was consumed.
	ErrExchangeConflict = errors.New("launch: exchange conflicts with the approved canonical exchange")
	// ErrAttestationMissing reports a missing in-memory decision
	// attestation. Only a new browser authorization can continue.
	ErrAttestationMissing = errors.New("launch: decision attestation is unavailable; a new browser authorization is required")
	// ErrBindingChanged reports an approved launch binding that moved
	// after approval.
	ErrBindingChanged = errors.New("launch: approved launch binding changed")
	// ErrStaleMissionVersion reports an upstream mission version that
	// moved past the approved version.
	ErrStaleMissionVersion = errors.New("launch: mission version is stale")
	// ErrUnsupportedKit reports an agent kit AuthScope does not list.
	ErrUnsupportedKit = errors.New("launch: agent kit is not supported by AuthScope")
	// ErrIsolationNotEnforced reports prepared artifacts whose isolation
	// profile is not enforced.
	ErrIsolationNotEnforced = errors.New("launch: upstream isolation is not enforced")
	// ErrExchangeStale reports an in-flight reservation whose owner died.
	// The attestation is gone with it; only a new browser authorization
	// can continue.
	ErrExchangeStale = errors.New("launch: exchange reservation went stale; a new browser authorization is required")
	// ErrExchangeFailed reports a previous exchange attempt that failed.
	ErrExchangeFailed = errors.New("launch: exchange failed")
	// ErrExchangeResultGone reports a completed exchange whose sealed
	// result is no longer available in memory or upstream.
	ErrExchangeResultGone = errors.New("launch: sealed launch result is no longer available; authorize again")
	// ErrAmbiguousExchange reports an in-flight exchange whose upstream
	// outcome cannot be determined. The preparation is never reissued;
	// a later retry reconciles again.
	ErrAmbiguousExchange = errors.New("launch: exchange outcome is ambiguous; retry the exchange")
)

// defaultDeliveryCap bounds the in-memory delivery cache.
const defaultDeliveryCap = 512

// launchExchangeStaleAfter bounds how long an exchange reservation (or a
// completed exchange receipt) stays usable. Past the window the
// reservation is dead and only a fresh browser authorization continues.
const launchExchangeStaleAfter = 10 * time.Minute

// codeStripeCount sizes the striped per-code lock. Striping bounds memory
// (entries are never added or removed); a collision only serializes two
// unrelated codes briefly.
const codeStripeCount = 64

// Config wires the launch service.
type Config struct {
	Store        store.Store
	WorkspaceID  string
	Authority    coreapi.Authority
	Attestations *authn.PendingDecisionAttestations
	// Keys is the pinned signing-key trust store. The service cannot
	// open a sealed envelope (only the CLI ephemeral key opens it), but
	// it refuses to adopt artifacts sealed under an unknown signing key.
	Keys *trust.KeyStore
	// Clock overrides time.Now for tests.
	Clock func() time.Time
	// DeliveryCap bounds the in-memory delivery cache. Zero selects the
	// default.
	DeliveryCap int
}

// ExchangeRequest carries the one-use authorization code and the PKCE
// verifier, both base64url.
type ExchangeRequest struct {
	Code     string
	Verifier string
}

// ExchangeResult is the prepared governed run. SealedEnvelope is the
// opaque sealed signed envelope; it is never persisted.
type ExchangeResult struct {
	RunID          string
	MissionRef     string
	SealedEnvelope []byte
}

// Service exchanges authorization codes for prepared launches.
type Service struct {
	store        store.Store
	workspace    string
	authority    coreapi.Authority
	attestations *authn.PendingDecisionAttestations
	keys         *trust.KeyStore
	clock        func() time.Time
	deliveryCap  int

	mu       sync.Mutex
	delivery map[string]ExchangeResult
	order    []string
	// codeStripes serializes concurrent exchanges of the same code
	// inside this process; the durable claim serializes across
	// processes.
	codeStripes [codeStripeCount]sync.Mutex
}

// NewService validates the config and returns a launch service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil {
		return nil, errors.New("launch: store is required")
	}
	if cfg.WorkspaceID == "" {
		return nil, errors.New("launch: workspace id is required")
	}
	if cfg.Authority == nil {
		return nil, errors.New("launch: authority is required")
	}
	if cfg.Attestations == nil {
		return nil, errors.New("launch: attestation cache is required")
	}
	if cfg.Keys == nil {
		return nil, errors.New("launch: signing-key trust store is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	cap := cfg.DeliveryCap
	if cap <= 0 {
		cap = defaultDeliveryCap
	}
	return &Service{
		store:        cfg.Store,
		workspace:    cfg.WorkspaceID,
		authority:    cfg.Authority,
		attestations: cfg.Attestations,
		keys:         cfg.Keys,
		clock:        clock,
		deliveryCap:  cap,
		delivery:     make(map[string]ExchangeResult),
	}, nil
}

// ExchangeAndPrepare exchanges one authorization code plus verifier for
// the prepared governed run, exactly once per code.
//
// A per-code stripe serializes concurrent submissions inside this
// process; the durable claim serializes across processes. The row's
// status decides the path: a completed row replays the sealed bytes
// (after the verifier is re-proven), a failed or expired row reports its
// terminal state, and an in-flight row reconciles the ambiguous upstream
// outcome instead of reissuing preparation. Only a fresh code reaches
// validation and the single PrepareLaunch call.
func (s *Service) ExchangeAndPrepare(ctx context.Context, req ExchangeRequest) (ExchangeResult, error) {
	codeRaw, err := base64.RawURLEncoding.DecodeString(req.Code)
	if err != nil || len(codeRaw) != 32 {
		return ExchangeResult{}, ErrExchangeNotFound
	}
	if _, err := base64.RawURLEncoding.DecodeString(req.Verifier); err != nil {
		return ExchangeResult{}, ErrInvalidExchange
	}
	codeHash := sha256.Sum256(codeRaw)
	codeHashHex := hex.EncodeToString(codeHash[:])

	unlock := s.lockCode(codeHash)
	defer unlock()
	now := s.clock()

	row, err := s.getIntent(ctx, codeHashHex)
	if err != nil {
		return ExchangeResult{}, err
	}
	if row == nil {
		// Fresh code: validate everything read-only before claiming, so
		// a failed check consumes nothing and leaves no reservation
		// behind.
		rec, pass, err := s.validateForExchange(ctx, codeHash, req.Verifier, now)
		if err != nil {
			return ExchangeResult{}, err
		}
		var claimed bool
		if err := s.store.WithTx(ctx, func(tx store.Tx) error {
			var err error
			claimed, err = tx.ClaimLaunchExchangeIntent(ctx, store.LaunchExchangeIntent{
				WorkspaceID:       s.workspace,
				CodeHash:          codeHashHex,
				AuthorizationID:   rec.AuthorizationID,
				PassID:            rec.PassID,
				AttestationDigest: rec.DecisionAttestationDigest,
			}, now)
			return err
		}); err != nil {
			return ExchangeResult{}, err
		}
		if !claimed {
			// Lost the claim race across processes: follow the
			// winner's row instead of preparing again.
			row, err = s.getIntent(ctx, codeHashHex)
			if err != nil {
				return ExchangeResult{}, err
			}
			if row == nil {
				return ExchangeResult{}, ErrExchangeConflict
			}
		} else {
			return s.ownExchange(ctx, rec, pass, codeHash, codeHashHex, now)
		}
	}
	return s.settleRow(ctx, codeHash, req.Verifier, codeHashHex, *row, now)
}

// lockCode serializes exchanges of one code inside this process.
func (s *Service) lockCode(codeHash [32]byte) func() {
	stripe := &s.codeStripes[int(codeHash[0])%codeStripeCount]
	stripe.Lock()
	return stripe.Unlock
}

// getIntent returns the durable exchange intent for a code hash, or nil
// when no exchange was ever claimed for it.
func (s *Service) getIntent(ctx context.Context, codeHashHex string) (*store.LaunchExchangeIntent, error) {
	var row store.LaunchExchangeIntent
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		row, err = tx.GetLaunchExchangeIntent(ctx, s.workspace, codeHashHex)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &row, nil
}

// settleRow follows an existing intent row by status. It never reissues
// PrepareLaunch.
func (s *Service) settleRow(ctx context.Context, codeHash [32]byte, verifier, codeHashHex string, row store.LaunchExchangeIntent, now time.Time) (ExchangeResult, error) {
	switch row.Status {
	case store.LaunchExchangeCompleted:
		return s.replayCompleted(ctx, codeHash, verifier, codeHashHex, row, now)
	case store.LaunchExchangeFailed:
		msg := row.Failure
		if msg == "" {
			msg = "previous exchange attempt failed"
		}
		return ExchangeResult{}, fmt.Errorf("%w: %s", ErrExchangeFailed, msg)
	case store.LaunchExchangeExpired:
		return ExchangeResult{}, ErrExchangeStale
	default:
		return s.reconcileOrphan(ctx, codeHash, codeHashHex, row, now)
	}
}

// replayCompleted replays the sealed bytes for an already completed
// exchange. The retry must still prove the original verifier; a receipt
// older than the stale window requires a fresh authorization. When the
// in-memory delivery is gone the sealed result is rebuilt through the
// idempotent upstream operation lookup, never by re-preparing.
func (s *Service) replayCompleted(ctx context.Context, codeHash [32]byte, verifier, codeHashHex string, row store.LaunchExchangeIntent, now time.Time) (ExchangeResult, error) {
	if now.Sub(row.UpdatedAt) > launchExchangeStaleAfter {
		return ExchangeResult{}, ErrExchangeStale
	}
	rec, err := s.store.GetCLIAuthorizationByCodeHash(ctx, s.workspace, codeHash)
	if err != nil {
		return ExchangeResult{}, err
	}
	if !authn.VerifyCodeChallenge(rec.CodeChallenge, verifier) {
		return ExchangeResult{}, ErrExchangeConflict
	}
	if res, ok := s.recallDelivery(codeHashHex); ok {
		return res, nil
	}
	return s.reconcileCompleted(ctx, codeHashHex)
}

// validateForExchange resolves the authorization by code hash and checks
// every pinned value before anything is consumed.
func (s *Service) validateForExchange(ctx context.Context, codeHash [32]byte, verifier string, now time.Time) (store.CLIAuthorization, store.MissionPassRecord, error) {
	var zeroAuth store.CLIAuthorization
	var zeroPass store.MissionPassRecord
	rec, err := s.store.GetCLIAuthorizationByCodeHash(ctx, s.workspace, codeHash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return zeroAuth, zeroPass, ErrExchangeNotFound
		}
		return zeroAuth, zeroPass, err
	}
	if subtleCompare32(rec.CodeHash, codeHash) != 1 {
		return zeroAuth, zeroPass, ErrExchangeNotFound
	}
	if err := authn.VerifyRecordIntegrity(rec); err != nil {
		return zeroAuth, zeroPass, fmt.Errorf("%w: authorization record", ErrBindingChanged)
	}
	if !now.Before(rec.ExpiresAt) {
		return zeroAuth, zeroPass, ErrCodeExpired
	}
	if rec.DecisionAttestationDigest == "" {
		return zeroAuth, zeroPass, fmt.Errorf("%w: authorization is not approved", ErrBindingChanged)
	}
	if !authn.VerifyCodeChallenge(rec.CodeChallenge, verifier) {
		return zeroAuth, zeroPass, ErrExchangeConflict
	}
	pass, err := s.store.GetMissionPass(ctx, s.workspace, rec.PassID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return zeroAuth, zeroPass, fmt.Errorf("%w: pass is gone", ErrBindingChanged)
		}
		return zeroAuth, zeroPass, err
	}
	if err := checkPassBinding(pass, rec, now); err != nil {
		return zeroAuth, zeroPass, err
	}
	if err := s.checkPosture(ctx, pass, now); err != nil {
		return zeroAuth, zeroPass, err
	}
	mission, err := s.authority.IntrospectMission(ctx, rec.MissionRef, coreapi.RequestOptions{WorkspaceID: s.workspace})
	if err != nil {
		return zeroAuth, zeroPass, fmt.Errorf("launch: introspect mission: %w", err)
	}
	if mission.Version != pass.AuthScopeMissionVersion {
		return zeroAuth, zeroPass, fmt.Errorf("%w: approved %d, upstream %d",
			ErrStaleMissionVersion, pass.AuthScopeMissionVersion, mission.Version)
	}
	kits, err := s.authority.ListAgentKits(ctx, coreapi.RequestOptions{WorkspaceID: s.workspace})
	if err != nil {
		return zeroAuth, zeroPass, fmt.Errorf("launch: list agent kits: %w", err)
	}
	if !kitSupported(kits, rec.AgentKitID, rec.AgentKitVersion) {
		return zeroAuth, zeroPass, fmt.Errorf("%w: %s %s", ErrUnsupportedKit, rec.AgentKitID, rec.AgentKitVersion)
	}
	return rec, pass, nil
}

// ownExchange drives the upstream preparation as the claim winner. The
// in-flight row is the may-have-been-sent marker: it is claimed before the
// upstream call so an ambiguous outcome reconciles instead of reissuing.
func (s *Service) ownExchange(ctx context.Context, rec store.CLIAuthorization, pass store.MissionPassRecord, codeHash [32]byte, codeHashHex string, now time.Time) (ExchangeResult, error) {
	// The attestation is one-use and in-memory only: take it now that this
	// request owns the exchange, and fail before any upstream request when
	// it is gone.
	att, ok := s.attestations.Take(rec.AuthorizationID)
	if !ok || att == nil {
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeFailed, "", "", "decision attestation unavailable", s.clock())
		return ExchangeResult{}, ErrAttestationMissing
	}
	if subtle.ConstantTimeCompare(att.CodeHash[:], codeHash[:]) != 1 || att.AttestationDigest != rec.DecisionAttestationDigest {
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeFailed, "", "", "decision attestation mismatch", s.clock())
		return ExchangeResult{}, ErrAttestationMissing
	}

	idempotencyKey := "ope-launch-" + codeHashHex
	upReq := coreapi.LaunchRequest{
		KitID:              rec.AgentKitID,
		IdempotencyKey:     idempotencyKey,
		EphemeralPublicKey: rec.EphemeralPublicKey,
	}
	artifacts, err := s.authority.PrepareLaunch(ctx, rec.MissionRef, upReq, att.Attestation, coreapi.RequestOptions{WorkspaceID: s.workspace})
	if err != nil {
		return s.handlePrepareError(ctx, err, idempotencyKey, codeHashHex, rec, pass)
	}
	return s.adoptArtifacts(ctx, artifacts, codeHashHex, rec, pass)
}

// handlePrepareError reconciles ambiguous upstream failures. A definite
// upstream denial settles failed; an ambiguous outcome reconciles through
// ReconcileOperation without reissuing PrepareLaunch.
func (s *Service) handlePrepareError(ctx context.Context, prepareErr error, idempotencyKey, codeHashHex string, rec store.CLIAuthorization, pass store.MissionPassRecord) (ExchangeResult, error) {
	var upErr *coreapi.UpstreamError
	if errors.As(prepareErr, &upErr) && upErr.StatusCode >= 400 && upErr.StatusCode < 500 {
		// A definite upstream denial: the run was not prepared.
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeFailed, "", "", "upstream denied the launch", s.clock())
		return ExchangeResult{}, fmt.Errorf("launch: prepare launch: %w", prepareErr)
	}
	if ctx.Err() != nil {
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeFailed, "", "", "exchange canceled", s.clock())
		return ExchangeResult{}, fmt.Errorf("launch: prepare launch: %w", prepareErr)
	}
	res, err := s.authority.ReconcileOperation(ctx, idempotencyKey, "", coreapi.RequestOptions{WorkspaceID: s.workspace})
	if err != nil {
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeFailed, "", "", "upstream outcome unknown", s.clock())
		return ExchangeResult{}, fmt.Errorf("launch: prepare launch: %v; reconcile: %w", prepareErr, err)
	}
	if res.Status != "completed" || res.Artifacts == nil {
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeFailed, "", "", "upstream operation did not complete", s.clock())
		return ExchangeResult{}, fmt.Errorf("launch: prepare launch: %v; reconcile status %q", prepareErr, res.Status)
	}
	return s.adoptArtifacts(ctx, *res.Artifacts, codeHashHex, rec, pass)
}

// checkSealedEnvelope validates the sealed envelope's outer structure
// and binds the outer signing key ID to a key the trust store knows. OPE
// cannot open the envelope here (only the CLI ephemeral private key
// opens it), but it refuses to adopt artifacts sealed under an unknown
// signing key instead of failing later at the CLI.
func (s *Service) checkSealedEnvelope(sealed []byte) error {
	head, err := ParseSealedEnvelopeHead(sealed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBindingChanged, err)
	}
	if head.Format != SealedEnvelopeFormat {
		return fmt.Errorf("%w: sealed envelope format %q", ErrBindingChanged, head.Format)
	}
	if head.Algorithm != SealAlgorithm {
		return fmt.Errorf("%w: sealed envelope algorithm %q", ErrBindingChanged, head.Algorithm)
	}
	if head.KeyID == "" {
		return fmt.Errorf("%w: sealed envelope has no key id", ErrBindingChanged)
	}
	trusted := false
	for _, id := range s.keys.KeyIDs() {
		if subtle.ConstantTimeCompare([]byte(id), []byte(head.KeyID)) == 1 {
			trusted = true
			break
		}
	}
	if !trusted {
		return fmt.Errorf("%w: sealed envelope key %q is not trusted", ErrBindingChanged, head.KeyID)
	}
	return nil
}

// adoptArtifacts validates prepared artifacts, persists only digests and
// run metadata, transitions the pass to launching, and delivers the sealed
// bytes to the waiter set.
func (s *Service) adoptArtifacts(ctx context.Context, artifacts coreapi.LaunchArtifacts, codeHashHex string, rec store.CLIAuthorization, pass store.MissionPassRecord) (ExchangeResult, error) {
	fail := func(msg string, err error) (ExchangeResult, error) {
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeFailed, "", "", msg, s.clock())
		return ExchangeResult{}, err
	}
	if artifacts.IsolationProfile != IsolationEnforced {
		return fail("isolation not enforced", fmt.Errorf("%w: %q", ErrIsolationNotEnforced, artifacts.IsolationProfile))
	}
	if artifacts.RunID == "" || len(artifacts.SealedSignedEnvelope) == 0 {
		return fail("upstream artifacts incomplete", fmt.Errorf("%w: upstream artifacts incomplete", ErrExchangeFailed))
	}
	if artifacts.MissionRef != rec.MissionRef {
		return fail("mission ref mismatch", fmt.Errorf("%w: mission ref mismatch", ErrBindingChanged))
	}
	if err := s.checkSealedEnvelope(artifacts.SealedSignedEnvelope); err != nil {
		return fail("sealed envelope key not trusted", err)
	}
	envelopeDigest := "sha256:" + hex.EncodeToString(sha256Of(artifacts.SealedSignedEnvelope))
	result := ExchangeResult{
		RunID:          artifacts.RunID,
		MissionRef:     artifacts.MissionRef,
		SealedEnvelope: append([]byte(nil), artifacts.SealedSignedEnvelope...),
	}
	now := s.clock()
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		current, err := tx.GetMissionPass(ctx, s.workspace, rec.PassID)
		if err != nil {
			return err
		}
		if err := checkPassBinding(current, rec, now); err != nil {
			return err
		}
		if current.StoreRevision != pass.StoreRevision {
			return fmt.Errorf("%w: pass changed during exchange", store.ErrConflict)
		}
		current.State = "launching"
		current.RunID = artifacts.RunID
		current.AuthScopeMissionVersion = artifacts.AuthScopeMissionVersion
		// DraftVersion is preserved: launching is a state transition, not
		// a new draft.
		if err := tx.PutMissionPass(ctx, current, current.StoreRevision); err != nil {
			return err
		}
		return tx.SettleLaunchExchangeIntent(ctx, s.workspace, codeHashHex,
			store.LaunchExchangeCompleted, artifacts.RunID, envelopeDigest, "", now)
	})
	if err != nil {
		return fail("launch settlement failed", fmt.Errorf("launch: settle exchange: %w", err))
	}
	s.rememberDelivery(codeHashHex, result)
	return result, nil
}

// followExisting handles a claim lost to an existing intent row.
// reconcileCompleted recovers the sealed result for a completed exchange
// whose in-memory delivery is gone, through the idempotent upstream
// operation lookup. It never reissues PrepareLaunch.
func (s *Service) reconcileCompleted(ctx context.Context, codeHashHex string) (ExchangeResult, error) {
	res, err := s.authority.ReconcileOperation(ctx, "ope-launch-"+codeHashHex, "", coreapi.RequestOptions{WorkspaceID: s.workspace})
	if err != nil {
		return ExchangeResult{}, fmt.Errorf("%w: %v", ErrExchangeResultGone, err)
	}
	if res.Status != "completed" || res.Artifacts == nil || len(res.Artifacts.SealedSignedEnvelope) == 0 {
		return ExchangeResult{}, ErrExchangeResultGone
	}
	result := ExchangeResult{
		RunID:          res.Artifacts.RunID,
		MissionRef:     res.Artifacts.MissionRef,
		SealedEnvelope: append([]byte(nil), res.Artifacts.SealedSignedEnvelope...),
	}
	s.rememberDelivery(codeHashHex, result)
	return result, nil
}

// reconcileOrphan handles an in-flight row whose owner is gone: an
// ambiguous upstream preparation is reconciled, never reissued. When the
// reservation outlives the stale window it expires and only a fresh
// browser authorization can continue. When nothing was prepared the
// outcome stays ambiguous; a later retry reconciles again.
func (s *Service) reconcileOrphan(ctx context.Context, codeHash [32]byte, codeHashHex string, row store.LaunchExchangeIntent, now time.Time) (ExchangeResult, error) {
	if now.Sub(row.UpdatedAt) > launchExchangeStaleAfter {
		s.settleInTx(ctx, codeHashHex, store.LaunchExchangeExpired, "", "", "exchange reservation went stale", s.clock())
		return ExchangeResult{}, ErrExchangeStale
	}
	res, err := s.authority.ReconcileOperation(ctx, "ope-launch-"+codeHashHex, "", coreapi.RequestOptions{WorkspaceID: s.workspace})
	if err == nil && res.Status == "completed" && res.Artifacts != nil && len(res.Artifacts.SealedSignedEnvelope) != 0 {
		// The run was prepared before the owner died. Adoption revalidates
		// the pass binding without consuming anything: the attestation is
		// gone, so adoption only proceeds when reconcile proves the run
		// exists.
		rec, err := s.store.GetCLIAuthorizationByCodeHash(ctx, s.workspace, codeHash)
		if err != nil {
			return ExchangeResult{}, err
		}
		pass, err := s.store.GetMissionPass(ctx, s.workspace, rec.PassID)
		if err != nil {
			return ExchangeResult{}, err
		}
		return s.adoptArtifacts(ctx, *res.Artifacts, codeHashHex, rec, pass)
	}
	return ExchangeResult{}, ErrAmbiguousExchange
}

// settleInTx best-effort settles an in-flight row. Settlement failures are
// not fatal to the caller: the row stays in flight and a later exchange
// reconciles it.
func (s *Service) settleInTx(ctx context.Context, codeHashHex, status, runID, envelopeDigest, failure string, now time.Time) {
	_ = s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.SettleLaunchExchangeIntent(ctx, s.workspace, codeHashHex, status, runID, envelopeDigest, failure, now)
	})
}

func (s *Service) rememberDelivery(codeHashHex string, res ExchangeResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.delivery[codeHashHex]; !ok {
		s.order = append(s.order, codeHashHex)
	}
	s.delivery[codeHashHex] = res
	for len(s.order) > s.deliveryCap {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.delivery, oldest)
	}
}

func (s *Service) recallDelivery(codeHashHex string) (ExchangeResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, ok := s.delivery[codeHashHex]
	return res, ok
}

// checkPassBinding requires the pass to still carry every value the
// authorization pinned at approval time.
func checkPassBinding(pass store.MissionPassRecord, rec store.CLIAuthorization, now time.Time) error {
	if pass.State != "approved" {
		return fmt.Errorf("%w: pass state is %q", ErrBindingChanged, pass.State)
	}
	if !now.Before(pass.ExpiresAt) {
		return fmt.Errorf("%w: pass expired", ErrBindingChanged)
	}
	if pass.ApprovedProposalDigest == "" || pass.ApprovedProposalDigest != rec.ProposalDigest {
		return fmt.Errorf("%w: proposal digest", ErrBindingChanged)
	}
	if pass.InvocationDigest != rec.InvocationDigest {
		return fmt.Errorf("%w: invocation digest", ErrBindingChanged)
	}
	if pass.AgentKitID != rec.AgentKitID || pass.AgentKitVersion != rec.AgentKitVersion {
		return fmt.Errorf("%w: agent kit", ErrBindingChanged)
	}
	if !equalStringSlices(pass.RunnerArguments, rec.RunnerArguments) {
		return fmt.Errorf("%w: runner arguments", ErrBindingChanged)
	}
	if pass.MissionRef != rec.MissionRef || pass.AuthScopeMissionVersion != rec.MissionVersion {
		return fmt.Errorf("%w: mission binding", ErrBindingChanged)
	}
	if pass.SourceRevision == "" || pass.SourceDigest == "" || pass.BaseSHA == "" {
		return fmt.Errorf("%w: source binding", ErrBindingChanged)
	}
	return nil
}

// checkPosture requires a clean, fresh workflow posture for the pinned
// base SHA on the pass connection.
func (s *Service) checkPosture(ctx context.Context, pass store.MissionPassRecord, now time.Time) error {
	posture, err := s.store.LatestWorkflowPosture(ctx, s.workspace, pass.ConnectionID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: no workflow posture for the pinned base", ErrBindingChanged)
		}
		return err
	}
	if posture.Outcome != "clean" {
		return fmt.Errorf("%w: workflow posture is %q", ErrBindingChanged, posture.Outcome)
	}
	if !now.Before(posture.ExpiresAt) {
		return fmt.Errorf("%w: workflow posture expired", ErrBindingChanged)
	}
	if !equalFoldConstTime(posture.HeadSHA, pass.BaseSHA) {
		return fmt.Errorf("%w: workflow posture head moved", ErrBindingChanged)
	}
	return nil
}

func kitSupported(kits []coreapi.AgentKit, kitID, version string) bool {
	for _, k := range kits {
		if k.KitID == kitID && k.Version == version {
			return true
		}
	}
	return false
}

func subtleCompare32(a, b [32]byte) int {
	return subtle.ConstantTimeCompare(a[:], b[:])
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalFoldConstTime(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		v |= ca ^ cb
	}
	return v == 0
}

func sha256Of(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
