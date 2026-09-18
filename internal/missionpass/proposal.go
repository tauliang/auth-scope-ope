package missionpass

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/github"
	"github.com/tauliang/authscope-ope/internal/store"
)

var (
	// ErrInvalidInput reports a request outside the fixed template or with
	// missing fields.
	ErrInvalidInput = errors.New("missionpass: invalid input")
	// ErrTemplateViolation reports an upstream shaped draft outside the
	// fixed local template.
	ErrTemplateViolation = errors.New("missionpass: shaped draft outside the fixed template")
	// ErrProposalMismatch reports a created proposal that does not carry
	// exactly what shaping fixed.
	ErrProposalMismatch = errors.New("missionpass: proposal does not match the shaped draft")
	// ErrStaleSource reports a trusted source whose revision moved under
	// the pinned revision.
	ErrStaleSource = errors.New("missionpass: stale source revision")
	// ErrUnsafePosture reports a workflow posture that is not clean.
	ErrUnsafePosture = errors.New("missionpass: unsafe workflow posture")
	// ErrNotDraft reports a revision attempted on a pass that left draft.
	ErrNotDraft = errors.New("missionpass: pass is not a draft")
	// ErrOperationInFlight reports an upstream operation still running.
	ErrOperationInFlight = errors.New("missionpass: upstream operation in flight")
	// ErrPendingReconciliation reports an ambiguous upstream outcome the
	// caller must reconcile before retrying.
	ErrPendingReconciliation = errors.New("missionpass: upstream outcome uncertain")
	// ErrDuplicateRequestInFlight reports a second draft-open request with
	// an idempotency key whose owner has not persisted its pass yet. The
	// caller should retry the same request; it will resolve to the
	// owner's pass once visible.
	ErrDuplicateRequestInFlight = errors.New("missionpass: duplicate draft-open request in flight")
)

// requestKeyDanglingAfter bounds the legitimate window between claiming
// a draft-open idempotency key and persisting the pass row: the owner
// performs its trusted reads and upstream calls in between. A mapping
// older than this with no pass row means the owner died without
// releasing the key, and only then may a retry reclaim it. It is a var
// so tests can shrink the window.
var requestKeyDanglingAfter = 10 * time.Minute

// Config wires the proposal service.
type Config struct {
	Store           store.Store
	Authority       coreapi.Authority
	Source          *github.Source
	Clock           func() time.Time
	UpstreamTimeout time.Duration
	// NewPassID generates the local pass ID. It defaults to 128 bits of
	// crypto randomness; tests inject a fixed ID.
	NewPassID func() (string, error)
}

// Service shapes and creates exact AuthScope mission proposals before
// founder review, and applies the only two founder edits (earlier expiry,
// lower aggregate-cost ceiling).
type Service struct {
	store           store.Store
	authority       coreapi.Authority
	source          *github.Source
	clock           func() time.Time
	upstreamTimeout time.Duration
	newPassID       func() (string, error)
}

// NewService builds the proposal service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Authority == nil || cfg.Source == nil {
		return nil, fmt.Errorf("missionpass: store, authority, and source are required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	newPassID := cfg.NewPassID
	if newPassID == nil {
		newPassID = defaultPassID
	}
	return &Service{
		store:           cfg.Store,
		authority:       cfg.Authority,
		source:          cfg.Source,
		clock:           clock,
		upstreamTimeout: timeout,
		newPassID:       newPassID,
	}, nil
}

func defaultPassID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("missionpass: pass ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func (s *Service) now() time.Time { return s.clock().UTC() }

// persistedPass is the full durable pass: the immutable proposal revision
// plus the trusted source identifiers needed to refresh and re-derive it.
type persistedPass struct {
	ProposalRecord
	ConnectionID       string
	IssueNumber        int64
	RepositoryName     string
	Objective          string
	AcceptanceCriteria []string
	ShapedDraftJSON    string
}

// CreateProposalInput opens a mission-pass draft for one issue.
// IdempotencyKey is the caller-supplied draft-open key: a retried request
// with the same key resolves to the same pass instead of opening a
// duplicate draft. Empty disables the mapping.
type CreateProposalInput struct {
	ConnectionID           string
	IssueNumber            int64
	ExpiresAt              time.Time
	MaxAggregateCostMicros int64
	IdempotencyKey         string
}

// ReviseProposalInput applies the only two founder edits to a draft.
type ReviseProposalInput struct {
	PassID                 string
	ExpectedStoreRevision  int64
	ExpectedDraftVersion   int64
	ExpiresAt              time.Time
	MaxAggregateCostMicros int64
}

// CreateProposal refreshes the trusted issue snapshot and workflow
// posture, shapes the mission inside the fixed template, creates the exact
// upstream proposal with a workspace-qualified idempotency key, and
// persists the returned values byte-for-byte. ApprovedProposalDigest stays
// empty and AuthScopeMissionVersion stays 0 until approval.
//
// The returned bool reports whether the request replayed an earlier
// attempt that claimed the same idempotency key: a replay returns the
// existing pass without issuing any upstream call. On an ambiguous
// upstream outcome the returned record is the persisted pending intent,
// together with ErrPendingReconciliation or ErrOperationInFlight, so the
// caller can present the pass the founder retries or polls.
func (s *Service) CreateProposal(ctx context.Context, workspaceID, actorID string, in CreateProposalInput) (ProposalRecord, bool, error) {
	now := s.now()
	if err := checkCreateInput(workspaceID, actorID, in, now); err != nil {
		return ProposalRecord{}, false, err
	}
	passID, replayed, err := s.claimRequestKey(ctx, workspaceID, in.IdempotencyKey)
	if err != nil {
		return ProposalRecord{}, false, err
	}
	if replayed {
		rec, err := s.LoadProposal(ctx, workspaceID, passID)
		if err != nil {
			return ProposalRecord{}, false, err
		}
		return rec, true, nil
	}
	// This attempt owns a fresh claim. If it fails before its pass row
	// is persisted, it releases the key so a corrected retry with the
	// same key can claim again. The key is only released while no pass
	// row exists for this attempt's pass ID, and no other attempt can
	// create a row under that ID, so releasing can never orphan a live
	// draft or permit a duplicate.
	if in.IdempotencyKey != "" {
		defer func() {
			rctx := context.WithoutCancel(ctx)
			if _, lerr := s.LoadProposal(rctx, workspaceID, passID); !errors.Is(lerr, store.ErrNotFound) {
				return
			}
			_ = s.store.DeleteMissionPassRequestKey(rctx, workspaceID, in.IdempotencyKey)
		}()
	}
	conn, err := s.store.GetConnection(ctx, workspaceID, in.ConnectionID)
	if err != nil {
		return ProposalRecord{}, false, err
	}
	// Trusted source refresh, then workflow-posture refresh: both must be
	// current before AuthScope shapes anything.
	snap, err := s.source.ReadIssue(ctx, workspaceID, conn, in.IssueNumber, "", "")
	if err != nil {
		return ProposalRecord{}, false, err
	}
	posture, err := s.source.CheckPosture(ctx, workspaceID, conn, snap.DefaultBranch, snap.BaseSHA)
	if err != nil {
		return ProposalRecord{}, false, err
	}
	if posture.Outcome != "clean" {
		return ProposalRecord{}, false, fmt.Errorf("%w: outcome %q", ErrUnsafePosture, posture.Outcome)
	}
	ttlSeconds := int64(in.ExpiresAt.Sub(now) / time.Second)
	if ttlSeconds <= 0 {
		return ProposalRecord{}, false, fmt.Errorf("%w: expiry is not in the future", ErrInvalidInput)
	}
	limits := EditableLimits{ExpiresAt: in.ExpiresAt.UTC(), MaxAggregateCostMicros: in.MaxAggregateCostMicros}
	shaped, err := s.shapeUpstream(ctx, workspaceID, actorID, snap, passID, limits, ttlSeconds,
		"missionpass-shape-"+workspaceID+"-"+passID)
	if err != nil {
		return ProposalRecord{}, false, err
	}
	idempotencyKey := "missionpass-proposal-" + workspaceID + "-" + passID + "-r1"
	intent := persistedPass{
		ProposalRecord: ProposalRecord{
			WorkspaceID:             workspaceID,
			PassID:                  passID,
			StoreRevision:           1,
			DraftVersion:            1,
			AuthScopeMissionVersion: 0,
			SourceRevision:          snap.SourceRevision,
			SourceDigest:            snap.SourceDigest,
			BaseSHA:                 snap.BaseSHA,
			MissionBranch:           MissionBranch(passID, in.IssueNumber),
			Limits:                  limits,
			State:                   PassDraft,
			Reconciliation:          ReconciliationPending,
		},
		ConnectionID:       in.ConnectionID,
		IssueNumber:        in.IssueNumber,
		RepositoryName:     snap.RepositoryFullName,
		Objective:          snap.Objective,
		AcceptanceCriteria: append([]string{}, snap.AcceptanceCriteria...),
		ShapedDraftJSON:    string(shaped.CanonicalDraft),
	}
	proposal, settled, persistExpected, err := s.createUpstream(ctx, workspaceID, actorID, snap, shaped, limits, ttlSeconds, idempotencyKey, intent, 0)
	if err != nil {
		return intent.ProposalRecord, false, err
	}
	rec := intent
	rec.ProposalRecord = ProposalRecord{
		WorkspaceID:             workspaceID,
		PassID:                  passID,
		StoreRevision:           persistExpected + 1,
		DraftVersion:            1,
		AuthScopeMissionVersion: 0,
		ProposalID:              proposal.ProposalID,
		ProposalDigest:          proposal.ProposalDigest,
		ApprovedProposalDigest:  "",
		SourceRevision:          snap.SourceRevision,
		SourceDigest:            snap.SourceDigest,
		BaseSHA:                 snap.BaseSHA,
		MissionBranch:           MissionBranch(passID, in.IssueNumber),
		AgentKitID:              proposal.AgentKitID,
		AgentKitVersion:         proposal.AgentKitVersion,
		RunnerArguments:         append([]string{}, proposal.RunnerArguments...),
		InvocationDigest:        proposal.InvocationDigest,
		Limits:                  limits,
		State:                   PassDraft,
		Reconciliation:          settled,
	}
	if err := s.persist(ctx, rec, persistExpected); err != nil {
		return ProposalRecord{}, false, err
	}
	return rec.ProposalRecord, false, nil
}

// claimRequestKey resolves a draft-open idempotency key to the pass that
// owns it. It returns the owning pass ID and whether this call replays an
// earlier attempt (no upstream calls follow a replay). An empty key
// disables the mapping and always creates a fresh pass.
//
// When a mapping exists but the owner's pass row is not visible, the
// owner is usually still inside its trusted reads or upstream calls, so
// this waits for the row first. Only a claim older than
// requestKeyDanglingAfter with no pass row counts as dangling (the owner
// died without releasing it); anything younger fails closed with
// ErrDuplicateRequestInFlight. The mapping is never deleted while a live
// owner might still persist under it, so a concurrent duplicate draft is
// impossible.
func (s *Service) claimRequestKey(ctx context.Context, workspaceID, key string) (string, bool, error) {
	if key == "" {
		passID, err := s.newPassID()
		if err != nil {
			return "", false, err
		}
		return passID, false, nil
	}
	if existing, err := s.store.GetMissionPassIDByRequestKey(ctx, workspaceID, key); err != nil {
		return "", false, err
	} else if existing != "" {
		if _, err := s.LoadProposal(ctx, workspaceID, existing); err == nil {
			return existing, true, nil
		}
		if _, err := s.awaitPassRow(ctx, workspaceID, existing); err == nil {
			return existing, true, nil
		}
		claimedAt, err := s.store.GetMissionPassRequestKeyClaimedAt(ctx, workspaceID, key)
		if err != nil {
			return "", false, err
		}
		// A negative age only means clock skew between the claim write
		// and this read; treat it as fresh so the decision fails closed.
		age := s.now().Sub(claimedAt)
		if age < 0 {
			age = 0
		}
		if age < requestKeyDanglingAfter {
			return "", false, fmt.Errorf("%w: retry the same request", ErrDuplicateRequestInFlight)
		}
		// Dangling mapping: the owner died without persisting or
		// releasing. Reclaim the key so a retry can proceed.
		if err := s.store.DeleteMissionPassRequestKey(ctx, workspaceID, key); err != nil {
			return "", false, err
		}
	}
	passID, err := s.newPassID()
	if err != nil {
		return "", false, err
	}
	winner, err := s.store.ClaimMissionPassRequestKey(ctx, workspaceID, key, passID)
	if err != nil {
		return "", false, err
	}
	if winner == passID {
		return passID, false, nil
	}
	// Lost the race: the winner owns this key. Wait briefly for its pass
	// row, then replay it instead of duplicating the draft.
	if _, err := s.awaitPassRow(ctx, workspaceID, winner); err == nil {
		return winner, true, nil
	}
	return "", false, fmt.Errorf("%w: retry the same request", ErrDuplicateRequestInFlight)
}

// awaitPassRowTimeout bounds how long a draft-open waits for a racing
// owner's pass row to appear before failing closed. It is a var so tests
// can shrink the wait.
var awaitPassRowTimeout = 5 * time.Second

// awaitPassRow waits briefly for a racing owner's pass row to appear.
func (s *Service) awaitPassRow(ctx context.Context, workspaceID, passID string) (ProposalRecord, error) {
	deadline := time.Now().Add(awaitPassRowTimeout)
	for {
		if rec, err := s.LoadProposal(ctx, workspaceID, passID); err == nil {
			return rec, nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return ProposalRecord{}, fmt.Errorf("missionpass: pass %q not yet visible", passID)
		}
		select {
		case <-ctx.Done():
			return ProposalRecord{}, ctx.Err()
		case <-time.After(remaining):
		}
	}
}

func checkCreateInput(workspaceID, actorID string, in CreateProposalInput, now time.Time) error {
	if workspaceID == "" || actorID == "" || in.ConnectionID == "" {
		return fmt.Errorf("%w: workspace, actor, and connection are required", ErrInvalidInput)
	}
	if in.IssueNumber <= 0 {
		return fmt.Errorf("%w: issue number must be positive", ErrInvalidInput)
	}
	if in.ExpiresAt.IsZero() || !in.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expiry must be in the future", ErrInvalidInput)
	}
	if in.ExpiresAt.After(now.Add(MaxTTL)) {
		return fmt.Errorf("%w: expiry past the two-hour template maximum", ErrInvalidInput)
	}
	if in.MaxAggregateCostMicros <= 0 || in.MaxAggregateCostMicros > MaxAggregateCostMicros {
		return fmt.Errorf("%w: budget outside the template maximum", ErrInvalidInput)
	}
	return nil
}

// shapeUpstream asks AuthScope to shape the mission and requires the
// response to remain inside the fixed template.
func (s *Service) shapeUpstream(ctx context.Context, workspaceID, actorID string, snap github.IssueSnapshot, passID string, limits EditableLimits, ttlSeconds int64, idempotencyKey string) (coreapi.MissionDraft, error) {
	uctx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	shaped, err := s.authority.ShapeMission(uctx,
		coreapi.ShapeMissionRequest{
			Title:          fmt.Sprintf("Issue #%d (%s)", snap.IssueNumber, snap.RepositoryFullName),
			Objective:      snap.Objective,
			Constraints:    snap.AcceptanceCriteria,
			BudgetMicros:   limits.MaxAggregateCostMicros,
			TTLSeconds:     ttlSeconds,
			RequestedRoles: []string{},
		},
		coreapi.RequestOptions{WorkspaceID: workspaceID, ActorID: actorID, IdempotencyKey: idempotencyKey})
	if err != nil {
		return coreapi.MissionDraft{}, fmt.Errorf("missionpass: shape mission: %w", err)
	}
	if err := ValidateShaped(shaped, ttlSeconds, limits.MaxAggregateCostMicros); err != nil {
		return coreapi.MissionDraft{}, err
	}
	return shaped, nil
}

// createUpstream creates the proposal with the workspace-qualified
// idempotency key. On an ambiguous failure it persists the given intent as
// reconciliation-pending (CAS against intentExpected: 0 creates the row),
// reconciles by the same key, and replays the same mutation only when
// reconcile reports completion; it never issues another proposal mutation.
// It returns the proposal, its reconciliation state, and the store revision
// the caller must expect when persisting the settled record (0 when no
// intent was written).
func (s *Service) createUpstream(ctx context.Context, workspaceID, actorID string, snap github.IssueSnapshot, shaped coreapi.MissionDraft, limits EditableLimits, ttlSeconds int64, idempotencyKey string, intent persistedPass, intentExpected int64) (coreapi.Proposal, ReconciliationState, int64, error) {
	req := coreapi.CreateProposalRequest{
		Title:            fmt.Sprintf("Issue #%d (%s)", snap.IssueNumber, snap.RepositoryFullName),
		Objective:        snap.Objective,
		Constraints:      snap.AcceptanceCriteria,
		BudgetMicros:     limits.MaxAggregateCostMicros,
		TTLSeconds:       ttlSeconds,
		InvocationDigest: shaped.InvocationDigest,
		IdempotencyKey:   idempotencyKey,
	}
	opts := coreapi.RequestOptions{WorkspaceID: workspaceID, ActorID: actorID, IdempotencyKey: idempotencyKey}
	proposal, err := s.createOnce(ctx, req, opts)
	if err == nil {
		if verr := ValidateProposal(shaped, proposal); verr != nil {
			return coreapi.Proposal{}, ReconciliationSettled, intentExpected, verr
		}
		return proposal, ReconciliationSettled, intentExpected, nil
	}
	if !isAmbiguousUpstream(err) {
		return coreapi.Proposal{}, ReconciliationSettled, intentExpected, fmt.Errorf("missionpass: create proposal: %w", err)
	}
	// Ambiguous outcome: persist the intent first so the pending
	// reconciliation survives a crash, then reconcile by the same key.
	intent.Reconciliation = ReconciliationPending
	if perr := s.persist(ctx, intent, intentExpected); perr != nil {
		return coreapi.Proposal{}, ReconciliationPending, 0,
			fmt.Errorf("missionpass: persist reconciliation intent: %w", perr)
	}
	intentRevision := intentExpected + 1
	outcome, rerr := s.reconcileOperation(ctx, workspaceID, idempotencyKey)
	if rerr != nil {
		return coreapi.Proposal{}, ReconciliationPending, intentRevision, rerr
	}
	switch outcome {
	case reconcileCompleted:
		// The timed-out mutation landed: replay the same mutation with
		// the same idempotency key to recover its exact result.
		replayed, rerr := s.createOnce(ctx, req, opts)
		if rerr != nil {
			return coreapi.Proposal{}, ReconciliationPending, intentRevision,
				fmt.Errorf("%w: replay after reconcile: %v", ErrPendingReconciliation, rerr)
		}
		if verr := ValidateProposal(shaped, replayed); verr != nil {
			return coreapi.Proposal{}, ReconciliationPending, intentRevision, verr
		}
		return replayed, ReconciliationSettled, intentRevision, nil
	case reconcileInflight:
		return coreapi.Proposal{}, ReconciliationPending, intentRevision, ErrOperationInFlight
	default:
		return coreapi.Proposal{}, ReconciliationPending, intentRevision, ErrPendingReconciliation
	}
}

func (s *Service) createOnce(ctx context.Context, req coreapi.CreateProposalRequest, opts coreapi.RequestOptions) (coreapi.Proposal, error) {
	uctx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	return s.authority.CreateProposal(uctx, req, opts)
}

// isAmbiguousUpstream mirrors the handoff's ambiguity rule: a timeout or a
// retryable upstream status means the mutation may have landed, so the
// caller must reconcile instead of issuing another mutation.
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

type reconcileOutcome int

const (
	reconcileAbsent reconcileOutcome = iota
	reconcileCompleted
	reconcileInflight
)

func (s *Service) reconcileOperation(ctx context.Context, workspaceID, idempotencyKey string) (reconcileOutcome, error) {
	op, err := s.authority.ReconcileOperation(ctx, idempotencyKey, "",
		coreapi.RequestOptions{WorkspaceID: workspaceID})
	if err != nil {
		var up *coreapi.UpstreamError
		if errors.As(err, &up) && up.StatusCode == 404 {
			return reconcileAbsent, nil
		}
		return reconcileAbsent, fmt.Errorf("%w: %v", ErrPendingReconciliation, err)
	}
	if op.OperationID == "" && op.IdempotencyKey == "" {
		return reconcileAbsent, nil
	}
	if strings.EqualFold(op.Status, "completed") {
		return reconcileCompleted, nil
	}
	return reconcileInflight, nil
}

// ReviseProposal applies the only two founder edits to a draft: an earlier
// expiry and a lower aggregate-cost ceiling. Every other field is
// immutable. A valid edit reruns shaping and creates a new upstream
// proposal with a fresh idempotency key, writes an immutable revision with
// DraftVersion + 1, and leaves AuthScopeMissionVersion at 0.
func (s *Service) ReviseProposal(ctx context.Context, workspaceID, actorID string, in ReviseProposalInput) (ProposalRecord, error) {
	now := s.now()
	if workspaceID == "" || actorID == "" || in.PassID == "" {
		return ProposalRecord{}, fmt.Errorf("%w: workspace, actor, and pass are required", ErrInvalidInput)
	}
	if in.ExpiresAt.IsZero() || in.MaxAggregateCostMicros <= 0 {
		return ProposalRecord{}, fmt.Errorf("%w: expiry and budget are required", ErrInvalidInput)
	}
	if in.ExpiresAt.After(now.Add(MaxTTL)) {
		return ProposalRecord{}, fmt.Errorf("%w: expiry past the two-hour template maximum", ErrInvalidInput)
	}
	if in.MaxAggregateCostMicros > MaxAggregateCostMicros {
		return ProposalRecord{}, fmt.Errorf("%w: budget above the template maximum", ErrInvalidInput)
	}
	stored, err := s.store.GetMissionPass(ctx, workspaceID, in.PassID)
	if err != nil {
		return ProposalRecord{}, err
	}
	current := fromStoreRecord(stored)
	if current.State != PassDraft {
		return ProposalRecord{}, fmt.Errorf("%w: state %q", ErrNotDraft, current.State)
	}
	if stored.StoreRevision != in.ExpectedStoreRevision || stored.DraftVersion != in.ExpectedDraftVersion {
		return ProposalRecord{}, fmt.Errorf("%w: expected store revision %d draft version %d",
			store.ErrConflict, in.ExpectedStoreRevision, in.ExpectedDraftVersion)
	}
	// Only narrowing edits are accepted: neither value may exceed the
	// template maximum (checked above) nor the current value, and at least
	// one must strictly narrow.
	expiry := in.ExpiresAt.UTC()
	if expiry.After(current.Limits.ExpiresAt) {
		return ProposalRecord{}, fmt.Errorf("%w: expiry after the current value", ErrInvalidInput)
	}
	if in.MaxAggregateCostMicros > current.Limits.MaxAggregateCostMicros {
		return ProposalRecord{}, fmt.Errorf("%w: budget above the current value", ErrInvalidInput)
	}
	if !expiry.Before(current.Limits.ExpiresAt) && in.MaxAggregateCostMicros >= current.Limits.MaxAggregateCostMicros {
		return ProposalRecord{}, fmt.Errorf("%w: revision must narrow expiry or budget", ErrInvalidInput)
	}
	conn, err := s.store.GetConnection(ctx, workspaceID, current.ConnectionID)
	if err != nil {
		return ProposalRecord{}, err
	}
	// Refresh against the pinned source: a moved issue or base fails
	// closed as stale instead of reshaping different authority.
	snap, err := s.source.ReadIssue(ctx, workspaceID, conn, current.IssueNumber, current.SourceRevision, current.BaseSHA)
	if err != nil {
		return ProposalRecord{}, mapSourceError(err)
	}
	posture, err := s.source.CheckPosture(ctx, workspaceID, conn, snap.DefaultBranch, snap.BaseSHA)
	if err != nil {
		return ProposalRecord{}, err
	}
	if posture.Outcome != "clean" {
		return ProposalRecord{}, fmt.Errorf("%w: outcome %q", ErrUnsafePosture, posture.Outcome)
	}
	ttlSeconds := int64(expiry.Sub(now) / time.Second)
	if ttlSeconds <= 0 {
		return ProposalRecord{}, fmt.Errorf("%w: expiry is not in the future", ErrInvalidInput)
	}
	limits := EditableLimits{ExpiresAt: expiry, MaxAggregateCostMicros: in.MaxAggregateCostMicros}
	newDraftVersion := current.DraftVersion + 1
	shaped, err := s.shapeUpstream(ctx, workspaceID, actorID, snap, current.PassID, limits, ttlSeconds,
		"missionpass-shape-"+workspaceID+"-"+current.PassID+"-r"+itoa(newDraftVersion))
	if err != nil {
		return ProposalRecord{}, err
	}
	// The timeout intent keeps the last known-good proposal values and
	// marks the row reconciliation-pending; a settled replay writes the
	// new revision over it.
	intent := current
	intent.Reconciliation = ReconciliationPending
	proposal, settled, persistExpected, err := s.createUpstream(ctx, workspaceID, actorID, snap, shaped, limits, ttlSeconds,
		"missionpass-proposal-"+workspaceID+"-"+current.PassID+"-r"+itoa(newDraftVersion), intent, stored.StoreRevision)
	if err != nil {
		return ProposalRecord{}, err
	}
	revised := current
	revised.StoreRevision = persistExpected + 1
	revised.DraftVersion = newDraftVersion
	revised.ProposalID = proposal.ProposalID
	revised.ProposalDigest = proposal.ProposalDigest
	revised.ApprovedProposalDigest = ""
	revised.AgentKitID = proposal.AgentKitID
	revised.AgentKitVersion = proposal.AgentKitVersion
	revised.RunnerArguments = append([]string{}, proposal.RunnerArguments...)
	revised.InvocationDigest = proposal.InvocationDigest
	revised.SourceRevision = snap.SourceRevision
	revised.SourceDigest = snap.SourceDigest
	revised.BaseSHA = snap.BaseSHA
	revised.Objective = snap.Objective
	revised.AcceptanceCriteria = append([]string{}, snap.AcceptanceCriteria...)
	revised.ShapedDraftJSON = string(shaped.CanonicalDraft)
	revised.Limits = limits
	revised.State = PassDraft
	revised.Reconciliation = settled
	// AuthScopeMissionVersion stays 0: no mission authority exists yet.
	if err := s.persist(ctx, revised, persistExpected); err != nil {
		return ProposalRecord{}, err
	}
	return revised.ProposalRecord, nil
}

func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}

// mapSourceError translates trusted-source staleness into the service's
// stale error; other source errors pass through for the HTTP layer.
func mapSourceError(err error) error {
	if errors.Is(err, github.ErrStaleSourceRevision) || errors.Is(err, github.ErrStaleBaseSHA) {
		return fmt.Errorf("%w: %v", ErrStaleSource, err)
	}
	return err
}

// persist writes one immutable proposal revision with compare-and-swap on
// the store revision.
func (s *Service) persist(ctx context.Context, rec persistedPass, expectedStoreRevision int64) error {
	return s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, toStoreRecord(rec), expectedStoreRevision)
	})
}

// LoadProposal reads the current proposal revision of a pass for review.
func (s *Service) LoadProposal(ctx context.Context, workspaceID, passID string) (ProposalRecord, error) {
	stored, err := s.store.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return ProposalRecord{}, err
	}
	return fromStoreRecord(stored).ProposalRecord, nil
}

// PassReview is the founder-facing review payload: the immutable proposal
// revision plus the trusted snapshot content it was shaped from and the
// canonical shaped draft for enforcement details.
type PassReview struct {
	ProposalRecord
	ConnectionID       string          `json:"connection_id"`
	IssueNumber        int64           `json:"issue_number"`
	RepositoryName     string          `json:"repository_name"`
	Objective          string          `json:"objective"`
	AcceptanceCriteria []string        `json:"acceptance_criteria"`
	ShapedDraft        json.RawMessage `json:"shaped_draft"`
}

// LoadReview loads the founder review payload for one pass.
func (s *Service) LoadReview(ctx context.Context, workspaceID, passID string) (PassReview, error) {
	stored, err := s.store.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return PassReview{}, err
	}
	full := fromStoreRecord(stored)
	return PassReview{
		ProposalRecord:     full.ProposalRecord,
		ConnectionID:       full.ConnectionID,
		IssueNumber:        full.IssueNumber,
		RepositoryName:     full.RepositoryName,
		Objective:          full.Objective,
		AcceptanceCriteria: full.AcceptanceCriteria,
		ShapedDraft:        json.RawMessage(full.ShapedDraftJSON),
	}, nil
}

func toStoreRecord(rec persistedPass) store.MissionPassRecord {
	r := rec.ProposalRecord
	return store.MissionPassRecord{
		WorkspaceID:             r.WorkspaceID,
		PassID:                  r.PassID,
		StoreRevision:           r.StoreRevision,
		DraftVersion:            r.DraftVersion,
		AuthScopeMissionVersion: r.AuthScopeMissionVersion,
		ConnectionID:            rec.ConnectionID,
		IssueNumber:             rec.IssueNumber,
		RepositoryName:          rec.RepositoryName,
		ProposalID:              r.ProposalID,
		ProposalDigest:          r.ProposalDigest,
		ApprovedProposalDigest:  r.ApprovedProposalDigest,
		SourceRevision:          r.SourceRevision,
		SourceDigest:            r.SourceDigest,
		BaseSHA:                 r.BaseSHA,
		MissionBranch:           r.MissionBranch,
		AgentKitID:              r.AgentKitID,
		AgentKitVersion:         r.AgentKitVersion,
		RunnerArguments:         append([]string{}, r.RunnerArguments...),
		InvocationDigest:        r.InvocationDigest,
		ExpiresAt:               r.Limits.ExpiresAt,
		MaxAggregateCostMicros:  r.Limits.MaxAggregateCostMicros,
		Objective:               rec.Objective,
		AcceptanceCriteria:      append([]string{}, rec.AcceptanceCriteria...),
		ShapedDraftJSON:         rec.ShapedDraftJSON,
		State:                   string(r.State),
		Reconciliation:          string(r.Reconciliation),
	}
}

func fromStoreRecord(stored store.MissionPassRecord) persistedPass {
	return persistedPass{
		ProposalRecord: ProposalRecord{
			WorkspaceID:             stored.WorkspaceID,
			PassID:                  stored.PassID,
			StoreRevision:           stored.StoreRevision,
			DraftVersion:            stored.DraftVersion,
			AuthScopeMissionVersion: stored.AuthScopeMissionVersion,
			ProposalID:              stored.ProposalID,
			ProposalDigest:          stored.ProposalDigest,
			ApprovedProposalDigest:  stored.ApprovedProposalDigest,
			SourceRevision:          stored.SourceRevision,
			SourceDigest:            stored.SourceDigest,
			BaseSHA:                 stored.BaseSHA,
			MissionBranch:           stored.MissionBranch,
			AgentKitID:              stored.AgentKitID,
			AgentKitVersion:         stored.AgentKitVersion,
			RunnerArguments:         append([]string{}, stored.RunnerArguments...),
			InvocationDigest:        stored.InvocationDigest,
			Limits:                  EditableLimits{ExpiresAt: stored.ExpiresAt, MaxAggregateCostMicros: stored.MaxAggregateCostMicros},
			State:                   PassState(stored.State),
			Reconciliation:          ReconciliationState(stored.Reconciliation),
		},
		ConnectionID:       stored.ConnectionID,
		IssueNumber:        stored.IssueNumber,
		RepositoryName:     stored.RepositoryName,
		Objective:          stored.Objective,
		AcceptanceCriteria: append([]string{}, stored.AcceptanceCriteria...),
		ShapedDraftJSON:    stored.ShapedDraftJSON,
	}
}
