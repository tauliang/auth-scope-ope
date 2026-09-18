// The receipt service owns the pass-owned loop of fetching the upstream
// receipt envelope, verifying it locally, transitioning the pass to its
// terminal outcome only on a verified receipt, and publishing the
// privacy-safe GitHub check exactly once. An invalid receipt leaves the
// pass in outcome_pending; a missing upstream receipt is not an error.
package receipt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// upstreamOperationStatuses maps upstream operation states to the
// publication reconciliation decision.
const (
	upstreamOperationCompleted = "completed"
	upstreamOperationFailed    = "failed"
	upstreamOperationRejected  = "rejected"
	upstreamOperationExpired   = "expired"
)

// Service verifies execution receipts and publishes GitHub checks.
type Service struct {
	store     store.Store
	authority coreapi.Authority
	keys      *trust.KeyStore
	verifier  *Verifier
	now       func() time.Time
}

// Config wires the receipt service.
type Config struct {
	Store     store.Store
	Authority coreapi.Authority
	Keys      *trust.KeyStore
	Now       func() time.Time
}

// NewService builds the receipt service.
func NewService(cfg Config) (*Service, error) {
	if cfg.Store == nil || cfg.Authority == nil || cfg.Keys == nil {
		return nil, fmt.Errorf("receipt: store, authority, and keys are required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Service{
		store:     cfg.Store,
		authority: cfg.Authority,
		keys:      cfg.Keys,
		verifier:  NewVerifier(cfg.Keys, now),
		now:       now,
	}, nil
}

func (s *Service) requestOptions(workspaceID string) coreapi.RequestOptions {
	return coreapi.RequestOptions{WorkspaceID: workspaceID, ActorID: "receipt-service"}
}

// buildBinding reconstructs the locally projected pass binding from
// the store: the pass record, its projected events, its decided
// expansions, and its repository connection. Every field comes from
// OPE's own projection; the receipt's claims are checked against this,
// never the other way around.
func (s *Service) buildBinding(ctx context.Context, tx store.Tx, workspaceID string, pass store.MissionPassRecord) (Binding, error) {
	b := Binding{
		WorkspaceID: workspaceID,
		MissionRef:  pass.MissionRef,
		GrantID:     pass.RunID,
	}
	events, err := tx.ListMissionEvents(ctx, workspaceID, pass.PassID, "", 10000)
	if err != nil {
		return Binding{}, fmt.Errorf("receipt: list events: %w", err)
	}
	versions := map[int64]bool{}
	// Walk newest first: outcome and repo binding come from the latest
	// event that carries them.
	for i := len(events) - 1; i >= 0; i-- {
		var se missionpass.SafeEvent
		if err := json.Unmarshal([]byte(events[i].Payload), &se); err != nil {
			continue
		}
		if se.AuthScopeMissionVersion > 0 {
			versions[se.AuthScopeMissionVersion] = true
		}
		switch se.Type {
		case missionpass.EventRunSucceeded:
			if b.Outcome == "" {
				b.Outcome = OutcomeSuccess
			}
		case missionpass.EventRunFailed:
			if b.Outcome == "" {
				b.Outcome = OutcomeFailure
			}
		}
		if b.Branch == "" && se.Branch != "" {
			b.Branch = se.Branch
		}
		if b.PullRequestNumber == 0 && se.PullRequestNumber != 0 {
			b.PullRequestNumber = se.PullRequestNumber
		}
		if b.HeadSHA == "" && se.HeadSHA != "" {
			b.HeadSHA = se.HeadSHA
		}
	}
	for v := range versions {
		b.MissionVersions = append(b.MissionVersions, v)
	}
	sort.Slice(b.MissionVersions, func(i, j int) bool { return b.MissionVersions[i] < b.MissionVersions[j] })
	intents, err := tx.ListExpansionIntents(ctx, workspaceID, store.ExpansionIntentCompleted)
	if err != nil {
		return Binding{}, fmt.Errorf("receipt: list expansion intents: %w", err)
	}
	seen := map[string]bool{}
	for _, in := range intents {
		if in.PassID != pass.PassID || in.UpstreamRef == "" || seen[in.UpstreamRef] {
			continue
		}
		seen[in.UpstreamRef] = true
		b.ExpansionDecisionRefs = append(b.ExpansionDecisionRefs, in.UpstreamRef)
	}
	sort.Strings(b.ExpansionDecisionRefs)
	if pass.ConnectionID != "" {
		conn, err := tx.GetConnection(ctx, workspaceID, pass.ConnectionID)
		if err != nil {
			return Binding{}, fmt.Errorf("receipt: get connection: %w", err)
		}
		b.RepositoryID = conn.RepositoryID
	}
	b.IssueNumber = pass.IssueNumber
	return b, nil
}

// isNotFound reports whether an authority error is a 404: the upstream
// resource is absent, which for receipts and bindings is a normal
// pending state, not a failure.
func isNotFound(err error) bool {
	var up *coreapi.UpstreamError
	return errors.As(err, &up) && up.StatusCode == http.StatusNotFound
}

// reasonCode extracts the fixed reason code from a verification error.
func reasonCode(err error) string {
	msg := err.Error()
	for _, code := range []string{ReasonBadSignature, ReasonBadKey, ReasonBadPayload, ReasonBadBinding} {
		if strings.Contains(msg, code) {
			return code
		}
	}
	return ReasonBadPayload
}

// refreshKeys fetches the served signing-key history and replaces the
// local key set when every key chains to the pinned root.
func (s *Service) refreshKeys(ctx context.Context, workspaceID string) error {
	history, err := s.authority.GetSigningKeys(ctx, s.requestOptions(workspaceID))
	if err != nil {
		return fmt.Errorf("receipt: fetch signing keys: %w", err)
	}
	served := make([]trust.ServedKey, 0, len(history.Keys))
	for _, k := range history.Keys {
		served = append(served, trust.ServedKey{
			KeyID:       k.KeyID,
			PublicKey:   k.PublicKey,
			ValidFrom:   k.ValidFrom,
			ValidUntil:  k.ValidUntil,
			RotatedFrom: k.RotatedFrom,
		})
	}
	if err := s.keys.RefreshFromHistory(served, time.Unix(history.ServedAt, 0).UTC(), s.now()); err != nil {
		return fmt.Errorf("receipt: refresh signing keys: %w", err)
	}
	// No verifier swap is needed: the verifier holds the same key
	// store pointer, and RefreshFromHistory replaces the set in
	// place under the store lock. Swapping s.verifier here would race
	// with concurrent verifications.
	return nil
}

// viewToRecord converts a verified view into its storage row. JSON
// columns carry the structured sub-documents; the raw envelope is
// dropped and never stored.
func viewToRecord(workspaceID, passID string, view *ReceiptView, at time.Time) (store.ReceiptViewRecord, error) {
	mustJSON := func(v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			return "[]"
		}
		return string(raw)
	}
	stringsJSON := func(v []string) string {
		if v == nil {
			return "[]"
		}
		return mustJSON(v)
	}
	rec := store.ReceiptViewRecord{
		WorkspaceID:               workspaceID,
		PassID:                    passID,
		Verification:              view.Verification,
		ReasonCode:                view.ReasonCode,
		ReceiptID:                 view.ReceiptID,
		GrantID:                   view.GrantID,
		MissionRef:                view.MissionRef,
		KeyID:                     view.KeyID,
		ReceiptDigest:             view.ReceiptDigest,
		SettlementDigest:          view.SettlementDigest,
		Outcome:                   view.Outcome,
		MissionVersionsJSON:       mustJSON(view.MissionVersions),
		ExpansionDecisionRefsJSON: stringsJSON(view.ExpansionDecisionRefs),
		RepositoryID:              view.RepositoryID,
		IssueNumber:               view.IssueNumber,
		Branch:                    view.Branch,
		PullRequestNumber:         view.PullRequestNumber,
		HeadSHA:                   view.HeadSHA,
		ChecksJSON:                mustJSON(view.Checks),
		AggregateCostMicros:       view.AggregateCostMicros,
		BudgetMicros:              view.BudgetMicros,
		HistoricalEnforcementJSON: mustJSON(view.HistoricalEnforcement),
		VerifiedAt:                at,
	}
	if view.SignedAt > 0 {
		rec.SignedAt = time.Unix(view.SignedAt, 0).UTC()
	}
	if view.StartedAt > 0 {
		rec.StartedAt = time.Unix(view.StartedAt, 0).UTC()
	}
	if view.FinishedAt > 0 {
		rec.FinishedAt = time.Unix(view.FinishedAt, 0).UTC()
	}
	return rec, nil
}

// recordToView rebuilds the rendered view from its storage row.
func recordToView(rec store.ReceiptViewRecord) (*ReceiptView, error) {
	var view ReceiptView
	unmarshal := func(raw string, v any) {
		if raw == "" {
			raw = "[]"
		}
		_ = json.Unmarshal([]byte(raw), v)
	}
	view.Verification = rec.Verification
	view.ReasonCode = rec.ReasonCode
	view.ReceiptID = rec.ReceiptID
	view.GrantID = rec.GrantID
	view.MissionRef = rec.MissionRef
	view.WorkspaceID = rec.WorkspaceID
	view.KeyID = rec.KeyID
	view.ReceiptDigest = rec.ReceiptDigest
	view.SettlementDigest = rec.SettlementDigest
	view.Outcome = rec.Outcome
	view.RepositoryID = rec.RepositoryID
	view.IssueNumber = rec.IssueNumber
	view.Branch = rec.Branch
	view.PullRequestNumber = rec.PullRequestNumber
	view.HeadSHA = rec.HeadSHA
	view.AggregateCostMicros = rec.AggregateCostMicros
	view.BudgetMicros = rec.BudgetMicros
	if !rec.SignedAt.IsZero() {
		view.SignedAt = rec.SignedAt.Unix()
	}
	if !rec.StartedAt.IsZero() {
		view.StartedAt = rec.StartedAt.Unix()
	}
	if !rec.FinishedAt.IsZero() {
		view.FinishedAt = rec.FinishedAt.Unix()
	}
	unmarshal(rec.MissionVersionsJSON, &view.MissionVersions)
	unmarshal(rec.ExpansionDecisionRefsJSON, &view.ExpansionDecisionRefs)
	unmarshal(rec.ChecksJSON, &view.Checks)
	unmarshal(rec.HistoricalEnforcementJSON, &view.HistoricalEnforcement)
	return &view, nil
}

// VerifyReceipt fetches the upstream receipt envelope for a pass,
// verifies it locally, and transitions the pass to its terminal outcome
// only when verification succeeds. An invalid receipt records an
// unverifiable verdict and leaves the pass in outcome_pending; a
// missing upstream receipt is not an error and returns a nil view.
// Verification is idempotent: a stored verdict is returned without
// touching upstream again.
func (s *Service) VerifyReceipt(ctx context.Context, workspaceID, passID string) (*ReceiptView, error) {
	// Phase 1: read the pass, any stored verdict, and the local
	// binding in one short transaction. Upstream calls happen
	// after the transaction commits: holding a store transaction
	// across network I/O would serialize every other writer.
	var pass store.MissionPassRecord
	var binding Binding
	var pending bool
	var out *ReceiptView
	var latchReason string
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		p, err := tx.GetMissionPass(ctx, workspaceID, passID)
		if err != nil {
			return err
		}
		pass = p
		stored, err := tx.GetReceiptView(ctx, workspaceID, passID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err == nil {
			view, verr := recordToView(stored)
			if verr != nil {
				return verr
			}
			out = view
			if stored.Verification == store.ReceiptUnverifiable {
				latchReason = stored.ReasonCode
			}
			return nil
		}
		if missionpass.PassState(p.State) != missionpass.PassOutcomePending {
			// Nothing to verify for a pass that is not awaiting its
			// receipt; the terminal transition (if any) already
			// happened through a verified receipt.
			return nil
		}
		b, berr := s.buildBinding(ctx, tx, workspaceID, p)
		if berr != nil {
			return berr
		}
		binding = b
		pending = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if out != nil || !pending {
		if latchReason != "" {
			return out, fmt.Errorf("%w: %s", ErrReceiptUnverifiable, latchReason)
		}
		return out, nil
	}
	// Phase 2: fetch and verify outside the transaction.
	env, err := s.authority.GetReceipt(ctx, pass.RunID, s.requestOptions(workspaceID))
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("receipt: fetch receipt: %w", err)
	}
	view, verr := s.verifier.Verify(env, binding)
	if verr != nil && isUnknownKey(verr) {
		// The signing key is unknown: refresh the key history
		// once and retry. A refresh that does not chain to the
		// pinned root fails closed below.
		if rerr := s.refreshKeys(ctx, workspaceID); rerr != nil {
			verr = unverifiable(ReasonBadKey, "signing-key refresh failed")
		} else {
			view, verr = s.verifier.Verify(env, binding)
		}
	}
	var verdict *ReceiptView
	var reason string
	if verr != nil {
		if !errors.Is(verr, ErrReceiptUnverifiable) {
			return nil, verr
		}
		// A verification failure is captured, not returned: the
		// unverifiable verdict must commit so the worker does not
		// hammer upstream on every poll. Only operational errors
		// roll back.
		reason = reasonCode(verr)
		verdict = &ReceiptView{
			Verification: store.ReceiptUnverifiable,
			ReasonCode:   reason,
			GrantID:      pass.RunID,
			MissionRef:   pass.MissionRef,
			WorkspaceID:  workspaceID,
		}
	} else {
		verdict = view
	}
	// Phase 3: store the verdict and, only on a locally verified
	// receipt, transition the pass while it is still
	// outcome_pending. A concurrent worker may have stored a
	// verdict while we were verifying; the first write wins.
	var raced *ReceiptView
	var racedReason string
	err = s.store.WithTx(ctx, func(tx store.Tx) error {
		stored, gerr := tx.GetReceiptView(ctx, workspaceID, passID)
		if gerr == nil {
			v, verr := recordToView(stored)
			if verr != nil {
				return verr
			}
			raced = v
			if stored.Verification == store.ReceiptUnverifiable {
				racedReason = stored.ReasonCode
			}
			return nil
		}
		if !errors.Is(gerr, store.ErrNotFound) {
			return gerr
		}
		rec, rerr := viewToRecord(workspaceID, passID, verdict, s.now())
		if rerr != nil {
			return rerr
		}
		if err := tx.PutReceiptView(ctx, rec); err != nil {
			return err
		}
		if verdict.Verification != store.ReceiptVerified {
			return nil
		}
		// Only a locally verified receipt moves the pass to a terminal
		// outcome. The transition is compare-and-swap on the store
		// revision so a concurrent terminal event cannot be
		// overwritten.
		var next missionpass.PassState
		switch verdict.Outcome {
		case OutcomeSuccess:
			next = missionpass.PassCompleted
		case OutcomeFailure:
			next = missionpass.PassFailed
		default:
			return fmt.Errorf("receipt: verified receipt has unknown outcome %q", verdict.Outcome)
		}
		current, cerr := tx.GetMissionPass(ctx, workspaceID, passID)
		if cerr != nil {
			return cerr
		}
		if missionpass.PassState(current.State) == missionpass.PassOutcomePending {
			current.State = string(next)
			current.Reconciliation = string(missionpass.ReconciliationSettled)
			if err := tx.PutMissionPass(ctx, current, current.StoreRevision); err != nil {
				return fmt.Errorf("receipt: settle pass: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if raced != nil {
		if racedReason != "" {
			return raced, fmt.Errorf("%w: %s", ErrReceiptUnverifiable, racedReason)
		}
		return raced, nil
	}
	if reason != "" {
		return verdict, fmt.Errorf("%w: %s", ErrReceiptUnverifiable, reason)
	}
	return verdict, nil
}

// isUnknownKey reports whether a verification error is an unknown
// signing key, the one case that justifies a key-history refresh.
func isUnknownKey(err error) bool {
	if !errors.Is(err, ErrReceiptUnverifiable) {
		return false
	}
	return strings.Contains(err.Error(), ReasonBadKey)
}

// PublishVerifiedCheck publishes the privacy-safe GitHub check for a
// verified receipt. The publication idempotency key is derived from the
// workspace, the receipt digest, and the repository binding triple, so
// retries and duplicate deliveries never create a second check run.
// The check carries only the outcome, the signed historical enforcement
// statuses, and a receipt-digest prefix.
func (s *Service) PublishVerifiedCheck(ctx context.Context, workspaceID, passID string) error {
	// Phase 1: read the verified receipt, the repository binding,
	// and the durable intent in one short transaction. The
	// in-flight intent commits here, before any upstream call, so
	// a crash or timeout still leaves reconcilable state. No
	// upstream calls happen while the transaction is open.
	var view *ReceiptView
	var bindingID string
	var key string
	var alreadySettled bool
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		pass, err := tx.GetMissionPass(ctx, workspaceID, passID)
		if err != nil {
			return err
		}
		stored, err := tx.GetReceiptView(ctx, workspaceID, passID)
		if err != nil {
			return fmt.Errorf("receipt: no verified receipt for pass %q", passID)
		}
		if stored.Verification != store.ReceiptVerified {
			return fmt.Errorf("receipt: pass %q receipt is %q, not verified", passID, stored.Verification)
		}
		v, err := recordToView(stored)
		if err != nil {
			return err
		}
		view = v
		if pass.ConnectionID != "" {
			conn, err := tx.GetConnection(ctx, workspaceID, pass.ConnectionID)
			if err != nil {
				return fmt.Errorf("receipt: get connection: %w", err)
			}
			bindingID = conn.RepositoryBindingRef
		}
		if bindingID == "" {
			return fmt.Errorf("receipt: pass %q has no repository binding", passID)
		}
		key = PublicationIDKey(workspaceID, view.ReceiptDigest, view.RepositoryID, view.PullRequestNumber, view.HeadSHA)
		inserted, err := tx.PutCheckPublicationIfAbsent(ctx, store.CheckPublicationRecord{
			WorkspaceID:       workspaceID,
			PassID:            passID,
			IdempotencyKey:    key,
			ReceiptDigest:     view.ReceiptDigest,
			RepositoryID:      view.RepositoryID,
			PullRequestNumber: view.PullRequestNumber,
			HeadSHA:           view.HeadSHA,
			BindingID:         bindingID,
			State:             store.CheckPublicationInFlight,
			CreatedAt:         s.now(),
			UpdatedAt:         s.now(),
		})
		if err != nil {
			return err
		}
		intent, err := tx.GetCheckPublication(ctx, workspaceID, key)
		if err != nil {
			return err
		}
		alreadySettled = !inserted && intent.State == store.CheckPublicationSettled
		return nil
	})
	if err != nil {
		return err
	}
	if alreadySettled {
		return nil
	}
	// Phase 2: publish outside the transaction.
	settle := func(state, checkRunID string) error {
		return s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.SetCheckPublicationState(ctx, workspaceID, key, state, checkRunID, s.now())
		})
	}
	req := MinimalCheckRequest(view, bindingID, key)
	if req.Name == "" {
		// A verified view always renders; this is defensive. A
		// check that cannot render can never succeed, so dispute
		// the intent instead of retrying forever.
		return settle(store.CheckPublicationDisputed, "")
	}
	res, err := s.authority.PublishGitHubCheck(ctx, req, s.requestOptions(workspaceID))
	if err != nil {
		if isNotFound(err) {
			// The binding is gone upstream: dispute rather than
			// retrying forever.
			return settle(store.CheckPublicationDisputed, "")
		}
		// A transient failure leaves the intent in flight for the
		// reconciler; the error is returned so the caller can
		// back off, and the durable intent is already committed.
		// The idempotency key makes the retry safe.
		return fmt.Errorf("receipt: publish check: %w", err)
	}
	if res.IdempotencyKey != key {
		return settle(store.CheckPublicationDisputed, res.CheckRunID)
	}
	return settle(store.CheckPublicationSettled, res.CheckRunID)
}

// ReconcilePublication settles an in-flight check publication against
// the upstream operation state. It runs even after the pass has gone
// terminal, so a check stuck in flight still settles. A terminal
// upstream failure disputes the intent instead of retrying forever.
func (s *Service) ReconcilePublication(ctx context.Context, workspaceID, passID string) error {
	// Phase 1: read the in-flight intent and the receipt view in
	// one short transaction. Upstream calls happen after the
	// transaction commits.
	var intent store.CheckPublicationRecord
	var view *ReceiptView
	var found bool
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		in, err := tx.GetLatestCheckPublicationForPass(ctx, workspaceID, passID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		if in.State == store.CheckPublicationSettled || in.State == store.CheckPublicationDisputed {
			return nil
		}
		stored, err := tx.GetReceiptView(ctx, workspaceID, passID)
		if err != nil {
			return err
		}
		v, err := recordToView(stored)
		if err != nil {
			return err
		}
		intent, view, found = in, v, true
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	settle := func(state, checkRunID string) error {
		return s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.SetCheckPublicationState(ctx, workspaceID, intent.IdempotencyKey, state, checkRunID, s.now())
		})
	}
	// Phase 2: reconcile against the upstream operation state
	// outside the transaction.
	rec, err := s.authority.ReconcileOperation(ctx, intent.IdempotencyKey, "", s.requestOptions(workspaceID))
	if err != nil {
		if isNotFound(err) {
			return settle(store.CheckPublicationDisputed, intent.CheckRunID)
		}
		return fmt.Errorf("receipt: reconcile publication: %w", err)
	}
	switch strings.ToLower(rec.Status) {
	case upstreamOperationCompleted:
		return settle(store.CheckPublicationSettled, intent.CheckRunID)
	case upstreamOperationFailed, upstreamOperationRejected, upstreamOperationExpired:
		return settle(store.CheckPublicationDisputed, intent.CheckRunID)
	default:
		// Still unknown upstream: republish with the same
		// idempotency key. Upstream dedupes, so this is safe.
		req := MinimalCheckRequest(view, intent.BindingID, intent.IdempotencyKey)
		if req.Name == "" {
			return fmt.Errorf("receipt: cannot render a public check for pass %q", passID)
		}
		res, err := s.authority.PublishGitHubCheck(ctx, req, s.requestOptions(workspaceID))
		if err != nil {
			if isNotFound(err) {
				return settle(store.CheckPublicationDisputed, intent.CheckRunID)
			}
			return fmt.Errorf("receipt: republish check: %w", err)
		}
		checkRunID := res.CheckRunID
		if checkRunID == "" {
			checkRunID = intent.CheckRunID
		}
		return settle(store.CheckPublicationSettled, checkRunID)
	}
}

// ReceiptStatus is the private receipt view for one pass.
type ReceiptStatus struct {
	PassID       string             `json:"pass_id"`
	Verification string             `json:"verification"`
	ReasonCode   string             `json:"reason_code,omitempty"`
	View         *ReceiptView       `json:"view,omitempty"`
	Publication  *PublicationStatus `json:"publication,omitempty"`
}

// PublicationStatus is the durable publication state for one pass.
type PublicationStatus struct {
	State             string `json:"state"`
	CheckRunID        string `json:"check_run_id,omitempty"`
	IdempotencyKey    string `json:"idempotency_key"`
	RepositoryID      int64  `json:"repository_id"`
	PullRequestNumber int64  `json:"pull_request_number"`
	HeadSHA           string `json:"head_sha"`
	UpdatedAt         string `json:"updated_at"`
}

// Get returns the private receipt view for a pass. A pass with no
// verified receipt reports pending; an unverifiable receipt reports
// its fixed reason code. The view never carries the raw envelope.
func (s *Service) Get(ctx context.Context, workspaceID, passID string) (*ReceiptStatus, error) {
	var out *ReceiptStatus
	err := s.store.WithTx(ctx, func(tx store.Tx) error {
		if _, err := tx.GetMissionPass(ctx, workspaceID, passID); err != nil {
			return err
		}
		status := &ReceiptStatus{PassID: passID, Verification: store.ReceiptStatePending}
		stored, err := tx.GetReceiptView(ctx, workspaceID, passID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			out = status
			return nil
		}
		status.Verification = stored.Verification
		status.ReasonCode = stored.ReasonCode
		if stored.Verification == store.ReceiptVerified {
			view, err := recordToView(stored)
			if err != nil {
				return err
			}
			status.View = view
		}
		intent, err := tx.GetLatestCheckPublicationForPass(ctx, workspaceID, passID)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				return err
			}
			out = status
			return nil
		}
		status.Publication = &PublicationStatus{
			State:             intent.State,
			CheckRunID:        intent.CheckRunID,
			IdempotencyKey:    intent.IdempotencyKey,
			RepositoryID:      intent.RepositoryID,
			PullRequestNumber: intent.PullRequestNumber,
			HeadSHA:           intent.HeadSHA,
			UpdatedAt:         intent.UpdatedAt.UTC().Format(time.RFC3339),
		}
		out = status
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
