// Event projection: the reconciliation worker reads authoritative mission
// events through Authority.ReadEvents and projects them here. Only the
// allowlisted SafeEvent fields are ever persisted: prompts, patches, issue
// bodies, transcripts, URLs, email addresses, and credentials never reach
// the store. Known event payloads are strict-decoded with unknown fields
// rejected. An unknown authenticated event type discards the payload,
// leaves the cursor unchanged, records only the fixed local
// incompatibility reason, marks the projection incompatible and stale,
// and latches the gate so business mutations fail closed until a parser
// and pinned-contract upgrade replays from the unchanged cursor.
package missionpass

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

// Known authoritative event types. Anything else arriving authenticated
// takes the incompatibility path, never the projection path.
const (
	EventMissionStarted     = "mission_started"
	EventActionChecked      = "action_checked"
	EventExpansionRequested = "expansion_requested"
	EventPullRequestCreated = "pull_request_created"
	EventRunSucceeded       = "run_succeeded"
	EventRunFailed          = "run_failed"
	EventMissionExpired     = "mission_expired"
	EventMissionRevoked     = "mission_revoked"
	EventReceiptReady       = "receipt_ready"
)

// SafeEvent is the allowlisted projection of one authoritative event.
// Every field is safe to persist and to render in the UI timeline.
type SafeEvent struct {
	EventID                 string    `json:"event_id"`
	Cursor                  string    `json:"cursor"`
	Type                    string    `json:"type"`
	OccurredAt              time.Time `json:"occurred_at"`
	AuthScopeMissionVersion int64     `json:"authscope_mission_version"`
	ResourceDigest          string    `json:"resource_digest"`
	ReasonCode              string    `json:"reason_code,omitempty"`
	Branch                  string    `json:"branch,omitempty"`
	PullRequestNumber       int64     `json:"pull_request_number,omitempty"`
	HeadSHA                 string    `json:"head_sha,omitempty"`
	CheckKind               string    `json:"check_kind,omitempty"`
	CheckOutcome            string    `json:"check_outcome,omitempty"`
}

// Fixed check-kind enum for action_checked events.
const (
	CheckKindPolicy     = "policy"
	CheckKindBuild      = "build"
	CheckKindTest       = "test"
	CheckKindSecretScan = "secret-scan"
)

// Fixed check-outcome enum for action_checked events.
const (
	CheckOutcomePassed = "passed"
	CheckOutcomeFailed = "failed"
)

// Fixed reason-code enum for events that carry one. Revocation reasons
// are a subset shared with the revocation flow.
const (
	EventReasonFounderRequested = "founder_requested"
	EventReasonSafetyConcern    = "safety_concern"
	EventReasonMissionSuperseded = "mission_superseded"
	EventReasonPolicyViolation  = "policy_violation"
	EventReasonExpired          = "expired"
	EventReasonUpstreamError    = "upstream_error"
)

// ErrProjectionIncompatible reports that an unknown authenticated event
// type latched the projection gate. The cursor is unchanged; business
// mutations stay blocked until a parser and pinned-contract upgrade
// replays from that cursor.
var ErrProjectionIncompatible = errors.New("missionpass: projection incompatible: unknown event type")

// ProjectionGate latches when an unknown authenticated event type
// arrives. coreapi.Gate implements it; business mutations fail closed
// while it is latched.
type ProjectionGate interface {
	NoteProjectionIncompatible(reason string)
}

var knownEventTypes = map[string]bool{
	EventMissionStarted:     true,
	EventActionChecked:      true,
	EventExpansionRequested: true,
	EventPullRequestCreated: true,
	EventRunSucceeded:       true,
	EventRunFailed:          true,
	EventMissionExpired:     true,
	EventMissionRevoked:     true,
	EventReceiptReady:       true,
}

var validCheckKinds = map[string]bool{
	CheckKindPolicy: true, CheckKindBuild: true, CheckKindTest: true, CheckKindSecretScan: true,
}

var validCheckOutcomes = map[string]bool{
	CheckOutcomePassed: true, CheckOutcomeFailed: true,
}

var validEventReasons = map[string]bool{
	EventReasonFounderRequested: true,
	EventReasonSafetyConcern:    true,
	EventReasonMissionSuperseded: true,
	EventReasonPolicyViolation:  true,
	EventReasonExpired:          true,
	EventReasonUpstreamError:    true,
}

// maxEventPayloadBytes caps one authoritative event payload. Anything
// larger is rejected before decoding.
const maxEventPayloadBytes = 16 * 1024

// eventClockSkew tolerates authority clock skew on occurred_at.
const eventClockSkew = 5 * time.Minute

// branchPattern accepts only generated mission branches.
var branchPattern = regexp.MustCompile(`^authscope/[A-Za-z0-9._-]+$`)

// Per-type payloads. Every payload carries the workspace, the mission
// version, and the resource digest; each type adds only its own
// allowlisted fields. Strict decoding rejects unknown fields.
type eventCommon struct {
	WorkspaceID    string `json:"workspace_id"`
	MissionVersion int64  `json:"mission_version"`
	ResourceDigest string `json:"resource_digest"`
}

type missionStartedPayload struct {
	eventCommon
	Branch  string `json:"branch"`
	HeadSHA string `json:"head_sha"`
}

type actionCheckedPayload struct {
	eventCommon
	CheckKind    string `json:"check_kind"`
	CheckOutcome string `json:"check_outcome"`
}

type expansionRequestedPayload struct {
	eventCommon
	ReasonCode string `json:"reason_code"`
}

type pullRequestCreatedPayload struct {
	eventCommon
	Branch            string `json:"branch"`
	PullRequestNumber int64  `json:"pull_request_number"`
	HeadSHA           string `json:"head_sha"`
}

type runSucceededPayload struct {
	eventCommon
	Branch  string `json:"branch"`
	HeadSHA string `json:"head_sha"`
}

type runFailedPayload struct {
	eventCommon
	ReasonCode string `json:"reason_code"`
}

type missionExpiredPayload struct {
	eventCommon
	ReasonCode string `json:"reason_code"`
}

type missionRevokedPayload struct {
	eventCommon
	ReasonCode string `json:"reason_code"`
}

type receiptReadyPayload struct {
	eventCommon
}

// EventProjector applies authoritative event pages to the local
// projection inside one store transaction per page.
type EventProjector struct {
	store store.Store
	gate  ProjectionGate
	clock func() time.Time
}

// NewEventProjector builds the projector. gate may be nil in contexts
// that never project unknown types; the incompatibility path requires
// it.
func NewEventProjector(st store.Store, gate ProjectionGate) *EventProjector {
	return &EventProjector{store: st, gate: gate, clock: time.Now}
}

// ApplyPage projects one authoritative page for a pass. It returns the
// number of newly stored events. The page is applied atomically: the
// known event insert and the cursor advance commit together. An unknown
// authenticated event type rolls the page back, marks the projection
// incompatible and stale with the fixed local reason, latches the gate,
// and returns ErrProjectionIncompatible.
func (p *EventProjector) ApplyPage(ctx context.Context, workspaceID, passID string, page coreapi.EventPage) (int, error) {
	if workspaceID == "" || passID == "" {
		return 0, fmt.Errorf("missionpass: apply page: workspace and pass IDs are required")
	}
	var stored int
	err := p.store.WithTx(ctx, func(tx store.Tx) error {
		n, err := p.applyPageTx(ctx, tx, workspaceID, passID, page)
		if err != nil {
			return err
		}
		stored = n
		return nil
	})
	if err != nil {
		if errors.Is(err, errUnknownEventType) {
			if merr := p.markIncompatible(ctx, workspaceID, passID); merr != nil {
				return 0, fmt.Errorf("missionpass: apply page: %v; mark incompatible: %w", err, merr)
			}
			return 0, ErrProjectionIncompatible
		}
		return 0, err
	}
	return stored, nil
}

var errUnknownEventType = errors.New("missionpass: unknown event type")

func (p *EventProjector) applyPageTx(ctx context.Context, tx store.Tx, workspaceID, passID string, page coreapi.EventPage) (int, error) {
	pass, err := tx.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return 0, fmt.Errorf("missionpass: apply page: %w", err)
	}
	proj, err := tx.GetMissionProjection(ctx, workspaceID, passID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, fmt.Errorf("missionpass: apply page: %w", err)
	}
	if err == nil && !proj.Compatible {
		return 0, ErrProjectionIncompatible
	}
	if len(page.Events) > 0 {
		if page.NextCursor == "" {
			return 0, fmt.Errorf("missionpass: apply page: page with events must carry a next cursor")
		}
	}
	now := p.clock()
	seq := proj.EventSeq
	versionFloor := proj.MissionVersion
	if pass.AuthScopeMissionVersion > versionFloor {
		versionFloor = pass.AuthScopeMissionVersion
	}
	maxVersion := versionFloor
	var prevOccurred time.Time
	stored := 0
	passChanged := false
	for i := range page.Events {
		ev := page.Events[i]
		safe, err := p.decodeEvent(ev, workspaceID, versionFloor, now, prevOccurred)
		if err != nil {
			if errors.Is(err, errUnknownEventType) {
				return 0, err
			}
			return 0, fmt.Errorf("missionpass: apply page: event %d: %w", i, err)
		}
		prevOccurred = safe.OccurredAt
		if safe.AuthScopeMissionVersion > maxVersion {
			maxVersion = safe.AuthScopeMissionVersion
		}
		seq++
		safe.Cursor = eventCursor(seq)
		raw, err := json.Marshal(safe)
		if err != nil {
			return 0, fmt.Errorf("missionpass: apply page: %w", err)
		}
		inserted, err := tx.PutEventIfAbsent(ctx, store.MissionEventRecord{
			WorkspaceID: workspaceID,
			PassID:      passID,
			EventID:     safe.EventID,
			EventType:   safe.Type,
			Cursor:      safe.Cursor,
			Payload:     string(raw),
			OccurredAt:  safe.OccurredAt,
		})
		if err != nil {
			return 0, fmt.Errorf("missionpass: apply page: %w", err)
		}
		if !inserted {
			// Idempotent replay of an event ID we already hold: keep
			// the sequence monotonic without storing twice.
			seq--
			continue
		}
		stored++
		changed, err := p.applyEventEffect(ctx, tx, &pass, safe)
		if err != nil {
			return 0, fmt.Errorf("missionpass: apply page: event %q: %w", safe.EventID, err)
		}
		if changed {
			passChanged = true
		}
	}
	if passChanged {
		if err := tx.PutMissionPass(ctx, pass, pass.StoreRevision); err != nil {
			return 0, fmt.Errorf("missionpass: apply page: %w", err)
		}
	}
	if stored > 0 && page.NextCursor == proj.Cursor {
		return 0, fmt.Errorf("missionpass: apply page: page cursor did not advance")
	}
	if err := tx.AdvanceProjection(ctx, workspaceID, passID, page.NextCursor, seq, maxVersion); err != nil {
		return 0, fmt.Errorf("missionpass: apply page: %w", err)
	}
	return stored, nil
}

// markIncompatible records the fixed local reason for an unknown
// authenticated event type in its own transaction: the payload is never
// stored, the cursor stays unchanged, and the projection is marked
// incompatible and stale.
func (p *EventProjector) markIncompatible(ctx context.Context, workspaceID, passID string) error {
	if p.gate == nil {
		return fmt.Errorf("missionpass: no projection gate configured")
	}
	if err := p.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.MarkProjectionIncompatible(ctx, workspaceID, passID, store.IncompatibleProjectionReason)
	}); err != nil {
		return err
	}
	p.gate.NoteProjectionIncompatible(store.IncompatibleProjectionReason)
	return nil
}

// eventCursor renders the local event sequence as a zero-padded,
// lexicographically ordered cursor.
func eventCursor(seq int64) string {
	return fmt.Sprintf("%020d", seq)
}

// decodeEvent strict-decodes one authoritative event into its allowlisted
// SafeEvent, validating the envelope, the payload size, the workspace,
// the monotonic mission version, the fixed enums, the branch pattern, and
// the event order within the page.
func (p *EventProjector) decodeEvent(ev coreapi.MissionEvent, workspaceID string, versionFloor int64, now, prevOccurred time.Time) (SafeEvent, error) {
	var safe SafeEvent
	if ev.EventID == "" || len(ev.EventID) > 128 {
		return safe, fmt.Errorf("invalid event ID")
	}
	if !knownEventTypes[ev.EventType] {
		return safe, fmt.Errorf("%w: %q", errUnknownEventType, ev.EventType)
	}
	if len(ev.Payload) == 0 || len(ev.Payload) > maxEventPayloadBytes {
		return safe, fmt.Errorf("payload size %d out of bounds", len(ev.Payload))
	}
	occurred := time.UnixMilli(ev.OccurredAt).UTC()
	if ev.OccurredAt <= 0 {
		return safe, fmt.Errorf("occurred_at must be positive")
	}
	if occurred.After(now.Add(eventClockSkew)) {
		return safe, fmt.Errorf("occurred_at is in the future")
	}
	if !prevOccurred.IsZero() && occurred.Before(prevOccurred) {
		return safe, fmt.Errorf("events out of order")
	}
	safe.EventID = ev.EventID
	safe.Type = ev.EventType
	safe.OccurredAt = occurred
	common, specific, err := decodePayload(ev.EventType, ev.Payload)
	if err != nil {
		return safe, err
	}
	if common.WorkspaceID != workspaceID {
		return safe, fmt.Errorf("workspace mismatch")
	}
	if common.MissionVersion < 0 {
		return safe, fmt.Errorf("mission version must not be negative")
	}
	if common.MissionVersion < versionFloor {
		return safe, fmt.Errorf("mission version %d below floor %d", common.MissionVersion, versionFloor)
	}
	if err := validateDigest(common.ResourceDigest); err != nil {
		return safe, fmt.Errorf("resource digest: %w", err)
	}
	safe.AuthScopeMissionVersion = common.MissionVersion
	safe.ResourceDigest = common.ResourceDigest
	if err := specific(&safe); err != nil {
		return safe, err
	}
	return safe, nil
}

// decodePayload strict-decodes the payload for a known type with unknown
// fields rejected, returning the common fields plus a closure that fills
// the type-specific SafeEvent fields.
func decodePayload(eventType string, raw json.RawMessage) (eventCommon, func(*SafeEvent) error, error) {
	var common eventCommon
	fill := func(*SafeEvent) error { return nil }
	dec := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return fmt.Errorf("strict decode: %w", err)
		}
		return nil
	}
	switch eventType {
	case EventMissionStarted:
		var pl missionStartedPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if err := validateBranch(pl.Branch); err != nil {
				return fmt.Errorf("branch: %w", err)
			}
			if err := validateSHA(pl.HeadSHA); err != nil {
				return fmt.Errorf("head SHA: %w", err)
			}
			s.Branch, s.HeadSHA = pl.Branch, pl.HeadSHA
			return nil
		}
	case EventActionChecked:
		var pl actionCheckedPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if !validCheckKinds[pl.CheckKind] {
				return fmt.Errorf("unknown check kind %q", pl.CheckKind)
			}
			if !validCheckOutcomes[pl.CheckOutcome] {
				return fmt.Errorf("unknown check outcome %q", pl.CheckOutcome)
			}
			s.CheckKind, s.CheckOutcome = pl.CheckKind, pl.CheckOutcome
			return nil
		}
	case EventExpansionRequested:
		var pl expansionRequestedPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if err := validateReason(pl.ReasonCode); err != nil {
				return err
			}
			s.ReasonCode = pl.ReasonCode
			return nil
		}
	case EventPullRequestCreated:
		var pl pullRequestCreatedPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if err := validateBranch(pl.Branch); err != nil {
				return fmt.Errorf("branch: %w", err)
			}
			if pl.PullRequestNumber <= 0 {
				return fmt.Errorf("pull request number must be positive")
			}
			if err := validateSHA(pl.HeadSHA); err != nil {
				return fmt.Errorf("head SHA: %w", err)
			}
			s.Branch, s.PullRequestNumber, s.HeadSHA = pl.Branch, pl.PullRequestNumber, pl.HeadSHA
			return nil
		}
	case EventRunSucceeded:
		var pl runSucceededPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if err := validateBranch(pl.Branch); err != nil {
				return fmt.Errorf("branch: %w", err)
			}
			if err := validateSHA(pl.HeadSHA); err != nil {
				return fmt.Errorf("head SHA: %w", err)
			}
			s.Branch, s.HeadSHA = pl.Branch, pl.HeadSHA
			return nil
		}
	case EventRunFailed:
		var pl runFailedPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if err := validateReason(pl.ReasonCode); err != nil {
				return err
			}
			s.ReasonCode = pl.ReasonCode
			return nil
		}
	case EventMissionExpired:
		var pl missionExpiredPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if err := validateReason(pl.ReasonCode); err != nil {
				return err
			}
			s.ReasonCode = pl.ReasonCode
			return nil
		}
	case EventMissionRevoked:
		var pl missionRevokedPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
		fill = func(s *SafeEvent) error {
			if err := validateReason(pl.ReasonCode); err != nil {
				return err
			}
			s.ReasonCode = pl.ReasonCode
			return nil
		}
	case EventReceiptReady:
		var pl receiptReadyPayload
		if err := dec(&pl); err != nil {
			return common, nil, err
		}
		common = pl.eventCommon
	default:
		return common, nil, fmt.Errorf("%w: %q", errUnknownEventType, eventType)
	}
	return common, fill, nil
}

func validateDigest(d string) error {
	if d == "" || len(d) > 128 {
		return fmt.Errorf("must be 1-128 characters")
	}
	return nil
}

func validateBranch(b string) error {
	if !branchPattern.MatchString(b) {
		return fmt.Errorf("must match %s", branchPattern)
	}
	return nil
}

func validateSHA(s string) error {
	if len(s) != 40 && len(s) != 64 {
		return fmt.Errorf("must be 40 or 64 hex characters")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return fmt.Errorf("must be hex: %w", err)
	}
	return nil
}

func validateReason(r string) error {
	if !validEventReasons[r] {
		return fmt.Errorf("unknown reason code %q", r)
	}
	return nil
}

// applyEventEffect applies the pass-state effect of one projected event.
// Run outcomes move to outcome_pending, never directly to terminal
// completion or failure. A locally verified receipt moves outcome_pending
// to completed or failed. Revocation and expiry move to their terminal
// states when the transition is legal; events for an already-terminal
// pass are no-ops. It reports whether the pass record changed.
func (p *EventProjector) applyEventEffect(ctx context.Context, tx store.Tx, pass *store.MissionPassRecord, safe SafeEvent) (bool, error) {
	switch safe.Type {
	case EventRunSucceeded, EventRunFailed:
		return p.movePass(pass, PassOutcomePending, true)
	case EventMissionRevoked:
		return p.movePass(pass, PassRevoked, false)
	case EventMissionExpired:
		return p.movePass(pass, PassExpired, false)
	case EventExpansionRequested:
		// An expansion request moves a running pass to
		// awaiting_expansion atomically with the event projection.
		// The pass returns to running when the decision settles.
		if PassState(pass.State) == PassRunning {
			return p.movePass(pass, PassAwaitingExpansion, false)
		}
		return false, nil
	case EventReceiptReady:
		return p.applyReceipt(ctx, tx, pass, safe)
	default:
		return false, nil
	}
}

// movePass moves the pass to the target state. toTerminal marks events
// whose target is terminal: when the pass is already terminal the event
// is a no-op instead of an error.
func (p *EventProjector) movePass(pass *store.MissionPassRecord, to PassState, fromRunOutcome bool) (bool, error) {
	if pass.State == string(to) {
		return false, nil
	}
	if fromRunOutcome && pass.State == string(PassOutcomePending) {
		// A second run outcome while the first is still pending
		// reconciliation keeps the original outcome state.
		return false, nil
	}
	if isTerminalPassState(PassState(pass.State)) {
		return false, nil
	}
	if err := Transition(PassState(pass.State), to); err != nil {
		return false, err
	}
	pass.State = string(to)
	if fromRunOutcome {
		// The run outcome is now known: the launch reconciliation that
		// was pending while the run was in flight settles.
		pass.Reconciliation = string(ReconciliationSettled)
	}
	return true, nil
}

// applyReceipt verifies a receipt locally: the receipt resource digest
// must match the most recent projected run outcome, and the pass must be
// outcome_pending. Only a locally verified receipt enters completed or
// failed. A receipt that does not verify fails closed so the mismatch is
// investigated instead of silently skipped.
func (p *EventProjector) applyReceipt(ctx context.Context, tx store.Tx, pass *store.MissionPassRecord, safe SafeEvent) (bool, error) {
	if isTerminalPassState(PassState(pass.State)) {
		return false, nil
	}
	if pass.State != string(PassOutcomePending) {
		return false, fmt.Errorf("receipt without a pending outcome")
	}
	outcome, err := latestRunOutcome(ctx, tx, pass.WorkspaceID, pass.PassID)
	if err != nil {
		return false, err
	}
	if outcome.Type == "" {
		return false, fmt.Errorf("receipt without a projected run outcome")
	}
	if outcome.ResourceDigest == "" || outcome.ResourceDigest != safe.ResourceDigest {
		return false, fmt.Errorf("receipt digest does not match the projected run outcome")
	}
	var to PassState
	switch outcome.Type {
	case EventRunSucceeded:
		to = PassCompleted
	case EventRunFailed:
		to = PassFailed
	default:
		return false, fmt.Errorf("unexpected run outcome type %q", outcome.Type)
	}
	if err := Transition(PassState(pass.State), to); err != nil {
		return false, err
	}
	pass.State = string(to)
	pass.Reconciliation = string(ReconciliationSettled)
	return true, nil
}

// latestRunOutcome returns the most recent projected run outcome event.
func latestRunOutcome(ctx context.Context, tx store.Tx, workspaceID, passID string) (SafeEvent, error) {
	var outcome SafeEvent
	events, err := tx.ListMissionEvents(ctx, workspaceID, passID, "", 10000)
	if err != nil {
		return outcome, fmt.Errorf("missionpass: list events: %w", err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		var safe SafeEvent
		if err := json.Unmarshal([]byte(events[i].Payload), &safe); err != nil {
			return outcome, fmt.Errorf("missionpass: decode stored event: %w", err)
		}
		if safe.Type == EventRunSucceeded || safe.Type == EventRunFailed {
			return safe, nil
		}
	}
	return outcome, nil
}

// isTerminalPassState reports whether the pass can never transition.
func isTerminalPassState(s PassState) bool {
	switch s {
	case PassCompleted, PassFailed, PassRevoked, PassExpired:
		return true
	}
	return false
}

// ProjectionStatus summarizes the durable projection state for the UI
// timeline: the fixed safe events plus the stale/reconciliation state.
type ProjectionStatus struct {
	Events         []SafeEvent
	Cursor         string
	Compatible     bool
	Stale          bool
	Reason         string
	Containment    string
	State          string
	Reconciliation string
	// RepositoryName is the verified repository binding (owner/repo)
	// from the trusted issue snapshot. The UI derives branch and PR
	// links only from this name plus projected numeric PR identifiers.
	RepositoryName string
}

// LoadProjection reads the projected safe events and the projection
// health for the timeline endpoint.
func (p *EventProjector) LoadProjection(ctx context.Context, workspaceID, passID, afterCursor string, limit int) (ProjectionStatus, error) {
	var status ProjectionStatus
	pass, err := p.store.GetMissionPass(ctx, workspaceID, passID)
	if err != nil {
		return status, err
	}
	status.State = pass.State
	status.Reconciliation = pass.Reconciliation
	status.RepositoryName = pass.RepositoryName
	records, err := p.store.ListMissionEvents(ctx, workspaceID, passID, afterCursor, limit)
	if err != nil {
		return status, err
	}
	for _, rec := range records {
		var safe SafeEvent
		if err := json.Unmarshal([]byte(rec.Payload), &safe); err != nil {
			return status, fmt.Errorf("missionpass: decode stored event: %w", err)
		}
		status.Events = append(status.Events, safe)
	}
	proj, err := p.store.GetMissionProjection(ctx, workspaceID, passID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			status.Compatible = true
			status.Containment = pass.Containment
			return status, nil
		}
		return status, err
	}
	status.Cursor = proj.Cursor
	status.Compatible = proj.Compatible
	status.Stale = proj.Stale
	status.Reason = proj.IncompatibilityReason
	status.Containment = pass.Containment
	return status, nil
}
