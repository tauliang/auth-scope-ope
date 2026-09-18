package missionpass

// Task 10: the event projector strict-decodes known payloads, persists
// only allowlisted SafeEvent fields, advances the cursor atomically with
// the event insert, moves run outcomes to outcome_pending, and takes the
// incompatibility path for unknown authenticated event types.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

type stubProjectionGate struct {
	blocked bool
	reason  string
}

func (s *stubProjectionGate) NoteProjectionIncompatible(reason string) {
	s.blocked = true
	s.reason = reason
}

func openEventStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	})
	return st
}

func seedEventPass(t *testing.T, st store.Store, workspace, passID string, state PassState) {
	t.Helper()
	ctx := context.Background()
	err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID:             workspace,
			PassID:                  passID,
			State:                   string(state),
			AuthScopeMissionVersion: 3,
			MissionRef:              "mission-1",
			CreatedAt:               time.Now().UTC(),
			UpdatedAt:               time.Now().UTC(),
		}, 0)
	})
	if err != nil {
		t.Fatalf("seed pass: %v", err)
	}
}

func eventPayload(t *testing.T, fields map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return raw
}

func basePayload(workspace string) map[string]any {
	return map[string]any{
		"workspace_id":    workspace,
		"mission_version": 3,
		"resource_digest": "abc123",
	}
}

func testEvent(id, typ string, occurred time.Time, payload json.RawMessage) coreapi.MissionEvent {
	return coreapi.MissionEvent{
		EventID:    id,
		EventType:  typ,
		OccurredAt: occurred.UnixMilli(),
		Payload:    payload,
	}
}

func TestApplyPageProjectsKnownEvents(t *testing.T) {
	st := openEventStore(t)
	gate := &stubProjectionGate{}
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, gate)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	pl := basePayload("ws-test")
	pl["branch"] = "authscope/pass-1-42"
	pl["head_sha"] = strings.Repeat("a", 40)
	page := coreapi.EventPage{
		Events: []coreapi.MissionEvent{
			testEvent("ev-1", EventMissionStarted, now.Add(-time.Minute), eventPayload(t, pl)),
			testEvent("ev-2", EventActionChecked, now, eventPayload(t, func() map[string]any {
				p := basePayload("ws-test")
				p["check_kind"] = CheckKindPolicy
				p["check_outcome"] = CheckOutcomePassed
				return p
			}())),
		},
		NextCursor: "cursor-2",
	}
	n, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page)
	if err != nil {
		t.Fatalf("ApplyPage: %v", err)
	}
	if n != 2 {
		t.Fatalf("stored = %d, want 2", n)
	}
	events, err := st.ListMissionEvents(ctx, "ws-test", "pass-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	var first SafeEvent
	if err := json.Unmarshal([]byte(events[0].Payload), &first); err != nil {
		t.Fatalf("decode safe event: %v", err)
	}
	if first.Branch != "authscope/pass-1-42" || first.HeadSHA != strings.Repeat("a", 40) {
		t.Fatalf("safe event fields = %+v", first)
	}
	if first.Cursor == "" || events[0].Cursor != first.Cursor {
		t.Fatalf("event cursor not assigned: %q", events[0].Cursor)
	}
	if events[0].Cursor >= events[1].Cursor {
		t.Fatalf("cursors not ordered: %q >= %q", events[0].Cursor, events[1].Cursor)
	}
	// Only allowlisted fields survive: the raw payload must not contain
	// anything outside the SafeEvent shape.
	if strings.Contains(events[0].Payload, "workspace_id") {
		t.Fatalf("stored payload leaks non-allowlisted fields: %s", events[0].Payload)
	}
	p, err := st.GetMissionProjection(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionProjection: %v", err)
	}
	if p.Cursor != "cursor-2" || p.EventSeq != 2 || p.MissionVersion != 3 {
		t.Fatalf("projection = %+v", p)
	}
	if !p.Compatible || p.Stale {
		t.Fatalf("projection should stay compatible: %+v", p)
	}
	if gate.blocked {
		t.Fatalf("gate latched unexpectedly")
	}
}

func TestApplyPageRejectsUnknownFields(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()

	pl := basePayload("ws-test")
	pl["branch"] = "authscope/pass-1-42"
	pl["head_sha"] = strings.Repeat("a", 40)
	pl["prompt"] = "do something secret"
	page := coreapi.EventPage{
		Events:     []coreapi.MissionEvent{testEvent("ev-1", EventMissionStarted, time.Now().UTC(), eventPayload(t, pl))},
		NextCursor: "cursor-1",
	}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err == nil {
		t.Fatalf("expected strict decode error")
	}
	events, err := st.ListMissionEvents(ctx, "ws-test", "pass-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("nothing should be stored, got %d events", len(events))
	}
}

func TestApplyPageUnknownTypeMarksIncompatible(t *testing.T) {
	st := openEventStore(t)
	gate := &stubProjectionGate{}
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, gate)
	ctx := context.Background()

	pl := basePayload("ws-test")
	pl["branch"] = "authscope/pass-1-42"
	pl["head_sha"] = strings.Repeat("a", 40)
	good := testEvent("ev-1", EventMissionStarted, time.Now().UTC().Add(-time.Minute), eventPayload(t, pl))
	bad := testEvent("ev-2", "mission_teleported", time.Now().UTC(), eventPayload(t, basePayload("ws-test")))
	page := coreapi.EventPage{Events: []coreapi.MissionEvent{good, bad}, NextCursor: "cursor-2"}

	_, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page)
	if !errors.Is(err, ErrProjectionIncompatible) {
		t.Fatalf("err = %v, want ErrProjectionIncompatible", err)
	}
	// The whole page rolls back: nothing stored, cursor unchanged.
	events, err := st.ListMissionEvents(ctx, "ws-test", "pass-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("page should roll back, got %d events", len(events))
	}
	p, err := st.GetMissionProjection(ctx, "ws-test", "pass-1")
	if err != nil {
		t.Fatalf("GetMissionProjection: %v", err)
	}
	if p.Compatible || !p.Stale {
		t.Fatalf("projection should be incompatible and stale: %+v", p)
	}
	if p.Cursor != "" {
		t.Fatalf("cursor must stay unchanged, got %q", p.Cursor)
	}
	if p.IncompatibilityReason != store.IncompatibleProjectionReason {
		t.Fatalf("reason = %q, want the fixed local reason", p.IncompatibilityReason)
	}
	if !gate.blocked || gate.reason != store.IncompatibleProjectionReason {
		t.Fatalf("gate not latched with fixed reason: %+v", gate)
	}
	// While incompatible, further pages fail fast without touching the
	// authority payload.
	page2 := coreapi.EventPage{
		Events:     []coreapi.MissionEvent{testEvent("ev-3", EventMissionStarted, time.Now().UTC(), eventPayload(t, pl))},
		NextCursor: "cursor-3",
	}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page2); !errors.Is(err, ErrProjectionIncompatible) {
		t.Fatalf("err = %v, want ErrProjectionIncompatible", err)
	}
}

func TestApplyPageValidatesEnvelope(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()
	now := time.Now().UTC()

	cases := map[string]struct {
		mutate func(map[string]any)
		typ    string
	}{
		"workspace mismatch": {func(p map[string]any) { p["workspace_id"] = "ws-other" }, EventMissionStarted},
		"version regression": {func(p map[string]any) { p["mission_version"] = 2 }, EventMissionStarted},
		"bad branch":         {func(p map[string]any) { p["branch"] = "main" }, EventMissionStarted},
		"bad sha":            {func(p map[string]any) { p["head_sha"] = "xyz" }, EventMissionStarted},
		"bad check outcome":  {func(p map[string]any) { p["check_outcome"] = "maybe" }, EventActionChecked},
		"bad reason":         {func(p map[string]any) { p["reason_code"] = "whatever" }, EventRunFailed},
		"bad pr number":      {func(p map[string]any) { p["pull_request_number"] = 0 }, EventPullRequestCreated},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			pl := basePayload("ws-test")
			pl["branch"] = "authscope/pass-1-42"
			pl["head_sha"] = strings.Repeat("b", 64)
			pl["check_kind"] = CheckKindBuild
			pl["check_outcome"] = CheckOutcomePassed
			pl["reason_code"] = EventReasonExpired
			pl["pull_request_number"] = 7
			tc.mutate(pl)
			page := coreapi.EventPage{
				Events:     []coreapi.MissionEvent{testEvent("ev-x", tc.typ, now, eventPayload(t, pl))},
				NextCursor: "cursor-x",
			}
			if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestApplyPageRejectsOversizePayload(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()

	pl := basePayload("ws-test")
	pl["branch"] = "authscope/pass-1-42"
	pl["head_sha"] = strings.Repeat("a", 40)
	pl["padding"] = strings.Repeat("x", 32*1024)
	page := coreapi.EventPage{
		Events:     []coreapi.MissionEvent{testEvent("ev-1", EventMissionStarted, time.Now().UTC(), eventPayload(t, pl))},
		NextCursor: "cursor-1",
	}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err == nil {
		t.Fatalf("expected payload size error")
	}
}

func TestApplyPageRejectsOutOfOrderEvents(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()
	now := time.Now().UTC()

	mk := func(id string, at time.Time) coreapi.MissionEvent {
		pl := basePayload("ws-test")
		pl["branch"] = "authscope/pass-1-42"
		pl["head_sha"] = strings.Repeat("a", 40)
		return testEvent(id, EventMissionStarted, at, eventPayload(t, pl))
	}
	page := coreapi.EventPage{
		Events:     []coreapi.MissionEvent{mk("ev-1", now), mk("ev-2", now.Add(-time.Minute))},
		NextCursor: "cursor-1",
	}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err == nil {
		t.Fatalf("expected order error")
	}
}

func TestApplyPageDuplicateEventIsIdempotent(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()

	pl := basePayload("ws-test")
	pl["branch"] = "authscope/pass-1-42"
	pl["head_sha"] = strings.Repeat("a", 40)
	ev := testEvent("ev-1", EventMissionStarted, time.Now().UTC(), eventPayload(t, pl))
	n, err := proj.ApplyPage(ctx, "ws-test", "pass-1", coreapi.EventPage{Events: []coreapi.MissionEvent{ev}, NextCursor: "cursor-1"})
	if err != nil || n != 1 {
		t.Fatalf("first apply: n=%d err=%v", n, err)
	}
	n, err = proj.ApplyPage(ctx, "ws-test", "pass-1", coreapi.EventPage{Events: []coreapi.MissionEvent{ev}, NextCursor: "cursor-1"})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if n != 0 {
		t.Fatalf("replay stored %d events, want 0", n)
	}
	events, _ := st.ListMissionEvents(ctx, "ws-test", "pass-1", "", 10)
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
}

func runOutcomePayload(t *testing.T, typ, digest string) json.RawMessage {
	t.Helper()
	pl := basePayload("ws-test")
	pl["resource_digest"] = digest
	if typ == EventRunSucceeded {
		pl["branch"] = "authscope/pass-1-42"
		pl["head_sha"] = strings.Repeat("c", 40)
	} else {
		pl["reason_code"] = EventReasonUpstreamError
	}
	return eventPayload(t, pl)
}

func TestApplyPageRunOutcomeMovesToOutcomePending(t *testing.T) {
	for _, typ := range []string{EventRunSucceeded, EventRunFailed} {
		t.Run(typ, func(t *testing.T) {
			st := openEventStore(t)
			seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
			proj := NewEventProjector(st, &stubProjectionGate{})
			ctx := context.Background()

			page := coreapi.EventPage{
				Events:     []coreapi.MissionEvent{testEvent("ev-1", typ, time.Now().UTC(), runOutcomePayload(t, typ, "digest-1"))},
				NextCursor: "cursor-1",
			}
			if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err != nil {
				t.Fatalf("ApplyPage: %v", err)
			}
			pass, err := st.GetMissionPass(ctx, "ws-test", "pass-1")
			if err != nil {
				t.Fatalf("GetMissionPass: %v", err)
			}
			if pass.State != string(PassOutcomePending) {
				t.Fatalf("state = %q, want outcome_pending", pass.State)
			}
			if pass.Reconciliation != string(ReconciliationSettled) {
				t.Fatalf("reconciliation = %q, want settled", pass.Reconciliation)
			}
		})
	}
}

func TestApplyPageReceiptReadyRecordsSignalWithoutTerminalizing(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()
	now := time.Now().UTC()

	outcome := testEvent("ev-1", EventRunSucceeded, now.Add(-time.Minute), runOutcomePayload(t, EventRunSucceeded, "digest-9"))
	receiptPl := basePayload("ws-test")
	receiptPl["resource_digest"] = "digest-9"
	receipt := testEvent("ev-2", EventReceiptReady, now, eventPayload(t, receiptPl))
	page := coreapi.EventPage{Events: []coreapi.MissionEvent{outcome, receipt}, NextCursor: "cursor-2"}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err != nil {
		t.Fatalf("ApplyPage: %v", err)
	}
	pass, _ := st.GetMissionPass(ctx, "ws-test", "pass-1")
	if pass.State != string(PassOutcomePending) {
		t.Fatalf("state = %q, want outcome_pending until the receipt is verified locally", pass.State)
	}
	if pass.ReceiptPendingAt.IsZero() {
		t.Fatalf("receipt-ready signal was not recorded on the pass")
	}
}

func TestApplyPageReceiptMismatchFailsClosed(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()
	now := time.Now().UTC()

	outcome := testEvent("ev-1", EventRunFailed, now.Add(-time.Minute), runOutcomePayload(t, EventRunFailed, "digest-9"))
	receiptPl := basePayload("ws-test")
	receiptPl["resource_digest"] = "different-digest"
	receipt := testEvent("ev-2", EventReceiptReady, now, eventPayload(t, receiptPl))
	page := coreapi.EventPage{Events: []coreapi.MissionEvent{outcome, receipt}, NextCursor: "cursor-2"}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err == nil {
		t.Fatalf("expected receipt verification error")
	}
	pass, _ := st.GetMissionPass(ctx, "ws-test", "pass-1")
	if pass.State != string(PassRunning) {
		t.Fatalf("failed page must roll back, state = %q", pass.State)
	}
}

func TestApplyPageTerminalEvents(t *testing.T) {
	cases := []struct {
		typ   string
		state PassState
		extra map[string]any
	}{
		{EventMissionRevoked, PassRevoked, map[string]any{"reason_code": EventReasonFounderRequested}},
		{EventMissionExpired, PassExpired, map[string]any{"reason_code": EventReasonExpired}},
	}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			st := openEventStore(t)
			seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
			proj := NewEventProjector(st, &stubProjectionGate{})
			ctx := context.Background()

			pl := basePayload("ws-test")
			for k, v := range tc.extra {
				pl[k] = v
			}
			page := coreapi.EventPage{
				Events:     []coreapi.MissionEvent{testEvent("ev-1", tc.typ, time.Now().UTC(), eventPayload(t, pl))},
				NextCursor: "cursor-1",
			}
			if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err != nil {
				t.Fatalf("ApplyPage: %v", err)
			}
			pass, _ := st.GetMissionPass(ctx, "ws-test", "pass-1")
			if pass.State != string(tc.state) {
				t.Fatalf("state = %q, want %q", pass.State, tc.state)
			}
		})
	}
}

func TestApplyPageTerminalPassIgnoresLaterEvents(t *testing.T) {
	st := openEventStore(t)
	seedEventPass(t, st, "ws-test", "pass-1", PassCompleted)
	proj := NewEventProjector(st, &stubProjectionGate{})
	ctx := context.Background()

	pl := basePayload("ws-test")
	pl["reason_code"] = EventReasonFounderRequested
	page := coreapi.EventPage{
		Events:     []coreapi.MissionEvent{testEvent("ev-1", EventMissionRevoked, time.Now().UTC(), eventPayload(t, pl))},
		NextCursor: "cursor-1",
	}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err != nil {
		t.Fatalf("ApplyPage: %v", err)
	}
	pass, _ := st.GetMissionPass(ctx, "ws-test", "pass-1")
	if pass.State != string(PassCompleted) {
		t.Fatalf("terminal pass must not transition, state = %q", pass.State)
	}
}

func TestLoadProjection(t *testing.T) {
	st := openEventStore(t)
	gate := &stubProjectionGate{}
	seedEventPass(t, st, "ws-test", "pass-1", PassRunning)
	proj := NewEventProjector(st, gate)
	ctx := context.Background()

	pl := basePayload("ws-test")
	pl["branch"] = "authscope/pass-1-42"
	pl["head_sha"] = strings.Repeat("a", 40)
	page := coreapi.EventPage{
		Events:     []coreapi.MissionEvent{testEvent("ev-1", EventMissionStarted, time.Now().UTC(), eventPayload(t, pl))},
		NextCursor: "cursor-1",
	}
	if _, err := proj.ApplyPage(ctx, "ws-test", "pass-1", page); err != nil {
		t.Fatalf("ApplyPage: %v", err)
	}
	status, err := proj.LoadProjection(ctx, "ws-test", "pass-1", "", 10)
	if err != nil {
		t.Fatalf("LoadProjection: %v", err)
	}
	if len(status.Events) != 1 || status.Events[0].Type != EventMissionStarted {
		t.Fatalf("status = %+v", status)
	}
	if !status.Compatible || status.Stale || status.Cursor != "cursor-1" {
		t.Fatalf("status health = %+v", status)
	}
	if _, err := proj.LoadProjection(ctx, "ws-test", "missing", "", 10); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
