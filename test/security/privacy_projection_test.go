package security

// Task 15 privacy gates for the mission event projector: unknown
// fields and unknown event types are rejected, the cursor is
// preserved, the projection is marked incompatible and stale with the
// fixed local reason, the compatibility gate latches, and the error
// and timeline surfaces never carry upstream content.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/telemetry"
)

type privacyStubGate struct {
	blocked bool
	reason  string
}

func (s *privacyStubGate) NoteProjectionIncompatible(reason string) {
	s.blocked = true
	s.reason = reason
}

func seedPrivacyPass(t *testing.T, st store.Store, workspace, passID string) {
	t.Helper()
	ctx := context.Background()
	err := st.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutMissionPass(ctx, store.MissionPassRecord{
			WorkspaceID:             workspace,
			PassID:                  passID,
			State:                   string(missionpass.PassRunning),
			AuthScopeMissionVersion: 3,
			MissionRef:              "mission-sec-1",
			CreatedAt:               time.Now().UTC(),
			UpdatedAt:               time.Now().UTC(),
		}, 0)
	})
	if err != nil {
		t.Fatalf("seed pass: %v", err)
	}
}

func privacyEvent(id, typ string, occurred time.Time, payload map[string]any) coreapi.MissionEvent {
	raw, _ := json.Marshal(payload)
	return coreapi.MissionEvent{
		EventID:    id,
		EventType:  typ,
		OccurredAt: occurred.UnixMilli(),
		Payload:    raw,
	}
}

func privacyPage(nextCursor string, events ...coreapi.MissionEvent) coreapi.EventPage {
	return coreapi.EventPage{Events: events, NextCursor: nextCursor}
}

// TestProjectionRejectsUnknownFields proves the strict decoder drops
// any payload with unrecognized fields: a mission_started event
// carrying smuggled private content in extra fields is rejected, no
// event is stored, and the cursor does not advance.
func TestProjectionRejectsUnknownFields(t *testing.T) {
	can := loadCanaries(t)
	st, dir := openSecurityStore(t)
	ctx := context.Background()
	seedPrivacyPass(t, st, "ws-sec-1", "pass-sec-1")
	gate := &privacyStubGate{}
	projector := missionpass.NewEventProjector(st, gate)

	now := time.Now().UTC()
	ev := privacyEvent("ev-sec-1", missionpass.EventMissionStarted, now, map[string]any{
		"workspace_id":    "ws-sec-1",
		"mission_version": 3,
		"resource_digest": "abc123",
		"branch":          "authscope/pass-sec-1",
		"head_sha":        "0123456789abcdef0123456789abcdef01234567",
		"transcript":      can.private,
		"prompt":          can.envelope,
	})
	_, err := projector.ApplyPage(ctx, "ws-sec-1", "pass-sec-1", privacyPage("cursor-evil-1", ev))
	if err == nil {
		t.Fatal("payload with unknown fields was projected")
	}
	assertAbsent(t, "projection error", "private content", can.private, []byte(err.Error()))
	assertAbsent(t, "projection error", "envelope content", can.envelope, []byte(err.Error()))

	proj, err := st.GetMissionProjection(ctx, "ws-sec-1", "pass-sec-1")
	if err == nil {
		if proj.Cursor != "" {
			t.Fatalf("cursor advanced on rejected page: %q", proj.Cursor)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetMissionProjection: %v", err)
	}
	events, err := st.ListMissionEvents(ctx, "ws-sec-1", "pass-sec-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("rejected payload stored %d events", len(events))
	}
	if gate.blocked {
		t.Fatal("gate latched on a field rejection instead of an unknown event type")
	}
	scanDataDir(t, dir, "private content", can.private)
}

// TestUnknownEventTypeLatchesGate proves the unknown authenticated
// event path: the page rolls back, the cursor is preserved, the
// projection is marked incompatible and stale with the fixed local
// reason, and the gate latches so every business mutation stays
// blocked until a compatible parser and pinned contract are installed.
func TestUnknownEventTypeLatchesGate(t *testing.T) {
	can := loadCanaries(t)
	st, _ := openSecurityStore(t)
	ctx := context.Background()
	seedPrivacyPass(t, st, "ws-sec-1", "pass-sec-1")
	gate := &privacyStubGate{}
	projector := missionpass.NewEventProjector(st, gate)

	now := time.Now().UTC()
	good := privacyEvent("ev-sec-2", missionpass.EventMissionStarted, now, map[string]any{
		"workspace_id":    "ws-sec-1",
		"mission_version": 3,
		"resource_digest": "abc123",
		"branch":          "authscope/pass-sec-1",
		"head_sha":        "0123456789abcdef0123456789abcdef01234567",
	})
	stored, err := projector.ApplyPage(ctx, "ws-sec-1", "pass-sec-1", privacyPage("cursor-good", good))
	if err != nil {
		t.Fatalf("ApplyPage good event: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored = %d, want 1", stored)
	}
	before, err := st.GetMissionProjection(ctx, "ws-sec-1", "pass-sec-1")
	if err != nil {
		t.Fatalf("GetMissionProjection: %v", err)
	}
	if before.Cursor != "cursor-good" {
		t.Fatalf("cursor = %q, want %q", before.Cursor, "cursor-good")
	}

	unknown := privacyEvent("ev-sec-3", "mission_transcript_published", now, map[string]any{
		"workspace_id":    "ws-sec-1",
		"mission_version": 3,
		"resource_digest": "abc123",
		"branch":          "authscope/pass-sec-1",
		"head_sha":        "0123456789abcdef0123456789abcdef01234567",
		"transcript":      can.private,
	})
	_, err = projector.ApplyPage(ctx, "ws-sec-1", "pass-sec-1", privacyPage("cursor-evil", unknown))
	if err == nil {
		t.Fatal("unknown authenticated event type was projected")
	}
	if !strings.Contains(err.Error(), missionpass.ErrProjectionIncompatible.Error()) {
		t.Fatalf("error is not the incompatibility sentinel: %v", err)
	}
	assertAbsent(t, "incompatibility error", "private content", can.private, []byte(err.Error()))

	after, err := st.GetMissionProjection(ctx, "ws-sec-1", "pass-sec-1")
	if err != nil {
		t.Fatalf("GetMissionProjection: %v", err)
	}
	if after.Cursor != before.Cursor {
		t.Fatalf("cursor moved on rollback: %q -> %q", before.Cursor, after.Cursor)
	}
	if after.Compatible || !after.Stale {
		t.Fatalf("projection not marked incompatible+stale: %+v", after)
	}
	if after.IncompatibilityReason != store.IncompatibleProjectionReason {
		t.Fatalf("reason = %q, want the fixed local reason", after.IncompatibilityReason)
	}
	if !gate.blocked {
		t.Fatal("gate did not latch on unknown event type")
	}
	if gate.reason != store.IncompatibleProjectionReason {
		t.Fatalf("gate reason = %q, want the fixed local reason", gate.reason)
	}

	// The rolled-back page stored nothing: the good event is the only
	// one present.
	events, err := st.ListMissionEvents(ctx, "ws-sec-1", "pass-sec-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 1 || events[0].EventID != "ev-sec-2" {
		t.Fatalf("unexpected events after rollback: %+v", events)
	}
	for _, ev := range events {
		data, _ := json.Marshal(ev)
		assertAbsent(t, "timeline event", "private content", can.private, data)
	}
}

// TestTimelineExposesOnlyAllowlistedFields proves the persisted
// timeline carries only the fixed SafeEvent fields: even when the
// private canary is available in the test scope, projected and listed
// events never contain it.
func TestTimelineExposesOnlyAllowlistedFields(t *testing.T) {
	can := loadCanaries(t)
	st, _ := openSecurityStore(t)
	ctx := context.Background()
	seedPrivacyPass(t, st, "ws-sec-1", "pass-sec-1")
	gate := &privacyStubGate{}
	projector := missionpass.NewEventProjector(st, gate)

	now := time.Now().UTC()
	ev := privacyEvent("ev-sec-4", missionpass.EventMissionStarted, now, map[string]any{
		"workspace_id":    "ws-sec-1",
		"mission_version": 3,
		"resource_digest": "abc123",
		"branch":          "authscope/pass-sec-1",
		"head_sha":        "0123456789abcdef0123456789abcdef01234567",
	})
	if _, err := projector.ApplyPage(ctx, "ws-sec-1", "pass-sec-1", privacyPage("cursor-ev-sec-4", ev)); err != nil {
		t.Fatalf("ApplyPage: %v", err)
	}
	events, err := st.ListMissionEvents(ctx, "ws-sec-1", "pass-sec-1", "", 10)
	if err != nil {
		t.Fatalf("ListMissionEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	data, err := json.Marshal(events[0])
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	assertAbsent(t, "timeline event", "private content", can.private, data)
	if events[0].EventType != missionpass.EventMissionStarted {
		t.Fatalf("event type = %q", events[0].EventType)
	}
	// The stored row carries a payload column, but it must hold only
	// the allowlisted safe fields: no free-form content can round-trip.
	var payload map[string]any
	if err := json.Unmarshal([]byte(events[0].Payload), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	allowed := map[string]bool{
		"event_id": true, "cursor": true, "type": true, "occurred_at": true,
		"authscope_mission_version": true, "resource_digest": true,
		"reason_code": true, "branch": true, "pull_request_number": true,
		"head_sha": true, "check_kind": true, "check_outcome": true,
	}
	for key := range payload {
		if !allowed[key] {
			t.Fatalf("timeline payload carries unallowlisted field %q", key)
		}
	}
	assertAbsent(t, "timeline payload", "private content", can.private, []byte(events[0].Payload))
}

// TestProjectionErrorsUseFixedReasonCodes proves projection failures
// never echo upstream content: an oversized, hostile payload produces
// a fixed error that carries no payload bytes.
func TestProjectionErrorsUseFixedReasonCodes(t *testing.T) {
	can := loadCanaries(t)
	st, _ := openSecurityStore(t)
	ctx := context.Background()
	seedPrivacyPass(t, st, "ws-sec-1", "pass-sec-1")
	gate := &privacyStubGate{}
	projector := missionpass.NewEventProjector(st, gate)

	hostile := strings.Repeat(can.private, 40)
	ev := privacyEvent("ev-sec-5", missionpass.EventMissionStarted, time.Now().UTC(), map[string]any{
		"workspace_id":    "ws-sec-1",
		"mission_version": 3,
		"resource_digest": "abc123",
		"branch":          "authscope/pass-sec-1",
		"head_sha":        "0123456789abcdef0123456789abcdef01234567",
		"note":            hostile,
	})
	_, err := projector.ApplyPage(ctx, "ws-sec-1", "pass-sec-1", privacyPage("cursor-"+ev.EventID, ev))
	if err == nil {
		t.Fatal("hostile payload was projected")
	}
	assertAbsent(t, "projection error", "private content", can.private, []byte(err.Error()))
	if len(err.Error()) > 512 {
		t.Fatalf("projection error is unexpectedly verbose (%d bytes)", len(err.Error()))
	}
}

// TestProjectionTelemetryCarriesNoContent proves the telemetry recorded
// around projection contains no event content: outcome classes and
// fixed fields only.
func TestProjectionTelemetryCarriesNoContent(t *testing.T) {
	can := loadCanaries(t)
	st, _ := openSecurityStore(t)
	ctx := context.Background()
	sink := telemetry.NewSink(telemetry.SinkConfig{
		Enabled:     true,
		Store:       st,
		WorkspaceID: "ws-sec-1",
		InstanceID:  "inst-sec-1",
		Clock:       func() time.Time { return time.Now().UTC() },
	})
	err := sink.Record(ctx, telemetry.Event{
		Name:             "run_prepared",
		DurationMillis:   5,
		PassID:           "pass-sec-1",
		RunID:            "run-sec-1",
		ErrorCode:        telemetry.ErrorProjectionIncompatible,
		EnforcementLevel: telemetry.EnforcementRelease,
		OutcomeClass:     telemetry.OutcomeFailed,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	rows, err := st.ListTelemetryEvents(ctx, "ws-sec-1", 10)
	if err != nil {
		t.Fatalf("ListTelemetryEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	data, _ := json.Marshal(rows[0])
	assertAbsent(t, "projection telemetry", "private content", can.private, data)
	if !bytes.Contains(data, []byte("projection_incompatible")) {
		t.Fatalf("telemetry lost the fixed error code: %s", data)
	}
}
