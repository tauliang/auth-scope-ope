package httpapi

// Tests for GET /api/v1/mission-passes/{id}/events: the safe projected
// event timeline. Only allowlisted safe fields leave the server.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/store"
)

func TestEventsRendersProjectedEvents(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	// Seed one safe event through the store; the projector's
	// ListMissionEvents reads exactly this shape.
	payload, err := json.Marshal(map[string]any{
		"event_id": "evt-1", "cursor": "c1", "type": "run_started",
		"occurred_at":               time.Now().UTC().Format(time.RFC3339),
		"authscope_mission_version": 3,
		"resource_digest":           "sha256:" + strings.Repeat("d", 64),
	})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	ctx := context.Background()
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		_, err := tx.PutEventIfAbsent(ctx, store.MissionEventRecord{
			WorkspaceID: "ws-test", PassID: passID, EventID: "evt-1",
			EventType: "run_started", Cursor: "c1", Payload: string(payload),
			OccurredAt: time.Now().UTC(),
		})
		return err
	}); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	rec := f.getPass(t, "/api/v1/mission-passes/"+passID+"/events")
	if rec.Code != http.StatusOK {
		t.Fatalf("events: status %d body %s", rec.Code, rec.Body.String())
	}
	var timeline struct {
		PassID         string `json:"pass_id"`
		State          string `json:"state"`
		Compatible     bool   `json:"compatible"`
		Containment    string `json:"containment"`
		RepositoryName string `json:"repository_name"`
		Events         []struct {
			EventID string `json:"event_id"`
			Type    string `json:"type"`
		} `json:"events"`
	}
	decodeBody(t, rec, &timeline)
	if timeline.PassID != passID {
		t.Errorf("pass_id = %q, want %q", timeline.PassID, passID)
	}
	if !timeline.Compatible {
		t.Errorf("compatible = false, want true")
	}
	if len(timeline.Events) != 1 || timeline.Events[0].EventID != "evt-1" || timeline.Events[0].Type != "run_started" {
		t.Errorf("events = %+v, want the seeded run_started event", timeline.Events)
	}
}

func TestEventsUnknownPass(t *testing.T) {
	f := newRevokeTestFixture(t)
	rec := f.getPass(t, "/api/v1/mission-passes/nope/events")
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestEventsCarriesRepositoryName(t *testing.T) {
	f := newRevokeTestFixture(t)
	passID := f.approvedPass(t)
	ctx := context.Background()
	if err := f.store.WithTx(ctx, func(tx store.Tx) error {
		rec, err := tx.GetMissionPass(ctx, "ws-test", passID)
		if err != nil {
			return err
		}
		rec.RepositoryName = "octo/mission-repo"
		return tx.PutMissionPass(ctx, rec, rec.StoreRevision)
	}); err != nil {
		t.Fatalf("set repository: %v", err)
	}
	rec := f.getPass(t, "/api/v1/mission-passes/"+passID+"/events")
	if rec.Code != http.StatusOK {
		t.Fatalf("events: status %d body %s", rec.Code, rec.Body.String())
	}
	var timeline struct {
		RepositoryName string `json:"repository_name"`
	}
	decodeBody(t, rec, &timeline)
	if timeline.RepositoryName != "octo/mission-repo" {
		t.Errorf("repository_name = %q, want octo/mission-repo", timeline.RepositoryName)
	}
}
