package httpapi

// Timeline: the safe event projection for one mission pass.
//
// GET /api/v1/mission-passes/{id}/events returns the allowlisted safe
// events plus the projection health. Reading reconciles an ambiguous
// revocation through the recorded intent; it never starts a new
// revocation. Only projected safe fields leave the server, so the
// browser timeline never renders raw authority payloads.

import (
	"net/http"
	"strconv"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/missionpass"
)

// timelinePageSize caps the events returned per timeline read.
const timelinePageSize = 100

// eventRoutes registers the timeline endpoint. It is a no-op when the
// event projector is not wired; without a projector there is no safe
// timeline to serve.
func eventRoutes(mux *http.ServeMux, deps Dependencies, projector *missionpass.EventProjector, revocation *missionpass.RevocationService) {
	if projector == nil {
		return
	}
	mux.HandleFunc("GET /api/v1/mission-passes/{id}/events",
		requireExactHost(deps.Config, func(w http.ResponseWriter, r *http.Request) {
			principal, _, err := authenticateRequest(deps, r)
			if err != nil {
				authnProblem(w, err)
				return
			}
			handleTimelineGet(projector, revocation, w, r, principal)
		}))
}

// timelineResponse is the wire shape of the safe timeline. Events are
// the projected safe events; cursor walks the projection forward.
type timelineResponse struct {
	PassID                string                  `json:"pass_id"`
	State                 string                  `json:"state"`
	Reconciliation        string                  `json:"reconciliation"`
	RepositoryName        string                  `json:"repository_name,omitempty"`
	Events                []missionpass.SafeEvent `json:"events"`
	Cursor                string                  `json:"cursor"`
	Compatible            bool                    `json:"compatible"`
	Stale                 bool                    `json:"stale"`
	IncompatibilityReason string                  `json:"incompatibility_reason,omitempty"`
	Containment           string                  `json:"containment"`
}

func handleTimelineGet(projector *missionpass.EventProjector, revocation *missionpass.RevocationService, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	passID := r.PathValue("id")
	if passID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid request", "The pass ID is required.")
		return
	}
	// Reading a pass reconciles an ambiguous revocation through the
	// recorded intent; it never repeats the upstream mutation.
	if revocation != nil {
		revocation.ReconcileRevocation(r.Context(), p.WorkspaceID, passID)
	}
	limit := timelinePageSize
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > timelinePageSize {
			writeProblem(w, http.StatusBadRequest, "invalid request", "The limit must be between 1 and 100.")
			return
		}
		limit = n
	}
	status, err := projector.LoadProjection(r.Context(), p.WorkspaceID, passID, r.URL.Query().Get("after"), limit)
	if err != nil {
		eventProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, timelineResponse{
		PassID:                passID,
		State:                 status.State,
		Reconciliation:        status.Reconciliation,
		RepositoryName:        status.RepositoryName,
		Events:                status.Events,
		Cursor:                status.Cursor,
		Compatible:            status.Compatible,
		Stale:                 status.Stale,
		IncompatibilityReason: status.Reason,
		Containment:           status.Containment,
	})
}

// eventProblem maps timeline failures to responses.
func eventProblem(w http.ResponseWriter, err error) {
	switch {
	case err == missionpass.ErrProjectionIncompatible:
		writeProblem(w, http.StatusConflict, "projection incompatible", "The event stream contains an event this release cannot project. The pass is suspended until a compatible release.")
	default:
		passProblem(w, err)
	}
}
