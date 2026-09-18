package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/expansion"
	"github.com/tauliang/authscope-ope/internal/telemetry"
)

// expansionRoutes registers the exact one-use expansion decision
// endpoints. The browser never submits or widens the authority delta:
// begin binds the canonical delta into a passkey challenge, and finish
// consumes the challenge and attests the exact binding.
func expansionRoutes(mux *http.ServeMux, deps Dependencies, authedStateChange func(func(http.ResponseWriter, *http.Request, authn.Principal)) http.HandlerFunc) {
	svc := deps.Expansion
	if svc == nil {
		return
	}
	mux.HandleFunc("GET /api/v1/mission-passes/{id}/expansions",
		requireExactHost(deps.Config, func(w http.ResponseWriter, r *http.Request) {
			principal, _, err := authenticateRequest(deps, r)
			if err != nil {
				authnProblem(w, err)
				return
			}
			passID := r.PathValue("id")
			if passID == "" {
				writeProblem(w, http.StatusBadRequest, "invalid request", "The pass ID is required.")
				return
			}
			pending, err := svc.ListPending(r.Context(), principal.WorkspaceID, passID)
			if err != nil {
				expansionProblem(w, err)
				return
			}
			writeJSON(w, http.StatusOK, expansionListResponse{
				PassID:     passID,
				Expansions: pending,
			})
		}))
	mux.HandleFunc("POST /api/v1/expansions/{id}/decide/begin", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		var req expansionBeginRequest
		if !decodeJSONBody(w, r, &req) {
			return
		}
		expansionID := r.PathValue("id")
		if expansionID == "" {
			writeProblem(w, http.StatusBadRequest, "invalid request", "The expansion ID is required.")
			return
		}
		var decision expansion.Decision
		if err := json.Unmarshal([]byte(`"`+req.Decision+`"`), &decision); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid decision", "The decision must be approve_once or deny.")
			return
		}
		begun, err := svc.BeginDecision(r.Context(), p, expansionID, decision)
		if err != nil {
			expansionProblem(w, err)
			return
		}
		writeJSON(w, http.StatusOK, expansionBeginResponse{
			ChallengeID:     begun.ChallengeID,
			Options:         begun.OptionsJSON,
			ExpansionID:     begun.ExpansionID,
			Decision:        string(begun.Decision),
			EffectiveExpiry: begun.EffectiveExpiry.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}))
	mux.HandleFunc("POST /api/v1/expansions/{id}/decide/finish", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		start := time.Now()
		var req expansionFinishRequest
		if !decodeJSONBody(w, r, &req) {
			return
		}
		expansionID := r.PathValue("id")
		if expansionID == "" {
			writeProblem(w, http.StatusBadRequest, "invalid request", "The expansion ID is required.")
			return
		}
		if req.ChallengeID == "" {
			writeProblem(w, http.StatusBadRequest, "invalid request", "The challenge ID is required.")
			return
		}
		assertion, err := json.Marshal(req.Assertion)
		if err != nil || len(req.Assertion) == 0 {
			writeProblem(w, http.StatusBadRequest, "invalid request", "The passkey assertion is required.")
			return
		}
		res, err := svc.FinishDecision(r.Context(), p, expansionID, req.ChallengeID, assertion)
		if err != nil {
			if errors.Is(err, expansion.ErrExpansionPending) {
				recordFunnel(deps.Telemetry, deps.Config.Mode, r.Context(), telemetry.EventExpansionDecided, start,
					"", "", telemetry.ErrorNone, telemetry.OutcomePending, 0)
				writeJSON(w, http.StatusAccepted, expansionPendingResponse{
					ExpansionID:    expansionID,
					Reconciliation: "pending",
				})
				return
			}
			recordFunnel(deps.Telemetry, deps.Config.Mode, r.Context(), telemetry.EventExpansionDecided, start,
				"", "", funnelErrorCode(err), telemetry.OutcomeFailed, 0)
			expansionProblem(w, err)
			return
		}
		recordFunnel(deps.Telemetry, deps.Config.Mode, r.Context(), telemetry.EventExpansionDecided, start,
			res.PassID, "", telemetry.ErrorNone, telemetry.OutcomeSuccess, 0)
		writeJSON(w, http.StatusOK, expansionFinishResponse{
			ExpansionID:             res.ExpansionID,
			PassID:                  res.PassID,
			Decision:                string(res.Decision),
			DecisionRef:             res.DecisionRef,
			AuthScopeMissionVersion: res.AuthScopeMissionVersion,
			State:                   res.State,
		})
	}))
}

type expansionBeginRequest struct {
	Decision string `json:"decision"`
}

type expansionFinishRequest struct {
	ChallengeID string         `json:"challenge_id"`
	Assertion   map[string]any `json:"assertion"`
}

type expansionListResponse struct {
	PassID     string                       `json:"pass_id"`
	Expansions []expansion.PendingExpansion `json:"expansions"`
}

type expansionBeginResponse struct {
	ChallengeID     string          `json:"challenge_id"`
	Options         json.RawMessage `json:"options"`
	ExpansionID     string          `json:"expansion_id"`
	Decision        string          `json:"decision"`
	EffectiveExpiry string          `json:"effective_expiry"`
}

type expansionFinishResponse struct {
	ExpansionID             string `json:"expansion_id"`
	PassID                  string `json:"pass_id"`
	Decision                string `json:"decision"`
	DecisionRef             string `json:"decision_ref"`
	AuthScopeMissionVersion int64  `json:"authscope_mission_version"`
	State                   string `json:"state"`
}

type expansionPendingResponse struct {
	ExpansionID    string `json:"expansion_id"`
	Reconciliation string `json:"reconciliation"`
}

// expansionProblem maps expansion service errors to HTTP problems.
func expansionProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, expansion.ErrInvalidDecision):
		writeProblem(w, http.StatusBadRequest, "invalid decision", "The decision must be approve_once or deny.")
	case errors.Is(err, expansion.ErrExpansionNotPending):
		writeProblem(w, http.StatusNotFound, "expansion not pending", "The expansion is not pending a decision.")
	case errors.Is(err, expansion.ErrExpansionStale):
		writeProblem(w, http.StatusConflict, "expansion stale", "The expansion delta is stale; reload the pending expansions.")
	case errors.Is(err, expansion.ErrExpansionConflict):
		writeProblem(w, http.StatusConflict, "expansion conflict", "A conflicting expansion decision is in progress.")
	case errors.Is(err, expansion.ErrExpansionBindingChanged):
		writeProblem(w, http.StatusConflict, "binding changed", "The expansion binding changed after the challenge was issued.")
	case errors.Is(err, expansion.ErrPassNotDecidable):
		writeProblem(w, http.StatusConflict, "pass not decidable", "The pass cannot decide expansions in its current state.")
	case errors.Is(err, authn.ErrCeremonyNotFound):
		writeProblem(w, http.StatusNotFound, "challenge not found", "The decision challenge is unknown or already consumed.")
	default:
		writeProblem(w, http.StatusInternalServerError, "expansion decision failed", "The expansion decision could not be completed.")
	}
}
