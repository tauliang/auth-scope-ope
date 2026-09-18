package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

// passRoutes registers the mission-pass proposal routes. The draft open
// and draft revise endpoints require the exact bound Host and Origin,
// exact JSON, a founder session, the session-bound CSRF token, and a
// caller-supplied Idempotency-Key. The read endpoint requires the exact
// Host and a founder session.
func passRoutes(mux *http.ServeMux, deps Dependencies, gh *githubServices) {
	if gh == nil || gh.source == nil {
		return
	}
	svc, err := missionpass.NewService(missionpass.Config{
		Store:     deps.Store,
		Authority: deps.Authority,
		Source:    gh.source,
	})
	if err != nil {
		return
	}
	strict := func(next http.HandlerFunc) http.HandlerFunc {
		return requireExactHost(deps.Config,
			requireExactOrigin(deps.Config,
				requireJSON(next)))
	}
	// authedStateChange enforces the full founder-session guard chain
	// for state-changing routes.
	authedStateChange := func(h func(w http.ResponseWriter, r *http.Request, p authn.Principal)) http.HandlerFunc {
		return strict(func(w http.ResponseWriter, r *http.Request) {
			principal, session, err := authenticateRequest(deps, r)
			if err != nil {
				authnProblem(w, err)
				return
			}
			if err := verifyRequestCSRF(r, session); err != nil {
				authnProblem(w, err)
				return
			}
			h(w, r, principal)
		})
	}
	mux.HandleFunc("POST /api/v1/mission-passes/drafts", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		handlePassDraftCreate(svc, w, r, p)
	}))
	mux.HandleFunc("PUT /api/v1/mission-passes/{id}/draft", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		handlePassDraftRevise(svc, w, r, p)
	}))
	mux.HandleFunc("GET /api/v1/mission-passes/{id}",
		requireExactHost(deps.Config, func(w http.ResponseWriter, r *http.Request) {
			principal, _, err := authenticateRequest(deps, r)
			if err != nil {
				authnProblem(w, err)
				return
			}
			handlePassGet(svc, w, r, principal)
		}))
}

// PassDraftCreateRequest opens a mission-pass draft for one issue. Only
// the two editable limits are founder-supplied; everything else is
// derived from the trusted issue snapshot and the fixed template.
type PassDraftCreateRequest struct {
	ConnectionID           string `json:"connection_id"`
	IssueNumber            int64  `json:"issue_number"`
	ExpiresAt              string `json:"expires_at"`
	MaxAggregateCostMicros int64  `json:"max_aggregate_cost_micros"`
}

// PassDraftReviseRequest applies the only two founder edits. Any other
// field is protected and rejected with 422.
type PassDraftReviseRequest struct {
	ExpectedStoreRevision  int64  `json:"expected_store_revision"`
	ExpectedDraftVersion   int64  `json:"expected_draft_version"`
	ExpiresAt              string `json:"expires_at"`
	MaxAggregateCostMicros int64  `json:"max_aggregate_cost_micros"`
}

// passProtectedFields are the draft fields no founder request may edit.
// Their presence in a revise body fails with 422; anything else unknown
// fails with 400 through strict decoding.
var passProtectedFields = []string{
	"objective", "acceptance_criteria",
	"repository", "repository_name", "issue", "issue_number",
	"branch", "mission_branch", "base_sha",
	"paths", "protected_paths", "actions", "allowed_actions",
	"ceilings", "fixed_ceilings",
	"agent_kit_id", "agent_kit_version",
	"runner_args", "runner_arguments",
	"invocation_digest", "proposal_digest",
	"enforcement",
}

func handlePassDraftCreate(svc *missionpass.Service, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	var req PassDraftCreateRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	expires, ok := parseExpiry(w, req.ExpiresAt)
	if !ok {
		return
	}
	rec, replayed, err := svc.CreateProposal(r.Context(), p.WorkspaceID, p.FounderID, missionpass.CreateProposalInput{
		ConnectionID:           req.ConnectionID,
		IssueNumber:            req.IssueNumber,
		ExpiresAt:              expires,
		MaxAggregateCostMicros: req.MaxAggregateCostMicros,
		IdempotencyKey:         key,
	})
	if err != nil {
		writePassResult(svc, w, r, p, rec.PassID, err)
		return
	}
	review, err := svc.LoadReview(r.Context(), p.WorkspaceID, rec.PassID)
	if err != nil {
		passProblem(w, err)
		return
	}
	// A fresh draft is 201; a replayed idempotent retry of a settled
	// draft is 200; a pending reconciliation is 202 either way.
	status := http.StatusCreated
	switch {
	case rec.Reconciliation == missionpass.ReconciliationPending:
		status = http.StatusAccepted
	case replayed:
		status = http.StatusOK
	}
	writeJSON(w, status, review)
}

func handlePassDraftRevise(svc *missionpass.Service, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	passID := r.PathValue("id")
	if passID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid request", "The pass ID is required.")
		return
	}
	req, ok := decodeReviseBody(w, r)
	if !ok {
		return
	}
	if _, ok := requireIdempotencyKey(w, r); !ok {
		return
	}
	expires, ok := parseExpiry(w, req.ExpiresAt)
	if !ok {
		return
	}
	rec, err := svc.ReviseProposal(r.Context(), p.WorkspaceID, p.FounderID, missionpass.ReviseProposalInput{
		PassID:                 passID,
		ExpectedStoreRevision:  req.ExpectedStoreRevision,
		ExpectedDraftVersion:   req.ExpectedDraftVersion,
		ExpiresAt:              expires,
		MaxAggregateCostMicros: req.MaxAggregateCostMicros,
	})
	if err != nil {
		writePassResult(svc, w, r, p, passID, err)
		return
	}
	review, err := svc.LoadReview(r.Context(), p.WorkspaceID, rec.PassID)
	if err != nil {
		passProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, review)
}

func handlePassGet(svc *missionpass.Service, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	passID := r.PathValue("id")
	if passID == "" {
		writeProblem(w, http.StatusBadRequest, "invalid request", "The pass ID is required.")
		return
	}
	review, err := svc.LoadReview(r.Context(), p.WorkspaceID, passID)
	if err != nil {
		passProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, review)
}

// writePassResult maps service outcomes to responses. An ambiguous
// upstream outcome returns 202 with the current review payload for the
// pending pass, so the founder sees the reconciliation state and can
// safely retry the same request: the draft-open idempotency key resolves
// to the same pass instead of duplicating it.
func writePassResult(svc *missionpass.Service, w http.ResponseWriter, r *http.Request, p authn.Principal, passID string, err error) {
	if errors.Is(err, missionpass.ErrPendingReconciliation) || errors.Is(err, missionpass.ErrOperationInFlight) {
		if passID != "" {
			if review, lerr := svc.LoadReview(r.Context(), p.WorkspaceID, passID); lerr == nil {
				writeJSON(w, http.StatusAccepted, review)
				return
			}
		}
		writeProblem(w, http.StatusAccepted, "reconciliation pending", "The upstream outcome is uncertain. Retry the same request.")
		return
	}
	passProblem(w, err)
}

// decodeReviseBody rejects protected fields with 422 before strict
// decoding rejects anything else unknown with 400.
func decodeReviseBody(w http.ResponseWriter, r *http.Request) (PassDraftReviseRequest, bool) {
	var req PassDraftReviseRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", "The request body could not be read.")
		return req, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", "The request body is not valid JSON.")
		return req, false
	}
	for _, f := range passProtectedFields {
		if _, ok := fields[f]; ok {
			writeProblem(w, http.StatusUnprocessableEntity, "protected field",
				"The field "+f+" is not editable. Only expiry and the aggregate cost ceiling can be narrowed.")
			return req, false
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", "The request body is not valid JSON.")
		return req, false
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeProblem(w, http.StatusBadRequest, "invalid request body", "The request body must contain a single JSON value.")
		return req, false
	}
	return req, true
}

func parseExpiry(w http.ResponseWriter, raw string) (time.Time, bool) {
	expires, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid expiry", "The expiry must be an RFC 3339 timestamp.")
		return time.Time{}, false
	}
	return expires, true
}

// passProblem maps mission-pass service errors to problem responses. The
// mapping is exhaustive over the service error set so no internal detail
// leaks.
func passProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, missionpass.ErrInvalidInput):
		writeProblem(w, http.StatusBadRequest, "invalid input", "The request was outside the fixed template or had missing fields.")
	case errors.Is(err, store.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "not found", "No such mission pass or connection.")
	case errors.Is(err, store.ErrConflict):
		writeProblem(w, http.StatusConflict, "revision conflict", "The pass changed under the expected revision. Reload and try again.")
	case errors.Is(err, missionpass.ErrStaleSource):
		writeProblem(w, http.StatusConflict, "stale source", "The issue or base moved under the pinned revision. Reload and try again.")
	case errors.Is(err, missionpass.ErrNotDraft):
		writeProblem(w, http.StatusConflict, "not a draft", "Only drafts can be revised.")
	case errors.Is(err, missionpass.ErrDuplicateRequestInFlight):
		writeProblem(w, http.StatusConflict, "request in flight", "A request with this idempotency key is already being processed. Retry the same request.")
	case errors.Is(err, missionpass.ErrTemplateViolation), errors.Is(err, missionpass.ErrProposalMismatch):
		writeProblem(w, http.StatusUnprocessableEntity, "upstream violation", "AuthScope returned a draft outside the fixed template.")
	case errors.Is(err, missionpass.ErrUnsafePosture):
		writeProblem(w, http.StatusUnprocessableEntity, "unsafe posture", "The workflow posture is not clean.")
	default:
		writeProblem(w, http.StatusInternalServerError, "internal error", "The request could not be completed.")
	}
}
