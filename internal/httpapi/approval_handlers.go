package httpapi

// approve/begin and approve/finish: the passkey approval flow. The
// browser supplies no binding or authority fields; the server binds the
// challenge to the exact proposal revision and the workspace session.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/github"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

// approvalBeginResponse returns the one-use challenge for the passkey
// ceremony. The client passes the challenge ID back at finish; the
// challenge bytes never leave the WebAuthn flow.
type approvalBeginResponse struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

// approvalFinishRequest carries the challenge ID and the credential's
// assertion. All binding and authority fields come from the server-side
// challenge record, never from the browser.
type approvalFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"`
}

// newApprovalService builds the approval service when the workload
// attestor is configured. It returns nil without an attestor; there is
// no approval flow to serve then.
func newApprovalService(deps Dependencies, source *github.Source) *missionpass.ApprovalService {
	if deps.Attestor == nil {
		return nil
	}
	approval, err := missionpass.NewApprovalService(missionpass.ApprovalConfig{
		Store:     deps.Store,
		Authority: deps.Authority,
		Source:    source,
		Authn:     deps.Authn,
		Attestor:  deps.Attestor,
	})
	if err != nil {
		return nil
	}
	return approval
}

// approvalRoutes registers the approval endpoints. It is a no-op when
// the approval service is nil; without a workload signing key there is
// no approval flow to serve.
func approvalRoutes(mux *http.ServeMux, svc *missionpass.Service, approval *missionpass.ApprovalService, authedStateChange func(func(http.ResponseWriter, *http.Request, authn.Principal)) http.HandlerFunc) {
	if approval == nil {
		return
	}
	mux.HandleFunc("POST /api/v1/mission-passes/{id}/approve/begin", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		passID := r.PathValue("id")
		if passID == "" {
			writeProblem(w, http.StatusBadRequest, "invalid request", "The pass ID is required.")
			return
		}
		begun, err := approval.Begin(r.Context(), p, passID)
		if err != nil {
			approvalProblem(w, err)
			return
		}
		writeJSON(w, http.StatusOK, approvalBeginResponse{
			ChallengeID: begun.ChallengeID,
			Options:     begun.OptionsJSON,
		})
	}))
	mux.HandleFunc("POST /api/v1/mission-passes/{id}/approve/finish", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		var req approvalFinishRequest
		if !decodeJSONBody(w, r, &req) {
			return
		}
		passID := r.PathValue("id")
		if passID == "" {
			writeProblem(w, http.StatusBadRequest, "invalid request", "The pass ID is required.")
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
		res, err := approval.Finish(r.Context(), p, passID, req.ChallengeID, assertion)
		if err != nil {
			if errors.Is(err, missionpass.ErrPendingReconciliation) {
				// The upstream outcome is uncertain: persist intent and
				// report 202 so the UI can reconcile through GET.
				if review, lerr := svc.LoadReview(r.Context(), p.WorkspaceID, passID); lerr == nil {
					writeJSON(w, http.StatusAccepted, review)
					return
				}
				writeProblem(w, http.StatusAccepted, "reconciliation pending", "The approval reached the upstream but the outcome is uncertain. Reopen the pass to reconcile.")
				return
			}
			approvalProblem(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}))
}

// approvalProblem maps approval failures to responses.
func approvalProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authn.ErrCeremonyNotFound):
		writeProblem(w, http.StatusNotFound, "approval challenge not found", "The approval challenge is unknown or expired. Begin a new approval.")
	case errors.Is(err, store.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "pass not found", "The mission pass does not exist.")
	case errors.Is(err, missionpass.ErrApprovalBindingChanged):
		writeProblem(w, http.StatusConflict, "proposal changed", "The proposal changed since the approval began. Review the new revision and approve it.")
	case errors.Is(err, missionpass.ErrNotDraft):
		writeProblem(w, http.StatusConflict, "pass not a draft", "The pass already left draft; it cannot be approved again.")
	case errors.Is(err, missionpass.ErrApprovalReconcilePending):
		writeProblem(w, http.StatusConflict, "reconciliation pending", "An earlier approval is still reconciling. Reopen the pass to check it.")
	default:
		passProblem(w, err)
	}
}
