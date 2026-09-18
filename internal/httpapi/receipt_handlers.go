// The authenticated private receipt view. There is no unauthenticated
// route, no public receipt-sharing route, and no manual check
// publication endpoint: publication is owned by the worker. The
// handler renders only the fixed verified projection from the receipt
// service, never raw envelopes or private detail.
package httpapi

import (
	"errors"
	"net/http"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/store"
)

// receiptRoutes registers the private receipt view. The route exists
// only when the receipt service is wired; without it there is no
// receipt to serve.
func receiptRoutes(mux *http.ServeMux, deps Dependencies) {
	if deps.Receipt == nil {
		return
	}
	mux.HandleFunc("GET /api/v1/mission-passes/{id}/receipt",
		requireExactHost(deps.Config, func(w http.ResponseWriter, r *http.Request) {
			principal, _, err := authenticateRequest(deps, r)
			if err != nil {
				authnProblem(w, err)
				return
			}
			handleReceiptGet(deps.Receipt, w, r, principal)
		}))
}

// handleReceiptGet renders the privacy-filtered receipt status for one
// pass. Unknown passes and passes from another workspace both report
// 404 so workspace membership cannot be probed.
func handleReceiptGet(svc *receipt.Service, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	status, err := svc.Get(r.Context(), p.WorkspaceID, r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "not found", "No such mission pass.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "receipt unavailable", "The receipt view could not be loaded.")
		return
	}
	writeJSON(w, http.StatusOK, status)
}
