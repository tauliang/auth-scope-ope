// Package httpapi exposes the local OPE product API. It presents authority,
// verifies local founder authentication, and renders verified results; it
// never evaluates authority itself.
package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
)

// maxBodyBytes bounds every JSON request body the local API accepts.
const maxBodyBytes = 1 << 20

// Dependencies wires the HTTP server. Later tasks add the store, AuthScope
// client, and session manager here.
type Dependencies struct {
	Config   config.Config
	Contract coreapi.ContractReport
}

// WorkspaceBinding is the immutable binding of this instance, once Task 2
// establishes it. Until then the bootstrap response omits it.
type WorkspaceBinding struct {
	WorkspaceID string `json:"workspace_id"`
	Hostname    string `json:"hostname"`
}

// CompatibilityStatus summarizes the upstream contract gate for the UI.
type CompatibilityStatus struct {
	Status      string   `json:"status"`
	CoreVersion string   `json:"core_version"`
	Problems    []string `json:"problems,omitempty"`
}

// BootstrapResponse is the first paint of the product: enrollment state,
// immutable workspace binding, compatibility status, and the authority
// display labels the UI may render. Nothing else is exposed here.
type BootstrapResponse struct {
	Enrolled        bool                `json:"enrolled"`
	Workspace       *WorkspaceBinding   `json:"workspace,omitempty"`
	Compatibility   CompatibilityStatus `json:"compatibility"`
	AuthorityLabels []string            `json:"authority_labels"`
}

// New builds the HTTP handler for the local OPE API.
func New(deps Dependencies) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/readyz", handleReadyz(deps.Contract))
	mux.HandleFunc("/api/v1/bootstrap", handleBootstrap(deps))

	return withSecurityHeaders(http.MaxBytesHandler(mux, maxBodyBytes))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReadyz(report coreapi.ContractReport) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !report.Ready() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":       "not_ready",
				"core_version": report.CoreVersion,
				"problems":     report.Problems,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "ready",
			"core_version": report.CoreVersion,
		})
	}
}

func handleBootstrap(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		status := "not_ready"
		if deps.Contract.Ready() {
			status = "ready"
		}
		writeJSON(w, http.StatusOK, BootstrapResponse{
			Enrolled: false,
			Compatibility: CompatibilityStatus{
				Status:      status,
				CoreVersion: deps.Contract.CoreVersion,
				Problems:    deps.Contract.Problems,
			},
			AuthorityLabels: []string{"AuthScope mission authority"},
		})
	}
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
