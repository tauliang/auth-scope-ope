// Package httpapi exposes the local OPE product API. It presents authority,
// verifies local founder authentication, and renders verified results; it
// never evaluates authority itself.
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/expansion"
	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/store"
)

// maxBodyBytes bounds every JSON request body the local API accepts.
const maxBodyBytes = 1 << 20

// Dependencies wires the HTTP server. Gate is the live upstream
// compatibility gate; Authority is the gated AuthScope client later
// services use. A nil Gate keeps the legacy contract-only readiness used
// by tests; production always wires one.
type Dependencies struct {
	Config   config.Config
	Contract coreapi.ContractReport
	Store    store.Store
	// Authn is the founder authentication service. It may be nil in tests
	// that only exercise the pre-authentication surface.
	Authn *authn.Service
	// Gate is the live compatibility gate. Nil in tests that only
	// exercise the contract surface.
	Gate *coreapi.Gate
	// Authority is the gated AuthScope client for later services.
	Authority coreapi.Authority
	// Attestor signs approval decision attestations with the workload
	// key. Nil in tests that do not exercise the approval routes; the
	// approval routes are registered only when it is present.
	Attestor *identity.DecisionAttestor
	// CLIAuth runs the one-use browser PKCE handoff for CLI launch
	// authorization. Nil in tests that do not exercise the CLI routes; the
	// CLI routes are registered only when it is present.
	CLIAuth *authn.CLIAuthorizationService
	// Launch exchanges one authorization code plus verifier for the
	// prepared governed run. Nil in tests that do not exercise the token
	// route; the token route is registered only when it is present.
	Launch launchExchanger
	// Revocation runs the founder's passkey revocation ceremony. Nil in
	// tests that do not exercise the revocation routes; the revocation
	// routes are registered only when it is present.
	Revocation *missionpass.RevocationService
	// Expansion runs the founder's passkey expansion decision ceremony.
	// Nil in tests that do not exercise the expansion routes; the
	// expansion routes are registered only when it is present.
	Expansion *expansion.Service
	// CLIRevocation runs the result-only loopback PKCE handoff for CLI
	// revocation. Nil in tests that do not exercise the CLI revocation
	// routes; they are registered only when it is present.
	CLIRevocation *missionpass.CLIRevocationService
	// Projector serves the safe event timeline. Nil in tests that do
	// not exercise the timeline route; it is registered only when it is
	// present.
	Projector *missionpass.EventProjector
	// Receipt serves the authenticated private receipt view. Nil in
	// tests that do not exercise the receipt route; the route is
	// registered only when it is present. There is no manual check
	// publication endpoint: publication is owned by the worker.
	Receipt *receipt.Service
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
	EnrollmentState string              `json:"enrollment_state"`
	Workspace       *WorkspaceBinding   `json:"workspace,omitempty"`
	Compatibility   CompatibilityStatus `json:"compatibility"`
	AuthorityLabels []string            `json:"authority_labels"`
}

// New builds the HTTP handler for the local OPE API.
func New(deps Dependencies) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", handleReadyz(deps.Contract, deps.Gate))
	mux.HandleFunc("GET /api/v1/bootstrap", handleBootstrap(deps))
	authRoutes(mux, deps)
	gh := newGitHubServices(deps)
	githubRoutes(mux, deps, gh)
	passRoutes(mux, deps, gh)
	receiptRoutes(mux, deps)
	cliRoutes(mux, deps)

	api := http.MaxBytesHandler(mux, maxBodyBytes)
	ui := spaHandler()
	// The embedded web UI serves GET requests for non-API paths, with
	// an index.html fallback for client-side routing. API paths keep
	// their exact 404/405 semantics: the UI never shadows them.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && isUIPath(r.URL.Path) {
			ui.ServeHTTP(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
	return withSecurityHeaders(h)
}

// isUIPath reports whether p is served by the web UI rather than the
// API: anything that is not an API, liveness, or readiness path.
func isUIPath(p string) bool {
	if p == "/healthz" || p == "/readyz" {
		return false
	}
	return !strings.HasPrefix(p, "/api/")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReadyz(report coreapi.ContractReport, gate *coreapi.Gate) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if !report.Ready() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":       "not_ready",
				"core_version": report.CoreVersion,
				"problems":     report.Problems,
			})
			return
		}
		// The live gate fails closed: readiness requires a successful
		// verification no older than thirty seconds. A nil gate keeps
		// the contract-only behavior used by tests; production always
		// wires one.
		if gate != nil && !gate.Healthy() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status":       "not_ready",
				"core_version": report.CoreVersion,
				"problems":     []string{"upstream compatibility not verified"},
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
		resp := BootstrapResponse{
			Enrolled:        false,
			EnrollmentState: string(authn.EnrollmentNeedsBootstrap),
			Compatibility: CompatibilityStatus{
				Status:      status,
				CoreVersion: deps.Contract.CoreVersion,
				Problems:    deps.Contract.Problems,
			},
			AuthorityLabels: []string{"AuthScope mission authority"},
		}
		if deps.Authn != nil {
			var bootstrapToken, sessionToken string
			if c, err := r.Cookie(deps.Authn.BootstrapCookieName()); err == nil {
				bootstrapToken = c.Value
			}
			if c, err := r.Cookie(deps.Authn.SessionCookieName()); err == nil {
				sessionToken = c.Value
			}
			if st, err := deps.Authn.EnrollmentStatus(r.Context(), bootstrapToken, sessionToken); err == nil {
				resp.Enrolled = st.Enrolled
				resp.EnrollmentState = string(st.State)
				resp.Workspace = &WorkspaceBinding{
					WorkspaceID: st.WorkspaceID,
					Hostname:    st.Hostname,
				}
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		// The API serves JSON only: deny every content source and
		// framing, and disable powerful browser features.
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), hid=(), serial=(), bluetooth=(), publickey-credentials-get=(), publickey-credentials-create=()")
		next.ServeHTTP(w, r)
	})
}
