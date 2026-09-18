package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/github"
	"github.com/tauliang/authscope-ope/internal/store"
)

// githubCompletionPath is the fixed same-origin path the AuthScope
// callback redirects to. It never carries query parameters: the opaque
// callback values are consumed server-side and never reflected.
const githubCompletionPath = "/connect/github/done"

// idempotencyKeyHeader carries the caller-supplied idempotency key on the
// GitHub begin and finish POSTs, matching the header AuthScope itself
// uses upstream.
const idempotencyKeyHeader = "Idempotency-Key"

// githubServices bundles the one shared Handoff instance (its in-memory
// binding-code cache must survive between the callback and finish calls)
// with the trusted issue source.
type githubServices struct {
	handoff *github.Handoff
	source  *github.Source
}

// newGitHubServices builds the shared services from the server
// dependencies, or returns nil when the GitHub surface is not wired
// (tests that only exercise the pre-auth surface). The AuthScope origin
// is normalized by the github package and required exactly on every
// upstream installation URL.
func newGitHubServices(deps Dependencies) *githubServices {
	if deps.Store == nil || deps.Authority == nil {
		return nil
	}
	handoff, err := github.NewHandoff(github.HandoffConfig{
		Store:           deps.Store,
		Authority:       deps.Authority,
		AuthScopeOrigin: deps.Config.AuthScopeURL,
		CompletionPath:  githubCompletionPath,
	})
	if err != nil {
		return nil
	}
	source, err := github.NewSource(github.SourceConfig{
		Store:     deps.Store,
		Authority: deps.Authority,
	})
	if err != nil {
		return nil
	}
	return &githubServices{handoff: handoff, source: source}
}

// githubRoutes registers the four GitHub connection routes. Begin and
// finish require the exact bound Host and Origin, a founder session, the
// session-bound CSRF token, exact JSON, and an Idempotency-Key header. The
// callback is the AuthScope redirect: it requires the exact Host only
// (navigations carry no Origin), never creates a session, and never
// finishes the binding. The issue read requires the exact Host and a
// founder session.
func githubRoutes(mux *http.ServeMux, deps Dependencies, gh *githubServices) {
	if gh == nil {
		return
	}
	strict := func(next http.HandlerFunc) http.HandlerFunc {
		return requireExactHost(deps.Config,
			requireExactOrigin(deps.Config,
				requireJSON(next)))
	}
	// authedPOST enforces the full founder-session guard chain for
	// state-changing routes.
	authedPOST := func(h func(w http.ResponseWriter, r *http.Request, p authn.Principal)) http.HandlerFunc {
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
	mux.HandleFunc("POST /api/v1/connections/github/begin", authedPOST(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		handleGitHubBegin(gh, w, r, p)
	}))
	mux.HandleFunc("POST /api/v1/connections/github/{handoff_id}/finish", authedPOST(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		handleGitHubFinish(gh, w, r, p)
	}))
	mux.HandleFunc("GET /api/v1/connections/github/callback",
		requireExactHost(deps.Config, func(w http.ResponseWriter, r *http.Request) {
			handleGitHubCallback(gh, w, r)
		}))
	mux.HandleFunc("GET /api/v1/connections/github/{id}/issues/{number}",
		requireExactHost(deps.Config, func(w http.ResponseWriter, r *http.Request) {
			principal, _, err := authenticateRequest(deps, r)
			if err != nil {
				authnProblem(w, err)
				return
			}
			handleGitHubIssue(gh, deps.Store, w, r, principal)
		}))
}

// requireIdempotencyKey extracts the caller-supplied idempotency key.
func requireIdempotencyKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.Header.Get(idempotencyKeyHeader))
	if key == "" || len(key) > 128 {
		writeProblem(w, http.StatusBadRequest, "idempotency key required", "Send a unique Idempotency-Key header with this request.")
		return "", false
	}
	return key, true
}

// GitHubBeginRequest opens the AuthScope-hosted installation handoff for
// one owner/name repository.
type GitHubBeginRequest struct {
	Repository string `json:"repository"`
}

// GitHubBeginResponse carries the local handoff ID and the fixed-origin
// AuthScope installation URL. The upstream one-use binding code is never
// returned.
type GitHubBeginResponse struct {
	HandoffID       string `json:"handoff_id"`
	InstallationURL string `json:"installation_url"`
	ExpiresAt       string `json:"expires_at"`
}

func handleGitHubBegin(gh *githubServices, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var req GitHubBeginRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	res, err := gh.handoff.Begin(r.Context(), p.WorkspaceID, p.SessionID, req.Repository, key)
	if err != nil {
		githubProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, GitHubBeginResponse{
		HandoffID:       res.HandoffID,
		InstallationURL: res.InstallationURL,
		ExpiresAt:       res.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// GitHubFinishRequest is the empty JSON object the finish POST requires.
// The handoff ID travels in the path; the binding code was captured from
// the AuthScope redirect server-side.
type GitHubFinishRequest struct{}

// GitHubConnectionView renders a persisted GitHub connection: immutable
// workspace and repository identity, installation, permission status, and
// verification time. No credential material is ever rendered.
type GitHubConnectionView struct {
	ConnectionID        string `json:"connection_id"`
	WorkspaceID         string `json:"workspace_id"`
	RepositoryBindingID string `json:"repository_binding_id"`
	InstallationID      int64  `json:"installation_id"`
	RepositoryID        int64  `json:"repository_id"`
	RepositoryName      string `json:"repository_name"`
	PermissionStatus    string `json:"permission_status"`
	VerifiedAt          string `json:"verified_at"`
}

func connectionView(c store.ConnectionRecord) GitHubConnectionView {
	return GitHubConnectionView{
		ConnectionID:        c.ConnectionID,
		WorkspaceID:         c.WorkspaceID,
		RepositoryBindingID: c.RepositoryBindingRef,
		InstallationID:      c.InstallationID,
		RepositoryID:        c.RepositoryID,
		RepositoryName:      c.RepositoryName,
		PermissionStatus:    c.PermissionStatus,
		VerifiedAt:          c.VerifiedAt.UTC().Format(time.RFC3339),
	}
}

func handleGitHubFinish(gh *githubServices, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	key, ok := requireIdempotencyKey(w, r)
	if !ok {
		return
	}
	var req GitHubFinishRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	handoffID := r.PathValue("handoff_id")
	res, err := gh.handoff.Finish(r.Context(), p.WorkspaceID, p.SessionID, handoffID, key)
	if err != nil {
		githubProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, connectionView(res.Connection))
}

func handleGitHubCallback(gh *githubServices, w http.ResponseWriter, r *http.Request) {
	// The entire callback query is untrusted redirect input: it is passed
	// to RecordCallback by value, never logged, and never reflected in
	// any response. RecordCallback enforces exactly the three accepted
	// parameters.
	redirect, err := gh.handoff.RecordCallback(r.Context(), r.URL.Query())
	if err != nil {
		githubProblem(w, err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// GitHubIssueSnapshotView renders the trusted, pinned issue snapshot. The
// source digest is AuthScope's canonical digest, never derived locally.
type GitHubIssueSnapshotView struct {
	WorkspaceID        string   `json:"workspace_id"`
	RepositoryBinding  string   `json:"repository_binding_id"`
	InstallationID     int64    `json:"installation_id"`
	RepositoryID       int64    `json:"repository_id"`
	RepositoryFullName string   `json:"repository_full_name"`
	IssueNumber        int64    `json:"issue_number"`
	SourceRevision     string   `json:"source_revision"`
	SourceDigest       string   `json:"source_digest"`
	DefaultBranch      string   `json:"default_branch"`
	BaseSHA            string   `json:"base_sha"`
	Objective          string   `json:"objective"`
	AcceptanceCriteria []string `json:"acceptance_criteria"`
}

// GitHubPostureView renders the persisted workflow-posture metadata: the
// digest, inspected head SHA, outcome, reason codes, and validity window.
// Workflow contents are never persisted or rendered.
type GitHubPostureView struct {
	Outcome     string   `json:"outcome"`
	ReasonCodes []string `json:"reason_codes"`
	HeadSHA     string   `json:"head_sha"`
	CheckedAt   string   `json:"checked_at"`
	ExpiresAt   string   `json:"expires_at"`
}

// GitHubIssueResponse pairs the pinned snapshot with the posture check
// that gates launch. A risky posture disables Authorize in the UI.
type GitHubIssueResponse struct {
	Snapshot GitHubIssueSnapshotView `json:"snapshot"`
	Posture  GitHubPostureView       `json:"posture"`
}

func handleGitHubIssue(gh *githubServices, st store.Store, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	connID := r.PathValue("id")
	number, err := strconv.ParseInt(r.PathValue("number"), 10, 64)
	if err != nil || number <= 0 {
		writeProblem(w, http.StatusBadRequest, "invalid issue number", "The issue number must be a positive integer.")
		return
	}
	conn, err := st.GetConnection(r.Context(), p.WorkspaceID, connID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(w, http.StatusNotFound, "connection not found", "No such GitHub connection in this workspace.")
			return
		}
		writeProblem(w, http.StatusInternalServerError, "internal error", "internal error.")
		return
	}
	snap, err := gh.source.ReadIssue(r.Context(), p.WorkspaceID, conn, number, "", "")
	if err != nil {
		githubProblem(w, err)
		return
	}
	// The posture check runs against the snapshot's pinned base: a stale
	// or risky posture disables Authorize for this issue.
	posture, err := gh.source.CheckPosture(r.Context(), p.WorkspaceID, conn, snap.DefaultBranch, snap.BaseSHA)
	if err != nil {
		githubProblem(w, err)
		return
	}
	criteria := snap.AcceptanceCriteria
	if criteria == nil {
		criteria = []string{}
	}
	reasons := posture.ReasonCodes
	if reasons == nil {
		reasons = []string{}
	}
	writeJSON(w, http.StatusOK, GitHubIssueResponse{
		Snapshot: GitHubIssueSnapshotView{
			WorkspaceID:        snap.WorkspaceID,
			RepositoryBinding:  snap.RepositoryBinding,
			InstallationID:     snap.InstallationID,
			RepositoryID:       snap.RepositoryID,
			RepositoryFullName: snap.RepositoryFullName,
			IssueNumber:        snap.IssueNumber,
			SourceRevision:     snap.SourceRevision,
			SourceDigest:       snap.SourceDigest,
			DefaultBranch:      snap.DefaultBranch,
			BaseSHA:            snap.BaseSHA,
			Objective:          snap.Objective,
			AcceptanceCriteria: criteria,
		},
		Posture: GitHubPostureView{
			Outcome:     posture.Outcome,
			ReasonCodes: reasons,
			HeadSHA:     posture.HeadSHA,
			CheckedAt:   posture.CheckedAt.UTC().Format(time.RFC3339),
			ExpiresAt:   posture.ExpiresAt.UTC().Format(time.RFC3339),
		},
	})
}

// githubProblem maps GitHub service errors to problem responses. Titles
// and details stay generic: binding codes, states, digests, and upstream
// messages are never reflected.
func githubProblem(w http.ResponseWriter, err error) {
	status, title := githubProblemStatus(err)
	writeProblem(w, status, title, title+".")
}

func githubProblemStatus(err error) (int, string) {
	var up *coreapi.UpstreamError
	if errors.As(err, &up) {
		switch {
		case up.StatusCode == 429:
			return http.StatusServiceUnavailable, "upstream rate limited"
		case up.StatusCode >= 500:
			return http.StatusBadGateway, "upstream unavailable"
		case up.StatusCode == 404:
			return http.StatusNotFound, "upstream resource not found"
		default:
			return http.StatusBadGateway, "upstream denied the request"
		}
	}
	switch {
	case errors.Is(err, github.ErrInvalidInput):
		return http.StatusBadRequest, "invalid request"
	case errors.Is(err, github.ErrHandoffNotFound):
		return http.StatusNotFound, "handoff not found"
	case errors.Is(err, github.ErrHandoffExpired):
		return http.StatusBadRequest, "handoff expired"
	case errors.Is(err, github.ErrDuplicateCallback):
		return http.StatusConflict, "callback already recorded"
	case errors.Is(err, github.ErrStateMismatch):
		return http.StatusBadRequest, "invalid callback"
	case errors.Is(err, github.ErrCallbackMissing):
		return http.StatusConflict, "callback required"
	case errors.Is(err, github.ErrBindingCodeUnavailable):
		return http.StatusBadRequest, "binding code unavailable"
	case errors.Is(err, github.ErrBindingCodeMismatch):
		return http.StatusBadRequest, "invalid callback"
	case errors.Is(err, github.ErrSessionMismatch):
		return http.StatusForbidden, "session mismatch"
	case errors.Is(err, github.ErrWorkspaceMismatch):
		return http.StatusForbidden, "workspace mismatch"
	case errors.Is(err, github.ErrRepositoryChanged):
		return http.StatusConflict, "repository identity changed"
	case errors.Is(err, github.ErrIssueUnavailable):
		return http.StatusNotFound, "issue not available"
	case errors.Is(err, github.ErrStaleSourceRevision):
		return http.StatusConflict, "stale source revision"
	case errors.Is(err, github.ErrStaleBaseSHA):
		return http.StatusConflict, "stale base SHA"
	case errors.Is(err, github.ErrBindingRevoked):
		return http.StatusGone, "binding revoked"
	case errors.Is(err, github.ErrUpstreamDenied):
		return http.StatusBadGateway, "upstream denied the request"
	case errors.Is(err, github.ErrPendingReconciliation):
		return http.StatusServiceUnavailable, "upstream outcome uncertain"
	case errors.Is(err, github.ErrOperationInFlight):
		return http.StatusConflict, "operation in flight"
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound, "not found"
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, store.ErrIdempotencyMismatch):
		return http.StatusBadRequest, "idempotency key reuse"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}
