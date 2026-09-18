package httpapi

// One-use browser PKCE handoff for CLI launch authorization.
//
// POST /api/v1/cli/authorizations opens a pending authorization. The CLI
// holds no session, so create is unauthenticated, strictly rate-limited,
// and bound to the exact approved launch binding; it grants no runtime
// authority.
//
// POST /api/v1/cli/authorizations/{id}/approve/begin and
// POST /api/v1/cli/authorizations/{id}/approve/finish run the founder's
// passkey decision in the browser under the full session guard chain
// (exact Host, exact Origin, JSON, founder session, CSRF). Finish mints
// the single 256-bit code and returns the loopback redirect; the UI shows
// only "Return to the CLI" afterwards.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tauliang/authscope-ope/internal/authn"
)

// cliRoutes registers the CLI handoff routes. They exist only when the CLI
// authorization service is wired.
func cliRoutes(mux *http.ServeMux, deps Dependencies) {
	svc := deps.CLIAuth
	if svc == nil {
		return
	}
	createLimiter := newRateLimiter(cliCreateRateLimit, cliCreateRateWindow)
	mux.HandleFunc("POST /api/v1/cli/authorizations",
		createLimiter.limit(requireJSON(func(w http.ResponseWriter, r *http.Request) {
			handleCLIAuthorizationCreate(svc, w, r)
		})))

	authed := func(h func(w http.ResponseWriter, r *http.Request, p authn.Principal)) http.HandlerFunc {
		return requireExactHost(deps.Config,
			requireExactOrigin(deps.Config,
				requireJSON(func(w http.ResponseWriter, r *http.Request) {
					principal, session, err := authenticateRequest(deps, r)
					if err != nil {
						authnProblem(w, err)
						return
					}
					if err := verifyRequestCSRF(r, session); err != nil {
						authnProblem(w, err)
						return
					}
					if _, ok := requireIdempotencyKey(w, r); !ok {
						return
					}
					h(w, r, principal)
				})))
	}
	mux.HandleFunc("POST /api/v1/cli/authorizations/{id}/approve/begin", authed(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		handleCLIAuthorizationApproveBegin(svc, w, r, p)
	}))
	mux.HandleFunc("POST /api/v1/cli/authorizations/{id}/approve/finish", authed(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
		handleCLIAuthorizationApproveFinish(svc, w, r, p)
	}))
}

// createCLIAuthorizationRequest is the CLI's wire request. Unknown fields
// are rejected, so no command or argument fields can be smuggled in.
type createCLIAuthorizationRequest struct {
	PassID              string `json:"pass_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	EphemeralPublicKey  string `json:"ephemeral_public_key"`
}

// CLIAuthorizationStart is the pending authorization returned to the CLI.
type CLIAuthorizationStart struct {
	AuthorizationID  string   `json:"authorization_id"`
	BrowserURL       string   `json:"browser_url"`
	ProposalDigest   string   `json:"proposal_digest"`
	AgentKitID       string   `json:"agent_kit_id"`
	AgentKitVersion  string   `json:"agent_kit_version"`
	RunnerArguments  []string `json:"runner_arguments"`
	InvocationDigest string   `json:"invocation_digest"`
}

// cliApproveBeginResponse is the browser decision the founder reviews.
type cliApproveBeginResponse struct {
	ChallengeID      string          `json:"challenge_id"`
	AssertionOptions json.RawMessage `json:"assertion_options"`
	PassID           string          `json:"pass_id"`
	RepositoryName   string          `json:"repository_name"`
	IssueNumber      int64           `json:"issue_number"`
	ProposalDigest   string          `json:"proposal_digest"`
	InvocationDigest string          `json:"invocation_digest"`
	AgentKitID       string          `json:"agent_kit_id"`
	AgentKitVersion  string          `json:"agent_kit_version"`
	RunnerArguments  []string        `json:"runner_arguments"`
}

// cliApproveFinishRequest carries the founder's assertion. On success the
// handler answers 302 to the exact loopback callback; there is no JSON
// finish response.
type cliApproveFinishRequest struct {
	ChallengeID string          `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"`
}

func handleCLIAuthorizationCreate(svc *authn.CLIAuthorizationService, w http.ResponseWriter, r *http.Request) {
	var req createCLIAuthorizationRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	start, _, err := svc.Create(r.Context(), authn.CLIAuthorizationRequest{
		PassID:              req.PassID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		EphemeralPublicKey:  req.EphemeralPublicKey,
	})
	if err != nil {
		cliAuthProblem(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, CLIAuthorizationStart{
		AuthorizationID:  start.ID,
		BrowserURL:       start.BrowserURL,
		ProposalDigest:   start.ProposalDigest,
		AgentKitID:       start.AgentKitID,
		AgentKitVersion:  start.AgentKitVersion,
		RunnerArguments:  start.RunnerArguments,
		InvocationDigest: start.InvocationDigest,
	})
}

func handleCLIAuthorizationApproveBegin(svc *authn.CLIAuthorizationService, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	id := r.PathValue("id")
	begun, err := svc.BeginBrowserDecision(r.Context(), p, id)
	if err != nil {
		cliAuthProblem(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, cliApproveBeginResponse{
		ChallengeID:      begun.ChallengeID,
		AssertionOptions: begun.OptionsJSON,
		PassID:           begun.PassID,
		RepositoryName:   begun.RepositoryName,
		IssueNumber:      begun.IssueNumber,
		ProposalDigest:   begun.ProposalDigest,
		InvocationDigest: begun.InvocationDigest,
		AgentKitID:       begun.AgentKitID,
		AgentKitVersion:  begun.AgentKitVersion,
		RunnerArguments:  begun.RunnerArguments,
	})
}

func handleCLIAuthorizationApproveFinish(svc *authn.CLIAuthorizationService, w http.ResponseWriter, r *http.Request, p authn.Principal) {
	var req cliApproveFinishRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	redirect, err := svc.FinishBrowserDecision(r.Context(), p, r.PathValue("id"), req.ChallengeID, req.Assertion)
	if err != nil {
		cliAuthProblem(w, err)
		return
	}
	// Task 8: the decision hands back to the CLI with a real redirect to
	// the exact loopback callback bound at create time, carrying the
	// one-use code and the original state. The UI shows only
	// "Return to the CLI" afterwards; the code is never rendered.
	http.Redirect(w, r, redirect, http.StatusFound)
}

// cliAuthProblem maps CLI handoff errors to problem responses without
// leaking secret material. Authn ceremony errors reuse the authn mapping.
func cliAuthProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authn.ErrInvalidPKCE),
		errors.Is(err, authn.ErrInvalidRedirectURI),
		errors.Is(err, authn.ErrInvalidEphemeralKey):
		writeProblem(w, http.StatusBadRequest, "invalid authorization request", "The CLI authorization request failed validation.")
	case errors.Is(err, authn.ErrCLIAuthorizationNotFound):
		writeProblem(w, http.StatusNotFound, "authorization not found", "The CLI authorization does not exist.")
	case errors.Is(err, authn.ErrPassNotApproved):
		writeProblem(w, http.StatusConflict, "pass not approved", "The pass is not approved for launch.")
	case errors.Is(err, authn.ErrCLIAuthorizationConflict):
		writeProblem(w, http.StatusConflict, "authorization conflict", "The CLI authorization request conflicts with an existing one.")
	case errors.Is(err, authn.ErrCLIBindingChanged):
		writeProblem(w, http.StatusConflict, "launch binding changed", "The approved launch binding changed; begin the decision again.")
	case errors.Is(err, authn.ErrCLIAuthorizationExpired):
		writeProblem(w, http.StatusGone, "authorization expired", "The CLI authorization expired; the CLI must start over.")
	default:
		authnProblem(w, err)
	}
}
