package httpapi

// revoke/begin and revoke/finish: the founder's passkey revocation flow.
// The browser supplies only the reason at begin and the challenge plus
// assertion at finish; every binding field comes from the server-side
// challenge record, never from the browser.
//
// The result-only CLI handoff reuses these same routes: the CLI
// registers with PKCE and a loopback callback, the founder opens the
// Mission view with the opaque request ID and runs the normal revoke
// begin/finish decision, and finish mints the single result code and
// 302s to the exact loopback callback when a CLI request ID is carried.
// The exchange returns only the opaque result reference plus the fixed
// containment state; no session or credential is ever issued.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/missionpass"
	"github.com/tauliang/authscope-ope/internal/store"
)

// revokeRoutes registers the revocation endpoints. Browser routes are
// a no-op when the revocation service is not wired; the CLI handoff
// routes are a no-op when the CLI revocation service is not wired.
func revokeRoutes(mux *http.ServeMux, deps Dependencies, authedStateChange func(func(http.ResponseWriter, *http.Request, authn.Principal)) http.HandlerFunc) {
	revocation := deps.Revocation
	if revocation != nil {
		mux.HandleFunc("POST /api/v1/mission-passes/{id}/revoke/begin", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
			var req revokeBeginRequest
			if !decodeJSONBody(w, r, &req) {
				return
			}
			passID := r.PathValue("id")
			if passID == "" {
				writeProblem(w, http.StatusBadRequest, "invalid request", "The pass ID is required.")
				return
			}
			begun, err := revocation.Begin(r.Context(), p, passID, req.Reason)
			if err != nil {
				revokeProblem(w, err)
				return
			}
			writeJSON(w, http.StatusOK, revokeBeginResponse{
				ChallengeID: begun.ChallengeID,
				Options:     begun.OptionsJSON,
			})
		}))
		mux.HandleFunc("POST /api/v1/mission-passes/{id}/revoke/finish", authedStateChange(func(w http.ResponseWriter, r *http.Request, p authn.Principal) {
			var req revokeFinishRequest
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
			handleRevokeFinish(deps, w, r, p, passID, req, assertion)
		}))
	}
	cliRevokeRoutes(mux, deps)
}

// handleRevokeFinish completes the revocation ceremony. When the
// request carries a CLI revocation request ID, the CLI request is
// validated before the revocation runs so an expired or foreign
// request fails before any mutation; after the one upstream result
// settles or becomes pending reconciliation, finish mints the one-use
// result code and redirects it with the original state to the exact
// loopback callback. The browser fetch follows the redirect so the
// code reaches the waiting CLI, and the page shows only
// "Return to the CLI."
func handleRevokeFinish(deps Dependencies, w http.ResponseWriter, r *http.Request, p authn.Principal, passID string, req revokeFinishRequest, assertion []byte) {
	revocation := deps.Revocation
	var cliReq *missionpass.CLILookupRequest
	if req.CLIRevocationID != "" {
		if deps.CLIRevocation == nil {
			writeProblem(w, http.StatusServiceUnavailable, "revocation unavailable", "The CLI revocation handoff is not configured.")
			return
		}
		var err error
		cliReq, err = deps.CLIRevocation.Lookup(r.Context(), p.WorkspaceID, req.CLIRevocationID)
		if err != nil {
			cliRevokeProblem(w, err)
			return
		}
		if cliReq.PassID != passID {
			writeProblem(w, http.StatusConflict, "revocation request conflict", "The CLI revocation request is bound to a different pass.")
			return
		}
	}
	res, err := revocation.Finish(r.Context(), p, passID, req.ChallengeID, assertion)
	containment := ""
	if err != nil {
		if !errors.Is(err, missionpass.ErrRevokePending) {
			revokeProblem(w, err)
			return
		}
		// The upstream outcome is uncertain: the intent is durable, so
		// report the honest pending state. The worker reconciles the
		// intent in the background.
		if cliReq == nil {
			writeJSON(w, http.StatusAccepted, revokePendingResponse{PassID: passID, Reconciliation: string(missionpass.ReconciliationPending)})
			return
		}
		containment = store.ContainmentPending
	} else {
		if cliReq == nil {
			writeJSON(w, http.StatusOK, res)
			return
		}
		containment = res.Containment
	}
	// The CLI handoff: mint the one-use result code bound to the
	// registered pass and mission, and hand it back with a real redirect
	// to the exact loopback callback. The code is never rendered.
	pass, err := deps.CLIRevocation.PassSummary(r.Context(), p.WorkspaceID, passID)
	if err != nil {
		revokeProblem(w, err)
		return
	}
	code, err := deps.CLIRevocation.MintResult(r.Context(), cliReq.RequestID, missionpass.RevocationDigestInput{
		WorkspaceID:    p.WorkspaceID,
		PassID:         passID,
		MissionRef:     pass.MissionRef,
		MissionVersion: pass.MissionVersion,
	}, containment)
	if err != nil {
		cliRevokeProblem(w, err)
		return
	}
	redirect, err := cliRevocationRedirect(cliReq.RedirectURI, code, cliReq.State)
	if err != nil {
		cliRevokeProblem(w, err)
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// cliRevocationRedirect builds the loopback callback URL carrying the
// one-use code and the original state. The registered redirect URI is
// validated at registration to be exactly http://127.0.0.1:port/callback
// with no query, fragment, or userinfo, so setting the code and state
// as the query is safe.
func cliRevocationRedirect(redirectURI, code, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// revokeBeginRequest carries the founder's revocation reason. Only the
// fixed normalized reason codes are accepted; the service rejects
// anything else.
type revokeBeginRequest struct {
	Reason string `json:"reason"`
}

// revokeBeginResponse returns the one-use challenge for the passkey
// ceremony. The client passes the challenge ID back at finish; the
// challenge bytes never leave the WebAuthn flow.
type revokeBeginResponse struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

// revokeFinishRequest carries the challenge ID and the credential's
// assertion. All binding and authority fields come from the server-side
// challenge record, never from the browser. The optional CLI revocation
// request ID hands the result back to a waiting CLI through the exact
// loopback callback.
type revokeFinishRequest struct {
	ChallengeID     string          `json:"challenge_id"`
	Assertion       json.RawMessage `json:"assertion"`
	CLIRevocationID string          `json:"cli_revocation_id,omitempty"`
}

// revokePendingResponse reports an ambiguous upstream outcome. The
// revocation intent is durable; the UI reconciles through the timeline.
type revokePendingResponse struct {
	PassID         string `json:"pass_id"`
	Reconciliation string `json:"reconciliation"`
}

// revokeProblem maps revocation failures to responses.
func revokeProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authn.ErrCeremonyNotFound):
		writeProblem(w, http.StatusNotFound, "revocation challenge not found", "The revocation challenge is unknown or expired. Begin a new revocation.")
	case errors.Is(err, store.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "pass not found", "The mission pass does not exist.")
	case errors.Is(err, missionpass.ErrInvalidRevocationReason):
		writeProblem(w, http.StatusBadRequest, "invalid reason", "The revocation reason must be founder_requested, safety_concern, or mission_superseded.")
	case errors.Is(err, missionpass.ErrRevokeBindingChanged):
		writeProblem(w, http.StatusConflict, "mission changed", "The mission changed since the revocation began. Begin the revocation again.")
	case errors.Is(err, missionpass.ErrPassNotRevocable):
		writeProblem(w, http.StatusConflict, "pass not revocable", "The pass cannot move to revoked from its current state.")
	case errors.Is(err, missionpass.ErrRevokeConflict):
		writeProblem(w, http.StatusConflict, "revocation in flight", "A revocation is already reconciling for this pass. Reopen the pass to check it.")
	default:
		passProblem(w, err)
	}
}

// cliRevokeRoutes registers the result-only CLI revocation handoff: the
// PKCE registration and the result-code exchange. Both are
// unauthenticated and strictly rate-limited. The browser decision runs
// through the normal revoke begin/finish routes above.
func cliRevokeRoutes(mux *http.ServeMux, deps Dependencies) {
	svc := deps.CLIRevocation
	if svc == nil {
		return
	}
	createLimiter := newRateLimiter(cliCreateRateLimit, cliCreateRateWindow)
	mux.HandleFunc("POST /api/v1/cli/revocations",
		createLimiter.limit(requireJSON(func(w http.ResponseWriter, r *http.Request) {
			var req cliRevocationRegisterRequest
			if !decodeJSONBody(w, r, &req) {
				return
			}
			// The challenge is fixed S256, like the launch handoff.
			if req.CodeChallengeMethod != "S256" {
				writeProblem(w, http.StatusBadRequest, "invalid revocation request", "The code challenge method must be S256.")
				return
			}
			start, err := svc.Register(r.Context(), missionpass.CLIRevocationRegisterRequest{
				PassID:        req.PassID,
				RedirectURI:   req.RedirectURI,
				State:         req.State,
				CodeChallenge: req.CodeChallenge,
			})
			if err != nil {
				cliRevokeProblem(w, err)
				return
			}
			writeJSON(w, http.StatusCreated, cliRevocationRegisterResponse{
				RequestID:        start.RequestID,
				BrowserURL:       start.BrowserURL,
				RevocationDigest: start.CanonicalDigest,
			})
		})))

	exchangeLimiter := newRateLimiter(cliTokenRateLimit, cliTokenRateWindow)
	mux.HandleFunc("POST /api/v1/cli/revocations/token",
		exchangeLimiter.limit(requireJSON(func(w http.ResponseWriter, r *http.Request) {
			var req cliRevocationExchangeRequest
			if !decodeJSONBody(w, r, &req) {
				return
			}
			res, err := svc.Exchange(r.Context(), req.Code, req.CodeVerifier, req.RedirectURI, req.State)
			if err != nil {
				cliRevokeExchangeProblem(w, err)
				return
			}
			writeJSON(w, http.StatusOK, cliRevocationExchangeResponse{
				ResultRef:   res.ResultRef,
				Containment: res.Containment,
			})
		})))
}

// cliRevocationRegisterRequest is the CLI's wire request. Unknown fields
// are rejected; the server binds the exact server-canonical revocation
// digest over the pass and its mission. The founder picks the reason in
// the browser.
type cliRevocationRegisterRequest struct {
	PassID              string `json:"pass_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// cliRevocationRegisterResponse returns the request the founder opens in
// the browser. The CLI verifies the revocation digest before opening it.
type cliRevocationRegisterResponse struct {
	RequestID        string `json:"request_id"`
	BrowserURL       string `json:"browser_url"`
	RevocationDigest string `json:"revocation_digest"`
}

// cliRevocationExchangeRequest carries the one-use code, its PKCE
// verifier, and the exact redirect URI and state bound at register time.
// The exchange returns only the opaque result reference plus the fixed
// containment state.
type cliRevocationExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
	RedirectURI  string `json:"redirect_uri"`
	State        string `json:"state"`
}

// cliRevokeExchangeProblem maps result-exchange failures. An unknown
// code or a mismatched verifier, state, or redirect URI is 401 without
// distinguishing which one failed.
func cliRevokeExchangeProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, missionpass.ErrCLIRevocationNotFound),
		errors.Is(err, missionpass.ErrCLIRevocationConflict):
		writeProblem(w, http.StatusUnauthorized, "invalid code", "The result code is unknown, expired, or the verifier does not match.")
	case errors.Is(err, missionpass.ErrCLIRevocationExpired):
		writeProblem(w, http.StatusGone, "result expired", "The revocation result expired; the CLI must start over.")
	default:
		cliRevokeProblem(w, err)
	}
}

// cliRevocationExchangeResponse is the CLI's whole result.
type cliRevocationExchangeResponse struct {
	ResultRef   string `json:"result_ref"`
	Containment string `json:"containment"`
}

// cliRevokeProblem maps CLI revocation failures to responses without
// leaking secret material. Authn ceremony errors reuse the authn mapping.
func cliRevokeProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authn.ErrInvalidPKCE),
		errors.Is(err, authn.ErrInvalidRedirectURI):
		writeProblem(w, http.StatusBadRequest, "invalid revocation request", "The CLI revocation request failed validation.")
	case errors.Is(err, missionpass.ErrCLIRevocationNotFound):
		writeProblem(w, http.StatusNotFound, "revocation request not found", "The CLI revocation request does not exist.")
	case errors.Is(err, missionpass.ErrCLIRevocationConflict):
		writeProblem(w, http.StatusConflict, "revocation request conflict", "The CLI revocation request conflicts with an existing one.")
	case errors.Is(err, missionpass.ErrCLIRevocationExpired):
		writeProblem(w, http.StatusGone, "revocation request expired", "The CLI revocation request expired; the CLI must start over.")
	case errors.Is(err, missionpass.ErrInvalidRevocationReason):
		writeProblem(w, http.StatusBadRequest, "invalid reason", "The revocation reason must be founder_requested, safety_concern, or mission_superseded.")
	default:
		revokeProblem(w, err)
	}
}
