package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/authn"
	"github.com/tauliang/authscope-ope/internal/config"
	"github.com/tauliang/authscope-ope/internal/store"
)

// csrfHeaderName carries the session-bound CSRF token on state-changing
// requests from the web UI. The token itself is returned once in the login
// or bootstrap completion response and kept in memory by the UI.
const csrfHeaderName = "X-CSRF-Token"

// sessionCookieMaxAge is the twelve-hour founder session lifetime.
const sessionCookieMaxAge = 12 * 60 * 60

// bootstrapCookieMaxAge bounds the bootstrap ceremony cookie.
const bootstrapCookieMaxAge = 15 * 60

// bootstrapCookiePath scopes the bootstrap ceremony cookie. The Task 3
// route plan splits the ceremony across /api/v1/bootstrap/* and
// /api/v1/auth/register/*, so no narrower path covers every route that
// must send the cookie back. Path=/ is also what the __Host- cookie
// prefix requires; only the bootstrap handlers read this cookie, and the
// ceremony token is one-use and short-lived.
const bootstrapCookiePath = "/"

// authRoutes registers the seven founder-authentication POST routes. Every
// route requires the exact bound Host and Origin, an exact
// application/json content type, and a body within the 1 MiB cap enforced
// by the outer MaxBytesHandler.
func authRoutes(mux *http.ServeMux, deps Dependencies) {
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return requireExactHost(deps.Config,
			requireExactOrigin(deps.Config,
				requireJSON(h)))
	}
	// Bootstrap (pre-session) endpoints reject a live founder session: an
	// authenticated client must not open a second enrollment.
	preSession := func(h http.HandlerFunc) http.HandlerFunc {
		return guard(rejectSessionReuse(deps, h))
	}
	mux.HandleFunc("POST /api/v1/bootstrap/begin", preSession(handleBootstrapBegin(deps)))
	mux.HandleFunc("POST /api/v1/auth/register/begin", preSession(handleBootstrapRegisterBegin(deps)))
	mux.HandleFunc("POST /api/v1/auth/register/finish", preSession(handleBootstrapRegisterFinish(deps)))
	mux.HandleFunc("POST /api/v1/bootstrap/recovery/begin", preSession(handleBootstrapRecoveryBegin(deps)))
	mux.HandleFunc("POST /api/v1/bootstrap/complete", preSession(handleBootstrapComplete(deps)))
	mux.HandleFunc("POST /api/v1/auth/login/begin", guard(handleLoginBegin(deps)))
	mux.HandleFunc("POST /api/v1/auth/login/finish", guard(handleLoginFinish(deps)))
}

// originHost returns the exact host (with port when present) the bound
// origin requires in the Host header.
func originHost(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Host
}

func requireExactHost(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	want := originHost(cfg.Origin)
	return func(w http.ResponseWriter, r *http.Request) {
		if want == "" || r.Host != want {
			writeProblem(w, http.StatusForbidden, "forbidden host", "The request host does not match this instance.")
			return
		}
		next(w, r)
	}
}

func requireExactOrigin(cfg config.Config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != cfg.Origin {
			writeProblem(w, http.StatusForbidden, "forbidden origin", "The request origin does not match this instance.")
			return
		}
		next(w, r)
	}
}

func requireJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			writeProblem(w, http.StatusUnsupportedMediaType, "unsupported media type", "Requests must use exactly application/json.")
			return
		}
		next(w, r)
	}
}

// rejectSessionReuse refuses pre-session endpoints to clients that already
// hold a live founder session.
func rejectSessionReuse(deps Dependencies, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Authn == nil {
			writeProblem(w, http.StatusServiceUnavailable, "authentication unavailable", "The authentication service is not configured.")
			return
		}
		if _, _, err := authenticateRequest(deps, r); err == nil {
			writeProblem(w, http.StatusConflict, "already authenticated", "This client already holds a founder session.")
			return
		}
		next(w, r)
	}
}

// authenticateRequest resolves the exact bound session cookie to the
// founder principal. A session token presented under any other cookie name
// is ignored.
func authenticateRequest(deps Dependencies, r *http.Request) (authn.Principal, *store.SessionRecord, error) {
	if deps.Authn == nil {
		return authn.Principal{}, nil, errors.New("httpapi: authentication service not configured")
	}
	cookie, err := r.Cookie(deps.Authn.SessionCookieName())
	if err != nil {
		return authn.Principal{}, nil, authn.ErrSessionNotFound
	}
	return deps.Authn.AuthenticateSessionToken(r.Context(), cookie.Value)
}

// verifyRequestCSRF compares the CSRF header against the session record in
// constant time. Authenticated state-changing endpoints must call this.
func verifyRequestCSRF(r *http.Request, rec *store.SessionRecord) error {
	return authn.VerifyCSRFToken(rec, r.Header.Get(csrfHeaderName))
}

// decodeJSONBody decodes exactly one JSON value and rejects unknown
// fields.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", "The request body is not valid JSON.")
		return false
	}
	// A second decode must hit EOF: anything else is trailing data, whether
	// another JSON value or stray bytes.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		writeProblem(w, http.StatusBadRequest, "invalid request body", "The request body must contain a single JSON value.")
		return false
	}
	return true
}

// writeProblem renders an application/problem+json error. Titles and
// details are generic: credential material, challenges, and tokens are
// never reflected.
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":   "about:blank",
		"title":  title,
		"status": status,
		"detail": detail,
	})
}

// authnProblem maps service errors to problem responses. The mapping is
// exhaustive over the authn error set so no internal detail leaks.
func authnProblem(w http.ResponseWriter, err error) {
	status, title := authnProblemStatus(err)
	writeProblem(w, status, title, title+".")
}

func authnProblemStatus(err error) (int, string) {
	switch {
	case errors.Is(err, authn.ErrAlreadyEnrolled):
		return http.StatusConflict, "founder already enrolled"
	case errors.Is(err, authn.ErrNotEnrolled):
		return http.StatusNotFound, "no founder enrolled"
	case errors.Is(err, authn.ErrBootstrapCode):
		return http.StatusUnauthorized, "invalid bootstrap code"
	case errors.Is(err, authn.ErrBootstrapCodeExpired):
		return http.StatusBadRequest, "bootstrap code expired"
	case errors.Is(err, authn.ErrCeremonyNotFound):
		return http.StatusNotFound, "ceremony not found"
	case errors.Is(err, authn.ErrCeremonyExpired):
		return http.StatusBadRequest, "ceremony expired"
	case errors.Is(err, authn.ErrCeremonyConsumed):
		return http.StatusConflict, "ceremony already used"
	case errors.Is(err, authn.ErrRecoveryRequired):
		return http.StatusBadRequest, "independent recovery method required"
	case errors.Is(err, authn.ErrRecoveryNotVerified):
		return http.StatusBadRequest, "recovery method not verified"
	case errors.Is(err, authn.ErrDuplicateCredential):
		return http.StatusConflict, "credential already registered"
	case errors.Is(err, authn.ErrSessionNotFound):
		return http.StatusUnauthorized, "session not found"
	case errors.Is(err, authn.ErrSessionExpired):
		return http.StatusUnauthorized, "session expired"
	case errors.Is(err, authn.ErrSessionRevoked):
		return http.StatusUnauthorized, "session revoked"
	case errors.Is(err, authn.ErrCSRFMismatch):
		return http.StatusForbidden, "CSRF token mismatch"
	case errors.Is(err, authn.ErrDecisionBinding):
		return http.StatusBadRequest, "decision binding mismatch"
	case errors.Is(err, authn.ErrStaleAssertion):
		return http.StatusBadRequest, "passkey assertion too old"
	case errors.Is(err, authn.ErrUserVerification):
		return http.StatusBadRequest, "user verification required"
	case errors.Is(err, authn.ErrInvalidPurpose):
		return http.StatusBadRequest, "invalid purpose"
	case errors.Is(err, authn.ErrVerificationFailed):
		return http.StatusBadRequest, "WebAuthn verification failed"
	case errors.Is(err, authn.ErrConflict):
		return http.StatusConflict, "conflict"
	default:
		return http.StatusInternalServerError, "internal error"
	}
}

// setAuthCookie writes a __Host- cookie with strict attributes.
func setAuthCookie(w http.ResponseWriter, name, value, path string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// clearAuthCookie removes a cookie previously set with setAuthCookie.
func clearAuthCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// bootstrapToken reads the bootstrap ceremony token from its exact cookie.
func bootstrapToken(deps Dependencies, r *http.Request) (string, bool) {
	if deps.Authn == nil {
		return "", false
	}
	cookie, err := r.Cookie(deps.Authn.BootstrapCookieName())
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func requireAuthn(deps Dependencies, w http.ResponseWriter) bool {
	if deps.Authn == nil {
		writeProblem(w, http.StatusServiceUnavailable, "authentication unavailable", "The authentication service is not configured.")
		return false
	}
	return true
}

func handleBootstrapBegin(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthn(deps, w) {
			return
		}
		var req struct {
			Code string `json:"code"`
		}
		if !decodeJSONBody(w, r, &req) {
			return
		}
		token, expiresAt, err := deps.Authn.Bootstrap().Begin(r.Context(), strings.TrimSpace(req.Code))
		if err != nil {
			authnProblem(w, err)
			return
		}
		setAuthCookie(w, deps.Authn.BootstrapCookieName(), token, bootstrapCookiePath, bootstrapCookieMaxAge)
		writeJSON(w, http.StatusOK, map[string]any{"expires_at": expiresAt.UTC().Format(time.RFC3339)})
	}
}

func handleBootstrapRegisterBegin(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthn(deps, w) {
			return
		}
		token, ok := bootstrapToken(deps, r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "bootstrap ceremony required", "Open enrollment with the terminal bootstrap code first.")
			return
		}
		var req struct {
			DisplayName string `json:"display_name"`
		}
		if !decodeJSONBody(w, r, &req) {
			return
		}
		res, err := deps.Authn.BeginBootstrapRegistration(r.Context(), token, strings.TrimSpace(req.DisplayName))
		if err != nil {
			authnProblem(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ceremony_id": res.CeremonyID,
			"options":     res.OptionsJSON,
		})
	}
}

func handleBootstrapRegisterFinish(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthn(deps, w) {
			return
		}
		token, ok := bootstrapToken(deps, r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "bootstrap ceremony required", "Open enrollment with the terminal bootstrap code first.")
			return
		}
		var req struct {
			CeremonyID string          `json:"ceremony_id"`
			Response   json.RawMessage `json:"response"`
		}
		if !decodeJSONBody(w, r, &req) {
			return
		}
		credentialID, err := deps.Authn.FinishRegistration(r.Context(), authn.FinishRegistrationRequest{
			CeremonyID:     req.CeremonyID,
			ResponseBody:   []byte(req.Response),
			BootstrapToken: token,
		})
		if err != nil {
			authnProblem(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"credential_id": credentialID})
	}
}

func handleBootstrapRecoveryBegin(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthn(deps, w) {
			return
		}
		token, ok := bootstrapToken(deps, r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "bootstrap ceremony required", "Open enrollment with the terminal bootstrap code first.")
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		if !decodeJSONBody(w, r, &req) {
			return
		}
		res, err := deps.Authn.Bootstrap().BeginRecovery(r.Context(), token, authn.RecoveryMethod(req.Method))
		if err != nil {
			authnProblem(w, err)
			return
		}
		body := map[string]any{"method": string(res.Method)}
		if res.CeremonyID != "" {
			body["ceremony_id"] = res.CeremonyID
			body["options"] = res.OptionsJSON
		}
		if res.RecoveryKey != "" {
			body["recovery_key"] = res.RecoveryKey
		}
		writeJSON(w, http.StatusOK, body)
	}
}

func handleBootstrapComplete(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthn(deps, w) {
			return
		}
		token, ok := bootstrapToken(deps, r)
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "bootstrap ceremony required", "Open enrollment with the terminal bootstrap code first.")
			return
		}
		var req struct {
			RecoveryConfirmation string `json:"recovery_confirmation"`
		}
		if !decodeJSONBody(w, r, &req) {
			return
		}
		res, err := deps.Authn.Bootstrap().Complete(r.Context(), token, strings.TrimSpace(req.RecoveryConfirmation))
		if err != nil {
			authnProblem(w, err)
			return
		}
		setAuthCookie(w, deps.Authn.SessionCookieName(), res.SessionToken, "/", sessionCookieMaxAge)
		clearAuthCookie(w, deps.Authn.BootstrapCookieName(), bootstrapCookiePath)
		writeJSON(w, http.StatusOK, map[string]any{"csrf_token": res.CSRFToken})
	}
}

func handleLoginBegin(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthn(deps, w) {
			return
		}
		var req struct{}
		if !decodeJSONBody(w, r, &req) {
			return
		}
		res, err := deps.Authn.BeginLogin(r.Context())
		if err != nil {
			authnProblem(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ceremony_id": res.CeremonyID,
			"options":     res.OptionsJSON,
		})
	}
}

func handleLoginFinish(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireAuthn(deps, w) {
			return
		}
		var req struct {
			CeremonyID string          `json:"ceremony_id"`
			Response   json.RawMessage `json:"response"`
		}
		if !decodeJSONBody(w, r, &req) {
			return
		}
		res, err := deps.Authn.FinishLogin(r.Context(), req.CeremonyID, []byte(req.Response))
		if err != nil {
			authnProblem(w, err)
			return
		}
		// Login always rotates the session: a fresh cookie replaces any
		// previous one.
		setAuthCookie(w, deps.Authn.SessionCookieName(), res.SessionToken, "/", sessionCookieMaxAge)
		writeJSON(w, http.StatusOK, map[string]any{"csrf_token": res.CSRFToken})
	}
}
