package httpapi

// RoutePosture describes the security posture of one registered HTTP
// route. It is the single source of truth for which authentication,
// CSRF, idempotency, and replay protections each route carries; the
// matrix in RouteMatrix must be updated whenever a route is added,
// removed, or re-guarded, and TestRouteMatrix fails otherwise.
type RoutePosture struct {
	// Method and Path are the ServeMux pattern as registered.
	Method string
	Path   string
	// Auth is one of: none, bootstrap-ceremony, founder-session,
	// cli-token, redirect-callback.
	Auth string
	// CSRF reports whether the session-bound X-CSRF-Token header is
	// required.
	CSRF bool
	// Idempotency is one of: none, caller-key, server-derived.
	Idempotency string
	// Replay notes the replay safety of the route.
	Replay string
}

// RouteMatrix lists every route registered by New with its security
// posture. State-changing founder routes require the session and its
// CSRF token; mutations carry an idempotency key supplied by the caller
// or derived deterministically server-side; pre-session ceremony routes
// carry short-lived one-use tokens instead of a session.
var RouteMatrix = []RoutePosture{
	// Liveness and first paint: no credentials of any kind.
	{Method: "GET", Path: "/healthz", Auth: "none", CSRF: false, Idempotency: "none", Replay: "no state; safe to repeat"},
	{Method: "GET", Path: "/readyz", Auth: "none", CSRF: false, Idempotency: "none", Replay: "no state; safe to repeat"},
	{Method: "GET", Path: "/api/v1/bootstrap", Auth: "none", CSRF: false, Idempotency: "none", Replay: "read-only first paint"},

	// Founder enrollment and login ceremonies: pre-session, guarded by
	// exact host and origin. The bootstrap code and ceremony tokens are
	// short-lived and one-use; a live session is rejected here.
	{Method: "POST", Path: "/api/v1/bootstrap/begin", Auth: "bootstrap-ceremony", CSRF: false, Idempotency: "none", Replay: "one-use terminal code; replay yields the same ceremony or an error"},
	{Method: "POST", Path: "/api/v1/auth/register/begin", Auth: "bootstrap-ceremony", CSRF: false, Idempotency: "none", Replay: "one-use ceremony token; a replayed begin opens a fresh ceremony"},
	{Method: "POST", Path: "/api/v1/auth/register/finish", Auth: "bootstrap-ceremony", CSRF: false, Idempotency: "none", Replay: "credential registration is bound to the ceremony; replays are rejected"},
	{Method: "POST", Path: "/api/v1/bootstrap/recovery/begin", Auth: "bootstrap-ceremony", CSRF: false, Idempotency: "none", Replay: "one-use recovery method token; replay yields the same method or an error"},
	{Method: "POST", Path: "/api/v1/bootstrap/complete", Auth: "bootstrap-ceremony", CSRF: false, Idempotency: "none", Replay: "consumes the ceremony token; replays are rejected"},
	{Method: "POST", Path: "/api/v1/auth/login/begin", Auth: "none", CSRF: false, Idempotency: "none", Replay: "one-use login challenge; replay yields a fresh challenge"},
	{Method: "POST", Path: "/api/v1/auth/login/finish", Auth: "none", CSRF: false, Idempotency: "none", Replay: "assertion is bound to the challenge; replays are rejected"},

	// Mission-pass approval: the founder session plus CSRF; the passkey
	// challenge is bound to the exact proposal revision and the
	// idempotency key is derived server-side, so a retried approval
	// reconciles to the same mission.
	{Method: "POST", Path: "/api/v1/mission-passes/{id}/approve/begin", Auth: "founder-session", CSRF: true, Idempotency: "server-derived", Replay: "one-use challenge bound to the proposal revision; retry reconciles"},
	{Method: "POST", Path: "/api/v1/mission-passes/{id}/approve/finish", Auth: "founder-session", CSRF: true, Idempotency: "server-derived", Replay: "one-use challenge; replay is rejected, retry reconciles"},

	// CLI handoffs: the CLI authenticates with its short-lived token;
	// browser decisions stay on the founder session with CSRF.
	{Method: "POST", Path: "/api/v1/cli/token", Auth: "none", CSRF: false, Idempotency: "none", Replay: "rate-limited exchange of a one-use PKCE code for a short-lived token"},
	{Method: "POST", Path: "/api/v1/cli/authorizations", Auth: "none", CSRF: false, Idempotency: "none", Replay: "rate-limited; creates a pending authorization whose PKCE code is one-use"},
	{Method: "POST", Path: "/api/v1/cli/authorizations/{id}/approve/begin", Auth: "founder-session", CSRF: true, Idempotency: "caller-key", Replay: "one-use challenge bound to the launch request; same key reconciles"},
	{Method: "POST", Path: "/api/v1/cli/authorizations/{id}/approve/finish", Auth: "founder-session", CSRF: true, Idempotency: "caller-key", Replay: "one-use challenge; replay is rejected, same key reconciles"},

	// Read-only founder views: the session authenticates; nothing mutates.
	{Method: "GET", Path: "/api/v1/mission-passes/{id}/events", Auth: "founder-session", CSRF: false, Idempotency: "none", Replay: "read-only projection"},
	{Method: "GET", Path: "/api/v1/mission-passes/{id}/expansions", Auth: "founder-session", CSRF: false, Idempotency: "none", Replay: "read-only list"},
	{Method: "GET", Path: "/api/v1/mission-passes/{id}", Auth: "founder-session", CSRF: false, Idempotency: "none", Replay: "read-only pass record"},
	{Method: "GET", Path: "/api/v1/mission-passes/{id}/receipt", Auth: "founder-session", CSRF: false, Idempotency: "none", Replay: "read-only receipt view"},
	{Method: "GET", Path: "/api/v1/connections/github/{id}/issues/{number}", Auth: "founder-session", CSRF: false, Idempotency: "none", Replay: "read-only snapshot; cached per issue revision"},

	// Expansion decisions: founder session plus CSRF; the decision key
	// is derived server-side so a retried decision reconciles.
	{Method: "POST", Path: "/api/v1/expansions/{id}/decide/begin", Auth: "founder-session", CSRF: true, Idempotency: "server-derived", Replay: "one-use challenge; retry reconciles to the same decision"},
	{Method: "POST", Path: "/api/v1/expansions/{id}/decide/finish", Auth: "founder-session", CSRF: true, Idempotency: "server-derived", Replay: "one-use challenge; replay is rejected, retry reconciles"},

	// GitHub binding: founder session plus CSRF; the handoff is
	// verified server-side and the caller key makes finish idempotent.
	{Method: "POST", Path: "/api/v1/connections/github/begin", Auth: "founder-session", CSRF: true, Idempotency: "caller-key", Replay: "same key returns the same handoff"},
	{Method: "POST", Path: "/api/v1/connections/github/{handoff_id}/finish", Auth: "founder-session", CSRF: true, Idempotency: "caller-key", Replay: "same key returns the same connection"},
	{Method: "GET", Path: "/api/v1/connections/github/callback", Auth: "redirect-callback", CSRF: false, Idempotency: "none", Replay: "AuthScope redirect; the handoff is verified server-side and finish is idempotent"},

	// Mission-pass drafts: founder session plus CSRF; the caller key
	// makes draft creation and revision idempotent.
	{Method: "POST", Path: "/api/v1/mission-passes/drafts", Auth: "founder-session", CSRF: true, Idempotency: "caller-key", Replay: "same key returns the same draft; changed content is rejected"},
	{Method: "PUT", Path: "/api/v1/mission-passes/{id}/draft", Auth: "founder-session", CSRF: true, Idempotency: "caller-key", Replay: "same key returns the same revision; changed content is rejected"},

	// Revocation: founder session plus CSRF; the revocation key is
	// derived server-side so a retried revocation reconciles instead of
	// duplicating.
	{Method: "POST", Path: "/api/v1/mission-passes/{id}/revoke/begin", Auth: "founder-session", CSRF: true, Idempotency: "server-derived", Replay: "one-use challenge; retry reconciles to the same revocation"},
	{Method: "POST", Path: "/api/v1/mission-passes/{id}/revoke/finish", Auth: "founder-session", CSRF: true, Idempotency: "server-derived", Replay: "one-use challenge; replay is rejected, retry reconciles"},

	// CLI revocation handoff: the CLI registers with S256 PKCE and
	// exchanges a one-use code for an opaque result reference.
	{Method: "POST", Path: "/api/v1/cli/revocations", Auth: "none", CSRF: false, Idempotency: "none", Replay: "rate-limited; one pending request id per pass"},
	{Method: "POST", Path: "/api/v1/cli/revocations/token", Auth: "none", CSRF: false, Idempotency: "none", Replay: "rate-limited exchange of a one-use code; replay is rejected"},
}
