package httpapi

// One-use code exchange for CLI launch preparation.
//
// POST /api/v1/cli/token exchanges one authorization code plus the PKCE
// verifier for the sealed signed envelope of the prepared governed run.
// The CLI holds no session, so the endpoint is unauthenticated, strictly
// rate-limited, and accepts only the code and verifier: no command,
// argument, or authority fields exist. The sealed envelope is opaque to
// this server; only the CLI's ephemeral key opens it.

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/launch"
)

// cliTokenRateLimit caps token exchanges per client IP.
const cliTokenRateLimit = 10

// cliTokenRateWindow is the fixed window for the token limit.
const cliTokenRateWindow = time.Minute

// launchExchanger exchanges one code plus verifier for a prepared run.
// *launch.Service satisfies it; tests stub it.
type launchExchanger interface {
	ExchangeAndPrepare(ctx context.Context, req launch.ExchangeRequest) (launch.ExchangeResult, error)
}

// cliTokenRequest is the wire form of the exchange. Unknown fields are
// rejected, so nothing but the code and verifier can be smuggled in.
type cliTokenRequest struct {
	Code     string `json:"code"`
	Verifier string `json:"verifier"`
}

// cliTokenResponse carries the prepared run. The sealed envelope is
// base64url; only the CLI's ephemeral private key opens it.
type cliTokenResponse struct {
	RunID          string `json:"run_id"`
	MissionRef     string `json:"mission_ref"`
	SealedEnvelope string `json:"sealed_envelope"`
}

func handleCLIToken(ex launchExchanger, w http.ResponseWriter, r *http.Request) {
	var req cliTokenRequest
	if !decodeJSONBody(w, r, &req) {
		return
	}
	res, err := ex.ExchangeAndPrepare(r.Context(), launch.ExchangeRequest{
		Code:     req.Code,
		Verifier: req.Verifier,
	})
	if err != nil {
		cliTokenProblem(w, err)
		return
	}
	writeJSON(w, http.StatusOK, cliTokenResponse{
		RunID:          res.RunID,
		MissionRef:     res.MissionRef,
		SealedEnvelope: base64.RawURLEncoding.EncodeToString(res.SealedEnvelope),
	})
}

// cliTokenProblem maps exchange errors to problem responses without
// leaking secret material. Retryable ambiguity surfaces as 503; a dead
// reservation or consumed attestation surfaces as 410 so the CLI starts
// a fresh browser authorization.
func cliTokenProblem(w http.ResponseWriter, err error) {
	var upErr *coreapi.UpstreamError
	switch {
	case errors.As(err, &upErr) && upErr.StatusCode >= 400 && upErr.StatusCode < 500:
		writeProblem(w, http.StatusForbidden, "launch denied", "The upstream authority denied the launch preparation.")
	case errors.As(err, &upErr):
		writeProblem(w, http.StatusBadGateway, "launch preparation failed", "The upstream launch preparation failed.")
	case errors.Is(err, launch.ErrInvalidExchange):
		writeProblem(w, http.StatusBadRequest, "invalid exchange request", "The exchange request failed validation.")
	case errors.Is(err, launch.ErrExchangeNotFound):
		writeProblem(w, http.StatusNotFound, "authorization code not found", "The authorization code is unknown or was never issued.")
	case errors.Is(err, launch.ErrCodeExpired),
		errors.Is(err, launch.ErrAttestationMissing),
		errors.Is(err, launch.ErrExchangeStale),
		errors.Is(err, launch.ErrExchangeResultGone):
		writeProblem(w, http.StatusGone, "authorization expired", "The launch authorization is no longer valid; authorize again in the browser.")
	case errors.Is(err, launch.ErrExchangeConflict),
		errors.Is(err, launch.ErrBindingChanged),
		errors.Is(err, launch.ErrStaleMissionVersion),
		errors.Is(err, launch.ErrExchangeFailed):
		writeProblem(w, http.StatusConflict, "exchange conflict", "The exchange conflicts with the approved launch; begin the decision again.")
	case errors.Is(err, launch.ErrUnsupportedKit),
		errors.Is(err, launch.ErrIsolationNotEnforced):
		writeProblem(w, http.StatusBadGateway, "launch preparation failed", "The upstream launch preparation did not meet policy.")
	case errors.Is(err, launch.ErrAmbiguousExchange):
		writeProblem(w, http.StatusServiceUnavailable, "exchange ambiguous", "The launch outcome is ambiguous; retry the exchange.")
	default:
		writeProblem(w, http.StatusInternalServerError, "exchange failed", "The code exchange failed.")
	}
}
