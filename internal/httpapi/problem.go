// Package httpapi problem details: the shared RFC 9457 problem writer
// and the upstream-error mapping. Titles and details are generic:
// credential material, challenges, tokens, signatures, and attestations
// never appear in problem responses.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tauliang/authscope-ope/internal/coreapi"
)

// Problem is an RFC 9457 problem-details object.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// WriteProblem renders an application/problem+json error.
func WriteProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{
		Type:   "about:blank",
		Title:  title,
		Status: status,
		Detail: detail,
	})
}

// UpstreamHTTPStatus maps an error from the AuthScope client to the local
// fail-closed HTTP status: authentication to 401, forbidden/denied to
// 403, missing workspace-qualified objects to 404, stale
// version/idempotency mismatch to 409, unavailable verified context to
// 412, rate limits to 429, and all other upstream uncertainty to 503. An
// upstream denial is never translated into a retryable allow path.
func UpstreamHTTPStatus(err error) int {
	var upErr *coreapi.UpstreamError
	if errors.As(err, &upErr) {
		return upErr.LocalStatus()
	}
	if errors.Is(err, coreapi.ErrGateNotHealthy) {
		return http.StatusServiceUnavailable
	}
	if errors.Is(err, coreapi.ErrResponseTooLarge) {
		return http.StatusServiceUnavailable
	}
	return http.StatusServiceUnavailable
}

// upstreamProblemTitle renders the generic title for an upstream failure.
// The upstream message is not reflected: problem details stay generic so
// no upstream-controlled text reaches the founder UI unchecked.
func upstreamProblemTitle(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "upstream authentication failed"
	case http.StatusForbidden:
		return "upstream denied the request"
	case http.StatusNotFound:
		return "upstream object not found"
	case http.StatusConflict:
		return "upstream version conflict"
	case http.StatusPreconditionFailed:
		return "verified context unavailable"
	case http.StatusTooManyRequests:
		return "upstream rate limit exceeded"
	default:
		return "upstream unavailable"
	}
}

// WriteUpstreamError maps an AuthScope client error to a problem response.
func WriteUpstreamError(w http.ResponseWriter, err error) {
	status := UpstreamHTTPStatus(err)
	title := upstreamProblemTitle(status)
	WriteProblem(w, status, title, title+".")
}

// RequireVerifiedGate is the shared mutation middleware. It rejects every
// business mutation with 503 while the upstream compatibility gate is
// missing or stale, including a healthy-to-stale transition after route
// registration. A nil gate also fails closed: production always wires one.
func RequireVerifiedGate(gate *coreapi.Gate) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if gate == nil || !gate.Healthy() {
				WriteProblem(w, http.StatusServiceUnavailable,
					"upstream unavailable", "Upstream compatibility is not verified.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
