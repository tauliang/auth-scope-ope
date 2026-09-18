package httpapi

// Strict per-IP rate limiting for unauthenticated routes. The CLI
// authorization create endpoint is the only unauthenticated state-changing
// route, so it gets a tight fixed-window limit.

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// cliCreateRateLimit caps CLI authorization creates per client IP.
const cliCreateRateLimit = 10

// cliCreateRateWindow is the fixed window for the create limit.
const cliCreateRateWindow = time.Minute

// rateLimiter is a fixed-window per-key rate limiter.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string]*rateWindow
	limitN int
	window time.Duration
}

type rateWindow struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: make(map[string]*rateWindow), limitN: limit, window: window}
}

// allow reports whether one more request from key fits the window.
func (l *rateLimiter) allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.hits[key]
	if !ok || now.After(w.reset) {
		l.hits[key] = &rateWindow{count: 1, reset: now.Add(l.window)}
		return true
	}
	if w.count >= l.limitN {
		return false
	}
	w.count++
	return true
}

// clientIP is the remote IP without the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limit rejects requests over the limit with a 429 problem response.
func (l *rateLimiter) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			writeProblem(w, http.StatusTooManyRequests, "too many requests", "The rate limit for this endpoint was exceeded.")
			return
		}
		next(w, r)
	}
}
