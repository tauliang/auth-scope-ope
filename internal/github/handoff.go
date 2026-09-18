// Package github owns the AuthScope-hosted GitHub App installation
// handoff and the trusted issue-snapshot import. AuthScope hosts the
// GitHub App installation, owns all GitHub OAuth state and credentials,
// and executes every provider read; OPE handles only opaque,
// AuthScope-issued values and never receives a GitHub token or OAuth
// code. The raw one-use binding code lives only in a bounded in-memory
// cache until finish, restart, or expiry; durable state holds only its
// SHA-256 digest.
package github

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

// equalStringConstTime compares two strings in constant time so workspace
// and binding identity checks never leak prefix information.
func equalStringConstTime(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var (
	// ErrInvalidInput reports a malformed begin/finish parameter.
	ErrInvalidInput = errors.New("github: invalid input")
	// ErrHandoffNotFound reports an unknown handoff ID.
	ErrHandoffNotFound = errors.New("github: handoff not found")
	// ErrHandoffExpired reports a handoff past its two-minute lifetime.
	ErrHandoffExpired = errors.New("github: handoff expired")
	// ErrStateMismatch reports a callback state that does not match the
	// stored state hash.
	ErrStateMismatch = errors.New("github: state mismatch")
	// ErrSessionMismatch reports a finish attempted without the original
	// authenticated session that began the handoff.
	ErrSessionMismatch = errors.New("github: session mismatch")
	// ErrCallbackMissing reports a finish attempted before the AuthScope
	// callback recorded the one-use binding code.
	ErrCallbackMissing = errors.New("github: callback not recorded")
	// ErrDuplicateCallback reports a second callback for a handoff whose
	// callback was already recorded. The first code wins; replays never
	// re-record.
	ErrDuplicateCallback = errors.New("github: callback already recorded")
	// ErrBindingCodeUnavailable reports a finish whose raw binding code is
	// gone from the in-memory cache (restart or expiry). The founder must
	// start a new handoff; OPE never exchanges a code it cannot verify
	// against the durable digest.
	ErrBindingCodeUnavailable = errors.New("github: binding code unavailable; start a new handoff")
	// ErrBindingCodeMismatch reports a cached code that does not match the
	// durable digest: the opaque code changed after the callback.
	ErrBindingCodeMismatch = errors.New("github: binding code mismatch")
	// ErrOperationInFlight reports a second caller while the first attempt
	// under the same idempotency key has not settled.
	ErrOperationInFlight = errors.New("github: operation in flight")
	// ErrPendingReconciliation reports an ambiguous upstream outcome that
	// reconciliation could not settle. The caller retries with the same
	// idempotency key; OPE never repeats the mutation blindly.
	ErrPendingReconciliation = errors.New("github: upstream outcome uncertain; retry with the same idempotency key")
	// ErrWorkspaceMismatch reports a binding whose workspace differs from
	// the instance-bound workspace.
	ErrWorkspaceMismatch = errors.New("github: binding workspace mismatch")
	// ErrInvalidInstallationURL reports an upstream installation URL whose
	// origin is not exactly the configured AuthScope origin.
	ErrInvalidInstallationURL = errors.New("github: installation URL origin mismatch")
	// ErrRepositoryChanged reports a binding whose immutable repository ID
	// no longer matches the connected record: the repository was
	// transferred or replaced under the same name.
	ErrRepositoryChanged = errors.New("github: repository identity changed")
	// ErrUpstreamDenied reports an upstream denial without a mappable
	// local status.
	ErrUpstreamDenied = errors.New("github: upstream denied the operation")
)

const (
	// handoffTTL is the two-minute lifetime of one installation handoff.
	handoffTTL = 2 * time.Minute
	// maxCachedCodes bounds the in-memory raw binding-code cache.
	maxCachedCodes = 128
	// maxCodeLength bounds the opaque binding code the callback accepts.
	maxCodeLength = 256
	// maxHandoffIDLength bounds the handoff ID accepted from callers.
	maxHandoffIDLength = 128
	// maxIdempotencyKeyLength bounds the caller-supplied idempotency key.
	maxIdempotencyKeyLength = 128
	// defaultUpstreamTimeout bounds one upstream AuthScope call.
	defaultUpstreamTimeout = 10 * time.Second
	// postureTTL is how long a workflow-posture check stays valid before
	// launch must recheck it.
	postureTTL = time.Hour
)

// repositoryPattern matches the owner/name shape the upstream contract
// pins for the begin request.
var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// GitHubHandoff is the in-memory view of an installation handoff. Only
// hashes leave this package toward durable storage.
type GitHubHandoff struct {
	ID                string
	WorkspaceID       string
	SessionID         string
	StateHash         [32]byte
	BindingCodeDigest [32]byte
	AuthScopeOrigin   string
	ExpiresAt         time.Time
	CallbackAt        *time.Time
	ConsumedAt        *time.Time
}

// BeginResult is the settled begin outcome returned to the browser: the
// local handoff ID and the fixed-origin AuthScope installation URL. The
// upstream one-use binding code is never returned.
type BeginResult struct {
	HandoffID       string    `json:"handoff_id"`
	InstallationURL string    `json:"installation_url"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// FinishResult is the settled finish outcome: the persisted connection.
type FinishResult struct {
	Connection store.ConnectionRecord `json:"connection"`
}

// NormalizeAuthScopeOrigin reduces a configured AuthScope base URL to
// its exact origin: lowercase scheme and host, no userinfo, path, query,
// or fragment. Release-versus-development HTTPS policy is enforced by the
// config package on AUTH_SCOPE_URL before this package ever sees it; both
// schemes normalize here so development can target a local AuthScope.
func NormalizeAuthScopeOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("github: AuthScope origin is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("github: invalid AuthScope origin: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("github: AuthScope origin must use http or https")
	}
	if u.User != nil {
		return "", fmt.Errorf("github: AuthScope origin must not carry userinfo")
	}
	host := strings.ToLower(u.Host)
	if host == "" {
		return "", fmt.Errorf("github: AuthScope origin must include a host")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("github: AuthScope origin must not carry a path, query, or fragment")
	}
	return scheme + "://" + host, nil
}

// HandoffConfig wires the handoff service.
type HandoffConfig struct {
	Store           store.Store
	Authority       coreapi.Authority
	AuthScopeOrigin string // exact origin of the configured AuthScope, e.g. https://authscope.example.com
	CompletionPath  string // fixed same-origin path the callback redirects to, e.g. /connect/github/done
	Clock           func() time.Time
	Rand            io.Reader
	UpstreamTimeout time.Duration
}

// codeEntry is one cached raw binding code with its expiry.
type codeEntry struct {
	code      string
	expiresAt time.Time
}

// Handoff manages the opaque AuthScope-hosted installation handoff. The
// raw one-use binding codes live only in the bounded in-memory cache;
// durable state holds only digests.
type Handoff struct {
	store           store.Store
	authority       coreapi.Authority
	authScopeOrigin string
	completionPath  string
	clock           func() time.Time
	rand            io.Reader
	upstreamTimeout time.Duration

	mu    sync.Mutex
	codes map[string]codeEntry

	finishLocks keyLock
}

// keyLock is a lock keyed by string. It serializes Finish per handoff ID
// so two callers with different idempotency keys cannot issue concurrent
// upstream finish calls for the same handoff; the loser of the local
// consume race would otherwise still have issued its own upstream
// mutation. Entries are dropped on unlock.
type keyLock struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// lock acquires the keyed lock and returns its releaser.
func (k *keyLock) lock(key string) func() {
	k.mu.Lock()
	l, ok := k.locks[key]
	if !ok {
		l = &sync.Mutex{}
		if k.locks == nil {
			k.locks = make(map[string]*sync.Mutex)
		}
		k.locks[key] = l
	}
	k.mu.Unlock()
	l.Lock()
	return func() {
		l.Unlock()
		k.mu.Lock()
		if k.locks[key] == l {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

// NewHandoff builds the handoff service.
func NewHandoff(cfg HandoffConfig) (*Handoff, error) {
	if cfg.Store == nil || cfg.Authority == nil {
		return nil, fmt.Errorf("github: store and authority are required")
	}
	origin, err := NormalizeAuthScopeOrigin(cfg.AuthScopeOrigin)
	if err != nil {
		return nil, err
	}
	if cfg.CompletionPath == "" {
		return nil, fmt.Errorf("github: completion path is required")
	}
	if !strings.HasPrefix(cfg.CompletionPath, "/") {
		return nil, fmt.Errorf("github: completion path must be a same-origin path")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	rnd := cfg.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = defaultUpstreamTimeout
	}
	return &Handoff{
		store:           cfg.Store,
		authority:       cfg.Authority,
		authScopeOrigin: origin,
		completionPath:  cfg.CompletionPath,
		clock:           clock,
		rand:            rnd,
		upstreamTimeout: timeout,
		codes:           make(map[string]codeEntry),
	}, nil
}

func (h *Handoff) now() time.Time { return h.clock().UTC() }

// randomHex returns n random bytes as lowercase hex.
func (h *Handoff) randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(h.rand, b); err != nil {
		return "", fmt.Errorf("github: cannot generate random material: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// upstreamCtx bounds one upstream call.
func (h *Handoff) upstreamCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, h.upstreamTimeout)
}

// isAmbiguous reports whether err leaves the upstream outcome uncertain:
// timeouts and upstream 503/504/429 answers may have applied the mutation.
func isAmbiguous(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return true
	}
	var up *coreapi.UpstreamError
	if errors.As(err, &up) {
		switch up.StatusCode {
		case 429, 503, 504:
			return true
		}
	}
	return false
}

func canonicalDigest(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

// beginIdempotency starts or replays the idempotent operation record.
func (h *Handoff) beginIdempotency(ctx context.Context, workspaceID, key, digest string) (store.IdempotencyResult, error) {
	if key == "" || len(key) > maxIdempotencyKeyLength {
		return store.IdempotencyResult{}, fmt.Errorf("%w: idempotency key is required", ErrInvalidInput)
	}
	var res store.IdempotencyResult
	err := h.store.WithTx(ctx, func(tx store.Tx) error {
		var err error
		res, err = tx.BeginIdempotency(ctx, store.IdempotencyRecord{
			WorkspaceID:     workspaceID,
			Key:             key,
			CanonicalDigest: digest,
		})
		return err
	})
	if err != nil {
		return store.IdempotencyResult{}, err
	}
	return res, nil
}

// Begin starts the opaque installation handoff. It requires the founder
// session that will finish the handoff, validates the repository shape,
// persists an operation intent, and calls BeginGitHubBinding exactly once
// per idempotency key. On an ambiguous failure it reconciles by the
// original key and replays with the same key instead of repeating the
// mutation. It returns only the settled handoff ID and the installation
// URL; the upstream binding code is discarded.
func (h *Handoff) Begin(ctx context.Context, workspaceID, sessionID, repository, idempotencyKey string) (BeginResult, error) {
	if workspaceID == "" || sessionID == "" {
		return BeginResult{}, fmt.Errorf("%w: workspace and session are required", ErrInvalidInput)
	}
	repository = strings.TrimSpace(repository)
	if repository == "" || len(repository) > 128 || !repositoryPattern.MatchString(repository) {
		return BeginResult{}, fmt.Errorf("%w: repository must be owner/name", ErrInvalidInput)
	}
	digest := canonicalDigest("ope/github-begin/v1", workspaceID, sessionID, repository)
	idem, err := h.beginIdempotency(ctx, workspaceID, idempotencyKey, digest)
	if err != nil {
		return BeginResult{}, err
	}
	if idem.Replay && idem.Completed {
		var res BeginResult
		if err := json.Unmarshal(idem.Result, &res); err != nil {
			return BeginResult{}, fmt.Errorf("github: corrupt stored begin result: %w", err)
		}
		return res, nil
	}
	if idem.Replay {
		// A previous attempt under this key never settled. Reconcile
		// before deciding: if AuthScope has no record, the earlier
		// attempt crashed before the mutation and it is safe to proceed;
		// if it completed, replay with the same key to recover the
		// original handoff. The canonical digest binds the session, so a
		// different session cannot replay this key.
		if settled, rerr := h.reconcileBegin(ctx, workspaceID, sessionID, idempotencyKey, repository); rerr == nil && settled.HandoffID != "" {
			return settled, nil
		} else if rerr != nil {
			return BeginResult{}, rerr
		}
	}

	upstream, err := h.beginUpstream(ctx, workspaceID, repository, idempotencyKey)
	if err != nil {
		return BeginResult{}, err
	}
	return h.settleBegin(ctx, workspaceID, sessionID, idempotencyKey, upstream)
}

// reconcileOutcome classifies the upstream operation record held under
// an idempotency key.
type reconcileOutcome int

const (
	// reconcileAbsent means AuthScope holds no record: the earlier
	// attempt never registered, so proceeding with the same key is safe.
	reconcileAbsent reconcileOutcome = iota
	// reconcileInflight means the operation is still pending: the caller
	// must back off and retry with the same key instead of repeating the
	// call blindly.
	reconcileInflight
	// reconcileCompleted means the operation settled: replay with the
	// same key to recover the original result instead of mutating again.
	reconcileCompleted
)

// reconcileOperation looks up the upstream operation by idempotency key
// and classifies it. A 404 or an empty record means absent; any other
// lookup failure leaves the outcome uncertain and reports pending
// reconciliation.
func (h *Handoff) reconcileOperation(ctx context.Context, workspaceID, idempotencyKey string) (reconcileOutcome, error) {
	op, err := h.authority.ReconcileOperation(ctx, idempotencyKey, "", coreapi.RequestOptions{WorkspaceID: workspaceID})
	if err != nil {
		var up *coreapi.UpstreamError
		if errors.As(err, &up) && up.StatusCode == http.StatusNotFound {
			return reconcileAbsent, nil
		}
		return reconcileAbsent, ErrPendingReconciliation
	}
	if op.OperationID == "" && op.IdempotencyKey == "" {
		return reconcileAbsent, nil
	}
	if strings.EqualFold(op.Status, "completed") {
		return reconcileCompleted, nil
	}
	return reconcileInflight, nil
}

// reconcileBegin reconciles an unsettled begin by idempotency key. A
// completed operation replays with the same key to recover the original
// handoff; an in-flight operation reports ErrOperationInFlight so the
// caller backs off; an absent operation reports not-settled so the caller
// may proceed as new with the same key.
func (h *Handoff) reconcileBegin(ctx context.Context, workspaceID, sessionID, idempotencyKey, repository string) (BeginResult, error) {
	outcome, err := h.reconcileOperation(ctx, workspaceID, idempotencyKey)
	if err != nil {
		return BeginResult{}, err
	}
	switch outcome {
	case reconcileCompleted:
		upstream, err := h.beginUpstreamReplay(ctx, workspaceID, repository, idempotencyKey)
		if err != nil {
			return BeginResult{}, ErrPendingReconciliation
		}
		return h.settleBegin(ctx, workspaceID, sessionID, idempotencyKey, upstream)
	case reconcileInflight:
		return BeginResult{}, ErrOperationInFlight
	default:
		return BeginResult{}, nil
	}
}

// beginUpstream calls BeginGitHubBinding once; on an ambiguous failure it
// reconciles by the original key and replays with the same key rather
// than repeating the mutation.
func (h *Handoff) beginUpstream(ctx context.Context, workspaceID, repository, idempotencyKey string) (coreapi.GitHubBindingHandoff, error) {
	uctx, cancel := h.upstreamCtx(ctx)
	defer cancel()
	upstream, err := h.authority.BeginGitHubBinding(uctx,
		coreapi.GitHubBindingBeginRequest{Repository: repository},
		coreapi.RequestOptions{WorkspaceID: workspaceID, IdempotencyKey: idempotencyKey})
	if err == nil {
		return upstream, nil
	}
	if !isAmbiguous(err) {
		return coreapi.GitHubBindingHandoff{}, err
	}
	outcome, rerr := h.reconcileOperation(ctx, workspaceID, idempotencyKey)
	if rerr != nil {
		return coreapi.GitHubBindingHandoff{}, rerr
	}
	switch outcome {
	case reconcileCompleted:
		return h.beginUpstreamReplay(ctx, workspaceID, repository, idempotencyKey)
	case reconcileInflight:
		return coreapi.GitHubBindingHandoff{}, ErrOperationInFlight
	default:
		// Absent after an ambiguous failure: the timed-out call may
		// still land. Do not repeat inside this request; the caller
		// retries with the same key and reconciles again.
		return coreapi.GitHubBindingHandoff{}, ErrPendingReconciliation
	}
}

// beginUpstreamReplay re-issues the begin with the identical idempotency
// key after reconciliation proved the operation completed. AuthScope must
// return the original handoff for a repeated key; this is a replay, not a
// new mutation.
func (h *Handoff) beginUpstreamReplay(ctx context.Context, workspaceID, repository, idempotencyKey string) (coreapi.GitHubBindingHandoff, error) {
	uctx, cancel := h.upstreamCtx(ctx)
	defer cancel()
	upstream, err := h.authority.BeginGitHubBinding(uctx,
		coreapi.GitHubBindingBeginRequest{Repository: repository},
		coreapi.RequestOptions{WorkspaceID: workspaceID, IdempotencyKey: idempotencyKey})
	if err != nil {
		return coreapi.GitHubBindingHandoff{}, ErrPendingReconciliation
	}
	return upstream, nil
}

// settleBegin validates the upstream installation URL, persists the
// handoff, and records the settled result for idempotent replay.
func (h *Handoff) settleBegin(ctx context.Context, workspaceID, sessionID, idempotencyKey string, upstream coreapi.GitHubBindingHandoff) (BeginResult, error) {
	if upstream.HandoffID == "" || upstream.InstallationURL == "" {
		return BeginResult{}, fmt.Errorf("%w: upstream handoff is incomplete", ErrUpstreamDenied)
	}
	// Mint the local handoff only after the upstream handoff settled; the
	// installation URL origin is verified before any state is stored.
	handoffID, err := h.randomHex(16)
	if err != nil {
		return BeginResult{}, err
	}
	state, err := h.randomHex(32)
	if err != nil {
		return BeginResult{}, err
	}
	finalURL, err := h.installationURLWithState(upstream.InstallationURL, handoffID, state)
	if err != nil {
		return BeginResult{}, err
	}
	now := h.now()
	rec := store.GitHubHandoffRecord{
		WorkspaceID:       workspaceID,
		HandoffID:         handoffID,
		SessionID:         sessionID,
		StateHash:         sha256Hex(state),
		UpstreamHandoffID: upstream.HandoffID,
		AuthScopeOrigin:   h.authScopeOrigin,
		ExpiresAt:         now.Add(handoffTTL),
	}
	res := BeginResult{HandoffID: handoffID, InstallationURL: finalURL, ExpiresAt: rec.ExpiresAt}
	raw, err := json.Marshal(res)
	if err != nil {
		return BeginResult{}, fmt.Errorf("github: cannot encode idempotent result: %w", err)
	}
	// The handoff row and the completed idempotency record commit
	// atomically: a crash before the commit leaves no row, so the retry
	// reconciles and replays upstream with the same key; a crash after
	// the commit replays the stored result.
	err = h.store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.PutGitHubHandoff(ctx, rec); err != nil {
			return err
		}
		return tx.CompleteIdempotency(ctx, workspaceID, idempotencyKey, raw)
	})
	if err != nil {
		return BeginResult{}, err
	}
	return res, nil
}

// installationURLWithState verifies the upstream installation URL has
// exactly the configured AuthScope origin and, when handoffID and state
// are provided, round-trips them as query parameters for the callback.
// The origin check happens before any parameter is added.
func (h *Handoff) installationURLWithState(raw, handoffID, state string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%w: malformed installation URL", ErrInvalidInstallationURL)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%w: unexpected scheme", ErrInvalidInstallationURL)
	}
	origin := u.Scheme + "://" + u.Host
	if !equalStringConstTime(origin, h.authScopeOrigin) {
		return "", fmt.Errorf("%w: got %q", ErrInvalidInstallationURL, origin)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: userinfo not allowed", ErrInvalidInstallationURL)
	}
	if handoffID == "" {
		return u.String(), nil
	}
	q := u.Query()
	q.Set("handoff_id", handoffID)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// callbackParams are the only query parameters the callback accepts.
var callbackParams = []string{"handoff_id", "code", "state"}

// RecordCallback records the AuthScope redirect. It accepts only the
// handoff ID, the opaque one-use binding code, and state; any other query
// field fails closed. It constant-time matches state, caches the raw code
// once in the bounded in-memory cache, persists only its digest, and
// returns the fixed same-origin completion path. It never finishes the
// binding, creates a session, or renders either opaque value.
func (h *Handoff) RecordCallback(ctx context.Context, values url.Values) (string, error) {
	for key := range values {
		allowed := false
		for _, p := range callbackParams {
			if equalStringConstTime(key, p) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("%w: unexpected callback parameter", ErrInvalidInput)
		}
	}
	handoffID := values.Get("handoff_id")
	code := values.Get("code")
	state := values.Get("state")
	// Each accepted parameter must appear exactly once; a repeated
	// parameter is a malformed callback, not a choice of values.
	for _, p := range callbackParams {
		if len(values[p]) != 1 {
			return "", fmt.Errorf("%w: parameter %q must appear exactly once", ErrInvalidInput, p)
		}
	}
	if handoffID == "" || len(handoffID) > maxHandoffIDLength ||
		code == "" || len(code) > maxCodeLength ||
		state == "" {
		return "", fmt.Errorf("%w: handoff_id, code, and state are required", ErrInvalidInput)
	}
	stateBytes, err := hex.DecodeString(state)
	if err != nil || len(stateBytes) != 32 {
		return "", fmt.Errorf("%w: state must be 256-bit hex", ErrInvalidInput)
	}

	rec, err := h.store.GetGitHubHandoffByID(ctx, handoffID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrHandoffNotFound
		}
		return "", err
	}
	now := h.now()
	if !rec.ExpiresAt.After(now) {
		return "", ErrHandoffExpired
	}
	if rec.ConsumedAt != nil {
		return "", ErrDuplicateCallback
	}
	if rec.CallbackAt != nil {
		return "", ErrDuplicateCallback
	}
	// The durable state hash is sha256Hex over the hex state string, the
	// same representation settleBegin stored. Compare as equal-length hex
	// in constant time.
	if !equalStringConstTime(sha256Hex(state), rec.StateHash) {
		return "", ErrStateMismatch
	}

	h.mu.Lock()
	h.evictExpiredCodesLocked(now)
	if len(h.codes) >= maxCachedCodes {
		h.evictOldestCodeLocked()
	}
	h.codes[handoffID] = codeEntry{code: code, expiresAt: rec.ExpiresAt}
	h.mu.Unlock()

	digest := sha256Hex(code)
	err = h.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.RecordGitHubHandoffCallback(ctx, rec.WorkspaceID, handoffID, digest, now)
	})
	if err != nil {
		// A lost race against a concurrent duplicate callback must not
		// leave a second code cached.
		h.mu.Lock()
		delete(h.codes, handoffID)
		h.mu.Unlock()
		return "", err
	}
	return h.completionPath, nil
}

// evictExpiredCodesLocked drops expired cache entries. Callers hold h.mu.
func (h *Handoff) evictExpiredCodesLocked(now time.Time) {
	for id, e := range h.codes {
		if !e.expiresAt.After(now) {
			delete(h.codes, id)
		}
	}
}

// evictOldestCodeLocked drops an arbitrary entry when the cache is full.
// Callers hold h.mu. Expiry eviction runs first, so this only triggers
// under sustained callback load.
func (h *Handoff) evictOldestCodeLocked() {
	for id := range h.codes {
		delete(h.codes, id)
		return
	}
}

// cachedCode returns the raw code for a handoff, if present and unexpired.
func (h *Handoff) cachedCode(handoffID string, now time.Time) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.codes[handoffID]
	if !ok || !e.expiresAt.After(now) {
		delete(h.codes, handoffID)
		return "", false
	}
	return e.code, true
}

// dropCachedCode removes the raw code after a settled outcome.
func (h *Handoff) dropCachedCode(handoffID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.codes, handoffID)
}

// Finish completes the handoff through AuthScope. It requires the
// original authenticated session, verifies the cached binding code
// against the durable digest in constant time, persists an operation
// intent, and calls FinishGitHubBinding exactly once per idempotency
// key. On an ambiguous failure it reconciles by the original key and
// replays with the same key instead of repeating the mutation. The raw
// code is cleared after a settled or reconciled outcome.
//
// Finish is serialized per handoff ID: two callers with different
// idempotency keys cannot issue concurrent upstream finish calls for the
// same handoff, so at most one upstream mutation ever happens per
// handoff.
func (h *Handoff) Finish(ctx context.Context, workspaceID, sessionID, handoffID, idempotencyKey string) (FinishResult, error) {
	if workspaceID == "" || sessionID == "" || handoffID == "" {
		return FinishResult{}, fmt.Errorf("%w: workspace, session, and handoff are required", ErrInvalidInput)
	}
	// The idempotency record is consulted before the handoff row: a
	// completed operation replays its stored result even though the
	// handoff is consumed. The canonical digest binds the session, so a
	// different session cannot replay this key.
	digest := canonicalDigest("ope/github-finish/v1", workspaceID, sessionID, handoffID)
	idem, err := h.beginIdempotency(ctx, workspaceID, idempotencyKey, digest)
	if err != nil {
		return FinishResult{}, err
	}
	if idem.Replay && idem.Completed {
		var res FinishResult
		if err := json.Unmarshal(idem.Result, &res); err != nil {
			return FinishResult{}, fmt.Errorf("github: corrupt stored finish result: %w", err)
		}
		return res, nil
	}
	unlock := h.finishLocks.lock(handoffID)
	defer unlock()
	rec, err := h.store.GetGitHubHandoff(ctx, workspaceID, handoffID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return FinishResult{}, ErrHandoffNotFound
		}
		return FinishResult{}, err
	}
	now := h.now()
	if !equalStringConstTime(rec.SessionID, sessionID) {
		return FinishResult{}, ErrSessionMismatch
	}
	if !rec.ExpiresAt.After(now) {
		return FinishResult{}, ErrHandoffExpired
	}
	if rec.ConsumedAt != nil {
		return FinishResult{}, fmt.Errorf("%w: handoff already consumed", ErrInvalidInput)
	}
	if rec.CallbackAt == nil || rec.BindingCodeDigest == "" {
		return FinishResult{}, ErrCallbackMissing
	}
	code, ok := h.cachedCode(handoffID, now)
	if !ok {
		return FinishResult{}, ErrBindingCodeUnavailable
	}
	presented := sha256.Sum256([]byte(code))
	stored, err := hex.DecodeString(rec.BindingCodeDigest)
	if err != nil || len(stored) != 32 {
		return FinishResult{}, fmt.Errorf("github: corrupt stored binding-code digest")
	}
	if subtle.ConstantTimeCompare(presented[:], stored) != 1 {
		return FinishResult{}, ErrBindingCodeMismatch
	}

	if idem.Replay {
		if settled, rerr := h.reconcileFinish(ctx, workspaceID, handoffID, idempotencyKey, code); rerr == nil && settled.Connection.ConnectionID != "" {
			return settled, nil
		} else if rerr != nil {
			return FinishResult{}, rerr
		}
	}

	binding, err := h.finishUpstream(ctx, workspaceID, rec.UpstreamHandoffID, code, idempotencyKey)
	if err != nil {
		return FinishResult{}, err
	}
	return h.settleFinish(ctx, workspaceID, handoffID, idempotencyKey, code, binding)
}

// finishUpstream calls FinishGitHubBinding once; on an ambiguous failure
// it reconciles by the original key and replays with the same key rather
// than repeating the mutation.
func (h *Handoff) finishUpstream(ctx context.Context, workspaceID, upstreamHandoffID, code, idempotencyKey string) (coreapi.RepositoryBinding, error) {
	uctx, cancel := h.upstreamCtx(ctx)
	defer cancel()
	binding, err := h.authority.FinishGitHubBinding(uctx,
		coreapi.GitHubBindingFinishRequest{HandoffID: upstreamHandoffID, BindingCode: code},
		coreapi.RequestOptions{WorkspaceID: workspaceID, IdempotencyKey: idempotencyKey})
	if err == nil {
		return binding, nil
	}
	if !isAmbiguous(err) {
		return coreapi.RepositoryBinding{}, err
	}
	outcome, rerr := h.reconcileOperation(ctx, workspaceID, idempotencyKey)
	if rerr != nil {
		return coreapi.RepositoryBinding{}, rerr
	}
	switch outcome {
	case reconcileCompleted:
		return h.finishUpstreamReplay(ctx, workspaceID, upstreamHandoffID, code, idempotencyKey)
	case reconcileInflight:
		return coreapi.RepositoryBinding{}, ErrOperationInFlight
	default:
		// Absent after an ambiguous failure: the timed-out call may
		// still have consumed the one-use code. Do not repeat inside
		// this request; the caller retries with the same key and
		// reconciles again.
		return coreapi.RepositoryBinding{}, ErrPendingReconciliation
	}
}

// finishUpstreamReplay re-issues the finish with the identical idempotency
// key after reconciliation proved the operation completed. AuthScope must
// return the original binding for a repeated key; this is a replay, not a
// new mutation. The one-use binding code stays valid for the replayed key.
func (h *Handoff) finishUpstreamReplay(ctx context.Context, workspaceID, upstreamHandoffID, code, idempotencyKey string) (coreapi.RepositoryBinding, error) {
	uctx, cancel := h.upstreamCtx(ctx)
	defer cancel()
	binding, err := h.authority.FinishGitHubBinding(uctx,
		coreapi.GitHubBindingFinishRequest{HandoffID: upstreamHandoffID, BindingCode: code},
		coreapi.RequestOptions{WorkspaceID: workspaceID, IdempotencyKey: idempotencyKey})
	if err != nil {
		return coreapi.RepositoryBinding{}, ErrPendingReconciliation
	}
	return binding, nil
}

// reconcileFinish reconciles an unsettled finish by idempotency key: a
// completed operation replays with the same key, an in-flight operation
// reports ErrOperationInFlight, and an absent operation reports
// not-settled so the caller may proceed as new with the same key.
func (h *Handoff) reconcileFinish(ctx context.Context, workspaceID, handoffID, idempotencyKey, code string) (FinishResult, error) {
	rec, err := h.store.GetGitHubHandoff(ctx, workspaceID, handoffID)
	if err != nil {
		return FinishResult{}, err
	}
	outcome, err := h.reconcileOperation(ctx, workspaceID, idempotencyKey)
	if err != nil {
		return FinishResult{}, err
	}
	switch outcome {
	case reconcileCompleted:
		binding, err := h.finishUpstreamReplay(ctx, workspaceID, rec.UpstreamHandoffID, code, idempotencyKey)
		if err != nil {
			return FinishResult{}, ErrPendingReconciliation
		}
		return h.settleFinish(ctx, workspaceID, handoffID, idempotencyKey, code, binding)
	case reconcileInflight:
		return FinishResult{}, ErrOperationInFlight
	default:
		return FinishResult{}, nil
	}
}

// settleFinish validates the binding, persists the connection
// transactionally (replacing any revoked binding), consumes the handoff,
// clears the raw code, and records the settled result.
func (h *Handoff) settleFinish(ctx context.Context, workspaceID, handoffID, idempotencyKey, code string, binding coreapi.RepositoryBinding) (FinishResult, error) {
	if binding.BindingID == "" || binding.RepositoryID == "" || binding.InstallationID == "" {
		return FinishResult{}, fmt.Errorf("%w: upstream binding is incomplete", ErrUpstreamDenied)
	}
	if !equalStringConstTime(binding.WorkspaceID, workspaceID) {
		return FinishResult{}, ErrWorkspaceMismatch
	}
	installationID, err := parseGitHubID(binding.InstallationID)
	if err != nil {
		return FinishResult{}, fmt.Errorf("%w: installation ID: %v", ErrInvalidInput, err)
	}
	repositoryID, err := parseGitHubID(binding.RepositoryID)
	if err != nil {
		return FinishResult{}, fmt.Errorf("%w: repository ID: %v", ErrInvalidInput, err)
	}
	now := h.now()
	conn := store.ConnectionRecord{
		WorkspaceID:          workspaceID,
		ConnectionID:         binding.BindingID,
		RepositoryBindingRef: binding.BindingID,
		InstallationID:       installationID,
		RepositoryID:         repositoryID,
		RepositoryName:       binding.Repository,
		PermissionStatus:     "ok",
		VerifiedAt:           now,
		CreatedAt:            now,
	}
	// Reconnection replaces a revoked binding transactionally: drop every
	// other connection of the workspace in the same transaction that
	// persists the new binding. Later tasks key missions off the
	// connection ID, so a replaced binding never reuses the revoked
	// binding's missions.
	existing, err := h.store.ListConnections(ctx, workspaceID)
	if err != nil {
		return FinishResult{}, err
	}
	res := FinishResult{Connection: conn}
	raw, err := json.Marshal(res)
	if err != nil {
		return FinishResult{}, fmt.Errorf("github: cannot encode idempotent result: %w", err)
	}
	// The connection, the consumed handoff, and the completed idempotency
	// record commit atomically. A crash before the commit leaves the
	// handoff unconsumed, so the retry reconciles and replays upstream
	// with the same key; a crash after the commit replays the stored
	// result. A concurrent second finish loses the consume race and fails
	// closed without a second upstream mutation.
	err = h.store.WithTx(ctx, func(tx store.Tx) error {
		for _, e := range existing {
			if e.ConnectionID != conn.ConnectionID {
				if err := tx.DeleteConnection(ctx, workspaceID, e.ConnectionID); err != nil {
					return err
				}
			}
		}
		if err := tx.PutConnection(ctx, conn); err != nil {
			return err
		}
		if err := tx.ConsumeGitHubHandoff(ctx, workspaceID, handoffID, now); err != nil {
			return err
		}
		return tx.CompleteIdempotency(ctx, workspaceID, idempotencyKey, raw)
	})
	if err != nil {
		return FinishResult{}, err
	}
	h.dropCachedCode(handoffID)
	return res, nil
}

// parseGitHubID parses an immutable GitHub numeric ID. Non-numeric IDs
// fail closed: OPE must never mistake one repository for another.
func parseGitHubID(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty ID")
	}
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a numeric ID")
		}
		n = n*10 + int64(c-'0')
		if n < 0 {
			return 0, fmt.Errorf("ID out of range")
		}
	}
	if n <= 0 {
		return 0, fmt.Errorf("ID must be positive")
	}
	return n, nil
}

// sortedUnique returns the sorted unique elements of in.
func sortedUnique(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
