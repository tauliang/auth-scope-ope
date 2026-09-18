package authn

// One-use browser PKCE handoff for CLI launch authorization.
//
// A CLI that wants to launch an approved pass has no browser session, so
// it cannot complete a passkey ceremony itself. Instead it opens a
// pending CLI authorization (Create), prints a browser URL, and waits on a
// loopback callback. The founder reviews the exact approved launch binding
// in the browser and completes a WebAuthn decision ceremony (Begin/Finish
//BrowserDecision). Finish mints a single 256-bit authorization code,
// stores only its SHA-256 hash, signs a cli_launch_authorization
// attestation for the authscope:prepare-launch audience, and redirects the
// code plus the original state to the CLI's loopback callback. The signed
// attestation lives only in the bounded in-memory PendingDecisionAttestations
// cache: a process restart loses it and invalidates pre-exchange approval.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/tauliang/authscope-ope/internal/identity"
	"github.com/tauliang/authscope-ope/internal/store"
)

var (
	// ErrInvalidPKCE reports PKCE parameters that fail validation. Only
	// the S256 method is accepted.
	ErrInvalidPKCE = errors.New("authn: invalid PKCE parameters")
	// ErrInvalidRedirectURI reports a redirect URI that is not the exact
	// loopback callback form.
	ErrInvalidRedirectURI = errors.New("authn: invalid redirect URI")
	// ErrInvalidEphemeralKey reports a malformed ephemeral X25519 public
	// key.
	ErrInvalidEphemeralKey = errors.New("authn: invalid ephemeral public key")
	// ErrPassNotApproved reports a CLI authorization for a pass that is
	// not in the approved state with a complete launch binding.
	ErrPassNotApproved = errors.New("authn: pass is not approved for launch")
	// ErrCLIAuthorizationNotFound reports an unknown CLI authorization or
	// pass.
	ErrCLIAuthorizationNotFound = errors.New("authn: CLI authorization not found")
	// ErrCLIAuthorizationConflict reports a canonical request that changed
	// under an existing authorization, or a second browser decision on an
	// already-approved authorization.
	ErrCLIAuthorizationConflict = errors.New("authn: CLI authorization conflict")
	// ErrCLIAuthorizationExpired reports a CLI authorization past its
	// two-minute expiry.
	ErrCLIAuthorizationExpired = errors.New("authn: CLI authorization expired")
	// ErrCLIBindingChanged reports an approved launch binding that moved
	// between browser begin and finish. The authorization is not consumed.
	ErrCLIBindingChanged = errors.New("authn: approved launch binding changed")
)

// approvedPassState is the mission pass state a CLI authorization requires.
const approvedPassState = "approved"

// pkceCodeLength is the raw byte length of PKCE verifiers, states, and
// authorization codes: 256 bits each.
const pkceCodeLength = 32

// cliAuthorizationTTL is the lifetime of a pending CLI authorization. The
// founder must complete the browser decision inside this window.
const cliAuthorizationTTL = 2 * time.Minute

// cliAttestationTTL is the lifetime of the signed launch attestation. The
// Task 9 exchange consumes it inside the authorization window.
const cliAttestationTTL = 2 * time.Minute

// NewPKCEVerifier generates a fresh 256-bit PKCE verifier (or state)
// encoded as base64url without padding.
func NewPKCEVerifier() (string, error) {
	raw, err := randomBytes(pkceCodeLength)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// CodeChallengeS256 derives the S256 code challenge for a verifier.
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyCodeChallenge checks a verifier against an S256 challenge in
// constant time. Only S256 is accepted; there is no plain fallback.
func VerifyCodeChallenge(challenge, verifier string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil || len(raw) != pkceCodeLength {
		return false
	}
	expected := CodeChallengeS256(verifier)
	if len(expected) != len(challenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) == 1
}

// ValidateLoopbackRedirectURI enforces the exact loopback callback form:
// http://127.0.0.1:<port>/callback with an unprivileged port. It rejects
// localhost, IPv6, other hosts, privileged ports, and any path, query,
// fragment, or userinfo beyond /callback. It returns the normalized URI.
func ValidateLoopbackRedirectURI(rawURI string) (string, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return "", fmt.Errorf("%w: unparsable", ErrInvalidRedirectURI)
	}
	if u.Scheme != "http" {
		return "", fmt.Errorf("%w: scheme must be http", ErrInvalidRedirectURI)
	}
	if u.Hostname() != "127.0.0.1" {
		return "", fmt.Errorf("%w: host must be 127.0.0.1", ErrInvalidRedirectURI)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1024 || port > 65535 {
		return "", fmt.Errorf("%w: port must be 1024-65535", ErrInvalidRedirectURI)
	}
	if u.EscapedPath() != "/callback" {
		return "", fmt.Errorf("%w: path must be /callback", ErrInvalidRedirectURI)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("%w: no query, fragment, or userinfo", ErrInvalidRedirectURI)
	}
	return fmt.Sprintf("http://127.0.0.1:%d/callback", port), nil
}

// validateEphemeralPublicKey checks a base64url-encoded 32-byte X25519
// public key.
func validateEphemeralPublicKey(encoded string) ([32]byte, error) {
	var zero [32]byte
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != pkceCodeLength {
		return zero, fmt.Errorf("%w: must be base64url 32 bytes", ErrInvalidEphemeralKey)
	}
	var out [32]byte
	copy(out[:], raw)
	return out, nil
}

// EphemeralX25519Keypair generates a fresh X25519 keypair for one CLI
// authorization. The private key stays in CLI memory only.
func EphemeralX25519Keypair() (priv, pub [32]byte, err error) {
	raw, err := randomBytes(pkceCodeLength)
	if err != nil {
		return priv, pub, err
	}
	copy(priv[:], raw)
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		var zero [32]byte
		priv = zero
		return priv, pub, fmt.Errorf("authn: x25519: %w", err)
	}
	copy(pub[:], p)
	return priv, pub, nil
}

// InvocationDigestForLaunch is OPE's pinned canonicalization of the launch
// binding: agent-kit ID/version plus the ordered runner arguments,
// domain-separated and hashed with SHA-256. The CLI recomputes it and
// rejects any mismatch with the authoritative stored digest, which fails
// the handoff closed when AuthScope's digest is unavailable or disagrees.
// It never replaces the stored authoritative digest.
func InvocationDigestForLaunch(agentKitID, agentKitVersion string, runnerArgs []string) string {
	args := runnerArgs
	if args == nil {
		args = []string{}
	}
	raw, err := json.Marshal(struct {
		Domain          string   `json:"domain"`
		AgentKitID      string   `json:"agent_kit_id"`
		AgentKitVersion string   `json:"agent_kit_version"`
		RunnerArguments []string `json:"runner_arguments"`
	}{
		Domain:          "authscope-ope/cli-launch/v1",
		AgentKitID:      agentKitID,
		AgentKitVersion: agentKitVersion,
		RunnerArguments: args,
	})
	if err != nil {
		// json.Marshal of this struct cannot fail; fail closed anyway.
		return "sha256:" + strings.Repeat("0", 64)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// CLIAuthorizationRequest is the CLI's unauthenticated request to open a
// pending authorization. It carries no command or argument fields: the
// launch binding comes only from the approved pass.
type CLIAuthorizationRequest struct {
	PassID              string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	EphemeralPublicKey  string
}

// CLIAuthorizationStart is the pending authorization returned to the CLI.
type CLIAuthorizationStart struct {
	ID               string
	BrowserURL       string
	ProposalDigest   string
	AgentKitID       string
	AgentKitVersion  string
	RunnerArguments  []string
	InvocationDigest string
}

// BegunCLIAuthorization is the browser decision the founder reviews.
type BegunCLIAuthorization struct {
	ChallengeID      string
	OptionsJSON      json.RawMessage
	PassID           string
	RepositoryName   string
	IssueNumber      int64
	ProposalDigest   string
	InvocationDigest string
	AgentKitID       string
	AgentKitVersion  string
	RunnerArguments  []string
}

// CLIAuthorizationConfig wires the CLI authorization service.
type CLIAuthorizationConfig struct {
	Store          store.Store
	Authn          *Service
	Attestor       *identity.DecisionAttestor
	BrowserBaseURL string
	Clock          func() time.Time
}

// CLIAuthorizationService opens pending CLI authorizations and runs the
// founder's browser decision over them.
type CLIAuthorizationService struct {
	store    store.Store
	authn    *Service
	attestor *identity.DecisionAttestor
	baseURL  string
	clock    func() time.Time
	cache    *PendingDecisionAttestations
}

// NewCLIAuthorizationService wires the service. BrowserBaseURL is the
// public origin the printed browser URL points at.
func NewCLIAuthorizationService(cfg CLIAuthorizationConfig) (*CLIAuthorizationService, error) {
	if cfg.Store == nil {
		return nil, errors.New("authn: CLI authorization store is required")
	}
	if cfg.Authn == nil {
		return nil, errors.New("authn: CLI authorization authn service is required")
	}
	if cfg.Attestor == nil {
		return nil, errors.New("authn: CLI authorization attestor is required")
	}
	if cfg.BrowserBaseURL == "" {
		return nil, errors.New("authn: CLI authorization browser base URL is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &CLIAuthorizationService{
		store:    cfg.Store,
		authn:    cfg.Authn,
		attestor: cfg.Attestor,
		baseURL:  strings.TrimSuffix(cfg.BrowserBaseURL, "/"),
		clock:    clock,
		cache:    NewPendingDecisionAttestations(),
	}, nil
}

// Attestations returns the bounded in-memory cache holding signed launch
// attestations pending the Task 9 code exchange.
func (s *CLIAuthorizationService) Attestations() *PendingDecisionAttestations {
	return s.cache
}

// workspaceID is the single instance workspace CLI authorizations bind to.
func (s *CLIAuthorizationService) workspaceID() string {
	return s.authn.Instance().WorkspaceID
}

// launchBinding is the exact approved launch binding a CLI authorization
// carries.
type launchBinding struct {
	PassID           string
	MissionRef       string
	MissionVersion   int64
	ProposalDigest   string
	InvocationDigest string
	AgentKitID       string
	AgentKitVersion  string
	RunnerArguments  []string
	RepositoryName   string
	IssueNumber      int64
}

// loadLaunchBinding loads the pass and requires the exact approved launch
// binding. It grants no runtime authority; it only reads the immutable
// instance workspace's pass record.
func (s *CLIAuthorizationService) loadLaunchBinding(ctx context.Context, passID string) (*launchBinding, error) {
	if passID == "" {
		return nil, ErrCLIAuthorizationNotFound
	}
	rec, err := s.store.GetMissionPass(ctx, s.workspaceID(), passID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrCLIAuthorizationNotFound
		}
		return nil, err
	}
	if rec.State != approvedPassState {
		return nil, fmt.Errorf("%w: state is %q", ErrPassNotApproved, rec.State)
	}
	// Task 8: the pass must be approved and unexpired at every step of
	// the handoff, not just at create.
	if !s.clock().UTC().Before(rec.ExpiresAt) {
		return nil, fmt.Errorf("%w: pass expired", ErrPassNotApproved)
	}
	b := &launchBinding{
		PassID:           rec.PassID,
		MissionRef:       rec.MissionRef,
		MissionVersion:   rec.AuthScopeMissionVersion,
		ProposalDigest:   rec.ApprovedProposalDigest,
		InvocationDigest: rec.InvocationDigest,
		AgentKitID:       rec.AgentKitID,
		AgentKitVersion:  rec.AgentKitVersion,
		RunnerArguments:  append([]string{}, rec.RunnerArguments...),
		RepositoryName:   rec.RepositoryName,
		IssueNumber:      rec.IssueNumber,
	}
	if b.ProposalDigest == "" || b.MissionRef == "" || b.MissionVersion <= 0 ||
		b.InvocationDigest == "" || b.AgentKitID == "" || b.AgentKitVersion == "" ||
		len(b.RunnerArguments) == 0 {
		return nil, fmt.Errorf("%w: incomplete launch binding", ErrPassNotApproved)
	}
	return b, nil
}

// canonicalRequestDigest binds the canonical idempotency digest to the
// exact request fields and approved values.
func canonicalRequestDigest(req CLIAuthorizationRequest, b *launchBinding) [32]byte {
	raw, _ := json.Marshal(struct {
		Domain           string   `json:"domain"`
		PassID           string   `json:"pass_id"`
		RedirectURI      string   `json:"redirect_uri"`
		State            string   `json:"state"`
		CodeChallenge    string   `json:"code_challenge"`
		EphemeralPubKey  string   `json:"ephemeral_public_key"`
		ProposalDigest   string   `json:"proposal_digest"`
		InvocationDigest string   `json:"invocation_digest"`
		AgentKitID       string   `json:"agent_kit_id"`
		AgentKitVersion  string   `json:"agent_kit_version"`
		RunnerArguments  []string `json:"runner_arguments"`
		MissionRef       string   `json:"mission_ref"`
		MissionVersion   int64    `json:"mission_version"`
	}{
		Domain:           "authscope-ope/cli-authorization-request/v1",
		PassID:           req.PassID,
		RedirectURI:      req.RedirectURI,
		State:            req.State,
		CodeChallenge:    req.CodeChallenge,
		EphemeralPubKey:  req.EphemeralPublicKey,
		ProposalDigest:   b.ProposalDigest,
		InvocationDigest: b.InvocationDigest,
		AgentKitID:       b.AgentKitID,
		AgentKitVersion:  b.AgentKitVersion,
		RunnerArguments:  b.RunnerArguments,
		MissionRef:       b.MissionRef,
		MissionVersion:   b.MissionVersion,
	})
	return sha256.Sum256(raw)
}

// validateCreateRequest enforces the strict PKCE, redirect, and ephemeral
// key rules before any state is touched.
func validateCreateRequest(req CLIAuthorizationRequest) (redirectURI string, err error) {
	if req.CodeChallengeMethod != "S256" {
		return "", fmt.Errorf("%w: only S256 is accepted", ErrInvalidPKCE)
	}
	stateRaw, err := base64.RawURLEncoding.DecodeString(req.State)
	if err != nil || len(stateRaw) != pkceCodeLength {
		return "", fmt.Errorf("%w: state must be base64url 256-bit", ErrInvalidPKCE)
	}
	challengeRaw, err := base64.RawURLEncoding.DecodeString(req.CodeChallenge)
	if err != nil || len(challengeRaw) != pkceCodeLength {
		return "", fmt.Errorf("%w: code challenge must be base64url SHA-256", ErrInvalidPKCE)
	}
	if _, err := validateEphemeralPublicKey(req.EphemeralPublicKey); err != nil {
		return "", err
	}
	redirectURI, err = ValidateLoopbackRedirectURI(req.RedirectURI)
	if err != nil {
		return "", err
	}
	return redirectURI, nil
}

// startFor builds the CLI-facing start payload for a stored record.
func startFor(rec store.CLIAuthorization, baseURL string) CLIAuthorizationStart {
	return CLIAuthorizationStart{
		ID:               rec.AuthorizationID,
		BrowserURL:       baseURL + "/authorize/cli/" + rec.AuthorizationID,
		ProposalDigest:   rec.ProposalDigest,
		AgentKitID:       rec.AgentKitID,
		AgentKitVersion:  rec.AgentKitVersion,
		RunnerArguments:  append([]string{}, rec.RunnerArguments...),
		InvocationDigest: rec.InvocationDigest,
	}
}

// Create opens a pending CLI authorization bound to the exact approved
// launch binding. The same canonical request replays the same pending
// authorization; changed content conflicts. It grants no runtime authority.
// replayCreate returns the start for an existing authorization when its
// canonical request digest matches the caller's, or fails closed when the
// record expired or the request moved.
func (s *CLIAuthorizationService) replayCreate(existing store.CLIAuthorization, wantDigest [32]byte, now time.Time) (CLIAuthorizationStart, bool, error) {
	if now.After(existing.ExpiresAt) {
		return CLIAuthorizationStart{}, false, ErrCLIAuthorizationExpired
	}
	// The record pins the exact canonical request digest from create time,
	// including the mission reference and version. A changed binding
	// conflicts instead of replaying.
	if existing.CanonicalRequestDigest != wantDigest {
		return CLIAuthorizationStart{}, false, ErrCLIAuthorizationConflict
	}
	return startFor(existing, s.baseURL), true, nil
}

func (s *CLIAuthorizationService) Create(ctx context.Context, req CLIAuthorizationRequest) (CLIAuthorizationStart, bool, error) {
	redirectURI, err := validateCreateRequest(req)
	if err != nil {
		return CLIAuthorizationStart{}, false, err
	}
	ws := s.workspaceID()
	binding, err := s.loadLaunchBinding(ctx, req.PassID)
	if err != nil {
		return CLIAuthorizationStart{}, false, err
	}
	now := s.clock().UTC()
	wantDigest := canonicalRequestDigest(CLIAuthorizationRequest{
		PassID: req.PassID, RedirectURI: redirectURI, State: req.State,
		CodeChallenge: req.CodeChallenge, EphemeralPublicKey: req.EphemeralPublicKey,
	}, binding)

	// Idempotent replay: the same state for the same pass either replays
	// the identical canonical request or conflicts.
	if existing, err := s.store.GetCLIAuthorizationByState(ctx, ws, req.PassID, req.State); err == nil {
		return s.replayCreate(existing, wantDigest, now)
	} else if !errors.Is(err, store.ErrNotFound) {
		return CLIAuthorizationStart{}, false, err
	}

	id, err := newCeremonyID()
	if err != nil {
		return CLIAuthorizationStart{}, false, err
	}
	rec := store.CLIAuthorization{
		WorkspaceID:            ws,
		AuthorizationID:        "cliauth-" + id,
		PassID:                 req.PassID,
		State:                  req.State,
		CodeChallenge:          req.CodeChallenge,
		RedirectURI:            redirectURI,
		EphemeralPublicKey:     req.EphemeralPublicKey,
		ProposalDigest:         binding.ProposalDigest,
		InvocationDigest:       binding.InvocationDigest,
		AgentKitID:             binding.AgentKitID,
		AgentKitVersion:        binding.AgentKitVersion,
		RunnerArguments:        append([]string{}, binding.RunnerArguments...),
		MissionRef:             binding.MissionRef,
		MissionVersion:         binding.MissionVersion,
		CanonicalRequestDigest: wantDigest,
		ExpiresAt:              now.Add(cliAuthorizationTTL),
		CreatedAt:              now,
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutCLIAuthorization(ctx, rec)
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Lost a concurrent create race on (workspace, pass, state):
			// the unique constraint kept exactly one row. Replay the
			// winner when the canonical request matches, conflict
			// otherwise.
			existing, gerr := s.store.GetCLIAuthorizationByState(ctx, ws, req.PassID, req.State)
			if gerr != nil {
				return CLIAuthorizationStart{}, false, ErrCLIAuthorizationConflict
			}
			return s.replayCreate(existing, wantDigest, now)
		}
		return CLIAuthorizationStart{}, false, err
	}
	return startFor(rec, s.baseURL), false, nil
}

// beginBinding loads the authorization and its current launch binding for
// the browser decision, failing closed on expiry, approval, or workspace
// mismatch.
func (s *CLIAuthorizationService) beginBinding(ctx context.Context, workspaceID, authorizationID string) (store.CLIAuthorization, *launchBinding, error) {
	rec, err := s.store.GetCLIAuthorization(ctx, s.workspaceID(), authorizationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.CLIAuthorization{}, nil, ErrCLIAuthorizationNotFound
		}
		return store.CLIAuthorization{}, nil, err
	}
	if workspaceID != s.workspaceID() {
		return store.CLIAuthorization{}, nil, fmt.Errorf("%w: workspace mismatch", ErrDecisionBinding)
	}
	now := s.clock().UTC()
	if now.After(rec.ExpiresAt) {
		return store.CLIAuthorization{}, nil, ErrCLIAuthorizationExpired
	}
	if rec.ApprovedAt != nil {
		return store.CLIAuthorization{}, nil, ErrCLIAuthorizationConflict
	}
	binding, err := s.loadLaunchBinding(ctx, rec.PassID)
	if err != nil {
		return store.CLIAuthorization{}, nil, err
	}
	// The record pins the exact approved values at create time. If the
	// live pass drifted from the pinned binding, fail closed instead of
	// silently rebinding the decision.
	if !bindingMatchesRecord(rec, binding) {
		return store.CLIAuthorization{}, nil, ErrCLIBindingChanged
	}
	return rec, binding, nil
}

// bindingMatchesRecord reports whether the reloaded launch binding still
// matches every exact approved value pinned in the authorization record.
func bindingMatchesRecord(rec store.CLIAuthorization, b *launchBinding) bool {
	return rec.ProposalDigest == b.ProposalDigest &&
		rec.InvocationDigest == b.InvocationDigest &&
		rec.AgentKitID == b.AgentKitID &&
		rec.AgentKitVersion == b.AgentKitVersion &&
		rec.MissionRef == b.MissionRef &&
		rec.MissionVersion == b.MissionVersion &&
		slices.Equal(rec.RunnerArguments, b.RunnerArguments)
}

// canonicalBeginBytes is the exact byte string the browser decision binds:
// authorization, workspace (through the ceremony), pass, mission, approved
// digests, kit, ordered arguments, callback, PKCE challenge, and ephemeral
// public key. The challenge nonce is bound by BeginDecision itself.
func canonicalBeginBytes(rec store.CLIAuthorization, b *launchBinding) []byte {
	raw, _ := json.Marshal(struct {
		Domain             string   `json:"domain"`
		AuthorizationID    string   `json:"authorization_id"`
		PassID             string   `json:"pass_id"`
		MissionRef         string   `json:"mission_ref"`
		MissionVersion     int64    `json:"mission_version"`
		ProposalDigest     string   `json:"proposal_digest"`
		InvocationDigest   string   `json:"invocation_digest"`
		AgentKitID         string   `json:"agent_kit_id"`
		AgentKitVersion    string   `json:"agent_kit_version"`
		RunnerArguments    []string `json:"runner_arguments"`
		RedirectURI        string   `json:"redirect_uri"`
		CodeChallenge      string   `json:"code_challenge"`
		EphemeralPublicKey string   `json:"ephemeral_public_key"`
	}{
		Domain:             "authscope-ope/cli-launch-decision/v1",
		AuthorizationID:    rec.AuthorizationID,
		PassID:             b.PassID,
		MissionRef:         b.MissionRef,
		MissionVersion:     b.MissionVersion,
		ProposalDigest:     b.ProposalDigest,
		InvocationDigest:   b.InvocationDigest,
		AgentKitID:         b.AgentKitID,
		AgentKitVersion:    b.AgentKitVersion,
		RunnerArguments:    b.RunnerArguments,
		RedirectURI:        rec.RedirectURI,
		CodeChallenge:      rec.CodeChallenge,
		EphemeralPublicKey: rec.EphemeralPublicKey,
	})
	return raw
}

// BeginBrowserDecision opens the founder's WebAuthn decision over the exact
// launch binding. The browser shows the pass, repository, issue, kit, and
// ordered arguments before the founder touches their passkey.
func (s *CLIAuthorizationService) BeginBrowserDecision(ctx context.Context, p Principal, authorizationID string) (*BegunCLIAuthorization, error) {
	rec, binding, err := s.beginBinding(ctx, p.WorkspaceID, authorizationID)
	if err != nil {
		return nil, err
	}
	challenge, options, err := s.authn.BeginDecision(ctx, p, DecisionCLILaunchAuthorization, rec.AuthorizationID, canonicalBeginBytes(rec, binding))
	if err != nil {
		return nil, err
	}
	return &BegunCLIAuthorization{
		ChallengeID:      challenge.ChallengeID,
		OptionsJSON:      options,
		PassID:           binding.PassID,
		RepositoryName:   binding.RepositoryName,
		IssueNumber:      binding.IssueNumber,
		ProposalDigest:   binding.ProposalDigest,
		InvocationDigest: binding.InvocationDigest,
		AgentKitID:       binding.AgentKitID,
		AgentKitVersion:  binding.AgentKitVersion,
		RunnerArguments:  append([]string{}, binding.RunnerArguments...),
	}, nil
}

// FinishBrowserDecision verifies the founder's assertion, signs the launch
// attestation, mints the single 256-bit code, and returns the loopback
// redirect carrying the code and the original state. The signed attestation
// is kept only in the bounded in-memory cache; the store keeps the code
// hash and the attestation digest.
func (s *CLIAuthorizationService) FinishBrowserDecision(ctx context.Context, p Principal, authorizationID, challengeID string, assertion []byte) (string, error) {
	rec, binding, err := s.beginBinding(ctx, p.WorkspaceID, authorizationID)
	if err != nil {
		return "", err
	}
	canonical := canonicalBeginBytes(rec, binding)
	verified, err := s.authn.FinishDecision(ctx, p, challengeID, DecisionCLILaunchAuthorization, rec.AuthorizationID, canonical, assertion)
	if err != nil {
		// A binding mismatch here means the approved launch binding moved
		// under the begun challenge. Surface it distinctly; the ceremony
		// is already consumed, but the authorization itself is untouched
		// and the founder can begin again.
		if errors.Is(err, ErrDecisionBinding) {
			return "", ErrCLIBindingChanged
		}
		return "", err
	}
	// Reload the approved pass and compare byte-for-byte with the binding
	// the challenge carried. This is the second line of defense after the
	// digest check inside FinishDecision.
	current, err := s.loadLaunchBinding(ctx, rec.PassID)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(canonicalBeginBytes(rec, current), canonical) {
		return "", ErrCLIBindingChanged
	}

	issuedAt := s.clock().UTC()
	proofDigest, err := cliCeremonyProofDigest(verified)
	if err != nil {
		return "", err
	}
	att, err := s.attestor.Attest(ctx, identity.DecisionClaims{
		WorkspaceID:               s.workspaceID(),
		FounderID:                 verified.FounderID,
		Audience:                  identity.AudiencePrepareLaunch,
		Purpose:                   identity.PurposeCLILaunchAuthorization,
		SubjectID:                 rec.AuthorizationID,
		DecisionDigest:            binding.ProposalDigest,
		InvocationDigest:          binding.InvocationDigest,
		AuthenticationMethod:      verified.Method,
		AuthenticationProofDigest: proofDigest,
		Nonce:                     verified.Nonce,
		IssuedAt:                  issuedAt,
		ExpiresAt:                 issuedAt.Add(cliAttestationTTL),
	})
	if err != nil {
		return "", fmt.Errorf("authn: sign launch attestation: %w", err)
	}
	attRaw, err := json.Marshal(att)
	if err != nil {
		return "", fmt.Errorf("authn: encode launch attestation: %w", err)
	}
	attSum := sha256.Sum256(attRaw)
	attDigest := "sha256:" + hex.EncodeToString(attSum[:])

	codeRaw, err := randomBytes(pkceCodeLength)
	if err != nil {
		return "", err
	}
	codeHash := sha256.Sum256(codeRaw)
	approvedAt := s.clock().UTC()

	// Atomically mark approved and store only the code hash plus the
	// attestation digest. The conditional update rejects a duplicate or
	// concurrent finish.
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.ApproveCLIAuthorization(ctx, s.workspaceID(), rec.AuthorizationID, challengeID, attDigest, codeHash, approvedAt)
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", ErrCLIAuthorizationConflict
		}
		return "", err
	}

	s.cache.Put(&PendingDecisionAttestation{
		AuthorizationID:   rec.AuthorizationID,
		Attestation:       att,
		AttestationDigest: attDigest,
		CodeHash:          codeHash,
		ExpiresAt:         rec.ExpiresAt,
	})

	code := base64.RawURLEncoding.EncodeToString(codeRaw)
	redirect := rec.RedirectURI + "?code=" + code + "&state=" + url.QueryEscape(rec.State)
	return redirect, nil
}

// cliCeremonyProofDigest covers the verified ceremony record without
// embedding the credential ID or the assertion.
func cliCeremonyProofDigest(verified *VerifiedDecision) (string, error) {
	raw, err := json.Marshal(struct {
		Method       string `json:"method"`
		ChallengeID  string `json:"challenge_id"`
		Nonce        string `json:"nonce"`
		WorkspaceID  string `json:"workspace_id"`
		SessionID    string `json:"session_id"`
		FounderID    string `json:"founder_id"`
		SubjectID    string `json:"subject_id"`
		Purpose      string `json:"purpose"`
		UserVerified bool   `json:"user_verified"`
	}{
		Method:       verified.Method,
		ChallengeID:  verified.ChallengeID,
		Nonce:        hex.EncodeToString(verified.Nonce[:]),
		WorkspaceID:  verified.WorkspaceID,
		SessionID:    verified.SessionID,
		FounderID:    verified.FounderID,
		SubjectID:    verified.SubjectID,
		Purpose:      string(verified.Purpose),
		UserVerified: verified.UserVerified,
	})
	if err != nil {
		return "", fmt.Errorf("authn: encode ceremony proof: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// PendingDecisionAttestation is the signed launch attestation waiting for
// the Task 9 code exchange. It lives only in process memory: a restart
// drops it and invalidates pre-exchange approval.
type PendingDecisionAttestation struct {
	AuthorizationID   string
	Attestation       identity.SignedDecisionAttestation
	AttestationDigest string
	CodeHash          [32]byte
	ExpiresAt         time.Time
}

// maxPendingAttestations bounds the in-memory cache.
const maxPendingAttestations = 64

// PendingDecisionAttestations is a bounded, one-use cache of signed launch
// attestations keyed by authorization ID.
type PendingDecisionAttestations struct {
	mu    sync.Mutex
	items map[string]*PendingDecisionAttestation
	order []string
}

// NewPendingDecisionAttestations returns an empty cache.
func NewPendingDecisionAttestations() *PendingDecisionAttestations {
	return &PendingDecisionAttestations{items: make(map[string]*PendingDecisionAttestation)}
}

// Put inserts an attestation, evicting the oldest entries beyond the bound.
func (c *PendingDecisionAttestations) Put(a *PendingDecisionAttestation) {
	if a == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[a.AuthorizationID]; !ok {
		c.order = append(c.order, a.AuthorizationID)
	}
	c.items[a.AuthorizationID] = a
	for len(c.order) > maxPendingAttestations {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.items, oldest)
	}
}

// Take removes and returns the attestation for id, exactly once. Expired
// entries are dropped and reported missing.
func (c *PendingDecisionAttestations) Take(id string) (*PendingDecisionAttestation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.items[id]
	if !ok {
		return nil, false
	}
	delete(c.items, id)
	for i, key := range c.order {
		if key == id {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	if time.Now().After(a.ExpiresAt) {
		return nil, false
	}
	return a, true
}

// EvictExpired drops entries past their expiry.
func (c *PendingDecisionAttestations) EvictExpired(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.order[:0]
	for _, key := range c.order {
		if a, ok := c.items[key]; ok && now.After(a.ExpiresAt) {
			delete(c.items, key)
			continue
		}
		kept = append(kept, key)
	}
	c.order = kept
}

// Len returns the number of cached attestations.
func (c *PendingDecisionAttestations) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
