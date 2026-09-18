// Package coreapi client: the narrow typed HTTP client for the upstream
// AuthScope mission-authority service. One injected http.Client carries a
// non-exportable workload signer on its transport; per-operation deadlines,
// disabled redirects, strict response decoding, and a 2 MiB response cap
// keep every call fail-closed. The transport never exposes a bearer token
// or signing key to callers.
package coreapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/identity"
)

// Authority is the narrow upstream surface OPE needs. Later services use
// this interface, never raw HTTP.
type Authority interface {
	Discover(context.Context) (Discovery, error)
	VerifyWorkspaceIdentity(context.Context, string) (WorkspaceIdentity, error)
	BeginGitHubBinding(context.Context, GitHubBindingBeginRequest, RequestOptions) (GitHubBindingHandoff, error)
	FinishGitHubBinding(context.Context, GitHubBindingFinishRequest, RequestOptions) (RepositoryBinding, error)
	GetRepositoryBinding(context.Context, string, RequestOptions) (RepositoryBinding, error)
	ReadGitHubIssue(context.Context, GitHubIssueRequest, RequestOptions) (GitHubIssueSnapshot, error)
	InspectWorkflowPosture(context.Context, WorkflowPostureRequest, RequestOptions) (WorkflowPosture, error)
	ListAgentKits(context.Context, RequestOptions) ([]AgentKit, error)
	ShapeMission(context.Context, ShapeMissionRequest, RequestOptions) (MissionDraft, error)
	CreateProposal(context.Context, CreateProposalRequest, RequestOptions) (Proposal, error)
	ApproveProposal(context.Context, string, identity.SignedDecisionAttestation, RequestOptions) (Mission, error)
	PrepareLaunch(context.Context, string, LaunchRequest, identity.SignedDecisionAttestation, RequestOptions) (LaunchArtifacts, error)
	IntrospectMission(context.Context, string, RequestOptions) (MissionStatus, error)
	RevokeMission(context.Context, string, RevokeRequest, identity.SignedDecisionAttestation, RequestOptions) (Revocation, error)
	ListExpansions(context.Context, string, RequestOptions) ([]Expansion, error)
	DecideExpansion(context.Context, string, ExpansionDecision, identity.SignedDecisionAttestation, RequestOptions) (ExpansionResult, error)
	ReadEvents(context.Context, string, string, RequestOptions) (EventPage, error)
	GetReceipt(context.Context, string, RequestOptions) (SignedReceipt, error)
	GetSigningKeys(context.Context, RequestOptions) (SigningKeyHistory, error)
	PublishGitHubCheck(context.Context, GitHubCheckRequest, RequestOptions) (GitHubCheckResult, error)
	ReconcileOperation(context.Context, string, string, RequestOptions) (OperationResult, error)
	ListActiveMissions(context.Context, RequestOptions) ([]ActiveMission, error)
	ContainWorkspace(context.Context, WorkspaceContainmentRequest, identity.SignedDecisionAttestation, RequestOptions) (WorkspaceContainment, error)
}

var (
	// ErrMissingWorkspace reports a request without a workspace scope.
	ErrMissingWorkspace = errors.New("coreapi: workspace_id is required")
	// ErrInvalidBaseURL reports a malformed AuthScope base URL.
	ErrInvalidBaseURL = errors.New("coreapi: invalid AuthScope base URL")
	// ErrInsecureBaseURL reports a non-HTTPS base URL outside development.
	ErrInsecureBaseURL = errors.New("coreapi: AuthScope base URL must use https outside development")
	// ErrNoSigner reports a client built without a workload signer.
	ErrNoSigner = errors.New("coreapi: workload signer is required")
	// ErrResponseTooLarge reports an upstream response over the 2 MiB cap.
	ErrResponseTooLarge = errors.New("coreapi: upstream response exceeds size cap")
	// ErrWorkspaceMismatch reports an identity bound to a different workspace.
	ErrWorkspaceMismatch = errors.New("coreapi: workload identity workspace mismatch")
	// ErrGateNotHealthy reports a business mutation attempted while the
	// compatibility gate is missing or stale.
	ErrGateNotHealthy = errors.New("coreapi: upstream compatibility gate is not healthy")
)

const (
	// maxResponseBytes caps every upstream response body at 2 MiB.
	maxResponseBytes = 2 << 20
	// maxRequestBodyBytes caps request bodies the client will sign and send.
	maxRequestBodyBytes = 8 << 20
	// defaultOpTimeout bounds one upstream operation.
	defaultOpTimeout = 15 * time.Second
)

// workloadAuthDomain separates transport authentication signatures from
// decision-attestation signatures.
const workloadAuthDomain = "authscope-ope/workload-auth/v1"

// sensitiveHeaders names headers whose values must never appear in errors
// or logs: authorization material, client certificates, workload
// signatures, decision attestations, and cookies.
var sensitiveHeaders = map[string]struct{}{
	"Authorization": {}, "Proxy-Authorization": {}, "Proxy-Authenticate": {},
	"Cookie": {}, "Set-Cookie": {},
	"X-Authscope-Workload-Signature": {}, "X-Authscope-Workload-Keyid": {},
	"X-Client-Cert": {}, "X-Ssl-Client-Cert": {}, "X-Forwarded-Tls-Client-Cert": {},
	"X-Decision-Attestation": {},
}

// redactHeaders returns a copy of h with sensitive values replaced.
func redactHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, v := range h {
		if _, ok := sensitiveHeaders[http.CanonicalHeaderKey(k)]; ok {
			out[k] = []string{"[redacted]"}
			continue
		}
		out[k] = v
	}
	return out
}

// workloadAuthTransport authenticates every request with the
// non-exportable workload signer. It signs a domain-separated payload of
// timestamp, method, path, and body digest, and sets only the key ID,
// timestamp, and signature headers. AuthScope derives the caller identity
// from this transport authentication, never from a client-selected header.
type workloadAuthTransport struct {
	signer identity.Signer
	base   http.RoundTripper
	clock  func() time.Time
}

// workloadAuthPayload builds the exact signed payload. Tests use it to
// verify transport signatures independently.
func workloadAuthPayload(timestamp, method, path, bodyDigestHex string) []byte {
	return []byte(strings.Join([]string{
		workloadAuthDomain, timestamp, method, path, bodyDigestHex,
	}, "\n"))
}

func (t *workloadAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(req.Body, maxRequestBodyBytes+1))
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("coreapi: cannot buffer request body: %w", err)
		}
		if int64(len(bodyBytes)) > maxRequestBodyBytes {
			return nil, fmt.Errorf("coreapi: request body exceeds %d bytes", maxRequestBodyBytes)
		}
	}
	sum := sha256.Sum256(bodyBytes)
	path := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}
	timestamp := strconv.FormatInt(t.clock().Unix(), 10)
	payload := workloadAuthPayload(timestamp, req.Method, path, hex.EncodeToString(sum[:]))
	sig, err := t.signer.Sign(req.Context(), payload)
	if err != nil {
		return nil, fmt.Errorf("coreapi: workload signing failed: %w", err)
	}
	out := req.Clone(req.Context())
	if len(bodyBytes) > 0 {
		out.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		out.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(bodyBytes)), nil
		}
		out.ContentLength = int64(len(bodyBytes))
	}
	out.Header.Set("X-AuthScope-Workload-KeyID", t.signer.KeyID())
	out.Header.Set("X-AuthScope-Workload-Timestamp", timestamp)
	out.Header.Set("X-AuthScope-Workload-Signature", base64.RawURLEncoding.EncodeToString(sig))
	return t.base.RoundTrip(out)
}

// Client is the typed AuthScope HTTP client.
type Client struct {
	httpClient     *http.Client
	base           *url.URL
	signer         identity.Signer
	defaultTimeout time.Duration
	authTransport  *workloadAuthTransport
}

// NewClient builds a client for baseURL. httpClient may be nil. mode is
// "development" or "release": only development accepts non-HTTPS base
// URLs. The client wraps the transport with workload-signer
// authentication and disables redirects.
func NewClient(baseURL string, httpClient *http.Client, signer identity.Signer, mode string) (*Client, error) {
	if signer == nil {
		return nil, ErrNoSigner
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%w: %q", ErrInvalidBaseURL, baseURL)
	}
	if mode != "development" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: got %q", ErrInsecureBaseURL, baseURL)
	}
	hc := &http.Client{}
	if httpClient != nil {
		cpy := *httpClient
		hc = &cpy
	}
	base := http.DefaultTransport
	if hc.Transport != nil {
		base = hc.Transport
	}
	auth := &workloadAuthTransport{signer: signer, base: base, clock: time.Now}
	hc.Transport = auth
	hc.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		httpClient:     hc,
		base:           u,
		signer:         signer,
		defaultTimeout: defaultOpTimeout,
		authTransport:  auth,
	}, nil
}

// canonicalJSON marshals v deterministically for request bodies.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("coreapi: cannot encode request: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("coreapi: cannot generate request id: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any, opts RequestOptions) error {
	return c.doInner(ctx, method, path, query, in, out, opts, true)
}

// doInner is the single request path. strict selects strict response
// decoding; discovery alone decodes leniently because its contract
// response schema is GenericObject.
func (c *Client) doInner(ctx context.Context, method, path string, query url.Values, in, out any, opts RequestOptions, strict bool) error {
	if opts.WorkspaceID == "" {
		return ErrMissingWorkspace
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = canonicalJSON(in); err != nil {
			return err
		}
	}
	target := c.base.ResolveReference(&url.URL{Path: path})
	if query != nil {
		target.RawQuery = query.Encode()
	}
	timeout := c.defaultTimeout
	if opts.Timeout > 0 {
		timeout = opts.Timeout
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
	if err != nil {
		return fmt.Errorf("coreapi: cannot build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AuthScope-Workspace", opts.WorkspaceID)
	requestID := opts.RequestID
	if requestID == "" {
		requestID = newRequestID()
	}
	req.Header.Set("X-Request-ID", requestID)
	if opts.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", opts.IdempotencyKey)
	}
	if opts.ActorID != "" {
		req.Header.Set("X-AuthScope-Actor", opts.ActorID)
	}
	if opts.TraceID != "" {
		req.Header.Set("X-Trace-ID", opts.TraceID)
	}
	if opts.MissionVersion > 0 {
		req.Header.Set("X-AuthScope-Mission-Version", strconv.FormatInt(opts.MissionVersion, 10))
	}
	return c.roundTrip(req, out, strict)
}

func (c *Client) roundTrip(req *http.Request, out any, strict bool) error {
	op := req.Method + " " + req.URL.EscapedPath()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Never interpolate headers, bodies, or signatures into errors.
		return fmt.Errorf("coreapi: %s: %w", op, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("coreapi: %s: cannot read response: %w", op, err)
	}
	if int64(len(raw)) > maxResponseBytes {
		return fmt.Errorf("%w: %s returned %d bytes", ErrResponseTooLarge, op, len(raw))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeUpstreamError(resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return fmt.Errorf("coreapi: %s: empty response body", op)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("coreapi: %s: cannot decode response: %w", op, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("coreapi: %s: trailing data in response", op)
	}
	return nil
}

// decodeUpstreamError decodes a non-2xx problem body without trusting it:
// an undecodable body still yields a 503-uncertainty error, and nothing
// from the body beyond the code, a truncated message, and the request ID
// reaches the error string.
func decodeUpstreamError(status int, raw []byte) error {
	up := &UpstreamError{StatusCode: status}
	var p upstreamProblem
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&p); err == nil {
		up.Code = p.Code
		up.Message = p.Message
		up.RequestID = p.RequestID
		up.Retryable = p.Retryable
	} else {
		up.Message = http.StatusText(status)
	}
	return up
}

func pathEscape(s string) string { return url.PathEscape(s) }

// attestationEnvelope renders a signed attestation for request bodies.
func attestationEnvelope(att identity.SignedDecisionAttestation) (map[string]any, error) {
	return identity.WireEnvelope(att)
}

// discoveryWire is the OPE view of the discovery document.
type discoveryWire struct {
	Version       string   `json:"version"`
	OpenAPISHA256 string   `json:"openapi_sha256"`
	Capabilities  []string `json:"capabilities"`
}

// Discover fetches the authority discovery document. It decodes leniently
// because the contract pins GenericObject for this response.
func (c *Client) Discover(ctx context.Context) (Discovery, error) {
	var wire discoveryWire
	opts := RequestOptions{WorkspaceID: "discovery"}
	if err := c.doInner(ctx, http.MethodGet, "/.well-known/mission-authority", nil, nil, &wire, opts, false); err != nil {
		return Discovery{}, err
	}
	if wire.Version == "" || wire.OpenAPISHA256 == "" {
		return Discovery{}, fmt.Errorf("%w: discovery document is incomplete", ErrIncompatibleCore)
	}
	return Discovery{
		Version:       wire.Version,
		OpenAPISHA256: wire.OpenAPISHA256,
		Capabilities:  wire.Capabilities,
	}, nil
}

// VerifyWorkspaceIdentity asks AuthScope for the workload identity derived
// from the authenticated transport, and checks it is restricted to the
// expected workspace. The identity never comes from a client header.
func (c *Client) VerifyWorkspaceIdentity(ctx context.Context, expectedWorkspace string) (WorkspaceIdentity, error) {
	var wid WorkspaceIdentity
	opts := RequestOptions{WorkspaceID: expectedWorkspace}
	if err := c.do(ctx, http.MethodPost, "/v1/identities/workload/verify", nil, nil, &wid, opts); err != nil {
		return WorkspaceIdentity{}, err
	}
	if wid.WorkspaceID != expectedWorkspace {
		return WorkspaceIdentity{}, fmt.Errorf("%w: got %q, want %q",
			ErrWorkspaceMismatch, wid.WorkspaceID, expectedWorkspace)
	}
	return wid, nil
}

// BeginGitHubBinding starts the one-time GitHub App binding handoff.
func (c *Client) BeginGitHubBinding(ctx context.Context, in GitHubBindingBeginRequest, opts RequestOptions) (GitHubBindingHandoff, error) {
	var out GitHubBindingHandoff
	if err := c.do(ctx, http.MethodPost, "/v1/integrations/github/bindings/begin", nil, in, &out, opts); err != nil {
		return GitHubBindingHandoff{}, err
	}
	return out, nil
}

// FinishGitHubBinding completes the handoff with the one-use binding code.
func (c *Client) FinishGitHubBinding(ctx context.Context, in GitHubBindingFinishRequest, opts RequestOptions) (RepositoryBinding, error) {
	var out RepositoryBinding
	if err := c.do(ctx, http.MethodPost, "/v1/integrations/github/bindings/finish", nil, in, &out, opts); err != nil {
		return RepositoryBinding{}, err
	}
	return out, nil
}

// GetRepositoryBinding reads one repository binding.
func (c *Client) GetRepositoryBinding(ctx context.Context, bindingID string, opts RequestOptions) (RepositoryBinding, error) {
	var out RepositoryBinding
	path := "/v1/integrations/github/bindings/" + pathEscape(bindingID)
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &out, opts); err != nil {
		return RepositoryBinding{}, err
	}
	return out, nil
}

// ReadGitHubIssue fetches a brokered, trusted issue snapshot.
func (c *Client) ReadGitHubIssue(ctx context.Context, in GitHubIssueRequest, opts RequestOptions) (GitHubIssueSnapshot, error) {
	var out GitHubIssueSnapshot
	if err := c.do(ctx, http.MethodPost, "/v1/integrations/github/issues/snapshot", nil, in, &out, opts); err != nil {
		return GitHubIssueSnapshot{}, err
	}
	return out, nil
}

// InspectWorkflowPosture inspects workflow posture at a ref.
func (c *Client) InspectWorkflowPosture(ctx context.Context, in WorkflowPostureRequest, opts RequestOptions) (WorkflowPosture, error) {
	var out WorkflowPosture
	if err := c.do(ctx, http.MethodPost, "/v1/integrations/github/workflow-posture", nil, in, &out, opts); err != nil {
		return WorkflowPosture{}, err
	}
	return out, nil
}

// ListAgentKits lists the supported coding-agent kits.
func (c *Client) ListAgentKits(ctx context.Context, opts RequestOptions) ([]AgentKit, error) {
	var out agentKitList
	if err := c.do(ctx, http.MethodGet, "/v1/agent-kits", nil, nil, &out, opts); err != nil {
		return nil, err
	}
	return out.Kits, nil
}

// ShapeMission shapes a mission draft from founder intent.
func (c *Client) ShapeMission(ctx context.Context, in ShapeMissionRequest, opts RequestOptions) (MissionDraft, error) {
	var out MissionDraft
	if err := c.do(ctx, http.MethodPost, "/v1/mission-proposals/shape", nil, in, &out, opts); err != nil {
		return MissionDraft{}, err
	}
	return out, nil
}

// CreateProposal creates an upstream mission proposal.
func (c *Client) CreateProposal(ctx context.Context, in CreateProposalRequest, opts RequestOptions) (Proposal, error) {
	var out Proposal
	if err := c.do(ctx, http.MethodPost, "/v1/mission-proposals", nil, in, &out, opts); err != nil {
		return Proposal{}, err
	}
	return out, nil
}

// ApproveProposal approves a proposal with a signed decision attestation.
func (c *Client) ApproveProposal(ctx context.Context, proposalID string, att identity.SignedDecisionAttestation, opts RequestOptions) (Mission, error) {
	env, err := attestationEnvelope(att)
	if err != nil {
		return Mission{}, err
	}
	var out Mission
	path := "/v1/mission-proposals/" + pathEscape(proposalID) + "/approve"
	if err := c.do(ctx, http.MethodPost, path, nil, approveProposalRequest{Attestation: env}, &out, opts); err != nil {
		return Mission{}, err
	}
	return out, nil
}

// PrepareLaunch prepares a governed launch with a signed attestation.
func (c *Client) PrepareLaunch(ctx context.Context, missionRef string, in LaunchRequest, att identity.SignedDecisionAttestation, opts RequestOptions) (LaunchArtifacts, error) {
	env, err := attestationEnvelope(att)
	if err != nil {
		return LaunchArtifacts{}, err
	}
	var out LaunchArtifacts
	path := "/v1/missions/" + pathEscape(missionRef) + "/launch/prepare"
	body := prepareLaunchRequest{IdempotencyKey: in.IdempotencyKey, KitID: in.KitID, Attestation: env}
	if err := c.do(ctx, http.MethodPost, path, nil, body, &out, opts); err != nil {
		return LaunchArtifacts{}, err
	}
	return out, nil
}

// IntrospectMission reads the current mission state.
func (c *Client) IntrospectMission(ctx context.Context, missionRef string, opts RequestOptions) (MissionStatus, error) {
	var out MissionStatus
	path := "/v1/missions/" + pathEscape(missionRef) + "/introspect"
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &out, opts); err != nil {
		return MissionStatus{}, err
	}
	return out, nil
}

// RevokeMission revokes a mission with a signed decision attestation.
func (c *Client) RevokeMission(ctx context.Context, missionRef string, in RevokeRequest, att identity.SignedDecisionAttestation, opts RequestOptions) (Revocation, error) {
	env, err := attestationEnvelope(att)
	if err != nil {
		return Revocation{}, err
	}
	var out Revocation
	path := "/v1/missions/" + pathEscape(missionRef) + "/revoke"
	body := revokeMissionRequest{Reason: in.Reason, Attestation: env}
	if err := c.do(ctx, http.MethodPost, path, nil, body, &out, opts); err != nil {
		return Revocation{}, err
	}
	return out, nil
}

// ListExpansions lists expansion requests for a mission.
func (c *Client) ListExpansions(ctx context.Context, missionRef string, opts RequestOptions) ([]Expansion, error) {
	var out expansionPage
	query := url.Values{"mission_ref": {missionRef}}
	if err := c.do(ctx, http.MethodGet, "/v1/expansion-requests", query, nil, &out, opts); err != nil {
		return nil, err
	}
	return out.Items, nil
}

// DecideExpansion approves or denies an expansion with a signed decision
// attestation. Denials route to the deny operation.
func (c *Client) DecideExpansion(ctx context.Context, expansionID string, decision ExpansionDecision, att identity.SignedDecisionAttestation, opts RequestOptions) (ExpansionResult, error) {
	env, err := attestationEnvelope(att)
	if err != nil {
		return ExpansionResult{}, err
	}
	verb := "deny"
	decisionName := "deny"
	if decision.Approve {
		verb = "approve"
		decisionName = "approve"
	}
	var out ExpansionResult
	path := "/v1/expansion-requests/" + pathEscape(expansionID) + "/" + verb
	body := expansionDecisionRequest{Decision: decisionName, Reason: decision.Reason, Attestation: env}
	if err := c.do(ctx, http.MethodPost, path, nil, body, &out, opts); err != nil {
		return ExpansionResult{}, err
	}
	return out, nil
}

// ReadEvents reads one page of authoritative mission events after a cursor.
func (c *Client) ReadEvents(ctx context.Context, missionRef, cursor string, opts RequestOptions) (EventPage, error) {
	var wire eventPageWire
	query := url.Values{"mission_ref": {missionRef}}
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	if err := c.do(ctx, http.MethodGet, "/v1/events", query, nil, &wire, opts); err != nil {
		return EventPage{}, err
	}
	return EventPage{Events: wire.Items, NextCursor: wire.NextCursor}, nil
}

// GetReceipt fetches the signed execution receipt for a grant.
func (c *Client) GetReceipt(ctx context.Context, grantID string, opts RequestOptions) (SignedReceipt, error) {
	var out SignedReceipt
	path := "/v1/executions/" + pathEscape(grantID) + "/receipt"
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &out, opts); err != nil {
		return SignedReceipt{}, err
	}
	return out, nil
}

// GetSigningKeys fetches the AuthScope signing-key history.
func (c *Client) GetSigningKeys(ctx context.Context, opts RequestOptions) (SigningKeyHistory, error) {
	var out SigningKeyHistory
	if err := c.do(ctx, http.MethodGet, "/.well-known/auth-scope-signing-keys", nil, nil, &out, opts); err != nil {
		return SigningKeyHistory{}, err
	}
	return out, nil
}

// PublishGitHubCheck publishes an idempotent GitHub check run.
func (c *Client) PublishGitHubCheck(ctx context.Context, in GitHubCheckRequest, opts RequestOptions) (GitHubCheckResult, error) {
	var out GitHubCheckResult
	if err := c.do(ctx, http.MethodPost, "/v1/integrations/github/check-runs", nil, in, &out, opts); err != nil {
		return GitHubCheckResult{}, err
	}
	return out, nil
}

// ReconcileOperation looks up an operation by workspace-qualified
// idempotency key for every ambiguous upstream mutation.
func (c *Client) ReconcileOperation(ctx context.Context, idempotencyKey, operationID string, opts RequestOptions) (OperationResult, error) {
	var out OperationResult
	path := "/v1/operations/" + pathEscape(idempotencyKey)
	var query url.Values
	if operationID != "" {
		query = url.Values{"operation_id": {operationID}}
	}
	if err := c.do(ctx, http.MethodGet, path, query, nil, &out, opts); err != nil {
		return OperationResult{}, err
	}
	return out, nil
}

// ListActiveMissions lists the workspace-scoped active missions,
// including missions absent from OPE's local store.
func (c *Client) ListActiveMissions(ctx context.Context, opts RequestOptions) ([]ActiveMission, error) {
	var out activeMissionList
	if err := c.do(ctx, http.MethodGet, "/v1/missions", nil, nil, &out, opts); err != nil {
		return nil, err
	}
	return out.Missions, nil
}

// ContainWorkspace atomically contains a workspace with a signed offline
// recovery containment attestation.
func (c *Client) ContainWorkspace(ctx context.Context, in WorkspaceContainmentRequest, att identity.SignedDecisionAttestation, opts RequestOptions) (WorkspaceContainment, error) {
	env, err := attestationEnvelope(att)
	if err != nil {
		return WorkspaceContainment{}, err
	}
	var out WorkspaceContainment
	path := "/v1/workspaces/" + pathEscape(opts.WorkspaceID) + "/contain"
	body := containWorkspaceRequest{Founder: in.Founder, IdempotencyKey: in.IdempotencyKey, Attestation: env}
	if err := c.do(ctx, http.MethodPost, path, nil, body, &out, opts); err != nil {
		return WorkspaceContainment{}, err
	}
	return out, nil
}

// GatedAuthority wraps an Authority and rejects every business mutation
// while the compatibility gate is missing or stale. Reads pass through;
// the gate itself uses Discover and VerifyWorkspaceIdentity.
type GatedAuthority struct {
	inner Authority
	gate  *Gate
}

// NewGatedAuthority wraps inner with the fail-closed mutation gate.
func NewGatedAuthority(inner Authority, gate *Gate) *GatedAuthority {
	return &GatedAuthority{inner: inner, gate: gate}
}

func (g *GatedAuthority) checkMutation() error {
	if g.gate == nil || !g.gate.Healthy() {
		return ErrGateNotHealthy
	}
	return nil
}

func (g *GatedAuthority) Discover(ctx context.Context) (Discovery, error) {
	return g.inner.Discover(ctx)
}

func (g *GatedAuthority) VerifyWorkspaceIdentity(ctx context.Context, workspace string) (WorkspaceIdentity, error) {
	return g.inner.VerifyWorkspaceIdentity(ctx, workspace)
}

func (g *GatedAuthority) BeginGitHubBinding(ctx context.Context, in GitHubBindingBeginRequest, opts RequestOptions) (GitHubBindingHandoff, error) {
	if err := g.checkMutation(); err != nil {
		return GitHubBindingHandoff{}, err
	}
	return g.inner.BeginGitHubBinding(ctx, in, opts)
}

func (g *GatedAuthority) FinishGitHubBinding(ctx context.Context, in GitHubBindingFinishRequest, opts RequestOptions) (RepositoryBinding, error) {
	if err := g.checkMutation(); err != nil {
		return RepositoryBinding{}, err
	}
	return g.inner.FinishGitHubBinding(ctx, in, opts)
}

func (g *GatedAuthority) GetRepositoryBinding(ctx context.Context, bindingID string, opts RequestOptions) (RepositoryBinding, error) {
	return g.inner.GetRepositoryBinding(ctx, bindingID, opts)
}

func (g *GatedAuthority) ReadGitHubIssue(ctx context.Context, in GitHubIssueRequest, opts RequestOptions) (GitHubIssueSnapshot, error) {
	return g.inner.ReadGitHubIssue(ctx, in, opts)
}

func (g *GatedAuthority) InspectWorkflowPosture(ctx context.Context, in WorkflowPostureRequest, opts RequestOptions) (WorkflowPosture, error) {
	return g.inner.InspectWorkflowPosture(ctx, in, opts)
}

func (g *GatedAuthority) ListAgentKits(ctx context.Context, opts RequestOptions) ([]AgentKit, error) {
	return g.inner.ListAgentKits(ctx, opts)
}

func (g *GatedAuthority) ShapeMission(ctx context.Context, in ShapeMissionRequest, opts RequestOptions) (MissionDraft, error) {
	if err := g.checkMutation(); err != nil {
		return MissionDraft{}, err
	}
	return g.inner.ShapeMission(ctx, in, opts)
}

func (g *GatedAuthority) CreateProposal(ctx context.Context, in CreateProposalRequest, opts RequestOptions) (Proposal, error) {
	if err := g.checkMutation(); err != nil {
		return Proposal{}, err
	}
	return g.inner.CreateProposal(ctx, in, opts)
}

func (g *GatedAuthority) ApproveProposal(ctx context.Context, proposalID string, att identity.SignedDecisionAttestation, opts RequestOptions) (Mission, error) {
	if err := g.checkMutation(); err != nil {
		return Mission{}, err
	}
	return g.inner.ApproveProposal(ctx, proposalID, att, opts)
}

func (g *GatedAuthority) PrepareLaunch(ctx context.Context, missionRef string, in LaunchRequest, att identity.SignedDecisionAttestation, opts RequestOptions) (LaunchArtifacts, error) {
	if err := g.checkMutation(); err != nil {
		return LaunchArtifacts{}, err
	}
	return g.inner.PrepareLaunch(ctx, missionRef, in, att, opts)
}

func (g *GatedAuthority) IntrospectMission(ctx context.Context, missionRef string, opts RequestOptions) (MissionStatus, error) {
	return g.inner.IntrospectMission(ctx, missionRef, opts)
}

func (g *GatedAuthority) RevokeMission(ctx context.Context, missionRef string, in RevokeRequest, att identity.SignedDecisionAttestation, opts RequestOptions) (Revocation, error) {
	if err := g.checkMutation(); err != nil {
		return Revocation{}, err
	}
	return g.inner.RevokeMission(ctx, missionRef, in, att, opts)
}

func (g *GatedAuthority) ListExpansions(ctx context.Context, missionRef string, opts RequestOptions) ([]Expansion, error) {
	return g.inner.ListExpansions(ctx, missionRef, opts)
}

func (g *GatedAuthority) DecideExpansion(ctx context.Context, expansionID string, decision ExpansionDecision, att identity.SignedDecisionAttestation, opts RequestOptions) (ExpansionResult, error) {
	if err := g.checkMutation(); err != nil {
		return ExpansionResult{}, err
	}
	return g.inner.DecideExpansion(ctx, expansionID, decision, att, opts)
}

func (g *GatedAuthority) ReadEvents(ctx context.Context, missionRef, cursor string, opts RequestOptions) (EventPage, error) {
	return g.inner.ReadEvents(ctx, missionRef, cursor, opts)
}

func (g *GatedAuthority) GetReceipt(ctx context.Context, grantID string, opts RequestOptions) (SignedReceipt, error) {
	return g.inner.GetReceipt(ctx, grantID, opts)
}

func (g *GatedAuthority) GetSigningKeys(ctx context.Context, opts RequestOptions) (SigningKeyHistory, error) {
	return g.inner.GetSigningKeys(ctx, opts)
}

func (g *GatedAuthority) PublishGitHubCheck(ctx context.Context, in GitHubCheckRequest, opts RequestOptions) (GitHubCheckResult, error) {
	if err := g.checkMutation(); err != nil {
		return GitHubCheckResult{}, err
	}
	return g.inner.PublishGitHubCheck(ctx, in, opts)
}

func (g *GatedAuthority) ReconcileOperation(ctx context.Context, idempotencyKey, operationID string, opts RequestOptions) (OperationResult, error) {
	return g.inner.ReconcileOperation(ctx, idempotencyKey, operationID, opts)
}

func (g *GatedAuthority) ListActiveMissions(ctx context.Context, opts RequestOptions) ([]ActiveMission, error) {
	return g.inner.ListActiveMissions(ctx, opts)
}

func (g *GatedAuthority) ContainWorkspace(ctx context.Context, in WorkspaceContainmentRequest, att identity.SignedDecisionAttestation, opts RequestOptions) (WorkspaceContainment, error) {
	if err := g.checkMutation(); err != nil {
		return WorkspaceContainment{}, err
	}
	return g.inner.ContainWorkspace(ctx, in, att, opts)
}

// compile-time check that Client and GatedAuthority satisfy Authority.
var (
	_ Authority = (*Client)(nil)
	_ Authority = (*GatedAuthority)(nil)
)
