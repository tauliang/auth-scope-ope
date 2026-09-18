// Trusted issue-snapshot import and workflow-posture inspection. Every
// provider read is executed by AuthScope through its credential broker;
// OPE never receives or handles a GitHub token. The snapshot is
// validated field by field and pinned to the immutable repository ID of
// the connection before it is returned.
package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
)

var (
	// ErrIssueUnavailable reports an issue that is closed, deleted, or
	// otherwise not importable.
	ErrIssueUnavailable = errors.New("github: issue is not available")
	// ErrStaleSourceRevision reports a snapshot whose provider source
	// revision moved under a pinned revision.
	ErrStaleSourceRevision = errors.New("github: stale source revision")
	// ErrStaleBaseSHA reports a snapshot whose base SHA moved under a
	// pinned base SHA.
	ErrStaleBaseSHA = errors.New("github: stale base SHA")
	// ErrBindingRevoked reports a repository binding AuthScope no longer
	// resolves.
	ErrBindingRevoked = errors.New("github: repository binding revoked")
	// ErrUnsafePosture reports a repository whose workflow posture allows
	// agent-controlled content to reach secrets, write tokens, spending,
	// deployments, or pull_request_target.
	ErrUnsafePosture = errors.New("github: unsafe workflow posture")
)

// IssueSnapshot is the immutable, trusted issue snapshot OPE pins for a
// mission pass. SourceDigest is the provider-derived canonical digest;
// OPE never derives it from generated mission text.
type IssueSnapshot struct {
	WorkspaceID        string   `json:"workspace_id"`
	RepositoryBinding  string   `json:"repository_binding_id"`
	InstallationID     int64    `json:"installation_id"`
	RepositoryID       int64    `json:"repository_id"`
	RepositoryFullName string   `json:"repository_full_name"`
	IssueNumber        int64    `json:"issue_number"`
	SourceRevision     string   `json:"source_revision"`
	SourceDigest       string   `json:"source_digest"`
	DefaultBranch      string   `json:"default_branch"`
	BaseSHA            string   `json:"base_sha"`
	Objective          string   `json:"objective"`
	AcceptanceCriteria []string `json:"acceptance_criteria"`
}

var (
	// canonicalDigestPattern pins the algorithm-tagged digest shape.
	canonicalDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// shaPattern accepts git SHA-1 and SHA-256 hex object names.
	shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
)

// SourceConfig wires the issue source.
type SourceConfig struct {
	Store           store.Store
	Authority       coreapi.Authority
	Clock           func() time.Time
	UpstreamTimeout time.Duration
}

// Source imports trusted issue snapshots and inspects workflow posture
// through the AuthScope broker.
type Source struct {
	store           store.Store
	authority       coreapi.Authority
	clock           func() time.Time
	upstreamTimeout time.Duration
}

// NewSource builds the issue source.
func NewSource(cfg SourceConfig) (*Source, error) {
	if cfg.Store == nil || cfg.Authority == nil {
		return nil, fmt.Errorf("github: store and authority are required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	timeout := cfg.UpstreamTimeout
	if timeout <= 0 {
		timeout = defaultUpstreamTimeout
	}
	return &Source{store: cfg.Store, authority: cfg.Authority, clock: clock, upstreamTimeout: timeout}, nil
}

func (s *Source) now() time.Time { return s.clock().UTC() }

// verifiedBinding resolves the connection's binding through AuthScope and
// requires it to still point at the same immutable repository ID the
// connection was verified against. A transferred or replaced repository
// (same name, different ID) fails closed here.
func (s *Source) verifiedBinding(ctx context.Context, workspaceID string, conn store.ConnectionRecord) (coreapi.RepositoryBinding, error) {
	uctx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	binding, err := s.authority.GetRepositoryBinding(uctx, conn.RepositoryBindingRef,
		coreapi.RequestOptions{WorkspaceID: workspaceID})
	if err != nil {
		var up *coreapi.UpstreamError
		if errors.As(err, &up) && up.StatusCode == 404 {
			return coreapi.RepositoryBinding{}, ErrBindingRevoked
		}
		return coreapi.RepositoryBinding{}, err
	}
	if !equalStringConstTime(binding.WorkspaceID, workspaceID) {
		return coreapi.RepositoryBinding{}, ErrWorkspaceMismatch
	}
	repositoryID, err := parseGitHubID(binding.RepositoryID)
	if err != nil {
		return coreapi.RepositoryBinding{}, fmt.Errorf("%w: repository ID: %v", ErrInvalidInput, err)
	}
	if repositoryID != conn.RepositoryID {
		return coreapi.RepositoryBinding{},
			fmt.Errorf("%w: was %d, now %d", ErrRepositoryChanged, conn.RepositoryID, repositoryID)
	}
	return binding, nil
}

// ReadIssue imports the trusted issue snapshot for a connection. It calls
// AuthScope's typed broker operation with the explicit workspace,
// binding, and issue number, verifies the binding still resolves to the
// connection's immutable repository ID, and requires a provider-derived
// source revision, canonical source digest, base ref, and base SHA.
// expectedSourceRevision and expectedBaseSHA are optional pins: when
// non-empty, a mismatch fails closed as stale. OPE never receives or
// handles the GitHub token.
func (s *Source) ReadIssue(ctx context.Context, workspaceID string, conn store.ConnectionRecord, issueNumber int64, expectedSourceRevision, expectedBaseSHA string) (IssueSnapshot, error) {
	if workspaceID == "" || conn.ConnectionID == "" || conn.RepositoryBindingRef == "" {
		return IssueSnapshot{}, fmt.Errorf("%w: workspace, connection, and binding are required", ErrInvalidInput)
	}
	if !equalStringConstTime(conn.WorkspaceID, workspaceID) {
		return IssueSnapshot{}, ErrWorkspaceMismatch
	}
	if issueNumber <= 0 {
		return IssueSnapshot{}, fmt.Errorf("%w: issue number must be positive", ErrInvalidInput)
	}
	binding, err := s.verifiedBinding(ctx, workspaceID, conn)
	if err != nil {
		return IssueSnapshot{}, err
	}
	uctx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	snap, err := s.authority.ReadGitHubIssue(uctx,
		coreapi.GitHubIssueRequest{BindingID: conn.RepositoryBindingRef, IssueNumber: issueNumber},
		coreapi.RequestOptions{WorkspaceID: workspaceID})
	if err != nil {
		var up *coreapi.UpstreamError
		if errors.As(err, &up) && up.StatusCode == 404 {
			return IssueSnapshot{}, ErrIssueUnavailable
		}
		return IssueSnapshot{}, err
	}
	if err := checkIssueSnapshot(workspaceID, conn.RepositoryBindingRef, issueNumber, snap, s.now()); err != nil {
		return IssueSnapshot{}, err
	}
	if expectedSourceRevision != "" && !equalStringConstTime(snap.SourceRevision, expectedSourceRevision) {
		return IssueSnapshot{}, fmt.Errorf("%w: pinned %q, upstream %q",
			ErrStaleSourceRevision, expectedSourceRevision, snap.SourceRevision)
	}
	if expectedBaseSHA != "" && !equalStringConstTime(snap.BaseSHA, expectedBaseSHA) {
		return IssueSnapshot{}, fmt.Errorf("%w: pinned %q, upstream %q",
			ErrStaleBaseSHA, expectedBaseSHA, snap.BaseSHA)
	}
	installationID, err := parseGitHubID(binding.InstallationID)
	if err != nil {
		return IssueSnapshot{}, fmt.Errorf("%w: installation ID: %v", ErrInvalidInput, err)
	}
	objective, criteria := normalizeIssueContent(snap.Title, snap.Body)
	return IssueSnapshot{
		WorkspaceID:        workspaceID,
		RepositoryBinding:  conn.RepositoryBindingRef,
		InstallationID:     installationID,
		RepositoryID:       conn.RepositoryID,
		RepositoryFullName: binding.Repository,
		IssueNumber:        issueNumber,
		SourceRevision:     snap.SourceRevision,
		SourceDigest:       snap.CanonicalDigest,
		DefaultBranch:      snap.BaseRef,
		BaseSHA:            snap.BaseSHA,
		Objective:          objective,
		AcceptanceCriteria: criteria,
	}, nil
}

// checkIssueSnapshot validates every field of the brokered snapshot. Any
// gap fails closed: OPE must not pin a snapshot it cannot fully verify.
func checkIssueSnapshot(workspaceID, bindingID string, issueNumber int64, snap coreapi.GitHubIssueSnapshot, now time.Time) error {
	if !equalStringConstTime(snap.WorkspaceID, workspaceID) {
		return fmt.Errorf("%w: snapshot workspace mismatch", ErrInvalidInput)
	}
	if !equalStringConstTime(snap.BindingID, bindingID) {
		return fmt.Errorf("%w: snapshot binding mismatch", ErrInvalidInput)
	}
	if snap.IssueNumber != issueNumber {
		return fmt.Errorf("%w: snapshot issue number mismatch", ErrInvalidInput)
	}
	if snap.State != "open" {
		return fmt.Errorf("%w: state %q", ErrIssueUnavailable, snap.State)
	}
	if strings.TrimSpace(snap.Title) == "" {
		return fmt.Errorf("%w: empty title", ErrInvalidInput)
	}
	if strings.TrimSpace(snap.BaseRef) == "" {
		return fmt.Errorf("%w: empty base ref", ErrInvalidInput)
	}
	if !shaPattern.MatchString(strings.ToLower(snap.BaseSHA)) {
		return fmt.Errorf("%w: malformed base SHA", ErrInvalidInput)
	}
	if strings.TrimSpace(snap.SourceRevision) == "" {
		return fmt.Errorf("%w: empty source revision", ErrInvalidInput)
	}
	if !canonicalDigestPattern.MatchString(snap.CanonicalDigest) {
		return fmt.Errorf("%w: malformed canonical digest", ErrInvalidInput)
	}
	if snap.SnapshotAt <= 0 {
		return fmt.Errorf("%w: missing snapshot time", ErrInvalidInput)
	}
	snapshotAt := time.Unix(snap.SnapshotAt, 0).UTC()
	if snapshotAt.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("%w: snapshot from the future", ErrInvalidInput)
	}
	return nil
}

// normalizeIssueContent derives the objective from the issue title and
// acceptance criteria from markdown task-list items in the body. The
// authoritative source digest always comes from AuthScope's canonical
// digest, never from this normalized text.
func normalizeIssueContent(title, body string) (string, []string) {
	objective := strings.Join(strings.Fields(title), " ")
	var criteria []string
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		item := ""
		for _, prefix := range []string{"- [ ]", "- [x]", "- [X]", "* [ ]", "* [x]", "* [X]"} {
			if strings.HasPrefix(trimmed, prefix) {
				item = strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
				break
			}
		}
		if item == "" || len(criteria) >= 50 {
			continue
		}
		if len(item) > 500 {
			item = item[:500]
		}
		duplicate := false
		for _, c := range criteria {
			if c == item {
				duplicate = true
				break
			}
		}
		if !duplicate {
			criteria = append(criteria, item)
		}
	}
	if criteria == nil {
		criteria = []string{}
	}
	return objective, criteria
}

// CheckPosture asks AuthScope to inspect the repository's workflow files,
// rules, token permissions, environments, and mission-branch trigger
// behavior at ref, whose inspected head SHA is headSHA. It first
// re-verifies the workspace-qualified connection identity and resolves
// the live binding against the connection's immutable repository ID, so a
// revoked or transferred binding fails closed before any posture is
// persisted. It persists only the posture digest, head SHA, outcome,
// reason codes, and expiry, and returns the persisted record. A risky
// posture marks the connection unavailable for launch.
func (s *Source) CheckPosture(ctx context.Context, workspaceID string, conn store.ConnectionRecord, ref, headSHA string) (store.WorkflowPostureRecord, error) {
	if workspaceID == "" || conn.ConnectionID == "" || conn.RepositoryBindingRef == "" {
		return store.WorkflowPostureRecord{}, fmt.Errorf("%w: workspace, connection, and binding are required", ErrInvalidInput)
	}
	if !equalStringConstTime(conn.WorkspaceID, workspaceID) {
		return store.WorkflowPostureRecord{}, ErrWorkspaceMismatch
	}
	if ref == "" || len(ref) > 256 {
		return store.WorkflowPostureRecord{}, fmt.Errorf("%w: ref is required", ErrInvalidInput)
	}
	if !shaPattern.MatchString(strings.ToLower(headSHA)) {
		return store.WorkflowPostureRecord{}, fmt.Errorf("%w: malformed head SHA", ErrInvalidInput)
	}
	if _, err := s.verifiedBinding(ctx, workspaceID, conn); err != nil {
		return store.WorkflowPostureRecord{}, err
	}
	uctx, cancel := context.WithTimeout(ctx, s.upstreamTimeout)
	defer cancel()
	posture, err := s.authority.InspectWorkflowPosture(uctx,
		coreapi.WorkflowPostureRequest{BindingID: conn.RepositoryBindingRef, Ref: ref},
		coreapi.RequestOptions{WorkspaceID: workspaceID})
	if err != nil {
		return store.WorkflowPostureRecord{}, err
	}
	if !equalStringConstTime(posture.BindingID, conn.RepositoryBindingRef) {
		return store.WorkflowPostureRecord{}, fmt.Errorf("%w: posture binding mismatch", ErrInvalidInput)
	}
	if !equalStringConstTime(posture.Ref, ref) {
		return store.WorkflowPostureRecord{}, fmt.Errorf("%w: posture ref mismatch", ErrInvalidInput)
	}
	if err := checkWorkflowPosture(posture); err != nil {
		return store.WorkflowPostureRecord{}, err
	}
	var risks []string
	for _, f := range posture.Findings {
		risks = append(risks, string(f.Risk))
	}
	reasonCodes := sortedUnique(risks)
	digest := postureDigest(posture)
	now := s.now()
	rec := store.WorkflowPostureRecord{
		WorkspaceID:   workspaceID,
		ConnectionID:  conn.ConnectionID,
		Ref:           ref,
		PostureDigest: digest,
		HeadSHA:       strings.ToLower(headSHA),
		Outcome:       string(posture.Posture),
		ReasonCodes:   reasonCodes,
		ExpiresAt:     now.Add(postureTTL),
		CheckedAt:     now,
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutWorkflowPosture(ctx, rec)
	}); err != nil {
		return store.WorkflowPostureRecord{}, err
	}
	return rec, nil
}

// checkWorkflowPosture validates the attested posture before anything
// is persisted: the outcome must be clean or risky, every risk must be a
// known value, and findings must agree with the outcome. Unknown or
// contradictory posture fails closed instead of being persisted as a
// launch gate.
func checkWorkflowPosture(p coreapi.WorkflowPosture) error {
	switch p.Posture {
	case coreapi.WorkflowPostureClean, coreapi.WorkflowPostureRisky:
	default:
		return fmt.Errorf("%w: unknown posture %q", ErrInvalidInput, string(p.Posture))
	}
	for _, f := range p.Findings {
		if strings.TrimSpace(f.Path) == "" {
			return fmt.Errorf("%w: finding without path", ErrInvalidInput)
		}
		switch f.Risk {
		case coreapi.WorkflowRiskSecretAccess, coreapi.WorkflowRiskWriteToken, coreapi.WorkflowRiskDeploymentTarget:
		default:
			return fmt.Errorf("%w: unknown risk %q", ErrInvalidInput, string(f.Risk))
		}
	}
	if p.Posture == coreapi.WorkflowPostureClean && len(p.Findings) > 0 {
		return fmt.Errorf("%w: clean posture with findings", ErrInvalidInput)
	}
	if p.Posture == coreapi.WorkflowPostureRisky && len(p.Findings) == 0 {
		return fmt.Errorf("%w: risky posture without findings", ErrInvalidInput)
	}
	return nil
}

// postureDigest pins the inspected posture: binding, ref, inspected
// workflow count, every finding path and risk, and the outcome. The
// digest is computed over AuthScope's attested posture delivered on the
// workload-authenticated transport.
func postureDigest(p coreapi.WorkflowPosture) string {
	var b strings.Builder
	b.WriteString(p.BindingID)
	b.WriteByte('\n')
	b.WriteString(p.Ref)
	b.WriteByte('\n')
	fmt.Fprintf(&b, "%d\n", p.WorkflowsInspected)
	paths := make([]string, 0, len(p.Findings))
	byPath := make(map[string]string, len(p.Findings))
	for _, f := range p.Findings {
		paths = append(paths, f.Path)
		byPath[f.Path] = string(f.Risk)
	}
	for _, path := range sortedUnique(paths) {
		b.WriteString(path)
		b.WriteByte('\n')
		b.WriteString(byPath[path])
		b.WriteByte('\n')
	}
	b.WriteString(string(p.Posture))
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
