// Local receipt verification: the trust boundary of Task 12. The
// verifier checks an upstream receipt envelope against locally pinned
// keys and the locally projected pass binding before anything is
// allowed to move a pass to a terminal outcome.
package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/store"
	"github.com/tauliang/authscope-ope/internal/trust"
)

// ErrReceiptUnverifiable marks a receipt that failed local
// verification. The wrapped reason is one of the fixed Reason codes.
var ErrReceiptUnverifiable = fmt.Errorf("receipt: unverifiable")

// maxClockSkew bounds how far a receipt signing time may lie in the
// future before it is rejected.
const maxClockSkew = 5 * time.Minute

// settlementDigestPattern is the locked upstream shape of the
// cumulative budget settlement digest: sha256 followed by 64 lowercase
// hex digits.
var settlementDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func unverifiable(reason, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrReceiptUnverifiable, reason, fmt.Sprintf(format, args...))
}

// Verifier checks receipt envelopes against pinned signing keys.
type Verifier struct {
	keys *trust.KeyStore
	now  func() time.Time
}

// NewVerifier builds a verifier over the pinned key set.
func NewVerifier(keys *trust.KeyStore, now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{keys: keys, now: now}
}

// Verify checks the envelope locally and returns the verified private
// view. The checks, in order: Ed25519 only, strict JSON decoding with
// unknown-field and trailing-data rejection, exact canonical payload
// bytes, payload semantics, signing-time key validity, signature over
// the raw payload bytes, and binding against the locally projected
// pass binding. Any failure returns ErrReceiptUnverifiable and leaves
// the pass in outcome_pending.
func (v *Verifier) Verify(env coreapi.SignedReceiptEnvelope, binding Binding) (*ReceiptView, error) {
	if env.Algorithm != "Ed25519" {
		return nil, unverifiable(ReasonBadPayload, "unsupported algorithm %q", env.Algorithm)
	}
	if env.KeyID == "" {
		return nil, unverifiable(ReasonBadKey, "empty key id")
	}
	if len(env.Payload) == 0 {
		return nil, unverifiable(ReasonBadPayload, "empty payload")
	}
	sig, err := base64.RawURLEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, unverifiable(ReasonBadSignature, "malformed signature")
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(env.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, unverifiable(ReasonBadPayload, "payload decode: %v", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, unverifiable(ReasonBadPayload, "trailing data after payload")
	}
	// The signature covers the exact canonical payload bytes: the
	// parsed payload must re-encode to the supplied bytes.
	canonical, err := CanonicalPayloadBytes(p)
	if err != nil {
		return nil, unverifiable(ReasonBadPayload, "canonical payload: %v", err)
	}
	if !bytes.Equal(canonical, env.Payload) {
		return nil, unverifiable(ReasonBadPayload, "payload is not in canonical form")
	}
	if err := checkPayloadSemantics(p, v.now()); err != nil {
		return nil, err
	}
	if p.KeyID != env.KeyID {
		return nil, unverifiable(ReasonBadKey, "payload key id %q does not match envelope key id %q", p.KeyID, env.KeyID)
	}
	signedAt := time.Unix(p.SignedAt, 0).UTC()
	key, err := v.keys.KeyAt(env.KeyID, signedAt)
	if err != nil {
		return nil, unverifiable(ReasonBadKey, "no valid signing key %q at %s: %v", env.KeyID, signedAt.Format(time.RFC3339), err)
	}
	if !ed25519.Verify(key, env.Payload, sig) {
		return nil, unverifiable(ReasonBadSignature, "signature does not verify")
	}
	if err := checkBinding(p, binding); err != nil {
		return nil, err
	}
	return &ReceiptView{
		Verification:          store.ReceiptVerified,
		ReceiptID:             p.ReceiptID,
		GrantID:               p.GrantID,
		MissionRef:            p.MissionRef,
		WorkspaceID:           p.WorkspaceID,
		KeyID:                 env.KeyID,
		SignedAt:              p.SignedAt,
		ReceiptDigest:         DigestPayload(env.Payload),
		SettlementDigest:      p.SettlementDigest,
		Outcome:               p.Outcome,
		MissionVersions:       append([]int64{}, p.MissionVersions...),
		ExpansionDecisionRefs: append([]string{}, p.ExpansionDecisionRefs...),
		RepositoryID:          p.RepositoryID,
		IssueNumber:           p.IssueNumber,
		Branch:                p.Branch,
		PullRequestNumber:     p.PullRequestNumber,
		HeadSHA:               p.HeadSHA,
		Checks:                append([]CheckSummary{}, p.Checks...),
		StartedAt:             p.StartedAt,
		FinishedAt:            p.FinishedAt,
		AggregateCostMicros:   p.AggregateCostMicros,
		BudgetMicros:          p.BudgetMicros,
		HistoricalEnforcement: append([]EnforcementSummary{}, p.HistoricalEnforcement...),
	}, nil
}

// checkPayloadSemantics validates the fixed receipt fields without any
// upstream call.
func checkPayloadSemantics(p Payload, now time.Time) error {
	if p.ReceiptID == "" || p.GrantID == "" || p.MissionRef == "" || p.WorkspaceID == "" {
		return unverifiable(ReasonBadPayload, "receipt, grant, mission, and workspace are required")
	}
	if p.Outcome != OutcomeSuccess && p.Outcome != OutcomeFailure {
		return unverifiable(ReasonBadPayload, "unknown outcome %q", p.Outcome)
	}
	if p.SignedAt <= 0 {
		return unverifiable(ReasonBadPayload, "missing signing time")
	}
	if !settlementDigestPattern.MatchString(p.SettlementDigest) {
		return unverifiable(ReasonBadPayload, "settlement digest %q is not a sha256 digest", p.SettlementDigest)
	}
	if signed := time.Unix(p.SignedAt, 0); signed.After(now.Add(maxClockSkew)) {
		return unverifiable(ReasonBadPayload, "signing time %s is in the future", signed.UTC().Format(time.RFC3339))
	}
	for _, ver := range p.MissionVersions {
		if ver <= 0 {
			return unverifiable(ReasonBadPayload, "mission version %d is not positive", ver)
		}
	}
	if p.StartedAt < 0 || p.FinishedAt < 0 {
		return unverifiable(ReasonBadPayload, "negative run timestamps")
	}
	if p.StartedAt > 0 && p.FinishedAt > 0 && p.FinishedAt < p.StartedAt {
		return unverifiable(ReasonBadPayload, "run finished before it started")
	}
	if p.AggregateCostMicros < 0 || p.BudgetMicros < 0 {
		return unverifiable(ReasonBadPayload, "negative cost or budget")
	}
	for i, c := range p.Checks {
		if c.Kind == "" || c.Outcome == "" {
			return unverifiable(ReasonBadPayload, "check %d is missing kind or outcome", i)
		}
	}
	for i, e := range p.HistoricalEnforcement {
		if e.Scope == "" || e.Level == "" {
			return unverifiable(ReasonBadPayload, "enforcement %d is missing scope or level", i)
		}
	}
	return nil
}

// checkBinding compares every binding claim in the payload against the
// locally projected binding. The receipt is checked against OPE's own
// projection; upstream is never asked whether its receipt is valid.
func checkBinding(p Payload, b Binding) error {
	if p.WorkspaceID != b.WorkspaceID {
		return unverifiable(ReasonBadBinding, "workspace %q does not match %q", p.WorkspaceID, b.WorkspaceID)
	}
	if p.MissionRef != b.MissionRef {
		return unverifiable(ReasonBadBinding, "mission ref %q does not match %q", p.MissionRef, b.MissionRef)
	}
	if p.GrantID != b.GrantID {
		return unverifiable(ReasonBadBinding, "grant %q does not match %q", p.GrantID, b.GrantID)
	}
	if p.Outcome != b.Outcome {
		return unverifiable(ReasonBadBinding, "outcome %q does not match projected %q", p.Outcome, b.Outcome)
	}
	if !equalInt64Sets(p.MissionVersions, b.MissionVersions) {
		return unverifiable(ReasonBadBinding, "mission versions %v do not match projected %v", p.MissionVersions, b.MissionVersions)
	}
	if !equalStringSets(p.ExpansionDecisionRefs, b.ExpansionDecisionRefs) {
		return unverifiable(ReasonBadBinding, "expansion decision refs %v do not match projected %v", p.ExpansionDecisionRefs, b.ExpansionDecisionRefs)
	}
	if p.RepositoryID != b.RepositoryID {
		return unverifiable(ReasonBadBinding, "repository %d does not match projected %d", p.RepositoryID, b.RepositoryID)
	}
	if p.IssueNumber != b.IssueNumber {
		return unverifiable(ReasonBadBinding, "issue %d does not match projected %d", p.IssueNumber, b.IssueNumber)
	}
	if p.Branch != b.Branch {
		return unverifiable(ReasonBadBinding, "branch %q does not match projected %q", p.Branch, b.Branch)
	}
	if p.PullRequestNumber != b.PullRequestNumber {
		return unverifiable(ReasonBadBinding, "pull request %d does not match projected %d", p.PullRequestNumber, b.PullRequestNumber)
	}
	if p.HeadSHA != b.HeadSHA {
		return unverifiable(ReasonBadBinding, "head sha %q does not match projected %q", p.HeadSHA, b.HeadSHA)
	}
	return nil
}

func equalInt64Sets(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]int64{}, a...)
	bc := append([]int64{}, b...)
	sort.Slice(ac, func(i, j int) bool { return ac[i] < ac[j] })
	sort.Slice(bc, func(i, j int) bool { return bc[i] < bc[j] })
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string{}, a...)
	bc := append([]string{}, b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
