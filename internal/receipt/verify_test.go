// Tests for local receipt signature verification. The verifier is the
// trust boundary of Task 12: it checks an upstream receipt envelope
// against locally pinned keys and the pass binding before anything is
// allowed to move a pass to a terminal outcome.
package receipt_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/coreapi"
	"github.com/tauliang/authscope-ope/internal/receipt"
	"github.com/tauliang/authscope-ope/internal/trust"
)

type testSigner struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newTestSigner(t *testing.T, id string) testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testSigner{id: id, pub: pub, priv: priv}
}

func fingerprintOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type pinKeySpec struct {
	signer     testSigner
	root       bool
	rotated    *testSigner
	validFrom  string
	validUntil string
}

func writePin(t *testing.T, keys []pinKeySpec) (path string, fps map[string]string) {
	t.Helper()
	type pinKey struct {
		KeyID             string `json:"key_id"`
		Algorithm         string `json:"algorithm"`
		PublicKey         string `json:"public_key"`
		Root              bool   `json:"root,omitempty"`
		RotatedFrom       string `json:"rotated_from,omitempty"`
		ValidFrom         string `json:"valid_from"`
		ValidUntil        string `json:"valid_until,omitempty"`
		RotationStatement string `json:"rotation_statement,omitempty"`
		RotationSignature string `json:"rotation_signature,omitempty"`
	}
	var out []pinKey
	fps = map[string]string{}
	for _, k := range keys {
		pk := pinKey{
			KeyID:     k.signer.id,
			Algorithm: "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(k.signer.pub),
			Root:      k.root,
			ValidFrom: k.validFrom,
		}
		if k.validUntil != "" {
			pk.ValidUntil = k.validUntil
		}
		if k.rotated != nil {
			stmt := map[string]any{
				"domain":          "authscope-signing-keys/rotation/v1",
				"previous_key_id": k.rotated.id,
				"new_key_id":      k.signer.id,
				"new_public_key":  base64.RawURLEncoding.EncodeToString(k.signer.pub),
				"issued_at":       time.Now().UTC().Format(time.RFC3339),
			}
			raw, err := json.Marshal(stmt)
			if err != nil {
				t.Fatalf("marshal rotation statement: %v", err)
			}
			sig := ed25519.Sign(k.rotated.priv, raw)
			pk.RotatedFrom = k.rotated.id
			pk.RotationStatement = base64.RawURLEncoding.EncodeToString(raw)
			pk.RotationSignature = base64.RawURLEncoding.EncodeToString(sig)
		}
		out = append(out, pk)
		fps[k.signer.id] = fingerprintOf(k.signer.pub)
	}
	rootFP := ""
	for _, k := range keys {
		if k.root {
			rootFP = fps[k.signer.id]
		}
	}
	doc := map[string]any{
		"format":                   "authscope-signing-keys/v1",
		"signing_root_fingerprint": rootFP,
		"keys":                     out,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal pin: %v", err)
	}
	path = t.TempDir() + "/pin.json"
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write pin: %v", err)
	}
	return path, fps
}

func newVerifier(t *testing.T, pinPath string, rootFP string, now time.Time) *receipt.Verifier {
	t.Helper()
	ks, err := trust.LoadSigningKeys(pinPath, rootFP)
	if err != nil {
		t.Fatalf("load signing keys: %v", err)
	}
	return receipt.NewVerifier(ks, func() time.Time { return now })
}

func baseBinding() receipt.Binding {
	return receipt.Binding{
		WorkspaceID:           "ws-test",
		MissionRef:            "mission-1",
		GrantID:               "run-1",
		Outcome:               receipt.OutcomeSuccess,
		MissionVersions:       []int64{3},
		ExpansionDecisionRefs: []string{"dec-1"},
		RepositoryID:          111,
		IssueNumber:           42,
		Branch:                "authscope/mission-1",
		PullRequestNumber:     7,
		HeadSHA:               strings.Repeat("a", 40),
	}
}

func basePayload(signer testSigner, now time.Time) receipt.Payload {
	return receipt.Payload{
		ReceiptID:             "rcpt-1",
		GrantID:               "run-1",
		MissionRef:            "mission-1",
		WorkspaceID:           "ws-test",
		KeyID:                 signer.id,
		SignedAt:              now.Unix(),
		Outcome:               receipt.OutcomeSuccess,
		MissionVersions:       []int64{3},
		ExpansionDecisionRefs: []string{"dec-1"},
		RepositoryID:          111,
		IssueNumber:           42,
		Branch:                "authscope/mission-1",
		PullRequestNumber:     7,
		HeadSHA:               strings.Repeat("a", 40),
		Checks:                []receipt.CheckSummary{{Kind: "unit_tests", Outcome: "passed"}},
		StartedAt:             now.Add(-time.Hour).Unix(),
		FinishedAt:            now.Add(-time.Minute).Unix(),
		AggregateCostMicros:   100,
		SettlementDigest:      "sha256:" + strings.Repeat("b", 64),
		HistoricalEnforcement: []receipt.EnforcementSummary{{Scope: "github", Level: "enforced"}},
	}
}

func signEnvelope(t *testing.T, signer testSigner, p receipt.Payload) coreapi.SignedReceiptEnvelope {
	t.Helper()
	raw, err := receipt.CanonicalPayloadBytes(p)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	sig := ed25519.Sign(signer.priv, raw)
	return coreapi.SignedReceiptEnvelope{
		Algorithm: "Ed25519",
		KeyID:     signer.id,
		Payload:   raw,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
}

func reasonOf(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatalf("expected verification error")
	}
	msg := err.Error()
	for _, code := range []string{
		receipt.ReasonBadSignature, receipt.ReasonBadKey,
		receipt.ReasonBadPayload, receipt.ReasonBadBinding,
	} {
		if strings.Contains(msg, code) {
			return code
		}
	}
	t.Fatalf("error %q carries no reason code", msg)
	return ""
}

func TestVerifyValidReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	env := signEnvelope(t, signer, basePayload(signer, now))
	view, err := v.Verify(env, baseBinding())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if view.Verification != "verified" {
		t.Errorf("verification = %q, want verified", view.Verification)
	}
	if view.Outcome != receipt.OutcomeSuccess || view.ReceiptID != "rcpt-1" || view.KeyID != signer.id {
		t.Errorf("unexpected view fields: %+v", view)
	}
	if view.ReceiptDigest == "" {
		t.Errorf("receipt digest is empty")
	}
	if len(view.MissionVersions) != 1 || view.MissionVersions[0] != 3 {
		t.Errorf("mission versions = %v", view.MissionVersions)
	}
}

func TestVerifyTamperedField(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	p := basePayload(signer, now)
	env := signEnvelope(t, signer, p)
	// Flip one byte inside the signed payload: the canonical form no
	// longer matches and the signature cannot verify.
	env.Payload[20] ^= 0x01
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload && got != receipt.ReasonBadSignature {
		t.Errorf("reason = %q, want bad_payload or bad_signature", got)
	}
}

func mustVerifyErr(v *receipt.Verifier, env coreapi.SignedReceiptEnvelope) error {
	_, err := v.Verify(env, baseBinding())
	return err
}

func TestVerifyWrongOutcomeBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	p := basePayload(signer, now)
	p.Outcome = receipt.OutcomeFailure
	env := signEnvelope(t, signer, p)
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadBinding {
		t.Errorf("reason = %q, want bad_binding", got)
	}
}

func TestVerifyUnsupportedAlgorithm(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	env := signEnvelope(t, signer, basePayload(signer, now))
	env.Algorithm = "RSA"
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload {
		t.Errorf("reason = %q, want bad_payload", got)
	}
}

func TestVerifyUnknownFieldRejected(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	raw, err := receipt.CanonicalPayloadBytes(basePayload(signer, now))
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	obj["sneaky_field"] = "nope"
	raw, err = json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sig := ed25519.Sign(signer.priv, raw)
	env := coreapi.SignedReceiptEnvelope{
		Algorithm: "Ed25519", KeyID: signer.id, Payload: raw,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload {
		t.Errorf("reason = %q, want bad_payload", got)
	}
}

func TestVerifyTrailingDataRejected(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	env := signEnvelope(t, signer, basePayload(signer, now))
	env.Payload = append(env.Payload, ' ')
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload {
		t.Errorf("reason = %q, want bad_payload", got)
	}
}

func TestVerifyNonCanonicalRejected(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	// Pretty-printed JSON decodes to the same payload but is not the
	// exact canonical bytes the signature must cover.
	raw, err := receipt.CanonicalPayloadBytes(basePayload(signer, now))
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, raw, "", "  "); err != nil {
		t.Fatalf("indent: %v", err)
	}
	prettyRaw := pretty.Bytes()
	sig := ed25519.Sign(signer.priv, prettyRaw)
	env := coreapi.SignedReceiptEnvelope{
		Algorithm: "Ed25519", KeyID: signer.id, Payload: prettyRaw,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload {
		t.Errorf("reason = %q, want bad_payload", got)
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	other := newTestSigner(t, "key-2")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	env := signEnvelope(t, other, basePayload(other, now))
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadKey {
		t.Errorf("reason = %q, want bad_key", got)
	}
}

func TestVerifyKeyNotYetValid(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	env := signEnvelope(t, signer, basePayload(signer, now))
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadKey {
		t.Errorf("reason = %q, want bad_key", got)
	}
}

func TestVerifyKeyExpired(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom:  now.Add(-2 * time.Hour).Format(time.RFC3339),
		validUntil: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	env := signEnvelope(t, signer, basePayload(signer, now))
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadKey {
		t.Errorf("reason = %q, want bad_key", got)
	}
}

func TestVerifyBindingMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	cases := map[string]func(*receipt.Binding){
		"workspace": func(b *receipt.Binding) { b.WorkspaceID = "ws-other" },
		"mission":   func(b *receipt.Binding) { b.MissionRef = "mission-9" },
		"grant":     func(b *receipt.Binding) { b.GrantID = "run-9" },
		"versions":  func(b *receipt.Binding) { b.MissionVersions = []int64{4} },
		"expansions": func(b *receipt.Binding) {
			b.ExpansionDecisionRefs = []string{"dec-1", "dec-2"}
		},
		"repository": func(b *receipt.Binding) { b.RepositoryID = 999 },
		"issue":      func(b *receipt.Binding) { b.IssueNumber = 43 },
		"branch":     func(b *receipt.Binding) { b.Branch = "other/branch" },
		"pull":       func(b *receipt.Binding) { b.PullRequestNumber = 8 },
		"head":       func(b *receipt.Binding) { b.HeadSHA = strings.Repeat("b", 40) },
	}
	for name, mutate := range cases {
		b := baseBinding()
		mutate(&b)
		env := signEnvelope(t, signer, basePayload(signer, now))
		if _, err := v.Verify(env, b); err == nil {
			t.Errorf("%s: expected bad_binding", name)
		} else if got := reasonOf(t, err); got != receipt.ReasonBadBinding {
			t.Errorf("%s: reason = %q, want bad_binding", name, got)
		}
	}
}

func TestVerifyFutureSigningTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	p := basePayload(signer, now)
	p.SignedAt = now.Add(time.Hour).Unix()
	env := signEnvelope(t, signer, p)
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload {
		t.Errorf("reason = %q, want bad_payload", got)
	}
}

func TestVerifyInvalidOutcome(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	p := basePayload(signer, now)
	p.Outcome = "maybe"
	env := signEnvelope(t, signer, p)
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload {
		t.Errorf("reason = %q, want bad_payload", got)
	}
}

func TestVerifySettlementDigest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	// The cumulative budget settlement digest is a required signed
	// field: it must be present and shaped like a sha256 digest.
	for _, digest := range []string{"", "not-a-digest", "sha256:" + strings.Repeat("z", 64)} {
		p := basePayload(signer, now)
		p.SettlementDigest = digest
		env := signEnvelope(t, signer, p)
		if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadPayload {
			t.Errorf("digest %q: reason = %q, want bad_payload", digest, got)
		}
	}

	// A well-formed digest verifies and is carried in the private view.
	p := basePayload(signer, now)
	env := signEnvelope(t, signer, p)
	view, err := v.Verify(env, baseBinding())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if view.SettlementDigest != p.SettlementDigest {
		t.Errorf("settlement digest = %q, want %q", view.SettlementDigest, p.SettlementDigest)
	}
}

func TestVerifyDoesNotProjectEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	// The signed free-text evidence is covered by the signature, but the
	// verified projection must never carry it into a rendered view.
	p := basePayload(signer, now)
	p.AcceptanceEvidence = []string{"the founder asked for retry with backoff"}
	p.TestSummaries = []string{"120 tests passed, 2 skipped"}
	p.ExceptionSummaries = []string{"panic: runtime error in worker"}
	p.BudgetNote = "budget stays under 5000 micros"
	env := signEnvelope(t, signer, p)
	view, err := v.Verify(env, baseBinding())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	for _, c := range canaries {
		if strings.Contains(string(raw), c) {
			t.Errorf("verified view leaks canary %q", c)
		}
	}
}

func TestVerifyPayloadKeyIDMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer := newTestSigner(t, "key-1")
	other := newTestSigner(t, "key-2")
	pinPath, fps := writePin(t, []pinKeySpec{{
		signer: signer, root: true,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}, {
		signer: other, root: false, rotated: &signer,
		validFrom: now.Add(-time.Hour).Format(time.RFC3339),
	}})
	v := newVerifier(t, pinPath, fps[signer.id], now)

	// Envelope names key-2 but the payload names key-1: the two must
	// agree before the signature is even checked.
	p := basePayload(signer, now)
	raw, err := receipt.CanonicalPayloadBytes(p)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	sig := ed25519.Sign(other.priv, raw)
	env := coreapi.SignedReceiptEnvelope{
		Algorithm: "Ed25519", KeyID: other.id, Payload: raw,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
	}
	if got := reasonOf(t, mustVerifyErr(v, env)); got != receipt.ReasonBadKey {
		t.Errorf("reason = %q, want bad_key", got)
	}
}
