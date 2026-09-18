package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testClaims() DecisionClaims {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	return DecisionClaims{
		WorkspaceID:               "ws-test",
		FounderID:                 "founder-1",
		Audience:                  AudienceProposalApproval,
		Purpose:                   PurposePassApproval,
		SubjectID:                 "proposal-1",
		DecisionDigest:            "sha256:" + strings.Repeat("a", 64),
		InvocationDigest:          "sha256:" + strings.Repeat("b", 64),
		AuthenticationMethod:      AuthMethodWebAuthnUV,
		AuthenticationProofDigest: "sha256:" + strings.Repeat("c", 64),
		Nonce:                     nonce,
		IssuedAt:                  now,
		ExpiresAt:                 now.Add(5 * time.Minute),
	}
}

func TestAttestRoundTrip(t *testing.T) {
	signer := NewEphemeralSigner()
	attestor := NewDecisionAttestor(signer)
	claims := testClaims()
	att, err := attestor.Attest(context.Background(), claims)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if att.Algorithm != AlgorithmTag {
		t.Fatalf("algorithm = %q", att.Algorithm)
	}
	if att.KeyID != signer.KeyID() {
		t.Fatalf("key id = %q", att.KeyID)
	}
	if att.IdentityDigest != signer.IdentityDigest() {
		t.Fatalf("identity digest = %q", att.IdentityDigest)
	}
	canonical, err := CanonicalClaimsJSON(claims, signer.KeyID(), signer.IdentityDigest())
	if err != nil {
		t.Fatalf("CanonicalClaimsJSON: %v", err)
	}
	if !ed25519.Verify(signer.PublicKey(), signedMessage(canonical), att.Signature) {
		t.Fatal("signature does not verify over the canonical claims")
	}
}

func TestAttestRejectsPurposeBindingViolations(t *testing.T) {
	signer := NewEphemeralSigner()
	attestor := NewDecisionAttestor(signer)
	cases := []struct {
		name   string
		mutate func(*DecisionClaims)
	}{
		{"unknown purpose", func(c *DecisionClaims) { c.Purpose = "do_anything" }},
		{"audience mismatch", func(c *DecisionClaims) { c.Audience = AudienceMissionRevoke }},
		{"method mismatch", func(c *DecisionClaims) { c.AuthenticationMethod = AuthMethodOfflineRecovery }},
		{"offline recovery with online purpose", func(c *DecisionClaims) {
			c.Purpose = PurposeOfflineRecoveryContain
			c.Audience = AudienceWorkspaceContain
			c.AuthenticationMethod = AuthMethodWebAuthnUV
		}},
		{"webauthn with offline purpose", func(c *DecisionClaims) {
			c.Purpose = PurposeOfflineRecoveryContain
			c.Audience = AudienceWorkspaceContain
			c.InvocationDigest = ""
		}},
		{"invocation digest on offline containment", func(c *DecisionClaims) {
			c.Purpose = PurposeOfflineRecoveryContain
			c.Audience = AudienceWorkspaceContain
			c.AuthenticationMethod = AuthMethodOfflineRecovery
		}},
		{"missing invocation digest", func(c *DecisionClaims) { c.InvocationDigest = "" }},
		{"empty workspace", func(c *DecisionClaims) { c.WorkspaceID = "" }},
		{"empty founder", func(c *DecisionClaims) { c.FounderID = "" }},
		{"empty subject", func(c *DecisionClaims) { c.SubjectID = "" }},
		{"bad decision digest", func(c *DecisionClaims) { c.DecisionDigest = "not-a-digest" }},
		{"bad proof digest", func(c *DecisionClaims) { c.AuthenticationProofDigest = "sha256:zzz" }},
		{"zero nonce", func(c *DecisionClaims) { c.Nonce = [32]byte{} }},
		{"expiry before issue", func(c *DecisionClaims) { c.ExpiresAt = c.IssuedAt.Add(-time.Second) }},
		{"ttl too long", func(c *DecisionClaims) { c.ExpiresAt = c.IssuedAt.Add(time.Hour) }},
		{"issued in future", func(c *DecisionClaims) {
			c.IssuedAt = time.Now().Add(10 * time.Minute)
			c.ExpiresAt = c.IssuedAt.Add(time.Minute)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := testClaims()
			tc.mutate(&claims)
			if _, err := attestor.Attest(context.Background(), claims); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestAttestOfflineRecoveryContain(t *testing.T) {
	signer := NewEphemeralSigner()
	attestor := NewDecisionAttestor(signer)
	claims := testClaims()
	claims.Purpose = PurposeOfflineRecoveryContain
	claims.Audience = AudienceWorkspaceContain
	claims.AuthenticationMethod = AuthMethodOfflineRecovery
	claims.InvocationDigest = ""
	claims.SubjectID = "ws-test"
	att, err := attestor.Attest(context.Background(), claims)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	canonical, err := CanonicalClaimsJSON(claims, signer.KeyID(), signer.IdentityDigest())
	if err != nil {
		t.Fatalf("CanonicalClaimsJSON: %v", err)
	}
	if !ed25519.Verify(signer.PublicKey(), signedMessage(canonical), att.Signature) {
		t.Fatal("signature does not verify")
	}
	if strings.Contains(string(canonical), "invocation_digest") {
		t.Fatalf("offline containment must not carry invocation_digest: %s", canonical)
	}
}

func TestAttestRequiresSigner(t *testing.T) {
	attestor := NewDecisionAttestor(nil)
	if _, err := attestor.Attest(context.Background(), testClaims()); err == nil {
		t.Fatal("expected an error for nil signer")
	}
}

func TestCanonicalClaimsAreDeterministic(t *testing.T) {
	claims := testClaims()
	signer := NewEphemeralSigner()
	first, err := CanonicalClaimsJSON(claims, signer.KeyID(), signer.IdentityDigest())
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalClaimsJSON(claims, signer.KeyID(), signer.IdentityDigest())
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("canonical claims are not deterministic")
	}
	// The nonce must be 43 base64url characters for 32 bytes.
	if !strings.Contains(string(first), `"nonce":"`+base64.RawURLEncoding.EncodeToString(claims.Nonce[:])+`"`) {
		t.Fatalf("nonce encoding wrong: %s", first)
	}
}

func TestWireEnvelopeMatchesContract(t *testing.T) {
	signer := NewEphemeralSigner()
	attestor := NewDecisionAttestor(signer)
	att, err := attestor.Attest(context.Background(), testClaims())
	if err != nil {
		t.Fatal(err)
	}
	env, err := WireEnvelope(att)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"algorithm", "key_id", "identity_digest", "claims", "signature"} {
		if _, ok := env[key]; !ok {
			t.Fatalf("envelope missing %q", key)
		}
	}
	sig, _ := env["signature"].(string)
	if len(sig) != 86 {
		t.Fatalf("signature length = %d, want 86 base64url chars", len(sig))
	}
	if _, err := base64.RawURLEncoding.DecodeString(sig); err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
}

func TestEphemeralSignerIsDevOnly(t *testing.T) {
	signer := NewEphemeralSigner()
	if !strings.HasPrefix(signer.KeyID(), "dev-ephemeral-") {
		t.Fatalf("dev signer key id must be marked dev-only, got %q", signer.KeyID())
	}
	if !strings.HasPrefix(signer.IdentityDigest(), "sha256:") {
		t.Fatalf("identity digest = %q", signer.IdentityDigest())
	}
}
