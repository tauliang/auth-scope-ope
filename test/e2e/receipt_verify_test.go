package e2e

// Fake-issued receipts are verified with the real production verifier.
// The fake signs receipt.Payload bytes in canonical form, so a receipt
// minted by the fake passes internal/receipt.Verifier exactly as an
// upstream receipt would.

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/receipt"
)

func newReceiptTestFake(t *testing.T, now time.Time) *FakeAuthScope {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return NewFakeAuthScope(FakeOptions{
		WorkspaceID:       "ws-receipt-test",
		WorkloadPublicKey: pub,
		Now:               func() time.Time { return now },
	})
}

func receiptTestBinding() receipt.Binding {
	return receipt.Binding{
		WorkspaceID:     "ws-receipt-test",
		MissionRef:      "mission-1",
		GrantID:         "grant-1",
		Outcome:         "success",
		MissionVersions: []int64{1},
	}
}

func TestFakeReceiptVerifiesWithRealVerifier(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := newReceiptTestFake(t, now)
	g := &fakeGrant{
		grantID:        "grant-1",
		missionRef:     "mission-1",
		budgetMicros:   1_000_000,
		remainingMicro: 400_000,
		outcome:        "success",
	}
	f.grants[g.grantID] = g
	env := f.signReceiptLocked(g)

	ks := pinFakeSigningKey(t, f, now)
	v := receipt.NewVerifier(ks, func() time.Time { return now })
	view, err := v.Verify(*env, receiptTestBinding())
	if err != nil {
		t.Fatalf("real verifier rejected the fake receipt: %v", err)
	}
	if view.ReceiptID != "receipt_grant-1" {
		t.Fatalf("receipt id = %q, want receipt_grant-1", view.ReceiptID)
	}
	if view.AggregateCostMicros != 600_000 {
		t.Fatalf("aggregate cost = %d, want 600000", view.AggregateCostMicros)
	}
	if view.Outcome != "success" || view.SignedAt != now.Unix() {
		t.Fatalf("unexpected verified view: %+v", view)
	}
}

func TestFakeReceiptTamperFailsRealVerifier(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := newReceiptTestFake(t, now)
	g := &fakeGrant{
		grantID:        "grant-1",
		missionRef:     "mission-1",
		budgetMicros:   1_000_000,
		remainingMicro: 400_000,
		outcome:        "success",
	}
	f.grants[g.grantID] = g
	env := f.signReceiptLocked(g)

	ks := pinFakeSigningKey(t, f, now)
	v := receipt.NewVerifier(ks, func() time.Time { return now })

	tampered := *env
	tampered.Payload = append([]byte{}, env.Payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 0x01
	if _, err := v.Verify(tampered, receiptTestBinding()); err == nil {
		t.Fatal("real verifier accepted a tampered fake receipt")
	}
}

func TestFakeReceiptWrongBindingFailsRealVerifier(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	f := newReceiptTestFake(t, now)
	g := &fakeGrant{
		grantID:        "grant-1",
		missionRef:     "mission-1",
		budgetMicros:   1_000_000,
		remainingMicro: 400_000,
		outcome:        "success",
	}
	f.grants[g.grantID] = g
	env := f.signReceiptLocked(g)

	ks := pinFakeSigningKey(t, f, now)
	v := receipt.NewVerifier(ks, func() time.Time { return now })

	binding := receiptTestBinding()
	binding.WorkspaceID = "ws-someone-else"
	if _, err := v.Verify(*env, binding); err == nil {
		t.Fatal("real verifier accepted a fake receipt under a foreign workspace binding")
	}
}
