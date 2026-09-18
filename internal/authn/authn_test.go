package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tauliang/authscope-ope/internal/store"
)

// fakeVerifier stubs WebAuthn ceremony cryptography. Outcomes are queued
// per ceremony index so tests stay deterministic.
type fakeVerifier struct {
	regOutcomes    []fakeRegOutcome
	assertOutcomes []fakeAssertOutcome

	beginRegCalls    []fakeBeginRegCall
	beginAssertCalls []fakeBeginAssertCall
}

type fakeRegOutcome struct {
	id           []byte
	publicKey    []byte
	signCount    uint32
	userVerified bool
	err          error
}

type fakeAssertOutcome struct {
	credentialID []byte
	newSignCount uint32
	userVerified bool
	err          error
}

type fakeBeginRegCall struct {
	user       CeremonyUser
	rpID       string
	origin     string
	excludeIDs [][]byte
}

type fakeBeginAssertCall struct {
	user       CeremonyUser
	rpID       string
	origin     string
	allowedIDs [][]byte
}

func (f *fakeVerifier) BeginRegistration(_ context.Context, user CeremonyUser, rpID, origin string, excludeIDs [][]byte) ([]byte, []byte, error) {
	idx := len(f.beginRegCalls)
	f.beginRegCalls = append(f.beginRegCalls, fakeBeginRegCall{user: user, rpID: rpID, origin: origin, excludeIDs: excludeIDs})
	return []byte(`{"type":"registration"}`), []byte(fmt.Sprintf(`{"idx":%d}`, idx)), nil
}

func (f *fakeVerifier) FinishRegistration(_ context.Context, _ CeremonyUser, sessionJSON, _ []byte) (RegisteredCredential, error) {
	var s struct {
		Idx int `json:"idx"`
	}
	if err := json.Unmarshal(sessionJSON, &s); err != nil {
		return RegisteredCredential{}, err
	}
	if s.Idx >= len(f.regOutcomes) {
		return RegisteredCredential{}, errors.New("fake: no registration outcome queued")
	}
	o := f.regOutcomes[s.Idx]
	if o.err != nil {
		return RegisteredCredential{}, o.err
	}
	return RegisteredCredential{
		ID:           o.id,
		PublicKey:    o.publicKey,
		SignCount:    o.signCount,
		Transports:   []string{"internal"},
		UserVerified: o.userVerified,
	}, nil
}

func (f *fakeVerifier) BeginAssertion(_ context.Context, user CeremonyUser, rpID, origin string, allowedIDs [][]byte) ([]byte, []byte, error) {
	idx := len(f.beginAssertCalls)
	f.beginAssertCalls = append(f.beginAssertCalls, fakeBeginAssertCall{user: user, rpID: rpID, origin: origin, allowedIDs: allowedIDs})
	return []byte(`{"type":"assertion"}`), []byte(fmt.Sprintf(`{"idx":%d}`, idx)), nil
}

func (f *fakeVerifier) FinishAssertion(_ context.Context, _ CeremonyUser, _ []StoredCredential, sessionJSON, _ []byte) (VerifiedAssertion, error) {
	var s struct {
		Idx int `json:"idx"`
	}
	if err := json.Unmarshal(sessionJSON, &s); err != nil {
		return VerifiedAssertion{}, err
	}
	if s.Idx >= len(f.assertOutcomes) {
		return VerifiedAssertion{}, errors.New("fake: no assertion outcome queued")
	}
	o := f.assertOutcomes[s.Idx]
	if o.err != nil {
		return VerifiedAssertion{}, o.err
	}
	return VerifiedAssertion{
		CredentialID: o.credentialID,
		NewSignCount: o.newSignCount,
		UserVerified: o.userVerified,
	}, nil
}

// testClock is a mutable clock for ceremony and session expiry tests.
type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time { return c.now }

func newTestService(t *testing.T) (*Service, *fakeVerifier, store.Store, *testClock) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close test store: %v", err)
		}
	})
	inst := store.InstanceRecord{
		InstanceID:        "inst-test-1",
		WorkspaceID:       "ws-test",
		Hostname:          "ope.example.com",
		Origin:            "https://ope.example.com",
		RPID:              "ope.example.com",
		SessionCookieName: store.DeriveSessionCookieName("inst-test-1"),
		CreatedAt:         time.Now().UTC(),
	}
	if err := db.WithTx(ctx, func(tx store.Tx) error {
		return tx.BindInstance(ctx, inst)
	}); err != nil {
		t.Fatalf("bind instance: %v", err)
	}
	fv := &fakeVerifier{}
	svc, err := NewService(ctx, db, fv)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	clock := &testClock{now: time.Now().UTC().Truncate(time.Second)}
	svc.now = clock.Now
	return svc, fv, db, clock
}

// enrollFounder runs the full bootstrap ceremony with the fake verifier
// and returns the founder session material.
func enrollFounder(t *testing.T, svc *Service, fv *fakeVerifier, method RecoveryMethod) (founderID, sessionToken, csrfToken string) {
	t.Helper()
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	if code == "" {
		t.Fatal("expected a bootstrap code for an unenrolled workspace")
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	fv.regOutcomes = append(fv.regOutcomes, fakeRegOutcome{
		id: []byte("cred-first"), publicKey: []byte("pk-first"), userVerified: true,
	})
	reg, err := svc.BeginBootstrapRegistration(ctx, token, "Shengquan")
	if err != nil {
		t.Fatalf("begin bootstrap registration: %v", err)
	}
	if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
		CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
	}); err != nil {
		t.Fatalf("finish bootstrap registration: %v", err)
	}
	var confirmation string
	switch method {
	case RecoveryMethodPasskey:
		fv.regOutcomes = append(fv.regOutcomes, fakeRegOutcome{
			id: []byte("cred-recovery"), publicKey: []byte("pk-recovery"), userVerified: true,
		})
		rec, err := svc.Bootstrap().BeginRecovery(ctx, token, RecoveryMethodPasskey)
		if err != nil {
			t.Fatalf("begin recovery: %v", err)
		}
		if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
			CeremonyID: rec.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
		}); err != nil {
			t.Fatalf("finish recovery registration: %v", err)
		}
	case RecoveryMethodOfflineKey:
		rec, err := svc.Bootstrap().BeginRecovery(ctx, token, RecoveryMethodOfflineKey)
		if err != nil {
			t.Fatalf("begin recovery: %v", err)
		}
		if rec.RecoveryKey == "" {
			t.Fatal("expected a one-time recovery key")
		}
		confirmation = rec.RecoveryKey
	default:
		t.Fatalf("unknown recovery method %q", method)
	}
	res, err := svc.Bootstrap().Complete(ctx, token, confirmation)
	if err != nil {
		t.Fatalf("bootstrap complete: %v", err)
	}
	return res.FounderID, res.SessionToken, res.CSRFToken
}

func mustPrincipal(t *testing.T, svc *Service, token string) Principal {
	t.Helper()
	p, _, err := svc.AuthenticateSessionToken(context.Background(), token)
	if err != nil {
		t.Fatalf("authenticate session: %v", err)
	}
	return p
}

func TestNewServiceRequiresInstanceBinding(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(t.TempDir(), "development")
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := NewService(ctx, db, &fakeVerifier{}); !errors.Is(err, ErrNoInstanceBinding) {
		t.Fatalf("expected ErrNoInstanceBinding, got %v", err)
	}
	if _, err := NewService(ctx, nil, &fakeVerifier{}); err == nil {
		t.Fatal("expected an error for a nil store")
	}
}

func TestBootstrapFullFlowPasskeyRecovery(t *testing.T) {
	svc, fv, db, _ := newTestService(t)
	ctx := context.Background()
	founderID, sessionToken, csrfToken := enrollFounder(t, svc, fv, RecoveryMethodPasskey)

	// The recovery registration must exclude the first credential so the
	// two passkeys are independent.
	if len(fv.beginRegCalls) != 2 {
		t.Fatalf("expected 2 registration ceremonies, got %d", len(fv.beginRegCalls))
	}
	excluded := fv.beginRegCalls[1].excludeIDs
	if len(excluded) != 1 || string(excluded[0]) != "cred-first" {
		t.Fatalf("recovery registration did not exclude the first credential: %q", excluded)
	}
	if fv.beginRegCalls[0].rpID != "ope.example.com" || fv.beginRegCalls[0].origin != "https://ope.example.com" {
		t.Fatalf("registration used wrong RP binding: %+v", fv.beginRegCalls[0])
	}
	if fv.beginRegCalls[0].user.DisplayName != "Shengquan" {
		t.Fatalf("display name not passed through: %q", fv.beginRegCalls[0].user.DisplayName)
	}

	founders, err := db.ListFounders(ctx, "ws-test")
	if err != nil {
		t.Fatalf("list founders: %v", err)
	}
	if len(founders) != 1 || founders[0].FounderID != founderID {
		t.Fatalf("unexpected founders: %+v", founders)
	}
	if founders[0].DisplayName != "Shengquan" {
		t.Fatalf("display name not persisted: %q", founders[0].DisplayName)
	}
	creds, err := db.ListWebAuthnCredentials(ctx, "ws-test", founderID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("expected 2 staged credentials flushed, got %d", len(creds))
	}

	p, rec, err := svc.AuthenticateSessionToken(ctx, sessionToken)
	if err != nil {
		t.Fatalf("authenticate first session: %v", err)
	}
	if p.FounderID != founderID || p.WorkspaceID != "ws-test" || rec.SessionID != p.SessionID {
		t.Fatalf("principal mismatch: %+v", p)
	}
	if err := VerifyCSRFToken(rec, csrfToken); err != nil {
		t.Fatalf("verify CSRF token: %v", err)
	}
	if err := VerifyCSRFToken(rec, "bogus"); !errors.Is(err, ErrCSRFMismatch) {
		t.Fatalf("expected ErrCSRFMismatch, got %v", err)
	}
}

func TestBootstrapOfflineRecovery(t *testing.T) {
	svc, fv, db, _ := newTestService(t)
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	fv.regOutcomes = append(fv.regOutcomes, fakeRegOutcome{
		id: []byte("cred-first"), publicKey: []byte("pk-first"), userVerified: true,
	})
	reg, err := svc.BeginBootstrapRegistration(ctx, token, "")
	if err != nil {
		t.Fatalf("begin bootstrap registration: %v", err)
	}
	if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
		CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
	}); err != nil {
		t.Fatalf("finish bootstrap registration: %v", err)
	}
	rec, err := svc.Bootstrap().BeginRecovery(ctx, token, RecoveryMethodOfflineKey)
	if err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	if rec.RecoveryKey == "" {
		t.Fatal("expected a one-time recovery key")
	}

	// A wrong confirmation must fail: possession of the printed key is
	// required.
	wrong := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if _, err := svc.Bootstrap().Complete(ctx, token, wrong); !errors.Is(err, ErrRecoveryNotVerified) {
		t.Fatalf("expected ErrRecoveryNotVerified, got %v", err)
	}
	res, err := svc.Bootstrap().Complete(ctx, token, rec.RecoveryKey)
	if err != nil {
		t.Fatalf("bootstrap complete: %v", err)
	}
	key, err := db.GetOfflineRecoveryKey(ctx, "ws-test", res.FounderID)
	if err != nil {
		t.Fatalf("get recovery key: %v", err)
	}
	if key.KeyHash == "" {
		t.Fatal("expected a stored recovery key hash")
	}
	if strings.Contains(key.KeyHash, rec.RecoveryKey) || key.KeyHash == rec.RecoveryKey {
		t.Fatal("raw recovery key must never be stored")
	}
}

func TestBootstrapRequiresIndependentRecovery(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	// Recovery cannot start before the first passkey is registered.
	if _, err := svc.Bootstrap().BeginRecovery(ctx, token, RecoveryMethodOfflineKey); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("expected ErrRecoveryRequired, got %v", err)
	}
	if _, err := svc.Bootstrap().Complete(ctx, token, ""); !errors.Is(err, ErrRecoveryRequired) {
		t.Fatalf("expected ErrRecoveryRequired on complete, got %v", err)
	}
}

func TestBootstrapRecoveryPasskeyMustBeIndependent(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	fv.regOutcomes = append(fv.regOutcomes,
		fakeRegOutcome{id: []byte("cred-same"), publicKey: []byte("pk-1"), userVerified: true},
		fakeRegOutcome{id: []byte("cred-same"), publicKey: []byte("pk-1"), userVerified: true},
	)
	reg, err := svc.BeginBootstrapRegistration(ctx, token, "")
	if err != nil {
		t.Fatalf("begin bootstrap registration: %v", err)
	}
	if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
		CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
	}); err != nil {
		t.Fatalf("finish bootstrap registration: %v", err)
	}
	rec, err := svc.Bootstrap().BeginRecovery(ctx, token, RecoveryMethodPasskey)
	if err != nil {
		t.Fatalf("begin recovery: %v", err)
	}
	// Registering the same passkey as the recovery method is rejected: the
	// recovery method must be independent.
	if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
		CeremonyID: rec.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
	}); !errors.Is(err, ErrDuplicateCredential) {
		t.Fatalf("expected ErrDuplicateCredential, got %v", err)
	}
}

func TestBootstrapCodeOneUse(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()

	if _, _, err := svc.Bootstrap().Begin(ctx, ""); !errors.Is(err, ErrBootstrapCode) {
		t.Fatalf("expected ErrBootstrapCode for empty code, got %v", err)
	}
	if _, _, err := svc.Bootstrap().Begin(ctx, "!!!not-base64!!!"); !errors.Is(err, ErrBootstrapCode) {
		t.Fatalf("expected ErrBootstrapCode for malformed code, got %v", err)
	}
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(code)
	raw[0] ^= 0xff
	wrong := base64.RawURLEncoding.EncodeToString(raw)
	if _, _, err := svc.Bootstrap().Begin(ctx, wrong); !errors.Is(err, ErrBootstrapCode) {
		t.Fatalf("expected ErrBootstrapCode for wrong code, got %v", err)
	}

	// Two ceremonies may open on the same code, but only one enrollment
	// can complete: the code is consumed atomically.
	token1, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("first begin: %v", err)
	}
	token2, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("second begin: %v", err)
	}
	for i, token := range []string{token1, token2} {
		fv.regOutcomes = append(fv.regOutcomes, fakeRegOutcome{
			id: []byte(fmt.Sprintf("cred-%d", i)), publicKey: []byte("pk"), userVerified: true,
		})
		reg, err := svc.BeginBootstrapRegistration(ctx, token, "")
		if err != nil {
			t.Fatalf("begin registration %d: %v", i, err)
		}
		if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
			CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
		}); err != nil {
			t.Fatalf("finish registration %d: %v", i, err)
		}
		rec, err := svc.Bootstrap().BeginRecovery(ctx, token, RecoveryMethodOfflineKey)
		if err != nil {
			t.Fatalf("begin recovery %d: %v", i, err)
		}
		if i == 0 {
			if _, err := svc.Bootstrap().Complete(ctx, token, rec.RecoveryKey); err != nil {
				t.Fatalf("first complete: %v", err)
			}
		} else {
			if _, err := svc.Bootstrap().Complete(ctx, token, rec.RecoveryKey); err == nil {
				t.Fatal("second enrollment with the same code must fail")
			}
		}
	}
}

func TestBootstrapDisabledAfterEnrollment(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)

	if code, err := svc.EnsureBootstrapCode(ctx); err != nil || code != "" {
		t.Fatalf("expected no code after enrollment, got %q, %v", code, err)
	}
	if _, _, err := svc.Bootstrap().Begin(ctx, "anything"); !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("expected ErrAlreadyEnrolled, got %v", err)
	}
}

func TestBootstrapCodeExpiry(t *testing.T) {
	svc, _, _, clock := newTestService(t)
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	clock.now = clock.now.Add(11 * time.Minute)
	if _, _, err := svc.Bootstrap().Begin(ctx, code); !errors.Is(err, ErrBootstrapCodeExpired) {
		t.Fatalf("expected ErrBootstrapCodeExpired, got %v", err)
	}
}

func TestBootstrapCeremonyExpiry(t *testing.T) {
	svc, _, _, clock := newTestService(t)
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	clock.now = clock.now.Add(16 * time.Minute)
	if _, err := svc.BeginBootstrapRegistration(ctx, token, ""); !errors.Is(err, ErrCeremonyExpired) {
		t.Fatalf("expected ErrCeremonyExpired, got %v", err)
	}
}

func TestRegistrationRequiresUserVerification(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	fv.regOutcomes = append(fv.regOutcomes, fakeRegOutcome{
		id: []byte("cred-1"), publicKey: []byte("pk-1"), userVerified: false,
	})
	reg, err := svc.BeginBootstrapRegistration(ctx, token, "")
	if err != nil {
		t.Fatalf("begin bootstrap registration: %v", err)
	}
	if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
		CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
	}); !errors.Is(err, ErrUserVerification) {
		t.Fatalf("expected ErrUserVerification, got %v", err)
	}
}

func TestRegistrationCeremonyOneUse(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	fv.regOutcomes = append(fv.regOutcomes,
		fakeRegOutcome{id: []byte("cred-1"), publicKey: []byte("pk-1"), userVerified: true},
	)
	reg, err := svc.BeginBootstrapRegistration(ctx, token, "")
	if err != nil {
		t.Fatalf("begin bootstrap registration: %v", err)
	}
	req := FinishRegistrationRequest{
		CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
	}
	if _, err := svc.FinishRegistration(ctx, req); err != nil {
		t.Fatalf("finish bootstrap registration: %v", err)
	}
	if _, err := svc.FinishRegistration(ctx, req); !errors.Is(err, ErrCeremonyNotFound) {
		t.Fatalf("expected ErrCeremonyNotFound on replay, got %v", err)
	}
}

func TestLoginFlow(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	founderID, _, _ := enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)

	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 1, userVerified: true,
	})
	begin, err := svc.BeginLogin(ctx)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	res, err := svc.FinishLogin(ctx, begin.CeremonyID, []byte("{}"))
	if err != nil {
		t.Fatalf("finish login: %v", err)
	}
	if res.FounderID != founderID {
		t.Fatalf("wrong founder: %q", res.FounderID)
	}
	p, rec, err := svc.AuthenticateSessionToken(ctx, res.SessionToken)
	if err != nil {
		t.Fatalf("authenticate login session: %v", err)
	}
	if p.FounderID != founderID || p.SessionID != rec.SessionID {
		t.Fatalf("principal mismatch: %+v", p)
	}
	if err := VerifyCSRFToken(rec, res.CSRFToken); err != nil {
		t.Fatalf("verify login CSRF: %v", err)
	}
	// The sign count advances on the asserted credential.
	creds, err := svc.founderCredentials(ctx, founderID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	for _, c := range creds {
		if string(c.ID) == "cred-first" && c.SignCount != 1 {
			t.Fatalf("sign count not advanced: %d", c.SignCount)
		}
	}
	// Login assertions are bound to the enrolled credentials.
	if len(fv.beginAssertCalls) != 1 {
		t.Fatalf("expected 1 login ceremony, got %d", len(fv.beginAssertCalls))
	}
	if len(fv.beginAssertCalls[0].allowedIDs) == 0 {
		t.Fatal("login must restrict allowed credentials")
	}
}

func TestLoginRequiresEnrollment(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	if _, err := svc.BeginLogin(context.Background()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("expected ErrNotEnrolled, got %v", err)
	}
}

func TestLoginCeremonyOneUse(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	fv.assertOutcomes = append(fv.assertOutcomes,
		fakeAssertOutcome{credentialID: []byte("cred-first"), newSignCount: 1, userVerified: true},
	)
	begin, err := svc.BeginLogin(ctx)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	if _, err := svc.FinishLogin(ctx, begin.CeremonyID, []byte("{}")); err != nil {
		t.Fatalf("finish login: %v", err)
	}
	if _, err := svc.FinishLogin(ctx, begin.CeremonyID, []byte("{}")); !errors.Is(err, ErrCeremonyNotFound) {
		t.Fatalf("expected ErrCeremonyNotFound on replay, got %v", err)
	}
}

func TestLoginRequiresUserVerification(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	fv.assertOutcomes = append(fv.assertOutcomes,
		fakeAssertOutcome{credentialID: []byte("cred-first"), newSignCount: 1, userVerified: false},
	)
	begin, err := svc.BeginLogin(ctx)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	if _, err := svc.FinishLogin(ctx, begin.CeremonyID, []byte("{}")); !errors.Is(err, ErrUserVerification) {
		t.Fatalf("expected ErrUserVerification, got %v", err)
	}
}

func TestInSessionRegistrationDuplicate(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	_, sessionToken, _ := enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p := mustPrincipal(t, svc, sessionToken)

	fv.regOutcomes = append(fv.regOutcomes, fakeRegOutcome{
		id: []byte("cred-first"), publicKey: []byte("pk-first"), userVerified: true,
	})
	reg, err := svc.BeginSessionRegistration(ctx, p, "Second key")
	if err != nil {
		t.Fatalf("begin session registration: %v", err)
	}
	// Existing credentials are excluded from re-registration.
	if len(fv.beginRegCalls) != 2 {
		t.Fatalf("expected 2 registration ceremonies, got %d", len(fv.beginRegCalls))
	}
	if len(fv.beginRegCalls[1].excludeIDs) == 0 {
		t.Fatal("in-session registration must exclude existing credentials")
	}
	if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
		CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), Principal: &p,
	}); !errors.Is(err, ErrDuplicateCredential) {
		t.Fatalf("expected ErrDuplicateCredential, got %v", err)
	}
}

func TestSessionExpiryAndRevocation(t *testing.T) {
	svc, fv, db, clock := newTestService(t)
	ctx := context.Background()
	_, sessionToken, _ := enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p, rec, err := svc.AuthenticateSessionToken(ctx, sessionToken)
	if err != nil {
		t.Fatalf("authenticate session: %v", err)
	}

	if _, _, err := svc.AuthenticateSessionToken(ctx, "bogus"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}

	if err := db.WithTx(ctx, func(tx store.Tx) error {
		return tx.RevokeSession(ctx, "ws-test", p.SessionID)
	}); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, _, err := svc.AuthenticateSessionToken(ctx, sessionToken); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
	_ = rec

	// A fresh session expires after twelve hours.
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 2, userVerified: true,
	})
	begin, err := svc.BeginLogin(ctx)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	res, err := svc.FinishLogin(ctx, begin.CeremonyID, []byte("{}"))
	if err != nil {
		t.Fatalf("finish login: %v", err)
	}
	clock.now = clock.now.Add(13 * time.Hour)
	if _, _, err := svc.AuthenticateSessionToken(ctx, res.SessionToken); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func loginPrincipal(t *testing.T, svc *Service, fv *fakeVerifier, signCount uint32) Principal {
	t.Helper()
	ctx := context.Background()
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: signCount, userVerified: true,
	})
	begin, err := svc.BeginLogin(ctx)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	res, err := svc.FinishLogin(ctx, begin.CeremonyID, []byte("{}"))
	if err != nil {
		t.Fatalf("finish login: %v", err)
	}
	return mustPrincipal(t, svc, res.SessionToken)
}

func TestDecisionFlow(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p := loginPrincipal(t, svc, fv, 3)

	claims := []byte(`{"pass":"pass-1","decision":"approve"}`)
	challenge, _, err := svc.BeginDecision(ctx, p, DecisionPassApproval, "pass-1", claims)
	if err != nil {
		t.Fatalf("begin decision: %v", err)
	}
	if challenge.Purpose != DecisionPassApproval || challenge.SubjectID != "pass-1" {
		t.Fatalf("challenge binding wrong: %+v", challenge)
	}
	if challenge.WorkspaceID != "ws-test" || challenge.SessionID != p.SessionID {
		t.Fatalf("challenge not bound to session: %+v", challenge)
	}
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 4, userVerified: true,
	})
	if err := svc.FinishDecision(ctx, p, challenge.ChallengeID, DecisionPassApproval, "pass-1", claims, []byte("{}")); err != nil {
		t.Fatalf("finish decision: %v", err)
	}
	// The decision assertion advances the sign count too.
	creds, err := svc.founderCredentials(ctx, p.FounderID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	for _, c := range creds {
		if string(c.ID) == "cred-first" && c.SignCount != 4 {
			t.Fatalf("decision did not advance sign count: %d", c.SignCount)
		}
	}
	// The challenge is one-use.
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 5, userVerified: true,
	})
	if err := svc.FinishDecision(ctx, p, challenge.ChallengeID, DecisionPassApproval, "pass-1", claims, []byte("{}")); !errors.Is(err, ErrCeremonyNotFound) {
		t.Fatalf("expected ErrCeremonyNotFound on replay, got %v", err)
	}
}

func TestDecisionBindingMismatch(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p := loginPrincipal(t, svc, fv, 3)
	claims := []byte(`{"pass":"pass-1","decision":"approve"}`)

	cases := []struct {
		name    string
		mutate  func(*Principal, *[]byte, *DecisionPurpose, *string)
		wantErr error
	}{
		{"wrong purpose", func(_ *Principal, _ *[]byte, pur *DecisionPurpose, _ *string) { *pur = DecisionPassRevocation }, ErrDecisionBinding},
		{"wrong subject", func(_ *Principal, _ *[]byte, _ *DecisionPurpose, sub *string) { *sub = "pass-2" }, ErrDecisionBinding},
		{"wrong claims", func(_ *Principal, c *[]byte, _ *DecisionPurpose, _ *string) {
			*c = []byte(`{"pass":"pass-1","decision":"reject"}`)
		}, ErrDecisionBinding},
		{"wrong session", func(pr *Principal, _ *[]byte, _ *DecisionPurpose, _ *string) { pr.SessionID = "other" }, ErrDecisionBinding},
		{"wrong workspace", func(pr *Principal, _ *[]byte, _ *DecisionPurpose, _ *string) { pr.WorkspaceID = "ws-other" }, ErrDecisionBinding},
		{"invalid purpose", func(_ *Principal, _ *[]byte, pur *DecisionPurpose, _ *string) { *pur = "bogus" }, ErrInvalidPurpose},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			challenge, _, err := svc.BeginDecision(ctx, p, DecisionPassApproval, "pass-1", claims)
			if err != nil {
				t.Fatalf("begin decision: %v", err)
			}
			finishP := p
			finishClaims := claims
			finishPurpose := DecisionPassApproval
			finishSubject := "pass-1"
			tc.mutate(&finishP, &finishClaims, &finishPurpose, &finishSubject)
			err = svc.FinishDecision(ctx, finishP, challenge.ChallengeID, finishPurpose, finishSubject, finishClaims, []byte("{}"))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestDecisionStaleAuth(t *testing.T) {
	svc, fv, _, clock := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p := loginPrincipal(t, svc, fv, 3)
	claims := []byte(`{"pass":"pass-1","decision":"approve"}`)
	challenge, _, err := svc.BeginDecision(ctx, p, DecisionPassApproval, "pass-1", claims)
	if err != nil {
		t.Fatalf("begin decision: %v", err)
	}
	// The passkey authentication backing the decision is older than five
	// minutes.
	stale := p
	stale.AuthTime = clock.now.Add(-6 * time.Minute)
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 4, userVerified: true,
	})
	if err := svc.FinishDecision(ctx, stale, challenge.ChallengeID, DecisionPassApproval, "pass-1", claims, []byte("{}")); !errors.Is(err, ErrStaleAssertion) {
		t.Fatalf("expected ErrStaleAssertion, got %v", err)
	}
}

func TestDecisionChallengeExpiry(t *testing.T) {
	svc, fv, _, clock := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p := loginPrincipal(t, svc, fv, 3)
	claims := []byte(`{"pass":"pass-1","decision":"approve"}`)
	challenge, _, err := svc.BeginDecision(ctx, p, DecisionPassApproval, "pass-1", claims)
	if err != nil {
		t.Fatalf("begin decision: %v", err)
	}
	clock.now = clock.now.Add(3 * time.Minute)
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 4, userVerified: true,
	})
	if err := svc.FinishDecision(ctx, p, challenge.ChallengeID, DecisionPassApproval, "pass-1", claims, []byte("{}")); !errors.Is(err, ErrCeremonyExpired) {
		t.Fatalf("expected ErrCeremonyExpired, got %v", err)
	}
}

func TestDecisionFailedVerificationConsumesChallenge(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p := loginPrincipal(t, svc, fv, 3)
	claims := []byte(`{"pass":"pass-1","decision":"approve"}`)
	challenge, _, err := svc.BeginDecision(ctx, p, DecisionPassApproval, "pass-1", claims)
	if err != nil {
		t.Fatalf("begin decision: %v", err)
	}
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{err: errors.New("bad signature")})
	if err := svc.FinishDecision(ctx, p, challenge.ChallengeID, DecisionPassApproval, "pass-1", claims, []byte("{}")); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("expected ErrVerificationFailed, got %v", err)
	}
	// A failed attempt cannot be retried with the same challenge.
	fv.assertOutcomes = append(fv.assertOutcomes, fakeAssertOutcome{
		credentialID: []byte("cred-first"), newSignCount: 4, userVerified: true,
	})
	if err := svc.FinishDecision(ctx, p, challenge.ChallengeID, DecisionPassApproval, "pass-1", claims, []byte("{}")); !errors.Is(err, ErrCeremonyNotFound) {
		t.Fatalf("expected ErrCeremonyNotFound after failed attempt, got %v", err)
	}
}

func TestDecisionInvalidPurposeAtBegin(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()
	enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	p := loginPrincipal(t, svc, fv, 3)
	if _, _, err := svc.BeginDecision(ctx, p, "bogus", "pass-1", []byte("{}")); !errors.Is(err, ErrInvalidPurpose) {
		t.Fatalf("expected ErrInvalidPurpose, got %v", err)
	}
}

func TestEnrollmentStatus(t *testing.T) {
	svc, fv, _, _ := newTestService(t)
	ctx := context.Background()

	status, err := svc.EnrollmentStatus(ctx, "", "")
	if err != nil {
		t.Fatalf("enrollment status: %v", err)
	}
	if status.Enrolled || status.State != EnrollmentNeedsBootstrap {
		t.Fatalf("unexpected status before enrollment: %+v", status)
	}

	code, err := svc.EnsureBootstrapCode(ctx)
	if err != nil {
		t.Fatalf("ensure bootstrap code: %v", err)
	}
	token, _, err := svc.Bootstrap().Begin(ctx, code)
	if err != nil {
		t.Fatalf("bootstrap begin: %v", err)
	}
	status, err = svc.EnrollmentStatus(ctx, token, "")
	if err != nil {
		t.Fatalf("enrollment status: %v", err)
	}
	if status.State != EnrollmentNeedsBootstrap {
		t.Fatalf("expected needs_bootstrap before first passkey, got %q", status.State)
	}
	fv.regOutcomes = append(fv.regOutcomes, fakeRegOutcome{
		id: []byte("cred-first"), publicKey: []byte("pk-first"), userVerified: true,
	})
	reg, err := svc.BeginBootstrapRegistration(ctx, token, "")
	if err != nil {
		t.Fatalf("begin bootstrap registration: %v", err)
	}
	if _, err := svc.FinishRegistration(ctx, FinishRegistrationRequest{
		CeremonyID: reg.CeremonyID, ResponseBody: []byte("{}"), BootstrapToken: token,
	}); err != nil {
		t.Fatalf("finish bootstrap registration: %v", err)
	}
	status, err = svc.EnrollmentStatus(ctx, token, "")
	if err != nil {
		t.Fatalf("enrollment status: %v", err)
	}
	if status.State != EnrollmentNeedsRecovery {
		t.Fatalf("expected needs_recovery_method, got %q", status.State)
	}

	_, sessionToken, _ := enrollFounder(t, svc, fv, RecoveryMethodOfflineKey)
	status, err = svc.EnrollmentStatus(ctx, "", "")
	if err != nil {
		t.Fatalf("enrollment status: %v", err)
	}
	if !status.Enrolled || status.State != EnrollmentLocked {
		t.Fatalf("expected locked after enrollment, got %+v", status)
	}
	status, err = svc.EnrollmentStatus(ctx, "", sessionToken)
	if err != nil {
		t.Fatalf("enrollment status: %v", err)
	}
	if status.State != EnrollmentAuthenticated {
		t.Fatalf("expected authenticated, got %q", status.State)
	}
}

func TestCookieNames(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	if got := svc.SessionCookieName(); got != "__Host-authscope-ope-session-inst-test-1" {
		t.Fatalf("unexpected session cookie name: %q", got)
	}
	if got := svc.BootstrapCookieName(); got != "__Host-authscope-ope-bootstrap-inst-test-1" {
		t.Fatalf("unexpected bootstrap cookie name: %q", got)
	}
	if !strings.HasPrefix(svc.SessionCookieName(), "__Host-") {
		t.Fatal("session cookie must use the __Host- prefix")
	}
}

func TestPrincipalContext(t *testing.T) {
	p := Principal{FounderID: "f1", WorkspaceID: "ws-test"}
	ctx := ContextWithPrincipal(context.Background(), p)
	got, ok := PrincipalFromContext(ctx)
	if !ok || got != p {
		t.Fatalf("principal round trip failed: %+v %v", got, ok)
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("expected no principal in a bare context")
	}
}
