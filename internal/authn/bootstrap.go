package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tauliang/authscope-ope/internal/store"
)

// RecoveryMethod is the independent recovery method enrolled alongside the
// first passkey.
type RecoveryMethod string

const (
	// RecoveryMethodPasskey enrolls a second passkey as the recovery method.
	RecoveryMethodPasskey RecoveryMethod = "passkey"
	// RecoveryMethodOfflineKey generates a one-time offline recovery key.
	RecoveryMethodOfflineKey RecoveryMethod = "offline_key"
)

// bootstrapCeremony is the in-memory server record of an enrollment
// ceremony. It is short-lived, single-use, and bound to the workspace.
type bootstrapCeremony struct {
	id                string
	tokenHash         [32]byte
	codeHash          string
	userHandle        []byte
	displayName       string
	firstCredentialID string
	recoveryMethod    RecoveryMethod
	recoveryKeyHash   [32]byte
	recoveryIssued    bool
	recoveryVerified  bool
	// stagedCredentials holds passkey credentials registered during the
	// ceremony; they are flushed to the store atomically at completion
	// because the founder row does not exist until then.
	stagedCredentials []*store.WebAuthnCredentialRecord
	createdAt         time.Time
	expiresAt         time.Time
	consumed          bool
}

// BootstrapService runs the one-use founder enrollment ceremony.
type BootstrapService struct {
	svc *Service
}

// Bootstrap returns the enrollment ceremony service.
func (s *Service) Bootstrap() *BootstrapService {
	return &BootstrapService{svc: s}
}

// b64 encodes random bytes for terminal display and cookies.
var b64 = base64.RawURLEncoding

// randomBytes returns n cryptographically random bytes.
func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("authn: random: %w", err)
	}
	return b, nil
}

// newCeremonyID returns a random 128-bit ceremony identifier.
func newCeremonyID() (string, error) {
	b, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sha256Hex hashes secret material for storage or comparison. Raw secrets
// are never persisted.
func sha256Hex(secret []byte) string {
	sum := sha256.Sum256(secret)
	return hex.EncodeToString(sum[:])
}

// EnsureBootstrapCode generates a fresh 128-bit one-use bootstrap code
// when no founder is enrolled yet, persists its SHA-256 hash with a
// ten-minute expiry, and returns the raw code for the controlling
// terminal. It returns an empty code when the workspace is already
// enrolled. The raw code is never stored or logged.
func (s *Service) EnsureBootstrapCode(ctx context.Context) (string, error) {
	n, err := s.store.CountFounders(ctx, s.instance.WorkspaceID)
	if err != nil {
		return "", fmt.Errorf("authn: count founders: %w", err)
	}
	if n > 0 {
		return "", nil
	}
	raw, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	code := b64.EncodeToString(raw)
	now := s.now().UTC()
	rec := store.BootstrapCodeRecord{
		WorkspaceID: s.instance.WorkspaceID,
		CodeHash:    sha256Hex(raw),
		CreatedAt:   now,
		ExpiresAt:   now.Add(bootstrapCodeTTL),
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutBootstrapCode(ctx, rec)
	}); err != nil {
		return "", fmt.Errorf("authn: persist bootstrap code: %w", err)
	}
	return code, nil
}

// Begin verifies the terminal bootstrap code in constant time and opens a
// short-lived bootstrap ceremony without consuming the code. It returns the
// raw ceremony token for the bootstrap-ceremony cookie.
func (b *BootstrapService) Begin(ctx context.Context, code string) (token string, expiresAt time.Time, err error) {
	svc := b.svc
	if enrolled, err := svc.enrolled(ctx); err != nil {
		return "", time.Time{}, err
	} else if enrolled {
		return "", time.Time{}, ErrAlreadyEnrolled
	}
	raw, err := b64.DecodeString(code)
	if err != nil || len(raw) != 16 {
		return "", time.Time{}, ErrBootstrapCode
	}
	rec, err := svc.store.GetBootstrapCode(ctx, svc.instance.WorkspaceID)
	if err != nil {
		return "", time.Time{}, ErrBootstrapCode
	}
	provided := sha256Hex(raw)
	if subtle.ConstantTimeCompare([]byte(provided), []byte(rec.CodeHash)) != 1 {
		return "", time.Time{}, ErrBootstrapCode
	}
	now := svc.now().UTC()
	if !rec.ExpiresAt.After(now) {
		return "", time.Time{}, ErrBootstrapCodeExpired
	}
	tokenBytes, err := randomBytes(32)
	if err != nil {
		return "", time.Time{}, err
	}
	userHandle, err := randomBytes(32)
	if err != nil {
		return "", time.Time{}, err
	}
	id, err := newCeremonyID()
	if err != nil {
		return "", time.Time{}, err
	}
	ceremony := &bootstrapCeremony{
		id:         id,
		tokenHash:  sha256.Sum256(tokenBytes),
		codeHash:   rec.CodeHash,
		userHandle: userHandle,
		createdAt:  now,
		expiresAt:  now.Add(bootstrapCeremonyTTL),
	}
	svc.mu.Lock()
	svc.bootstrap[id] = ceremony
	svc.bootstrapByToken[ceremony.tokenHash] = id
	svc.mu.Unlock()
	return b64.EncodeToString(tokenBytes), ceremony.expiresAt, nil
}

// RecoveryBeginResult describes the started recovery method.
type RecoveryBeginResult struct {
	Method RecoveryMethod
	// For RecoveryMethodPasskey: the registration ceremony to complete.
	CeremonyID  string
	OptionsJSON json.RawMessage
	// For RecoveryMethodOfflineKey: the raw key, displayed exactly once.
	RecoveryKey string
}

// BeginRecovery starts the independent recovery method of a bootstrap
// ceremony. The first passkey must already be registered. For the offline
// key method it generates a 256-bit key, stores only its hash, and returns
// the raw key exactly once; the caller must confirm possession at
// Complete.
func (b *BootstrapService) BeginRecovery(ctx context.Context, ceremonyToken string, method RecoveryMethod) (*RecoveryBeginResult, error) {
	svc := b.svc
	if method != RecoveryMethodPasskey && method != RecoveryMethodOfflineKey {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPurpose, method)
	}
	ceremony, err := svc.liveBootstrapCeremony(ceremonyToken)
	if err != nil {
		return nil, err
	}
	if ceremony.firstCredentialID == "" {
		return nil, ErrRecoveryRequired
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if ceremony.recoveryMethod != "" {
		return nil, fmt.Errorf("%w: recovery method already started", ErrConflict)
	}
	switch method {
	case RecoveryMethodPasskey:
		ceremony.recoveryMethod = RecoveryMethodPasskey
		// Exclude the first passkey so the recovery method is independent.
		var exclude [][]byte
		if id, err := b64.DecodeString(ceremony.firstCredentialID); err == nil {
			exclude = [][]byte{id}
		}
		result, err := svc.beginRegistrationLocked(ceremony, "Founder", true, exclude)
		if err != nil {
			ceremony.recoveryMethod = ""
			return nil, err
		}
		return &RecoveryBeginResult{
			Method:      RecoveryMethodPasskey,
			CeremonyID:  result.CeremonyID,
			OptionsJSON: result.OptionsJSON,
		}, nil
	default:
		raw, err := randomBytes(32)
		if err != nil {
			return nil, err
		}
		ceremony.recoveryMethod = RecoveryMethodOfflineKey
		ceremony.recoveryKeyHash = sha256.Sum256(raw)
		ceremony.recoveryIssued = true
		return &RecoveryBeginResult{
			Method:      RecoveryMethodOfflineKey,
			RecoveryKey: b64.EncodeToString(raw),
		}, nil
	}
}

// BootstrapCompleteResult carries the first founder session.
type BootstrapCompleteResult struct {
	FounderID    string
	SessionToken string
	CSRFToken    string
}

// Complete verifies the bootstrap ceremony, the first passkey, and the
// confirmed independent recovery method, then in one transaction consumes
// the bootstrap code and ceremony and creates the first founder session. A
// failure or replay creates no partial founder session.
func (b *BootstrapService) Complete(ctx context.Context, ceremonyToken, recoveryConfirmation string) (*BootstrapCompleteResult, error) {
	svc := b.svc
	ceremony, err := svc.liveBootstrapCeremony(ceremonyToken)
	if err != nil {
		return nil, err
	}
	if ceremony.firstCredentialID == "" {
		return nil, ErrRecoveryRequired
	}
	switch ceremony.recoveryMethod {
	case RecoveryMethodPasskey:
		if !ceremony.recoveryVerified {
			return nil, ErrRecoveryNotVerified
		}
	case RecoveryMethodOfflineKey:
		if !ceremony.recoveryIssued {
			return nil, ErrRecoveryNotVerified
		}
		raw, err := b64.DecodeString(recoveryConfirmation)
		if err != nil || len(raw) != 32 {
			return nil, ErrRecoveryNotVerified
		}
		provided := sha256.Sum256(raw)
		if subtle.ConstantTimeCompare(provided[:], ceremony.recoveryKeyHash[:]) != 1 {
			return nil, ErrRecoveryNotVerified
		}
	default:
		return nil, ErrRecoveryRequired
	}

	now := svc.now().UTC()
	founderID, err := newCeremonyID()
	if err != nil {
		return nil, err
	}
	sessionID, sessionToken, csrfToken, err := svc.newSessionMaterial()
	if err != nil {
		return nil, err
	}
	// Hash the raw token bytes, matching AuthenticateSessionToken and
	// VerifyCSRFToken, which decode the presented base64 before hashing.
	sessionRaw, err := b64.DecodeString(sessionToken)
	if err != nil {
		return nil, err
	}
	csrfRaw, err := b64.DecodeString(csrfToken)
	if err != nil {
		return nil, err
	}
	// All durable writes happen in one transaction: founder, staged passkey
	// credentials, optional recovery key hash, code consumption, and the
	// first session. The in-memory ceremony is consumed only after the
	// commit succeeds.
	err = svc.store.WithTx(ctx, func(tx store.Tx) error {
		if err := tx.CreateFounder(ctx, store.FounderRecord{
			WorkspaceID: svc.instance.WorkspaceID,
			FounderID:   founderID,
			DisplayName: ceremony.displayName,
			CreatedAt:   now,
		}); err != nil {
			return err
		}
		for _, staged := range ceremony.stagedCredentials {
			staged.FounderID = founderID
			if err := tx.PutWebAuthnCredential(ctx, *staged); err != nil {
				return err
			}
		}
		if ceremony.recoveryMethod == RecoveryMethodOfflineKey {
			if err := tx.PutOfflineRecoveryKey(ctx, store.OfflineRecoveryKeyRecord{
				WorkspaceID: svc.instance.WorkspaceID,
				FounderID:   founderID,
				KeyHash:     hex.EncodeToString(ceremony.recoveryKeyHash[:]),
				CreatedAt:   now,
			}); err != nil {
				return err
			}
		}
		if err := tx.ConsumeBootstrapCode(ctx, svc.instance.WorkspaceID, ceremony.codeHash, now); err != nil {
			return err
		}
		return tx.CreateSession(ctx, store.SessionRecord{
			WorkspaceID:   svc.instance.WorkspaceID,
			SessionID:     sessionID,
			SessionHash:   sha256Hex(sessionRaw),
			FounderID:     founderID,
			CSRFTokenHash: sha256Hex(csrfRaw),
			CreatedAt:     now,
			ExpiresAt:     now.Add(sessionTTL),
		})
	})
	if err != nil {
		return nil, fmt.Errorf("authn: complete bootstrap: %w", err)
	}
	svc.mu.Lock()
	ceremony.consumed = true
	delete(svc.bootstrap, ceremony.id)
	delete(svc.bootstrapByToken, ceremony.tokenHash)
	svc.mu.Unlock()
	return &BootstrapCompleteResult{
		FounderID:    founderID,
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
	}, nil
}

// IssueRecoveryBootstrapCode generates a fresh 128-bit one-use
// bootstrap code for an enrolled workspace after an offline recovery,
// persists its SHA-256 hash with a ten-minute expiry, and returns the
// raw code bytes for the controlling terminal. Unlike
// EnsureBootstrapCode it does not require the workspace to be
// unenrolled: recovery wipes authentication state and the founder
// re-enrolls through this code, choosing a replacement recovery method
// during the ceremony. The raw code is never stored or logged; the
// caller must zero the returned slice after delivering it.
func IssueRecoveryBootstrapCode(ctx context.Context, st store.Store, workspaceID string) ([]byte, time.Time, error) {
	if st == nil {
		return nil, time.Time{}, errors.New("authn: store is required")
	}
	var raw []byte
	var expiresAt time.Time
	if err := st.WithTx(ctx, func(tx store.Tx) error {
		var err error
		raw, expiresAt, err = IssueRecoveryBootstrapCodeTx(ctx, tx, workspaceID, time.Now().UTC())
		return err
	}); err != nil {
		return nil, time.Time{}, err
	}
	return raw, expiresAt, nil
}

// IssueRecoveryBootstrapCodeTx generates one raw 128-bit bootstrap code
// and stores its SHA-256 hash inside the caller's transaction. The raw
// bytes are returned for one-time delivery; the caller must zero them
// after delivery. Keeping persistence inside the caller's transaction
// lets offline recovery issue the code atomically with its resets.
func IssueRecoveryBootstrapCodeTx(ctx context.Context, tx store.Tx, workspaceID string, now time.Time) ([]byte, time.Time, error) {
	if tx == nil {
		return nil, time.Time{}, errors.New("authn: transaction is required")
	}
	if workspaceID == "" {
		return nil, time.Time{}, errors.New("authn: workspace ID is required")
	}
	raw, err := randomBytes(16)
	if err != nil {
		return nil, time.Time{}, err
	}
	now = now.UTC()
	expiresAt := now.Add(bootstrapCodeTTL)
	rec := store.BootstrapCodeRecord{
		WorkspaceID: workspaceID,
		CodeHash:    sha256Hex(raw),
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}
	if err := tx.PutBootstrapCode(ctx, rec); err != nil {
		for i := range raw {
			raw[i] = 0
		}
		return nil, time.Time{}, fmt.Errorf("authn: persist recovery bootstrap code: %w", err)
	}
	return raw, expiresAt, nil
}

// enrolled reports whether the workspace has a founder.
func (s *Service) enrolled(ctx context.Context) (bool, error) {
	n, err := s.store.CountFounders(ctx, s.instance.WorkspaceID)
	if err != nil {
		return false, fmt.Errorf("authn: count founders: %w", err)
	}
	return n > 0, nil
}

// liveBootstrapCeremony resolves a ceremony token to its live ceremony.
func (s *Service) liveBootstrapCeremony(ceremonyToken string) (*bootstrapCeremony, error) {
	raw, err := b64.DecodeString(ceremonyToken)
	if err != nil || len(raw) != 32 {
		return nil, ErrCeremonyNotFound
	}
	tokenHash := sha256.Sum256(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bootstrapByToken[tokenHash]
	if !ok {
		return nil, ErrCeremonyNotFound
	}
	ceremony, ok := s.bootstrap[id]
	if !ok || ceremony.consumed {
		return nil, ErrCeremonyConsumed
	}
	now := s.now().UTC()
	if !ceremony.expiresAt.After(now) {
		return nil, ErrCeremonyExpired
	}
	return ceremony, nil
}
