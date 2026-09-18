package authn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tauliang/authscope-ope/internal/store"
)

// BootstrapCookiePrefix is the __Host- cookie prefix for the bootstrap
// ceremony. The full name appends the instance ID, keeping ceremonies
// unique per instance.
const BootstrapCookiePrefix = "__Host-authscope-ope-bootstrap-"

// SessionCookieName returns the bound per-instance session cookie name.
func (s *Service) SessionCookieName() string {
	return s.instance.SessionCookieName
}

// BootstrapCookieName derives the bootstrap-ceremony cookie name from the
// instance ID.
func (s *Service) BootstrapCookieName() string {
	return BootstrapCookiePrefix + s.instance.InstanceID
}

// newSessionMaterial generates a session ID, a 256-bit opaque session
// token, and a 256-bit CSRF token. Only their hashes are stored.
func (s *Service) newSessionMaterial() (sessionID, token, csrfToken string, err error) {
	id, err := newCeremonyID()
	if err != nil {
		return "", "", "", err
	}
	tokenBytes, err := randomBytes(32)
	if err != nil {
		return "", "", "", err
	}
	csrfBytes, err := randomBytes(32)
	if err != nil {
		return "", "", "", err
	}
	return id, b64.EncodeToString(tokenBytes), b64.EncodeToString(csrfBytes), nil
}

// AuthenticateSessionToken validates a raw session cookie value and
// returns the immutable principal plus the stored session record. The
// token is hashed before lookup; raw tokens never reach the store.
func (s *Service) AuthenticateSessionToken(ctx context.Context, token string) (Principal, *store.SessionRecord, error) {
	raw, err := b64.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != 32 {
		return Principal{}, nil, ErrSessionNotFound
	}
	rec, err := s.store.GetSessionByHash(ctx, s.instance.WorkspaceID, sha256Hex(raw))
	if err != nil {
		return Principal{}, nil, ErrSessionNotFound
	}
	now := s.now().UTC()
	if rec.Revoked {
		return Principal{}, nil, ErrSessionRevoked
	}
	if !rec.ExpiresAt.After(now) {
		return Principal{}, nil, ErrSessionExpired
	}
	csrfHash, err := hex.DecodeString(rec.CSRFTokenHash)
	if err != nil || len(csrfHash) != 32 {
		return Principal{}, nil, fmt.Errorf("authn: corrupt CSRF hash: %w", err)
	}
	var csrfArr [32]byte
	copy(csrfArr[:], csrfHash)
	return Principal{
		FounderID:     rec.FounderID,
		WorkspaceID:   rec.WorkspaceID,
		SessionID:     rec.SessionID,
		AuthTime:      rec.CreatedAt,
		CSRFTokenHash: csrfArr,
	}, &rec, nil
}

// VerifyCSRFToken compares a presented CSRF token against the session
// record in constant time.
func VerifyCSRFToken(rec *store.SessionRecord, presented string) error {
	raw, err := b64.DecodeString(strings.TrimSpace(presented))
	if err != nil || len(raw) != 32 {
		return ErrCSRFMismatch
	}
	presentedHash := sha256.Sum256(raw)
	storedHash, err := hex.DecodeString(rec.CSRFTokenHash)
	if err != nil || len(storedHash) != 32 {
		return ErrCSRFMismatch
	}
	if subtle.ConstantTimeCompare(presentedHash[:], storedHash) != 1 {
		return ErrCSRFMismatch
	}
	return nil
}

// EnrollmentState is the founder enrollment state reported to the UI.
type EnrollmentState string

const (
	// EnrollmentNeedsBootstrap means no founder is enrolled yet.
	EnrollmentNeedsBootstrap EnrollmentState = "needs_bootstrap"
	// EnrollmentNeedsRecovery means a bootstrap ceremony is in progress
	// and the independent recovery method is still pending.
	EnrollmentNeedsRecovery EnrollmentState = "needs_recovery_method"
	// EnrollmentLocked means a founder is enrolled but this client holds
	// no live session.
	EnrollmentLocked EnrollmentState = "locked"
	// EnrollmentAuthenticated means this client holds a live session.
	EnrollmentAuthenticated EnrollmentState = "authenticated"
)

// EnrollmentStatus is the first-paint enrollment report.
type EnrollmentStatus struct {
	Enrolled    bool
	State       EnrollmentState
	WorkspaceID string
	Hostname    string
}

// EnrollmentStatus reports enrollment for the workspace, refined by the
// client's cookies: a live bootstrap ceremony in progress, or a live
// founder session.
func (s *Service) EnrollmentStatus(ctx context.Context, bootstrapToken, sessionToken string) (*EnrollmentStatus, error) {
	status := &EnrollmentStatus{
		WorkspaceID: s.instance.WorkspaceID,
		Hostname:    s.instance.Hostname,
	}
	enrolled, err := s.enrolled(ctx)
	if err != nil {
		return nil, err
	}
	status.Enrolled = enrolled
	if !enrolled {
		status.State = EnrollmentNeedsBootstrap
		if bootstrapToken != "" {
			if ceremony, err := s.liveBootstrapCeremony(bootstrapToken); err == nil && ceremony.firstCredentialID != "" {
				status.State = EnrollmentNeedsRecovery
			}
		}
		return status, nil
	}
	status.State = EnrollmentLocked
	if sessionToken != "" {
		if _, _, err := s.AuthenticateSessionToken(ctx, sessionToken); err == nil {
			status.State = EnrollmentAuthenticated
		}
	}
	return status, nil
}
