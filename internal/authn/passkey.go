package authn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tauliang/authscope-ope/internal/store"
)

// CeremonyUser identifies the WebAuthn user handle of a ceremony.
type CeremonyUser struct {
	ID          []byte
	Name        string
	DisplayName string
}

// StoredCredential is a registered passkey the verifier checks an
// assertion against.
type StoredCredential struct {
	ID        []byte
	PublicKey []byte
	SignCount uint32
}

// RegisteredCredential is the verified output of a registration ceremony.
type RegisteredCredential struct {
	ID           []byte
	PublicKey    []byte
	SignCount    uint32
	Transports   []string
	UserVerified bool
}

// VerifiedAssertion is the verified output of an assertion ceremony.
type VerifiedAssertion struct {
	CredentialID []byte
	NewSignCount uint32
	UserVerified bool
}

// Verifier abstracts the WebAuthn ceremony cryptography. The production
// implementation delegates to go-webauthn bound to the instance RP ID and
// origin; unit tests stub it and the service enforces ceremony state,
// binding, expiry, and single use.
type Verifier interface {
	// BeginRegistration issues creation options and an opaque session
	// blob. excludeIDs lists credential IDs the authenticator must not
	// reuse.
	BeginRegistration(ctx context.Context, user CeremonyUser, rpID, origin string, excludeIDs [][]byte) (optionsJSON, sessionJSON []byte, err error)
	// FinishRegistration verifies an attestation response against the
	// session blob.
	FinishRegistration(ctx context.Context, user CeremonyUser, sessionJSON, responseBody []byte) (RegisteredCredential, error)
	// BeginAssertion issues request options and an opaque session blob for
	// a login or decision ceremony. allowedIDs restricts the credentials
	// the authenticator may use.
	BeginAssertion(ctx context.Context, user CeremonyUser, rpID, origin string, allowedIDs [][]byte) (optionsJSON, sessionJSON []byte, err error)
	// FinishAssertion verifies an assertion response against the session
	// blob and the stored credentials.
	FinishAssertion(ctx context.Context, user CeremonyUser, creds []StoredCredential, sessionJSON, responseBody []byte) (VerifiedAssertion, error)
}

type ceremonyKind string

const (
	ceremonyRegistration ceremonyKind = "registration"
	ceremonyLogin        ceremonyKind = "login"
	ceremonyDecision     ceremonyKind = "decision"
)

// webauthnCeremony is the in-memory server record of a one-use WebAuthn
// ceremony. Exactly one scope is set: a bootstrap ceremony, or an
// authenticated session for in-session registration.
type webauthnCeremony struct {
	id                  string
	kind                ceremonyKind
	sessionJSON         []byte
	userID              []byte
	bootstrapCeremonyID string
	sessionID           string
	founderID           string
	isRecovery          bool
	decision            *DecisionChallenge
	createdAt           time.Time
	expiresAt           time.Time
	consumed            bool
}

// RegistrationBeginResult carries the ceremony the browser must complete.
type RegistrationBeginResult struct {
	CeremonyID  string
	OptionsJSON json.RawMessage
}

// BeginBootstrapRegistration starts the first (or the recovery second)
// passkey registration inside a bootstrap ceremony.
func (s *Service) BeginBootstrapRegistration(ctx context.Context, bootstrapToken string, displayName string) (*RegistrationBeginResult, error) {
	ceremony, err := s.liveBootstrapCeremony(bootstrapToken)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if displayName != "" {
		ceremony.displayName = displayName
	}
	return s.beginRegistrationLocked(ceremony, displayName, false, nil)
}

// beginRegistrationLocked issues a registration ceremony bound to the
// bootstrap ceremony. The caller holds s.mu. recovery marks the ceremony
// as the independent recovery method.
func (s *Service) beginRegistrationLocked(ceremony *bootstrapCeremony, displayName string, recovery bool, excludeIDs [][]byte) (*RegistrationBeginResult, error) {
	now := s.now().UTC()
	ttl := registrationCeremonyTTL
	if recovery {
		// The recovery registration must finish before the ceremony does.
		if ceremony.expiresAt.Sub(now) < ttl {
			ttl = ceremony.expiresAt.Sub(now)
		}
	}
	id, err := newCeremonyID()
	if err != nil {
		return nil, err
	}
	name := displayName
	if name == "" {
		name = "Founder"
	}
	user := CeremonyUser{
		ID:          ceremony.userHandle,
		Name:        "founder",
		DisplayName: name,
	}
	optionsJSON, sessionJSON, err := s.verifier.BeginRegistration(
		context.Background(), user, s.instance.RPID, s.instance.Origin, excludeIDs)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	s.ceremonies[id] = &webauthnCeremony{
		id:                  id,
		kind:                ceremonyRegistration,
		sessionJSON:         sessionJSON,
		userID:              ceremony.userHandle,
		bootstrapCeremonyID: ceremony.id,
		isRecovery:          recovery,
		createdAt:           now,
		expiresAt:           now.Add(ttl),
	}
	return &RegistrationBeginResult{CeremonyID: id, OptionsJSON: optionsJSON}, nil
}

// BeginSessionRegistration starts a passkey registration for an
// authenticated founder, for example to add a second passkey later. The
// caller must have verified the session and its CSRF token.
func (s *Service) BeginSessionRegistration(ctx context.Context, p Principal, displayName string) (*RegistrationBeginResult, error) {
	if p.WorkspaceID != s.instance.WorkspaceID {
		return nil, fmt.Errorf("%w: workspace mismatch", ErrDecisionBinding)
	}
	creds, err := s.founderCredentials(ctx, p.FounderID)
	if err != nil {
		return nil, err
	}
	var exclude [][]byte
	for _, c := range creds {
		exclude = append(exclude, c.ID)
	}
	name := displayName
	if name == "" {
		name = "Founder"
	}
	user := CeremonyUser{
		ID:          []byte(p.FounderID),
		Name:        "founder",
		DisplayName: name,
	}
	optionsJSON, sessionJSON, err := s.verifier.BeginRegistration(
		ctx, user, s.instance.RPID, s.instance.Origin, exclude)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	now := s.now().UTC()
	id, err := newCeremonyID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.ceremonies[id] = &webauthnCeremony{
		id:          id,
		kind:        ceremonyRegistration,
		sessionJSON: sessionJSON,
		userID:      []byte(p.FounderID),
		sessionID:   p.SessionID,
		founderID:   p.FounderID,
		createdAt:   now,
		expiresAt:   now.Add(registrationCeremonyTTL),
	}
	s.mu.Unlock()
	return &RegistrationBeginResult{CeremonyID: id, OptionsJSON: optionsJSON}, nil
}

// FinishRegistrationRequest completes a registration ceremony.
type FinishRegistrationRequest struct {
	CeremonyID string
	// ResponseBody is the raw attestation JSON from the browser.
	ResponseBody []byte
	// Exactly one scope proof:
	BootstrapToken string
	Principal      *Principal
}

// FinishRegistration verifies the attestation, rejects duplicate
// credential IDs, stores the public credential, and advances the
// bootstrap ceremony when the registration belongs to one.
func (s *Service) FinishRegistration(ctx context.Context, req FinishRegistrationRequest) (string, error) {
	ceremony, err := s.consumeCeremony(req.CeremonyID, ceremonyRegistration)
	if err != nil {
		return "", err
	}
	if err := s.checkRegistrationScope(req, ceremony); err != nil {
		return "", err
	}
	user := CeremonyUser{ID: ceremony.userID, Name: "founder", DisplayName: "Founder"}
	registered, err := s.verifier.FinishRegistration(ctx, user, ceremony.sessionJSON, req.ResponseBody)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	if !registered.UserVerified {
		return "", ErrUserVerification
	}
	if len(registered.ID) == 0 || len(registered.PublicKey) == 0 {
		return "", fmt.Errorf("%w: empty credential", ErrVerificationFailed)
	}
	credentialID := base64.RawURLEncoding.EncodeToString(registered.ID)
	now := s.now().UTC()
	founderID := ceremony.founderID
	if ceremony.bootstrapCeremonyID != "" {
		// The founder row is created at bootstrap completion, so the
		// credential cannot be stored yet (foreign key). It is staged on
		// the bootstrap ceremony and flushed atomically at completion.
		s.mu.Lock()
		bc, ok := s.bootstrap[ceremony.bootstrapCeremonyID]
		if !ok || bc.consumed {
			s.mu.Unlock()
			return "", ErrCeremonyConsumed
		}
		for _, staged := range bc.stagedCredentials {
			if staged.CredentialID == credentialID {
				s.mu.Unlock()
				return "", ErrDuplicateCredential
			}
		}
		if ceremony.isRecovery {
			bc.recoveryMethod = RecoveryMethodPasskey
			bc.recoveryVerified = true
		} else {
			bc.firstCredentialID = credentialID
		}
		bc.stagedCredentials = append(bc.stagedCredentials, &store.WebAuthnCredentialRecord{
			WorkspaceID:  s.instance.WorkspaceID,
			CredentialID: credentialID,
			PublicKey:    registered.PublicKey,
			SignCount:    registered.SignCount,
			Transports:   joinTransports(registered.Transports),
			CreatedAt:    now,
		})
		s.mu.Unlock()
		return credentialID, nil
	}
	// In-session registration: the founder already exists.
	rec := store.WebAuthnCredentialRecord{
		WorkspaceID:  s.instance.WorkspaceID,
		CredentialID: credentialID,
		FounderID:    founderID,
		PublicKey:    registered.PublicKey,
		SignCount:    registered.SignCount,
		Transports:   joinTransports(registered.Transports),
		CreatedAt:    now,
	}
	if err := s.store.WithTx(ctx, func(tx store.Tx) error {
		return tx.PutWebAuthnCredential(ctx, rec)
	}); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return "", ErrDuplicateCredential
		}
		return "", err
	}
	return credentialID, nil
}

// checkRegistrationScope verifies the finish scope proof matches the
// ceremony scope.
func (s *Service) checkRegistrationScope(req FinishRegistrationRequest, ceremony *webauthnCeremony) error {
	if ceremony.bootstrapCeremonyID != "" {
		if req.BootstrapToken == "" || req.Principal != nil {
			return fmt.Errorf("%w: bootstrap registration requires the ceremony token", ErrCeremonyNotFound)
		}
		bc, err := s.liveBootstrapCeremony(req.BootstrapToken)
		if err != nil {
			return err
		}
		if bc.id != ceremony.bootstrapCeremonyID {
			return fmt.Errorf("%w: registration bound to another ceremony", ErrCeremonyNotFound)
		}
		return nil
	}
	if req.Principal == nil || req.BootstrapToken != "" {
		return fmt.Errorf("%w: session registration requires the founder session", ErrCeremonyNotFound)
	}
	if req.Principal.SessionID != ceremony.sessionID || req.Principal.FounderID != ceremony.founderID {
		return fmt.Errorf("%w: registration bound to another session", ErrCeremonyNotFound)
	}
	return nil
}

// LoginBeginResult carries the login ceremony the browser must complete.
type LoginBeginResult struct {
	CeremonyID  string
	OptionsJSON json.RawMessage
}

// BeginLogin starts a passkey login ceremony for the enrolled founder.
func (s *Service) BeginLogin(ctx context.Context) (*LoginBeginResult, error) {
	founder, err := s.singleFounder(ctx)
	if err != nil {
		return nil, err
	}
	creds, err := s.founderCredentials(ctx, founder.FounderID)
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, fmt.Errorf("%w: no passkey enrolled", ErrNotEnrolled)
	}
	var allowed [][]byte
	for _, c := range creds {
		allowed = append(allowed, c.ID)
	}
	user := CeremonyUser{
		ID:          []byte(founder.FounderID),
		Name:        "founder",
		DisplayName: founder.DisplayName,
	}
	optionsJSON, sessionJSON, err := s.verifier.BeginAssertion(
		ctx, user, s.instance.RPID, s.instance.Origin, allowed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	now := s.now().UTC()
	id, err := newCeremonyID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.ceremonies[id] = &webauthnCeremony{
		id:          id,
		kind:        ceremonyLogin,
		sessionJSON: sessionJSON,
		userID:      []byte(founder.FounderID),
		founderID:   founder.FounderID,
		createdAt:   now,
		expiresAt:   now.Add(loginCeremonyTTL),
	}
	s.mu.Unlock()
	return &LoginBeginResult{CeremonyID: id, OptionsJSON: optionsJSON}, nil
}

// LoginFinishResult carries the fresh founder session. The session is
// always new: login rotates the session instead of reusing one.
type LoginFinishResult struct {
	FounderID    string
	SessionToken string
	CSRFToken    string
}

// FinishLogin verifies the assertion and mints a fresh session.
func (s *Service) FinishLogin(ctx context.Context, ceremonyID string, responseBody []byte) (*LoginFinishResult, error) {
	ceremony, err := s.consumeCeremony(ceremonyID, ceremonyLogin)
	if err != nil {
		return nil, err
	}
	verified, err := s.verifyAssertion(ctx, ceremony, responseBody)
	if err != nil {
		return nil, err
	}
	sessionID, sessionToken, csrfToken, err := s.newSessionMaterial()
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
	now := s.now().UTC()
	err = s.store.WithTx(ctx, func(tx store.Tx) error {
		if verified.NewSignCount > 0 {
			credID := base64.RawURLEncoding.EncodeToString(verified.CredentialID)
			if err := tx.UpdateWebAuthnCredentialSignCount(ctx, s.instance.WorkspaceID, credID, verified.NewSignCount); err != nil {
				return err
			}
		}
		return tx.CreateSession(ctx, store.SessionRecord{
			WorkspaceID:   s.instance.WorkspaceID,
			SessionID:     sessionID,
			SessionHash:   sha256Hex(sessionRaw),
			FounderID:     ceremony.founderID,
			CSRFTokenHash: sha256Hex(csrfRaw),
			CreatedAt:     now,
			ExpiresAt:     now.Add(sessionTTL),
		})
	})
	if err != nil {
		return nil, fmt.Errorf("authn: finish login: %w", err)
	}
	return &LoginFinishResult{
		FounderID:    ceremony.founderID,
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
	}, nil
}

// BeginDecision issues a one-use decision challenge bound to the exact
// server-supplied canonical claims. It returns the challenge record and
// the assertion options for the browser. There is no generic public
// decision route; resource-specific routes in later tasks call this.
func (s *Service) BeginDecision(ctx context.Context, p Principal, purpose DecisionPurpose, subjectID string, canonicalClaims []byte) (*DecisionChallenge, json.RawMessage, error) {
	if !validDecisionPurpose(purpose) {
		return nil, nil, ErrInvalidPurpose
	}
	if subjectID == "" {
		return nil, nil, fmt.Errorf("%w: subject is required", ErrInvalidPurpose)
	}
	if len(canonicalClaims) == 0 {
		return nil, nil, fmt.Errorf("%w: canonical claims are required", ErrDecisionBinding)
	}
	if p.WorkspaceID != s.instance.WorkspaceID {
		return nil, nil, fmt.Errorf("%w: workspace mismatch", ErrDecisionBinding)
	}
	creds, err := s.founderCredentials(ctx, p.FounderID)
	if err != nil {
		return nil, nil, err
	}
	if len(creds) == 0 {
		return nil, nil, fmt.Errorf("%w: no passkey enrolled", ErrNotEnrolled)
	}
	var allowed [][]byte
	for _, c := range creds {
		allowed = append(allowed, c.ID)
	}
	user := CeremonyUser{ID: []byte(p.FounderID), Name: "founder", DisplayName: "Founder"}
	optionsJSON, sessionJSON, err := s.verifier.BeginAssertion(
		ctx, user, s.instance.RPID, s.instance.Origin, allowed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	digest := sha256.Sum256(canonicalClaims)
	nonce, err := randomBytes(32)
	if err != nil {
		return nil, nil, err
	}
	var nonceArr [32]byte
	copy(nonceArr[:], nonce)
	now := s.now().UTC()
	id, err := newCeremonyID()
	if err != nil {
		return nil, nil, err
	}
	challenge := &DecisionChallenge{
		ChallengeID: id,
		WorkspaceID: p.WorkspaceID,
		SessionID:   p.SessionID,
		SubjectID:   subjectID,
		Purpose:     purpose,
		Digest:      digest,
		Nonce:       nonceArr,
		ExpiresAt:   now.Add(decisionChallengeTTL),
	}
	s.mu.Lock()
	s.ceremonies[id] = &webauthnCeremony{
		id:          id,
		kind:        ceremonyDecision,
		sessionJSON: sessionJSON,
		userID:      []byte(p.FounderID),
		founderID:   p.FounderID,
		decision:    challenge,
		createdAt:   now,
		expiresAt:   challenge.ExpiresAt,
	}
	s.mu.Unlock()
	return challenge, optionsJSON, nil
}

// FinishDecision verifies a decision assertion against the stored
// challenge binding. The challenge is atomically consumed before
// verification, so a replay or a failed attempt cannot be retried with the
// same challenge. The founder's passkey authentication must be fresher
// than five minutes.
func (s *Service) FinishDecision(ctx context.Context, p Principal, challengeID string, purpose DecisionPurpose, subjectID string, canonicalClaims []byte, assertion []byte) error {
	if !validDecisionPurpose(purpose) {
		return ErrInvalidPurpose
	}
	ceremony, err := s.consumeCeremony(challengeID, ceremonyDecision)
	if err != nil {
		return err
	}
	d := ceremony.decision
	if d == nil {
		return ErrDecisionBinding
	}
	digest := sha256.Sum256(canonicalClaims)
	if d.WorkspaceID != p.WorkspaceID ||
		d.WorkspaceID != s.instance.WorkspaceID ||
		d.SessionID != p.SessionID ||
		d.SubjectID != subjectID ||
		d.Purpose != purpose ||
		d.Digest != digest {
		return ErrDecisionBinding
	}
	if s.now().UTC().Sub(p.AuthTime) > decisionAuthFreshness {
		return ErrStaleAssertion
	}
	verified, err := s.verifyAssertion(ctx, ceremony, assertion)
	if err != nil {
		return err
	}
	// Advance the credential sign count exactly as login does, so clone
	// detection keeps working across decision assertions.
	if verified.NewSignCount > 0 {
		credID := base64.RawURLEncoding.EncodeToString(verified.CredentialID)
		err := s.store.WithTx(ctx, func(tx store.Tx) error {
			return tx.UpdateWebAuthnCredentialSignCount(ctx, s.instance.WorkspaceID, credID, verified.NewSignCount)
		})
		if err != nil {
			return fmt.Errorf("authn: finish decision: %w", err)
		}
	}
	return nil
}

// verifyAssertion runs the verifier over a consumed assertion ceremony,
// requires user verification, and advances the credential sign count.
func (s *Service) verifyAssertion(ctx context.Context, ceremony *webauthnCeremony, responseBody []byte) (*VerifiedAssertion, error) {
	creds, err := s.founderCredentials(ctx, ceremony.founderID)
	if err != nil {
		return nil, err
	}
	var stored []StoredCredential
	for _, c := range creds {
		stored = append(stored, StoredCredential{ID: c.ID, PublicKey: c.PublicKey, SignCount: c.SignCount})
	}
	user := CeremonyUser{ID: ceremony.userID, Name: "founder", DisplayName: "Founder"}
	verified, err := s.verifier.FinishAssertion(ctx, user, stored, ceremony.sessionJSON, responseBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}
	if !verified.UserVerified {
		return nil, ErrUserVerification
	}
	return &verified, nil
}

// consumeCeremony atomically takes a one-use ceremony. It fails when the
// ceremony is unknown, already consumed, expired, or of the wrong kind.
func (s *Service) consumeCeremony(id string, kind ceremonyKind) (*webauthnCeremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ceremony, ok := s.ceremonies[id]
	if !ok {
		return nil, ErrCeremonyNotFound
	}
	if ceremony.consumed {
		return nil, ErrCeremonyConsumed
	}
	now := s.now().UTC()
	if !ceremony.expiresAt.After(now) {
		delete(s.ceremonies, id)
		return nil, ErrCeremonyExpired
	}
	if ceremony.kind != kind {
		return nil, ErrCeremonyNotFound
	}
	ceremony.consumed = true
	delete(s.ceremonies, id)
	return ceremony, nil
}

// singleFounder returns the enrolled founder. V1 serves exactly one.
func (s *Service) singleFounder(ctx context.Context) (store.FounderRecord, error) {
	founders, err := s.store.ListFounders(ctx, s.instance.WorkspaceID)
	if err != nil {
		return store.FounderRecord{}, fmt.Errorf("authn: list founders: %w", err)
	}
	if len(founders) == 0 {
		return store.FounderRecord{}, ErrNotEnrolled
	}
	return founders[0], nil
}

// founderCredentials returns the founder's registered passkeys with raw
// credential IDs decoded.
func (s *Service) founderCredentials(ctx context.Context, founderID string) ([]credentialView, error) {
	recs, err := s.store.ListWebAuthnCredentials(ctx, s.instance.WorkspaceID, founderID)
	if err != nil {
		return nil, fmt.Errorf("authn: list credentials: %w", err)
	}
	var out []credentialView
	for _, r := range recs {
		id, err := base64.RawURLEncoding.DecodeString(r.CredentialID)
		if err != nil {
			return nil, fmt.Errorf("authn: decode credential ID: %w", err)
		}
		out = append(out, credentialView{ID: id, PublicKey: r.PublicKey, SignCount: r.SignCount})
	}
	return out, nil
}

type credentialView struct {
	ID        []byte
	PublicKey []byte
	SignCount uint32
}

func joinTransports(transports []string) string {
	out := ""
	for i, tr := range transports {
		if i > 0 {
			out += ","
		}
		out += tr
	}
	return out
}
