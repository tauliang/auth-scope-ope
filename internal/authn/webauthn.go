package authn

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// webAuthnVerifier is the production Verifier. It delegates ceremony
// cryptography to go-webauthn, configured with the exact bound RP ID and
// origin and requiring user verification for registration, login, and
// decision assertions.
type webAuthnVerifier struct {
	wa *webauthn.WebAuthn
}

// NewWebAuthnVerifier builds the production verifier for one instance.
// rpID and origin must be the bound instance values.
func NewWebAuthnVerifier(rpID, origin string) (Verifier, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: "AuthScope OPE",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// User verification is required for every ceremony; the
			// service additionally rejects ceremonies the verifier
			// reports as unverified.
			UserVerification: protocol.VerificationRequired,
		},
		// Attestation is not needed for a local-first product; "none"
		// keeps enrollment working with platform authenticators while
		// the credential public key still authenticates the founder.
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		return nil, fmt.Errorf("authn: webauthn config: %w", err)
	}
	return &webAuthnVerifier{wa: wa}, nil
}

// waUser adapts CeremonyUser and stored credentials to webauthn.User.
type waUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte          { return u.id }
func (u waUser) WebAuthnName() string        { return u.name }
func (u waUser) WebAuthnDisplayName() string { return u.displayName }
func (u waUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
func (u waUser) WebAuthnIcon() string { return "" }

func (v *webAuthnVerifier) BeginRegistration(ctx context.Context, user CeremonyUser, rpID, origin string, excludeIDs [][]byte) ([]byte, []byte, error) {
	var exclude []protocol.CredentialDescriptor
	for _, id := range excludeIDs {
		exclude = append(exclude, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: id,
		})
	}
	creation, session, err := v.wa.BeginRegistration(
		waUser{id: user.ID, name: user.Name, displayName: user.DisplayName},
		webauthn.WithRegistrationRelyingPartyID(rpID),
		webauthn.WithRegistrationOrigin(origin),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(creation, session)
}

func (v *webAuthnVerifier) FinishRegistration(_ context.Context, user CeremonyUser, sessionJSON, responseBody []byte) (RegisteredCredential, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseBody)
	if err != nil {
		return RegisteredCredential{}, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return RegisteredCredential{}, fmt.Errorf("authn: decode ceremony: %w", err)
	}
	cred, err := v.wa.CreateCredential(
		waUser{id: user.ID, name: user.Name, displayName: user.DisplayName},
		session, parsed)
	if err != nil {
		return RegisteredCredential{}, err
	}
	var transports []string
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	return RegisteredCredential{
		ID:           cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Transports:   transports,
		UserVerified: cred.Flags.UserVerified,
	}, nil
}

func (v *webAuthnVerifier) BeginAssertion(ctx context.Context, user CeremonyUser, rpID, origin string, allowedIDs [][]byte) ([]byte, []byte, error) {
	var allowed []protocol.CredentialDescriptor
	for _, id := range allowedIDs {
		allowed = append(allowed, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: id,
		})
	}
	assertion, session, err := v.wa.BeginLogin(
		waUser{id: user.ID, name: user.Name, displayName: user.DisplayName},
		webauthn.WithLoginRelyingPartyID(rpID),
		webauthn.WithLoginOrigin(origin),
		webauthn.WithAllowedCredentials(allowed),
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, nil, err
	}
	return marshalCeremony(assertion, session)
}

func (v *webAuthnVerifier) FinishAssertion(_ context.Context, user CeremonyUser, creds []StoredCredential, sessionJSON, responseBody []byte) (VerifiedAssertion, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBytes(responseBody)
	if err != nil {
		return VerifiedAssertion{}, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return VerifiedAssertion{}, fmt.Errorf("authn: decode ceremony: %w", err)
	}
	var waCreds []webauthn.Credential
	for _, c := range creds {
		waCreds = append(waCreds, webauthn.Credential{
			ID:        c.ID,
			PublicKey: c.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	cred, err := v.wa.ValidateLogin(
		waUser{id: user.ID, name: user.Name, displayName: user.DisplayName, credentials: waCreds},
		session, parsed)
	if err != nil {
		return VerifiedAssertion{}, err
	}
	return VerifiedAssertion{
		CredentialID: cred.ID,
		NewSignCount: cred.Authenticator.SignCount,
		UserVerified: cred.Flags.UserVerified,
	}, nil
}

func marshalCeremony(options any, session *webauthn.SessionData) ([]byte, []byte, error) {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: encode options: %w", err)
	}
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("authn: encode ceremony: %w", err)
	}
	return optionsJSON, sessionJSON, nil
}
