//go:build fido2

package fido2

import (
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnProvider abstracts the go-webauthn library for testability.
type WebAuthnProvider interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
	BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}

// DefaultWebAuthnProvider wraps the go-webauthn library.
type DefaultWebAuthnProvider struct {
	wa *webauthn.WebAuthn
}

// NewDefaultWebAuthnProvider creates a WebAuthnProvider using the given webauthn.WebAuthn.
func NewDefaultWebAuthnProvider(wa *webauthn.WebAuthn) *DefaultWebAuthnProvider {
	return &DefaultWebAuthnProvider{wa: wa}
}

// BeginRegistration delegates to the underlying webauthn.WebAuthn.BeginRegistration.
func (p *DefaultWebAuthnProvider) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return p.wa.BeginRegistration(user, opts...)
}

// FinishRegistration delegates to the underlying webauthn.WebAuthn.FinishRegistration.
func (p *DefaultWebAuthnProvider) FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	return p.wa.FinishRegistration(user, session, response)
}

// BeginLogin delegates to the underlying webauthn.WebAuthn.BeginLogin.
func (p *DefaultWebAuthnProvider) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return p.wa.BeginLogin(user, opts...)
}

// FinishLogin delegates to the underlying webauthn.WebAuthn.FinishLogin.
func (p *DefaultWebAuthnProvider) FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
	return p.wa.FinishLogin(user, session, response)
}
