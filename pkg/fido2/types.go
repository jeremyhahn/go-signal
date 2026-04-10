//go:build fido2

// Package fido2 provides WebAuthn/FIDO2 credential management for the
// Signal server, including credential storage, session handling, and
// ceremony orchestration.
package fido2

import "time"

// FIDO2Credential represents a registered WebAuthn credential bound to an
// account. It stores the public key material and metadata required to verify
// authentication assertions.
type FIDO2Credential struct {
	CredentialID    string    `json:"credentialId"`
	AccountUUID     string    `json:"accountUuid"`
	Name            string    `json:"name"`
	PublicKey       []byte    `json:"publicKey"`
	AttestationType string    `json:"attestationType"`
	AAGUID          []byte    `json:"aaguid"`
	SignCount       uint32    `json:"signCount"`
	CloneWarning    bool      `json:"cloneWarning"`
	Transport       []string  `json:"transport"`
	CreatedAt       time.Time `json:"createdAt"`
	LastUsedAt      time.Time `json:"lastUsedAt"`
}

// FIDO2Session holds the state of an in-progress WebAuthn ceremony. Sessions
// are short-lived and expire after a configured duration.
type FIDO2Session struct {
	ID          string           `json:"id"`
	AccountUUID string           `json:"accountUuid,omitempty"`
	Username    string           `json:"username,omitempty"`
	Challenge   []byte           `json:"challenge"`
	SessionData []byte           `json:"sessionData"`
	Type        FIDO2SessionType `json:"type"`
	CreatedAt   time.Time        `json:"createdAt"`
	ExpiresAt   time.Time        `json:"expiresAt"`
}

// FIDO2SessionType identifies the kind of WebAuthn ceremony.
type FIDO2SessionType string

const (
	// SessionTypeRegistration is the initial credential creation ceremony.
	SessionTypeRegistration FIDO2SessionType = "registration"

	// SessionTypeLogin is the authentication assertion ceremony.
	SessionTypeLogin FIDO2SessionType = "login"

	// SessionTypeEnrollment is an additional credential enrollment ceremony
	// for an already-authenticated account.
	SessionTypeEnrollment FIDO2SessionType = "enrollment"
)

// IsExpired reports whether the session has passed its expiration time.
func (s *FIDO2Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// WebAuthnUser is a minimal user representation for WebAuthn ceremonies.
type WebAuthnUser struct {
	ID          []byte
	Name        string
	DisplayName string
}

// WebAuthnID returns the user handle for WebAuthn operations.
func (u *WebAuthnUser) WebAuthnID() []byte { return u.ID }

// WebAuthnName returns the username for WebAuthn operations.
func (u *WebAuthnUser) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName returns the human-readable display name for WebAuthn
// operations.
func (u *WebAuthnUser) WebAuthnDisplayName() string { return u.DisplayName }
