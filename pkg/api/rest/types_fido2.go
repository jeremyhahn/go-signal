//go:build fido2

package rest

// FIDO2CapabilitiesResponse is returned by GET /v1/fido2/capabilities and
// describes the server's FIDO2/WebAuthn configuration.
type FIDO2CapabilitiesResponse struct {
	Enabled          bool   `json:"enabled"`
	RPID             string `json:"rpId"`
	RPName           string `json:"rpName"`
	AllowFIDO2Only   bool   `json:"allowFido2Only"`
	RequireMFA       bool   `json:"requireMfa"`
	Attestation      string `json:"attestation"`
	UserVerification string `json:"userVerification"`
}

// FIDO2BeginRegistrationRequest is the body for POST /v1/fido2/session.
type FIDO2BeginRegistrationRequest struct {
	Username string `json:"username"`
}

// FIDO2SessionResponse wraps session metadata returned to clients after a
// ceremony initiation.
type FIDO2SessionResponse struct {
	SessionID string `json:"sessionId"`
	Type      string `json:"type"`
	ExpiresAt int64  `json:"expiresAt"`
}

// FIDO2BeginEnrollmentRequest is the body for POST /v1/fido2/enroll.
type FIDO2BeginEnrollmentRequest struct {
	CredentialName string `json:"credentialName"`
}

// FIDO2BeginLoginRequest is the body for POST /v1/fido2/auth/begin.
type FIDO2BeginLoginRequest struct {
	AccountUUID string `json:"accountUuid"`
}

// FIDO2LoginResponse is returned after a successful FIDO2 login ceremony.
type FIDO2LoginResponse struct {
	AccountUUID string `json:"accountUuid"`
	Token       string `json:"token"`
}

// FIDO2CredentialResponse represents a single FIDO2 credential in API
// responses, omitting sensitive fields such as the public key.
type FIDO2CredentialResponse struct {
	CredentialID    string   `json:"credentialId"`
	Name            string   `json:"name"`
	AttestationType string   `json:"attestationType"`
	Transport       []string `json:"transport"`
	CreatedAt       int64    `json:"createdAt"`
	LastUsedAt      int64    `json:"lastUsedAt"`
}

// FIDO2CredentialListResponse wraps a list of credentials for the API response
// envelope.
type FIDO2CredentialListResponse struct {
	Credentials []FIDO2CredentialResponse `json:"credentials"`
}

// FIDO2RenameCredentialRequest is the body for PUT /v1/fido2/credentials/{id}/name.
type FIDO2RenameCredentialRequest struct {
	Name string `json:"name"`
}

// FIDO2BeginResponse combines session metadata with WebAuthn options (either
// CredentialCreation or CredentialAssertion) so the client can drive the
// ceremony.
type FIDO2BeginResponse struct {
	Session FIDO2SessionResponse `json:"session"`
	Options any                  `json:"options"`
}
