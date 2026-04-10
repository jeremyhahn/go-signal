package rest

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// generateChallenge creates a 32-byte random challenge encoded as base64.
func generateChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// handleDeviceCheckAttestChallenge handles GET /v1/devicecheck/attest and
// returns a random challenge for device attestation.
func (s *Server) handleDeviceCheckAttestChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := generateChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"challenge": challenge,
	})
}

// handleDeviceCheckAttest handles PUT /v1/devicecheck/attest. Device
// attestation verification is not yet implemented; returns 501.
func (s *Server) handleDeviceCheckAttest(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}

// handleDeviceCheckAssertChallenge handles GET /v1/devicecheck/assert and
// returns a random challenge for device assertion.
func (s *Server) handleDeviceCheckAssertChallenge(w http.ResponseWriter, r *http.Request) {
	challenge, err := generateChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"challenge": challenge,
	})
}

// handleDeviceCheckAssert handles POST /v1/devicecheck/assert. Device
// assertion verification is not yet implemented; returns 501.
func (s *Server) handleDeviceCheckAssert(w http.ResponseWriter, r *http.Request) {
	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	writeError(w, http.StatusNotImplemented, "not implemented")
}
