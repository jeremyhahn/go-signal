//go:build fido2

package rest

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jeremyhahn/go-signal/pkg/fido2"
)

// writeFIDO2Error maps a FIDO2 domain error to the correct HTTP status code
// and writes a JSON error response.
func writeFIDO2Error(w http.ResponseWriter, err error) {
	var (
		credNotFound  *fido2.CredentialNotFoundError
		credExists    *fido2.CredentialExistsError
		sessNotFound  *fido2.SessionNotFoundError
		noCredentials *fido2.NoCredentialsError
		sessExpired   *fido2.SessionExpiredError
		ceremonyErr   *fido2.CeremonyError
		invalidType   *fido2.InvalidSessionTypeError
	)

	switch {
	case errors.As(err, &credNotFound):
		writeError(w, http.StatusNotFound, "credential not found")
	case errors.As(err, &sessNotFound):
		writeError(w, http.StatusNotFound, "session not found")
	case errors.As(err, &noCredentials):
		writeError(w, http.StatusNotFound, "no credentials found")
	case errors.As(err, &credExists):
		writeError(w, http.StatusConflict, "credential already exists")
	case errors.As(err, &sessExpired):
		writeError(w, http.StatusGone, "session expired")
	case errors.As(err, &ceremonyErr):
		writeError(w, http.StatusBadRequest, "ceremony failed")
	case errors.As(err, &invalidType):
		writeError(w, http.StatusBadRequest, "invalid session type")
	default:
		writeError(w, http.StatusInternalServerError, "internal server error")
	}
}

// handleFIDO2Capabilities returns the server's FIDO2 configuration.
func (s *Server) handleFIDO2Capabilities(w http.ResponseWriter, _ *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	writeJSON(w, http.StatusOK, FIDO2CapabilitiesResponse{
		Enabled:          state.config.Enabled,
		RPID:             state.config.RPID,
		RPName:           state.config.RPName,
		AllowFIDO2Only:   state.config.AllowFIDO2Only,
		RequireMFA:       state.config.RequireMFA,
		Attestation:      state.config.Attestation,
		UserVerification: state.config.UserVerification,
	})
}

// handleFIDO2BeginRegistration starts a new FIDO2 registration ceremony for
// a previously unauthenticated user.
func (s *Server) handleFIDO2BeginRegistration(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	var req FIDO2BeginRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	session, creation, err := state.manager.BeginRegistration(r.Context(), req.Username, req.Username)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	writeJSON(w, http.StatusOK, FIDO2BeginResponse{
		Session: FIDO2SessionResponse{
			SessionID: session.ID,
			Type:      string(session.Type),
			ExpiresAt: session.ExpiresAt.Unix(),
		},
		Options: creation,
	})
}

// handleFIDO2GetSession retrieves a FIDO2 session by ID.
func (s *Server) handleFIDO2GetSession(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return
	}

	session, err := state.manager.GetSession(r.Context(), sessionID)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	writeJSON(w, http.StatusOK, FIDO2SessionResponse{
		SessionID: session.ID,
		Type:      string(session.Type),
		ExpiresAt: session.ExpiresAt.Unix(),
	})
}

// handleFIDO2CompleteRegistration finishes a registration ceremony and stores
// the new credential.
func (s *Server) handleFIDO2CompleteRegistration(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return
	}

	cred, err := state.manager.CompleteRegistration(r.Context(), sessionID, r)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	writeJSON(w, http.StatusOK, credentialToResponse(cred))
}

// handleFIDO2BeginEnrollment starts an enrollment ceremony for adding a new
// credential to an already-authenticated account.
func (s *Server) handleFIDO2BeginEnrollment(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req FIDO2BeginEnrollmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	session, creation, err := state.manager.BeginEnrollment(r.Context(), acct.UUID, req.CredentialName)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	writeJSON(w, http.StatusOK, FIDO2BeginResponse{
		Session: FIDO2SessionResponse{
			SessionID: session.ID,
			Type:      string(session.Type),
			ExpiresAt: session.ExpiresAt.Unix(),
		},
		Options: creation,
	})
}

// handleFIDO2CompleteEnrollment finishes an enrollment ceremony and stores the
// new credential.
func (s *Server) handleFIDO2CompleteEnrollment(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	sessionID := r.PathValue("id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session id is required")
		return
	}

	cred, err := state.manager.CompleteEnrollment(r.Context(), sessionID, r)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	writeJSON(w, http.StatusOK, credentialToResponse(cred))
}

// handleFIDO2BeginLogin starts a login ceremony for the specified account.
func (s *Server) handleFIDO2BeginLogin(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	var req FIDO2BeginLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.AccountUUID == "" {
		writeError(w, http.StatusBadRequest, "accountUuid is required")
		return
	}

	session, assertion, err := state.manager.BeginLogin(r.Context(), req.AccountUUID)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	writeJSON(w, http.StatusOK, FIDO2BeginResponse{
		Session: FIDO2SessionResponse{
			SessionID: session.ID,
			Type:      string(session.Type),
			ExpiresAt: session.ExpiresAt.Unix(),
		},
		Options: assertion,
	})
}

// handleFIDO2CompleteLogin finishes a login ceremony. The session ID is
// supplied in the request body as JSON.
func (s *Server) handleFIDO2CompleteLogin(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	var body struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.SessionID == "" {
		writeError(w, http.StatusBadRequest, "sessionId is required")
		return
	}

	accountUUID, err := state.manager.CompleteLogin(r.Context(), body.SessionID, r)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	writeJSON(w, http.StatusOK, FIDO2LoginResponse{
		AccountUUID: accountUUID,
		Token:       "", // Token generation is handled by the auth layer.
	})
}

// handleFIDO2ListCredentials returns all FIDO2 credentials for the
// authenticated account.
func (s *Server) handleFIDO2ListCredentials(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	creds, err := state.manager.ListCredentials(r.Context(), acct.UUID)
	if err != nil {
		writeFIDO2Error(w, err)
		return
	}

	resp := FIDO2CredentialListResponse{
		Credentials: make([]FIDO2CredentialResponse, len(creds)),
	}
	for i, c := range creds {
		resp.Credentials[i] = credentialToResponse(c)
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleFIDO2DeleteCredential removes a credential from the authenticated
// account.
func (s *Server) handleFIDO2DeleteCredential(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	credentialID := r.PathValue("id")
	if credentialID == "" {
		writeError(w, http.StatusBadRequest, "credential id is required")
		return
	}

	if err := state.manager.DeleteCredential(r.Context(), acct.UUID, credentialID); err != nil {
		writeFIDO2Error(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleFIDO2RenameCredential updates the display name of a credential
// belonging to the authenticated account.
func (s *Server) handleFIDO2RenameCredential(w http.ResponseWriter, r *http.Request) {
	state := getFIDO2State(s)
	if state == nil {
		writeError(w, http.StatusNotFound, "fido2 not configured")
		return
	}

	acct := accountFromContext(r.Context())
	if acct == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	credentialID := r.PathValue("id")
	if credentialID == "" {
		writeError(w, http.StatusBadRequest, "credential id is required")
		return
	}

	var req FIDO2RenameCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := state.manager.RenameCredential(r.Context(), acct.UUID, credentialID, req.Name); err != nil {
		writeFIDO2Error(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// credentialToResponse converts a FIDO2Credential domain object to the API
// response representation, converting timestamps to Unix epoch seconds.
func credentialToResponse(c *fido2.FIDO2Credential) FIDO2CredentialResponse {
	transport := c.Transport
	if transport == nil {
		transport = []string{}
	}
	return FIDO2CredentialResponse{
		CredentialID:    c.CredentialID,
		Name:            c.Name,
		AttestationType: c.AttestationType,
		Transport:       transport,
		CreatedAt:       c.CreatedAt.Unix(),
		LastUsedAt:      c.LastUsedAt.Unix(),
	}
}
