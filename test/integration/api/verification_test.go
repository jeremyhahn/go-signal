//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerification_CreateSession(t *testing.T) {
	env := setupTestEnv(t)

	reqBody := map[string]any{
		"number":    uniquePhoneNumber(),
		"transport": "sms",
	}
	resp := env.doRequest(t, "POST", "/v1/verification/session", reqBody, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var session map[string]any
	decodeJSON(t, resp, &session)
	assert.NotEmpty(t, session["id"])

	allowedToRequestCode, ok := session["allowedToRequestCode"].(bool)
	require.True(t, ok, "allowedToRequestCode field missing or not a bool in response")
	assert.True(t, allowedToRequestCode)

	verified, ok := session["verified"].(bool)
	require.True(t, ok, "verified field missing or not a bool in response")
	assert.False(t, verified)
}

func TestVerification_FullFlow(t *testing.T) {
	env := setupTestEnv(t)

	// Create a verification session.
	reqBody := map[string]any{"number": uniquePhoneNumber(), "transport": "sms"}
	resp := env.doRequest(t, "POST", "/v1/verification/session", reqBody, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var session map[string]any
	decodeJSON(t, resp, &session)
	sessionID := session["id"].(string)

	// Request a verification code.
	resp = env.doRequest(t, "POST", "/v1/verification/session/"+sessionID+"/code", nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Submit the verification code (auto-verified in test mode).
	submitReq := map[string]any{"code": "123456"}
	resp = env.doRequest(t, "PUT", "/v1/verification/session/"+sessionID+"/code", submitReq, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &session)
	verified, ok := session["verified"].(bool)
	require.True(t, ok, "verified field missing or not a bool after code submission")
	assert.True(t, verified)

	// Fetch the session to confirm it remains verified.
	resp = env.doRequest(t, "GET", "/v1/verification/session/"+sessionID, nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &session)
	verified, ok = session["verified"].(bool)
	require.True(t, ok, "verified field missing or not a bool after session fetch")
	assert.True(t, verified)
}

func TestVerification_InvalidSession(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v1/verification/session/nonexistent", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestVerification_RequestCodeInvalidSession(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "POST", "/v1/verification/session/nonexistent/code", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestVerification_SubmitCodeInvalidSession(t *testing.T) {
	env := setupTestEnv(t)
	submitReq := map[string]any{"code": "123456"}
	resp := env.doRequest(t, "PUT", "/v1/verification/session/nonexistent/code", submitReq, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestVerification_CreateSessionMissingNumber(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "POST", "/v1/verification/session", map[string]any{}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}
