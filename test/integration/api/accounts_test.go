//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccounts_Whoami(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/accounts/whoami", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var identity map[string]any
	decodeJSON(t, resp, &identity)
	assert.Equal(t, uuid, identity["uuid"])
	assert.Equal(t, number, identity["number"])
}

func TestAccounts_WhoamiWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v1/accounts/whoami", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_CheckAccountExists(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	resp := env.doRequest(t, "HEAD", "/v1/accounts/account/"+uuid, nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_CheckAccountNotExists(t *testing.T) {
	env := setupTestEnv(t)
	// Use a well-formed UUID that is guaranteed not to exist. A malformed
	// identifier (e.g. "nonexistent-uuid") now returns 400 because the server
	// validates the shape before touching the store; a legitimate-looking but
	// unregistered UUID correctly yields 404.
	resp := env.doRequest(t, "HEAD", "/v1/accounts/account/00000000-0000-0000-0000-000000000001", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_UpdateAttributes(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	attrs := map[string]any{
		"name":            base64.StdEncoding.EncodeToString([]byte("Updated Name")),
		"fetchesMessages": false,
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/attributes/", attrs, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_UpdateAttributesWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "PUT", "/v1/accounts/attributes/", map[string]any{}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_DeleteAccount(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	resp := env.doAuthRequest(t, "DELETE", "/v1/accounts/me", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Verify the account is gone.
	resp = env.doRequest(t, "HEAD", "/v1/accounts/account/"+uuid, nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_DeleteAccountWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "DELETE", "/v1/accounts/me", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_RegisterAndSetGCM(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	gcmReq := map[string]any{
		"gcmRegistrationId": "test-gcm-token-12345",
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/gcm/", gcmReq, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Delete GCM registration.
	resp = env.doAuthRequest(t, "DELETE", "/v1/accounts/gcm/", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_RegisterAndSetAPN(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	apnReq := map[string]any{
		"apnRegistrationId":  "test-apn-token-12345",
		"voipRegistrationId": "test-voip-token-12345",
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/apn/", apnReq, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Delete APN registration.
	resp = env.doAuthRequest(t, "DELETE", "/v1/accounts/apn/", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_WhoamiAfterAttributeUpdate(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	// Update attributes.
	attrs := map[string]any{
		"name":            base64.StdEncoding.EncodeToString([]byte("New Name")),
		"fetchesMessages": true,
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/attributes/", attrs, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Whoami should still return the same UUID and number.
	resp = env.doAuthRequest(t, "GET", "/v1/accounts/whoami", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var identity map[string]any
	decodeJSON(t, resp, &identity)
	assert.Equal(t, uuid, identity["uuid"])
	assert.Equal(t, number, identity["number"])
}
