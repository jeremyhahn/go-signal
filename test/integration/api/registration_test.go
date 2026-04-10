//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistration_Success(t *testing.T) {
	env := setupTestEnv(t)
	uuid, pni := registerTestAccount(t, env, uniquePhoneNumber(), "test-password")
	assert.NotEmpty(t, uuid)
	assert.NotEmpty(t, pni)
}

func TestRegistration_ReRegistrationReplacesAccount(t *testing.T) {
	env := setupTestEnv(t)

	number := uniquePhoneNumber()
	uuid1, _ := registerTestAccount(t, env, number, "password1")

	// Re-registration with the same number should succeed, replacing the
	// existing account with a new UUID (matching Signal's behavior).
	uuid2, pni2 := registerTestAccount(t, env, number, "password2")

	assert.NotEmpty(t, uuid2)
	assert.NotEmpty(t, pni2)
	assert.NotEqual(t, uuid1, uuid2, "re-registration should assign a new UUID")

	// The old account should no longer be accessible with old credentials.
	resp := env.doAuthRequest(t, "GET", "/v1/accounts/whoami", nil, uuid1, "password1")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()

	// The new account should be accessible with new credentials.
	resp = env.doAuthRequest(t, "GET", "/v1/accounts/whoami", nil, uuid2, "password2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestRegistration_MissingAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "POST", "/v1/registration", map[string]any{}, nil)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestRegistration_MissingIdentityKey(t *testing.T) {
	env := setupTestEnv(t)

	regReq := map[string]any{
		"accountAttributes": map[string]any{
			"fetchesMessages": true,
			"registrationId":  1234,
		},
		// Missing aciIdentityKey and pniIdentityKey -- these will be empty
		// strings, which base64-decode to empty slices.
		"aciIdentityKey":  "",
		"pniIdentityKey":  "",
		"aciSignedPreKey": testSignedPreKey(1),
		"pniSignedPreKey": testSignedPreKey(2),
	}

	creds := base64.StdEncoding.EncodeToString([]byte(uniquePhoneNumber() + ":password"))
	resp := env.doRequest(t, "POST", "/v1/registration", regReq, map[string]string{
		"Authorization": "Basic " + creds,
	})
	// The server should reject registrations with missing/empty identity keys.
	// The account manager validates that identityKey must not be empty.
	require.True(t, resp.StatusCode >= 400 && resp.StatusCode < 600,
		"expected error status code, got %d", resp.StatusCode)
	resp.Body.Close()
}

func TestRegistration_InvalidIdentityKeyEncoding(t *testing.T) {
	env := setupTestEnv(t)

	regReq := map[string]any{
		"accountAttributes": map[string]any{
			"fetchesMessages": true,
			"registrationId":  1234,
		},
		"aciIdentityKey":  "!!!not-valid-base64!!!",
		"pniIdentityKey":  base64.StdEncoding.EncodeToString([]byte("test-pni-identity-key-32bytes!!")),
		"aciSignedPreKey": testSignedPreKey(1),
		"pniSignedPreKey": testSignedPreKey(2),
	}

	creds := base64.StdEncoding.EncodeToString([]byte(uniquePhoneNumber() + ":password"))
	resp := env.doRequest(t, "POST", "/v1/registration", regReq, map[string]string{
		"Authorization": "Basic " + creds,
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestRegistration_ResponseContainsUUIDAndPNI(t *testing.T) {
	env := setupTestEnv(t)

	// Use the full registration flow (verification + registration) to ensure
	// the response contains the expected fields.
	uuid, pni := registerTestAccount(t, env, uniquePhoneNumber(), "mypassword")

	assert.NotEmpty(t, uuid, "uuid must be present in response")
	assert.NotEmpty(t, pni, "pni must be present in response")
}
