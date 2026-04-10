//go:build integration

package api

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertificates_GetDeliveryCertificate(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/certificate/delivery", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	cert, ok := result["certificate"].(string)
	require.True(t, ok, "certificate field must be a string")
	assert.NotEmpty(t, cert, "certificate must not be empty")

	expiry, ok := result["certificateExpiry"].(float64)
	require.True(t, ok, "certificateExpiry field must be a number")
	assert.Greater(t, int64(expiry), time.Now().UnixMilli(), "certificate expiry must be in the future")
}

func TestCertificates_GetDeliveryCertificateWithoutE164(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/certificate/delivery?includeE164=false", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	cert, ok := result["certificate"].(string)
	require.True(t, ok, "certificate field must be a string")
	assert.NotEmpty(t, cert, "certificate must not be empty")
}

func TestCertificates_GetDeliveryCertificateWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v1/certificate/delivery", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestCertificates_GetGroupCredentials(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	now := time.Now().Unix()
	startSeconds := now
	endSeconds := now + 86400*2 // 3 days total

	path := fmt.Sprintf("/v1/certificate/auth/group?redemptionStartSeconds=%d&redemptionEndSeconds=%d",
		startSeconds, endSeconds)

	resp := env.doAuthRequest(t, "GET", path, nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	pni, ok := result["pni"].(string)
	require.True(t, ok, "pni field must be a string")
	assert.NotEmpty(t, pni, "pni must not be empty")

	credentials, ok := result["credentials"].([]any)
	require.True(t, ok, "credentials field must be an array")
	assert.NotEmpty(t, credentials, "credentials must not be empty")
}

func TestCertificates_GetGroupCredentialsWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	now := time.Now().Unix()
	path := fmt.Sprintf("/v1/certificate/auth/group?redemptionStartSeconds=%d&redemptionEndSeconds=%d",
		now, now+86400)

	resp := env.doRequest(t, "GET", path, nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestCertificates_GetGroupCredentialsMissingParams(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/certificate/auth/group", nil, uuid, "pass123")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}
