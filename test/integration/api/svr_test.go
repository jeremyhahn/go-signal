//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSVR_GetBackupAuth(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v2/backup/auth", nil, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	assert.NotEmpty(t, result["username"])
	assert.NotEmpty(t, result["password"])
}

func TestSVR_GetSVRAuth(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v2/svr/auth", nil, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	assert.NotEmpty(t, result["username"])
	assert.NotEmpty(t, result["password"])
}

func TestSVR_CheckAuth(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	body := map[string]any{
		"passwords": []string{"pw1", "pw2"},
	}
	resp := env.doAuthRequest(t, "POST", "/v2/backup/auth/check", body, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	matches, ok := result["matches"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "no-match", matches["pw1"])
	assert.Equal(t, "no-match", matches["pw2"])
}
