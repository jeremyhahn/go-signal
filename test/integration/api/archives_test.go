//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArchives_GetAuth(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	// Backup credential issuance is not yet implemented; expect 501.
	resp := env.doAuthRequest(t, "GET", "/v1/archives/auth", nil, uuid, "pass123")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	resp.Body.Close()
}

func TestArchives_GetInfo(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	// Backup information retrieval is not yet implemented; expect 501.
	resp := env.doAuthRequest(t, "GET", "/v1/archives", nil, uuid, "pass123")
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	resp.Body.Close()
}

func TestArchives_GetAuthWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/archives/auth", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
