//go:build integration

package api

import (
	"encoding/base64"
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

	// GET /v1/archives returns 401 without ZK auth headers and 501 with any headers when backups are not configured.
	fakePresentation := base64.StdEncoding.EncodeToString(make([]byte, 64))
	fakeSignature := base64.StdEncoding.EncodeToString(make([]byte, 64))
	headers := map[string]string{
		"X-Signal-ZK-Auth":           fakePresentation,
		"X-Signal-ZK-Auth-Signature": fakeSignature,
	}
	resp := env.doRequest(t, "GET", "/v1/archives", nil, headers)
	require.Equal(t, http.StatusNotImplemented, resp.StatusCode)
	resp.Body.Close()
}

func TestArchives_GetAuthWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/archives/auth", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
