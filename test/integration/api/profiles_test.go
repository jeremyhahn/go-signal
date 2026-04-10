//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfiles_SetAndGet(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	profileReq := map[string]any{
		"version":    "testversion1",
		"name":       base64.StdEncoding.EncodeToString([]byte("Test User")),
		"about":      base64.StdEncoding.EncodeToString([]byte("Hello!")),
		"aboutEmoji": base64.StdEncoding.EncodeToString([]byte("wave")),
		"commitment": base64.StdEncoding.EncodeToString([]byte("commitment-value-padding!!!!!!")),
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/profile", profileReq, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Get the versioned profile.
	resp = env.doAuthRequest(t, "GET", "/v1/profile/"+uuid+"/testversion1", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var profile map[string]any
	decodeJSON(t, resp, &profile)
	assert.NotEmpty(t, profile["name"])
	assert.Equal(t, uuid, profile["uuid"])
}

func TestProfiles_GetNonexistentProfile(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/profile/nonexistent-uuid/v1", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestProfiles_GetUnversioned(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Getting the unversioned profile for an account that has no profile
	// should still return 200 with minimal account-level data.
	resp := env.doAuthRequest(t, "GET", "/v1/profile/"+uuid, nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var profile map[string]any
	decodeJSON(t, resp, &profile)
	assert.Equal(t, uuid, profile["uuid"])
}

func TestProfiles_GetUnversionedAfterSet(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Set a versioned profile.
	profileReq := map[string]any{
		"version":    "v1",
		"name":       base64.StdEncoding.EncodeToString([]byte("Alice")),
		"commitment": base64.StdEncoding.EncodeToString([]byte("commitment-value-alice-padding!")),
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/profile", profileReq, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Fetch the latest (unversioned) profile.
	resp = env.doAuthRequest(t, "GET", "/v1/profile/"+uuid, nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var profile map[string]any
	decodeJSON(t, resp, &profile)
	assert.Equal(t, uuid, profile["uuid"])
	assert.NotEmpty(t, profile["name"])
}

func TestProfiles_SetWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "PUT", "/v1/profile", map[string]any{}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestProfiles_MultipleVersions(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Set version 1.
	profileV1 := map[string]any{
		"version":    "v1",
		"name":       base64.StdEncoding.EncodeToString([]byte("Alice V1")),
		"commitment": base64.StdEncoding.EncodeToString([]byte("commitment-v1-padding!!!!!!!!!!")),
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/profile", profileV1, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Set version 2.
	profileV2 := map[string]any{
		"version":    "v2",
		"name":       base64.StdEncoding.EncodeToString([]byte("Alice V2")),
		"commitment": base64.StdEncoding.EncodeToString([]byte("commitment-v2-padding!!!!!!!!!!")),
	}
	resp = env.doAuthRequest(t, "PUT", "/v1/profile", profileV2, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Fetch version 1.
	resp = env.doAuthRequest(t, "GET", "/v1/profile/"+uuid+"/v1", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var p1 map[string]any
	decodeJSON(t, resp, &p1)
	name1Bytes, _ := base64.StdEncoding.DecodeString(p1["name"].(string))
	assert.Equal(t, "Alice V1", string(name1Bytes))

	// Fetch version 2.
	resp = env.doAuthRequest(t, "GET", "/v1/profile/"+uuid+"/v2", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var p2 map[string]any
	decodeJSON(t, resp, &p2)
	name2Bytes, _ := base64.StdEncoding.DecodeString(p2["name"].(string))
	assert.Equal(t, "Alice V2", string(name2Bytes))
}
