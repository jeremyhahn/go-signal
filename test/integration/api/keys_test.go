//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeys_UploadAndGetCount(t *testing.T) {
	env := setupTestEnv(t)
	acct := registerTestAccountFull(t, env, uniquePhoneNumber(), "pass123")

	// Upload pre-keys for the authenticated user's primary device. The signed
	// pre-key must be signed with the account's ACI identity key.
	keysReq := map[string]any{
		"preKeys": []map[string]any{
			{"keyId": 100, "publicKey": base64.StdEncoding.EncodeToString([]byte("prekey-public-100-padding!!!!!!"))},
			{"keyId": 101, "publicKey": base64.StdEncoding.EncodeToString([]byte("prekey-public-101-padding!!!!!!"))},
		},
		"signedPreKey": signedPreKeyFor(t, 200, acct.ACIKeys.identityKeyPair),
		"pqPreKeys": []map[string]any{
			kemPreKeyFor(t, 300, acct.ACIKeys.identityKeyPair),
			kemPreKeyFor(t, 301, acct.ACIKeys.identityKeyPair),
		},
	}
	resp := env.doAuthRequest(t, "PUT", "/v2/keys", keysReq, acct.UUID, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Retrieve the pre-key count for the authenticated user.
	resp = env.doAuthRequest(t, "GET", "/v2/keys", nil, acct.UUID, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Decode into map[string]any to handle mixed int/bool fields in the response.
	var count map[string]any
	decodeJSON(t, resp, &count)
	assert.Equal(t, float64(2), count["count"])
	assert.Equal(t, float64(3), count["pqCount"]) // 2 uploaded + 1 from registration
}

func TestKeys_GetPreKeysForUser(t *testing.T) {
	env := setupTestEnv(t)
	acct := registerTestAccountFull(t, env, uniquePhoneNumber(), "pass123")

	// Upload additional pre-keys for the registered user. The signed pre-key
	// must be signed with the account's ACI identity key.
	keysReq := map[string]any{
		"preKeys": []map[string]any{
			{"keyId": 100, "publicKey": base64.StdEncoding.EncodeToString([]byte("prekey-public-100-padding!!!!!!"))},
		},
		"signedPreKey": signedPreKeyFor(t, 200, acct.ACIKeys.identityKeyPair),
		"pqPreKeys": []map[string]any{
			kemPreKeyFor(t, 300, acct.ACIKeys.identityKeyPair),
		},
	}
	resp := env.doAuthRequest(t, "PUT", "/v2/keys", keysReq, acct.UUID, "pass123")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Another user fetches pre-keys for the first user.
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass456")
	resp = env.doAuthRequest(t, "GET", "/v2/keys/"+acct.UUID+"/1", nil, uuid2, "pass456")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var preKeyResp map[string]any
	decodeJSON(t, resp, &preKeyResp)
	assert.NotEmpty(t, preKeyResp["identityKey"])
	devices, ok := preKeyResp["devices"].([]any)
	require.True(t, ok, "devices should be an array")
	assert.Len(t, devices, 1)

	// Verify the device entry has the expected fields.
	device := devices[0].(map[string]any)
	assert.NotNil(t, device["signedPreKey"])
}

func TestKeys_GetPreKeysForNonexistentUser(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Use a valid UUID format that doesn't exist in the store.
	resp := env.doAuthRequest(t, "GET", "/v2/keys/00000000-0000-0000-0000-000000000000/1", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestKeys_UploadWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "PUT", "/v2/keys", map[string]any{}, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestKeys_GetCountWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v2/keys", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestKeys_GetPreKeysForAllDevices(t *testing.T) {
	env := setupTestEnv(t)
	acct := registerTestAccountFull(t, env, uniquePhoneNumber(), "pass123")

	// Upload pre-keys. The signed pre-key must be signed with the ACI identity key.
	keysReq := map[string]any{
		"preKeys": []map[string]any{
			{"keyId": 100, "publicKey": base64.StdEncoding.EncodeToString([]byte("prekey-public-100-padding!!!!!!"))},
		},
		"signedPreKey": signedPreKeyFor(t, 200, acct.ACIKeys.identityKeyPair),
	}
	resp := env.doAuthRequest(t, "PUT", "/v2/keys", keysReq, acct.UUID, "pass123")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Fetch pre-keys for all devices using the wildcard "*".
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass456")
	resp = env.doAuthRequest(t, "GET", "/v2/keys/"+acct.UUID+"/*", nil, uuid2, "pass456")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var preKeyResp map[string]any
	decodeJSON(t, resp, &preKeyResp)
	devices, ok := preKeyResp["devices"].([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(devices), 1)
}

func TestKeys_ConsumesOneTimePreKey(t *testing.T) {
	env := setupTestEnv(t)
	acct := registerTestAccountFull(t, env, uniquePhoneNumber(), "pass123")

	// Upload 2 EC pre-keys. The signed pre-key must be signed with the ACI identity key.
	keysReq := map[string]any{
		"preKeys": []map[string]any{
			{"keyId": 100, "publicKey": base64.StdEncoding.EncodeToString([]byte("prekey-public-100-padding!!!!!!"))},
			{"keyId": 101, "publicKey": base64.StdEncoding.EncodeToString([]byte("prekey-public-101-padding!!!!!!"))},
		},
		"signedPreKey": signedPreKeyFor(t, 200, acct.ACIKeys.identityKeyPair),
	}
	resp := env.doAuthRequest(t, "PUT", "/v2/keys", keysReq, acct.UUID, "pass123")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Another user fetches pre-keys, consuming one EC pre-key.
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass456")
	resp = env.doAuthRequest(t, "GET", "/v2/keys/"+acct.UUID+"/1", nil, uuid2, "pass456")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Check count -- should be decremented by 1.
	resp = env.doAuthRequest(t, "GET", "/v2/keys", nil, acct.UUID, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// Decode into map[string]any to handle mixed int/bool fields in the response.
	var count map[string]any
	decodeJSON(t, resp, &count)
	assert.Equal(t, float64(1), count["count"])
}
