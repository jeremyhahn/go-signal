//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeysCheck_MatchingKey(t *testing.T) {
	env := setupTestEnv(t)
	acct1 := registerTestAccountFull(t, env, uniquePhoneNumber(), "pass1")
	acct2 := registerTestAccountFull(t, env, uniquePhoneNumber(), "pass2")

	// Submit the exact identity keys that were used during registration so the
	// fingerprints match and the server reports no mismatches.
	checkReq := map[string]any{
		"identityKeys": []map[string]any{
			{"uuid": acct1.UUID, "identityKey": acct1.ACIKeys.identityKeyB64},
			{"uuid": acct2.UUID, "identityKey": acct2.ACIKeys.identityKeyB64},
		},
	}

	resp := env.doAuthRequest(t, "POST", "/v2/keys/check", checkReq, acct1.UUID, "pass1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	fingerprints, ok := result["identityKeyFingerprints"].([]any)
	require.True(t, ok, "identityKeyFingerprints should be an array")
	assert.Empty(t, fingerprints, "matching keys should produce no mismatches")
}

func TestKeysCheck_MismatchedKey(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass2")

	// Submit a wrong identity key for uuid2 (a fresh random key that doesn't
	// match what was stored during registration).
	wrongKeys := generateTestKeyMaterial(t)

	checkReq := map[string]any{
		"identityKeys": []map[string]any{
			{"uuid": uuid2, "identityKey": wrongKeys.identityKeyB64},
		},
	}

	resp := env.doAuthRequest(t, "POST", "/v2/keys/check", checkReq, uuid1, "pass1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	fingerprints, ok := result["identityKeyFingerprints"].([]any)
	require.True(t, ok, "identityKeyFingerprints should be an array")
	require.Len(t, fingerprints, 1, "should have exactly one mismatch")

	mismatch := fingerprints[0].(map[string]any)
	assert.Equal(t, uuid2, mismatch["uuid"])
	assert.NotEmpty(t, mismatch["identityKey"], "mismatch should include the stored identity key")
	assert.NotEqual(t, wrongKeys.identityKeyB64, mismatch["identityKey"], "returned key should differ from submitted wrong key")
}

func TestKeysCheck_WithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	checkReq := map[string]any{
		"identityKeys": []map[string]any{},
	}
	resp := env.doRequest(t, "POST", "/v2/keys/check", checkReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
