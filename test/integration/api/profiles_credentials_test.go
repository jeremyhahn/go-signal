//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProfiles_GetWithCredential(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Generate a wire-valid credential request and the matching commitment.
	credentialRequest, commitmentB64 := profileCredentialReqAndCommitment(t, uuid)

	// Set a versioned profile carrying that commitment.
	profileReq := map[string]any{
		"version":    "v1",
		"name":       validProfileName(),
		"commitment": commitmentB64,
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/profile", profileReq, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Fetch the profile with the credential request. The endpoint requires
	// authentication (Basic auth or Unidentified-Access-Key header).
	resp = env.doAuthRequest(t, "GET", "/v1/profile/"+uuid+"/v1/"+credentialRequest, nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var profile map[string]any
	decodeJSON(t, resp, &profile)
	assert.Equal(t, uuid, profile["uuid"])
	assert.NotEmpty(t, profile["name"])

	// Verify the credential field is present.
	credential, ok := profile["credential"].(map[string]any)
	require.True(t, ok, "credential should be an object")
	assert.NotEmpty(t, credential["credential"], "credential should have a credential string")
	assert.NotNil(t, credential["redemptionTime"], "credential should have a redemptionTime")
}

func TestProfiles_GetWithCredentialNonexistentProfile(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Without a stored profile (and thus no profile-key commitment) a
	// credential cannot be issued — the endpoint returns 404.
	credentialRequest, _ := profileCredentialReqAndCommitment(t, uuid)
	resp := env.doAuthRequest(t, "GET", "/v1/profile/"+uuid+"/nonexistent/"+credentialRequest, nil, uuid, "pass123")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestProfiles_BatchIdentityCheck(t *testing.T) {
	env := setupTestEnv(t)
	uuid1, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass1")
	uuid2, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass2")

	// Use a fingerprint that does not match the stored identity key hash to
	// trigger a mismatch.
	wrongFingerprint := base64.StdEncoding.EncodeToString([]byte{0x00, 0x00, 0x00, 0x00})

	batchReq := map[string]any{
		"elements": []map[string]any{
			{"uuid": uuid1, "fingerprint": wrongFingerprint},
			{"uuid": uuid2, "fingerprint": wrongFingerprint},
		},
	}

	resp := env.doAuthRequest(t, "POST", "/v1/profile/identity_check/batch", batchReq, uuid1, "pass1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	elements, ok := result["elements"].([]any)
	require.True(t, ok, "elements should be an array")
	assert.Len(t, elements, 2, "both should be mismatches since fingerprints are wrong")

	// Verify each mismatch includes the stored identity key.
	for _, elem := range elements {
		entry := elem.(map[string]any)
		assert.NotEmpty(t, entry["uuid"])
		assert.NotEmpty(t, entry["identityKey"])
	}
}

func TestProfiles_BatchIdentityCheckWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	batchReq := map[string]any{
		"elements": []map[string]any{},
	}
	resp := env.doRequest(t, "POST", "/v1/profile/identity_check/batch", batchReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
