//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_FullRegistrationAndMessaging exercises the complete user journey:
// registration, key upload, profile setup, key exchange, messaging, retrieval,
// and account deletion.
func TestE2E_FullRegistrationAndMessaging(t *testing.T) {
	env := setupTestEnv(t)

	// === User A registers ===
	acctA := registerTestAccountFull(t, env, uniquePhoneNumber(), "passwordA")
	uuidA := acctA.UUID
	require.NotEmpty(t, uuidA)

	// Upload pre-keys for User A. Signed pre-keys must use User A's ACI identity key.
	keysReqA := map[string]any{
		"preKeys": []map[string]any{
			{"keyId": 1, "publicKey": base64.StdEncoding.EncodeToString([]byte("userA-prekey-public-key-pad!!!"))},
			{"keyId": 2, "publicKey": base64.StdEncoding.EncodeToString([]byte("userA-prekey-public-key2-pad!!"))},
		},
		"signedPreKey": signedPreKeyFor(t, 10, acctA.ACIKeys.identityKeyPair),
		"pqPreKeys":    []map[string]any{kemPreKeyFor(t, 20, acctA.ACIKeys.identityKeyPair)},
	}
	resp := env.doAuthRequest(t, "PUT", "/v2/keys", keysReqA, uuidA, "passwordA")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Set profile for User A.
	profileA := map[string]any{
		"version":    "v1",
		"name":       base64.StdEncoding.EncodeToString([]byte("Alice")),
		"commitment": base64.StdEncoding.EncodeToString([]byte("commitment-value-alice-padding!")),
	}
	resp = env.doAuthRequest(t, "PUT", "/v1/profile", profileA, uuidA, "passwordA")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// === User B registers ===
	uuidB, _ := registerTestAccount(t, env, uniquePhoneNumber(), "passwordB")
	require.NotEmpty(t, uuidB)

	// User B fetches User A's pre-keys for session establishment.
	resp = env.doAuthRequest(t, "GET", "/v2/keys/"+uuidA+"/1", nil, uuidB, "passwordB")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var preKeyResp map[string]any
	decodeJSON(t, resp, &preKeyResp)
	assert.NotEmpty(t, preKeyResp["identityKey"])
	devices := preKeyResp["devices"].([]any)
	assert.Len(t, devices, 1)

	// User B fetches User A's profile.
	resp = env.doAuthRequest(t, "GET", "/v1/profile/"+uuidA+"/v1", nil, uuidB, "passwordB")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var profileResp map[string]any
	decodeJSON(t, resp, &profileResp)
	assert.NotEmpty(t, profileResp["name"])

	// User B sends a message to User A.
	msgReq := map[string]any{
		"messages": []map[string]any{{
			"type":                1,
			"destinationDeviceId": 1,
			"content":             base64.StdEncoding.EncodeToString([]byte("Hello Alice!")),
			"timestamp":           uint64(time.Now().UnixMilli()),
		}},
		"timestamp": uint64(time.Now().UnixMilli()),
		"urgent":    true,
	}
	resp = env.doAuthRequest(t, "PUT", "/v1/messages/"+uuidA, msgReq, uuidB, "passwordB")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// User A retrieves messages.
	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuidA, "passwordA")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var msgList map[string]any
	decodeJSON(t, resp, &msgList)
	msgs := msgList["messages"].([]any)
	assert.Len(t, msgs, 1)

	// Verify the message came from User B.
	firstMsg := msgs[0].(map[string]any)
	assert.Equal(t, uuidB, firstMsg["source"])

	// User A checks pre-key count. One EC pre-key was consumed when User B
	// fetched pre-keys, so 1 should remain out of the 2 uploaded.
	resp = env.doAuthRequest(t, "GET", "/v2/keys", nil, uuidA, "passwordA")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	// Decode into map[string]any to handle mixed int/bool fields in the response.
	var keyCount map[string]any
	decodeJSON(t, resp, &keyCount)
	assert.Equal(t, float64(1), keyCount["count"])

	// User A checks whoami.
	resp = env.doAuthRequest(t, "GET", "/v1/accounts/whoami", nil, uuidA, "passwordA")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var whoami map[string]any
	decodeJSON(t, resp, &whoami)
	assert.Equal(t, uuidA, whoami["uuid"])

	// User A deletes their account.
	resp = env.doAuthRequest(t, "DELETE", "/v1/accounts/me", nil, uuidA, "passwordA")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Verify User A is gone.
	resp = env.doRequest(t, "HEAD", "/v1/accounts/account/"+uuidA, nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

// TestE2E_VerificationThenRegistration exercises the verification flow followed
// by account registration.
func TestE2E_VerificationThenRegistration(t *testing.T) {
	env := setupTestEnv(t)

	// Step 1: Create verification session.
	verifyNumber := uniquePhoneNumber()
	reqBody := map[string]any{"number": verifyNumber, "transport": "sms"}
	resp := env.doRequest(t, "POST", "/v1/verification/session", reqBody, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var session map[string]any
	decodeJSON(t, resp, &session)
	sessionID := session["id"].(string)

	// Step 2: Request code.
	resp = env.doRequest(t, "POST", "/v1/verification/session/"+sessionID+"/code", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Step 3: Submit code.
	submitReq := map[string]any{"code": "123456"}
	resp = env.doRequest(t, "PUT", "/v1/verification/session/"+sessionID+"/code", submitReq, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	decodeJSON(t, resp, &session)
	require.True(t, session["verified"].(bool))

	// Step 4: Register with the verified number.
	uuid, _ := registerTestAccount(t, env, verifyNumber, "verifiedpass")
	assert.NotEmpty(t, uuid)

	// Verify the account exists.
	resp = env.doRequest(t, "HEAD", "/v1/accounts/account/"+uuid, nil, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

// TestE2E_BidirectionalMessaging tests that two users can exchange messages in
// both directions.
func TestE2E_BidirectionalMessaging(t *testing.T) {
	env := setupTestEnv(t)
	uuidA, _ := registerTestAccount(t, env, uniquePhoneNumber(), "passA")
	uuidB, _ := registerTestAccount(t, env, uniquePhoneNumber(), "passB")

	// A sends to B.
	msgReq := map[string]any{
		"messages": []map[string]any{{
			"type": 1, "destinationDeviceId": 1,
			"content":   base64.StdEncoding.EncodeToString([]byte("Hello B from A")),
			"timestamp": uint64(time.Now().UnixMilli()),
		}},
		"timestamp": uint64(time.Now().UnixMilli()),
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/messages/"+uuidB, msgReq, uuidA, "passA")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// B sends to A.
	msgReq["messages"] = []map[string]any{{
		"type": 1, "destinationDeviceId": 1,
		"content":   base64.StdEncoding.EncodeToString([]byte("Hello A from B")),
		"timestamp": uint64(time.Now().UnixMilli()),
	}}
	resp = env.doAuthRequest(t, "PUT", "/v1/messages/"+uuidA, msgReq, uuidB, "passB")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// A retrieves messages (should have 1 from B).
	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuidA, "passA")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listA map[string]any
	decodeJSON(t, resp, &listA)
	msgsA := listA["messages"].([]any)
	assert.Len(t, msgsA, 1)
	assert.Equal(t, uuidB, msgsA[0].(map[string]any)["source"])

	// B retrieves messages (should have 1 from A).
	resp = env.doAuthRequest(t, "GET", "/v1/messages", nil, uuidB, "passB")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listB map[string]any
	decodeJSON(t, resp, &listB)
	msgsB := listB["messages"].([]any)
	assert.Len(t, msgsB, 1)
	assert.Equal(t, uuidA, msgsB[0].(map[string]any)["source"])
}
