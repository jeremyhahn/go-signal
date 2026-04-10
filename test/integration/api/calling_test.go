//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalling_GetRelays(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v2/calling/relays", nil, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	relays, ok := result["relays"].([]any)
	require.True(t, ok)
	assert.NotEmpty(t, relays)
}

func TestCalling_GetCallLinkAuth(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	// Create a valid CreateCallLinkCredentialRequest using the zkgroup API.
	var requestRandomness zkgroup.RandomnessBytes
	for i := range requestRandomness {
		requestRandomness[i] = byte(i)
	}
	roomID := []byte("test-room-id-123")
	reqCtx, err := zkgroup.NewCreateCallLinkCredentialRequestContext(roomID, requestRandomness)
	require.NoError(t, err)

	request := reqCtx.GetRequest()
	serialized := zkgroup.SerializeCreateCallLinkCredentialRequest(request)

	body := calling.CreateCallLinkCredentialRequest{
		CreateCallLinkCredentialRequest: serialized,
	}

	resp := env.doAuthRequest(t, "POST", "/v1/call-link/create-auth", body, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	assert.NotEmpty(t, result["credential"])
	assert.NotZero(t, result["redemptionTime"])
}

func TestCalling_GetCallLinkAuth_WithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "POST", "/v1/call-link/create-auth", nil, nil)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestCalling_GetCallLinkAuth_EmptyBody(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "POST", "/v1/call-link/create-auth", nil, uuid, "pass123")
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}
