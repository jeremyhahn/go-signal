//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPayments_GetAuth(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/payments/auth", nil, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	assert.NotEmpty(t, result["username"])
	assert.NotEmpty(t, result["password"])
}

func TestPayments_GetConversions(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/payments/conversions", nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	currencies, ok := result["currencies"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, currencies)
}
