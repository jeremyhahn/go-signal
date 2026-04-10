//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigV2_GetRemoteConfig(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	resp := env.doAuthRequest(t, "GET", "/v2/config", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)

	config, ok := result["config"].([]any)
	require.True(t, ok, "config should be an array")
	require.GreaterOrEqual(t, len(config), 6, "should have at least 6 config items")

	// Verify expected config item names are present.
	expectedNames := map[string]bool{
		"global.calling":    false,
		"global.groupsv2":   false,
		"global.storage":    false,
		"global.senderKey":  false,
		"global.stories":    false,
		"global.giftBadges": false,
	}

	for _, item := range config {
		entry, ok := item.(map[string]any)
		require.True(t, ok)
		name, ok := entry["name"].(string)
		require.True(t, ok)
		if _, exists := expectedNames[name]; exists {
			expectedNames[name] = true
			assert.Equal(t, true, entry["enabled"], "config item %s should be enabled", name)
			assert.Equal(t, "TRUE", entry["value"], "config item %s should have value TRUE", name)
		}
	}

	for name, found := range expectedNames {
		assert.True(t, found, "expected config item %s not found", name)
	}
}

func TestConfigV2_GetRemoteConfigWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v2/config", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
