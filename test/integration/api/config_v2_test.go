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

	// The canonical Java RemoteConfigurationResponse is
	// `Map<String, String> config` — a name→value object, NOT an array.
	config, ok := result["config"].(map[string]any)
	require.True(t, ok, "config should be a JSON object (name→value map)")
	require.GreaterOrEqual(t, len(config), 6, "should have at least 6 config items")

	// The test environment seeds these global flags at 100%, so every
	// account receives the value "TRUE".
	expectedNames := []string{
		"global.calling",
		"global.groupsv2",
		"global.storage",
		"global.senderKey",
		"global.stories",
		"global.giftBadges",
	}
	for _, name := range expectedNames {
		value, present := config[name]
		assert.True(t, present, "expected config item %s not found", name)
		assert.Equal(t, "TRUE", value, "config item %s should have value TRUE", name)
	}
}

func TestConfigV2_GetRemoteConfigWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v2/config", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
