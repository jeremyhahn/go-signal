//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevices_ListDevices(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/devices", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var deviceList map[string]any
	decodeJSON(t, resp, &deviceList)
	devices, ok := deviceList["devices"].([]any)
	require.True(t, ok, "devices should be an array")
	assert.Len(t, devices, 1) // primary device only

	// Verify the primary device has ID 1.
	dev := devices[0].(map[string]any)
	assert.Equal(t, float64(1), dev["id"])
}

func TestDevices_ListDevicesWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v1/devices", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestDevices_DeviceHasTimestamps(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	resp := env.doAuthRequest(t, "GET", "/v1/devices", nil, uuid, "pass123")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var deviceList map[string]any
	decodeJSON(t, resp, &deviceList)
	devices := deviceList["devices"].([]any)
	dev := devices[0].(map[string]any)

	// Created and lastSeen should be positive Unix millisecond timestamps.
	created, ok := dev["created"].(float64)
	require.True(t, ok)
	assert.Greater(t, created, float64(0))

	lastSeen, ok := dev["lastSeen"].(float64)
	require.True(t, ok)
	assert.Greater(t, lastSeen, float64(0))
}
