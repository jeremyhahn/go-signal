//go:build integration

package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccounts_SetRegistrationLock(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	req := map[string]any{
		"registrationLock": "123456",
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/registration_lock", req, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Verify via whoami that the account is still accessible.
	resp = env.doAuthRequest(t, "GET", "/v1/accounts/whoami", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_SetRegistrationLockEmptyPin(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	req := map[string]any{
		"registrationLock": "",
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/registration_lock", req, uuid, "pass123")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_RemoveRegistrationLock(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Set registration lock first.
	req := map[string]any{
		"registrationLock": "123456",
	}
	resp := env.doAuthRequest(t, "PUT", "/v1/accounts/registration_lock", req, uuid, "pass123")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Remove registration lock.
	resp = env.doAuthRequest(t, "DELETE", "/v1/accounts/registration_lock", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_RemoveRegistrationLockIdempotent(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Remove registration lock without setting one first (should still succeed).
	resp := env.doAuthRequest(t, "DELETE", "/v1/accounts/registration_lock", nil, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_SetPhoneNumberDiscoverability(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Set discoverable to true.
	req := map[string]any{
		"discoverableByPhoneNumber": true,
	}
	resp := env.doAuthRequest(t, "PUT", "/v2/accounts/phone_number_discoverability", req, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	// Set discoverable to false.
	req["discoverableByPhoneNumber"] = false
	resp = env.doAuthRequest(t, "PUT", "/v2/accounts/phone_number_discoverability", req, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_SetPhoneNumberDiscoverabilityToggle(t *testing.T) {
	env := setupTestEnv(t)
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Toggle discoverable true then false and verify data report reflects the change.
	req := map[string]any{"discoverableByPhoneNumber": true}
	resp := env.doAuthRequest(t, "PUT", "/v2/accounts/phone_number_discoverability", req, uuid, "pass123")
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()

	req["discoverableByPhoneNumber"] = false
	resp = env.doAuthRequest(t, "PUT", "/v2/accounts/phone_number_discoverability", req, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_GetDataReport(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	resp := env.doAuthRequest(t, "GET", "/v2/accounts/data_report", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var report map[string]any
	decodeJSON(t, resp, &report)
	assert.Equal(t, uuid, report["uuid"])
	assert.Equal(t, number, report["e164"])
	deviceIDs, ok := report["deviceIds"].([]any)
	require.True(t, ok)
	assert.Len(t, deviceIDs, 1)
	assert.Equal(t, float64(1), deviceIDs[0])
}

func TestAccounts_GetDataReportMultipleDevices(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	uuid, _ := registerTestAccount(t, env, number, "pass123")

	// The account should have one device by default.
	resp := env.doAuthRequest(t, "GET", "/v2/accounts/data_report", nil, uuid, "pass123")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var report map[string]any
	decodeJSON(t, resp, &report)
	assert.Equal(t, uuid, report["uuid"])
	deviceIDs, ok := report["deviceIds"].([]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(deviceIDs), 1)
}

func TestAccounts_SetRegistrationLockWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	req := map[string]any{
		"registrationLock": "123456",
	}
	resp := env.doRequest(t, "PUT", "/v1/accounts/registration_lock", req, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestAccounts_GetDataReportWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/v2/accounts/data_report", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}
