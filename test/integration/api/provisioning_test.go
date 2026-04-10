//go:build integration

package api

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevices_GetProvisioningCode(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-prov-code"
	uuid, _ := registerTestAccount(t, env, number, password)

	resp := env.doAuthRequest(t, "GET", "/v1/devices/provisioning/code", nil, uuid, password)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	decodeJSON(t, resp, &result)
	assert.NotEmpty(t, result["verificationCode"])
}

func TestDevices_GetProvisioningCodeUnique(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-prov-uniq"
	uuid, _ := registerTestAccount(t, env, number, password)

	// Request two codes and ensure they are different.
	resp1 := env.doAuthRequest(t, "GET", "/v1/devices/provisioning/code", nil, uuid, password)
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	var result1 map[string]any
	decodeJSON(t, resp1, &result1)

	resp2 := env.doAuthRequest(t, "GET", "/v1/devices/provisioning/code", nil, uuid, password)
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var result2 map[string]any
	decodeJSON(t, resp2, &result2)

	assert.NotEqual(t, result1["verificationCode"], result2["verificationCode"])
}

func TestDevices_LinkDevice(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-link-dev"
	uuid, _ := registerTestAccount(t, env, number, password)

	// Get provisioning code.
	resp := env.doAuthRequest(t, "GET", "/v1/devices/provisioning/code", nil, uuid, password)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var codeResult map[string]any
	decodeJSON(t, resp, &codeResult)
	code := codeResult["verificationCode"].(string)

	// Link a new device.
	linkReq := map[string]any{
		"verificationCode": code,
		"accountAttributes": map[string]any{
			"fetchesMessages":   true,
			"registrationId":    9999,
			"pniRegistrationId": 8888,
			"name":              base64.StdEncoding.EncodeToString([]byte("Linked Device")),
			"capabilities":      map[string]bool{"storage": true},
		},
		"aciSignedPreKey":       testSignedPreKey(10),
		"pniSignedPreKey":       testSignedPreKey(11),
		"aciPqLastResortPreKey": testKEMPreKey(12),
		"pniPqLastResortPreKey": testKEMPreKey(13),
	}

	linkResp := env.doAuthRequest(t, "PUT", "/v1/devices/link", linkReq, uuid, password)
	require.Equal(t, http.StatusOK, linkResp.StatusCode)

	var linkResult map[string]any
	decodeJSON(t, linkResp, &linkResult)
	deviceId := linkResult["deviceId"].(float64)
	assert.Greater(t, deviceId, float64(1), "new device ID should be > 1")

	// Verify the device appears in the devices list.
	listResp := env.doAuthRequest(t, "GET", "/v1/devices", nil, uuid, password)
	require.Equal(t, http.StatusOK, listResp.StatusCode)

	var listResult map[string]any
	decodeJSON(t, listResp, &listResult)
	devices := listResult["devices"].([]any)
	assert.Len(t, devices, 2, "should have primary + linked device")
}

func TestDevices_LinkDeviceInvalidCode(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-link-invalid"
	uuid, _ := registerTestAccount(t, env, number, password)

	// Try to link with an invalid code.
	linkReq := map[string]any{
		"verificationCode": "invalid-code-12345",
		"accountAttributes": map[string]any{
			"fetchesMessages":   true,
			"registrationId":    9999,
			"pniRegistrationId": 8888,
			"name":              base64.StdEncoding.EncodeToString([]byte("Bad Device")),
			"capabilities":      map[string]bool{},
		},
		"aciSignedPreKey":       testSignedPreKey(10),
		"pniSignedPreKey":       testSignedPreKey(11),
		"aciPqLastResortPreKey": testKEMPreKey(12),
		"pniPqLastResortPreKey": testKEMPreKey(13),
	}

	linkResp := env.doAuthRequest(t, "PUT", "/v1/devices/link", linkReq, uuid, password)
	assert.Equal(t, http.StatusForbidden, linkResp.StatusCode)
	linkResp.Body.Close()
}

func TestDevices_SetCapabilities(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-caps"
	uuid, _ := registerTestAccount(t, env, number, password)

	capsReq := map[string]any{
		"capabilities": map[string]bool{
			"storage":  true,
			"transfer": true,
		},
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/devices/capabilities", capsReq, uuid, password)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestDevices_SetCapabilitiesEmpty(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-caps-empty"
	uuid, _ := registerTestAccount(t, env, number, password)

	capsReq := map[string]any{
		"capabilities": map[string]bool{},
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/devices/capabilities", capsReq, uuid, password)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestDevices_GetProvisioningCodeWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doRequest(t, "GET", "/v1/devices/provisioning/code", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestDevices_LinkDeviceWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	linkReq := map[string]any{
		"verificationCode": "some-code",
		"accountAttributes": map[string]any{
			"fetchesMessages": true,
			"registrationId":  1234,
		},
	}

	resp := env.doRequest(t, "PUT", "/v1/devices/link", linkReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestDevices_SetCapabilitiesWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	capsReq := map[string]any{
		"capabilities": map[string]bool{"storage": true},
	}

	resp := env.doRequest(t, "PUT", "/v1/devices/capabilities", capsReq, nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestDevices_SendProvisioningMessage(t *testing.T) {
	env := setupTestEnv(t)
	// The endpoint requires authentication; register an account to obtain credentials.
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	// Send a provisioning message to a destination (even if no WebSocket
	// session is listening, the endpoint should return 204).
	provMsg := map[string]any{
		"body": base64.StdEncoding.EncodeToString([]byte("provisioning-data")),
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/provisioning/some-destination-uuid", provMsg, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}

func TestDevices_SendProvisioningMessageEmptyBody(t *testing.T) {
	env := setupTestEnv(t)
	// The endpoint requires authentication; register an account to obtain credentials.
	uuid, _ := registerTestAccount(t, env, uniquePhoneNumber(), "pass123")

	provMsg := map[string]any{
		"body": "",
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/provisioning/another-destination", provMsg, uuid, "pass123")
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
}
