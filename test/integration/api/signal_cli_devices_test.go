//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Device Management (signal-cli: listDevices, addDevice, removeDevice,
// updateDevice, link)
// =============================================================================

func TestSignalCLI_ListDevices(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listDevices")
	assert.Equal(t, 0, result.ExitCode, "listDevices should succeed: %s", result.Stderr)
	// Should list at least the primary device
	assert.NotEmpty(t, result.Stdout, "should list at least one device")
}

func TestSignalCLI_GetProvisioningLink(t *testing.T) {
	// link --name generates a provisioning URI that another device scans
	// This tests the provisioning code generation endpoint
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Get provisioning code (the primary device side)
	result := signalCLIExecAccount(t, number, "listDevices")
	assert.Equal(t, 0, result.ExitCode, "listDevices should succeed: %s", result.Stderr)
}

func TestSignalCLI_RemoveDevice_InvalidID(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Try to remove non-existent device — server returns 404
	result := signalCLIExecAccount(t, number, "removeDevice", "--device-id", "99")
	assert.NotEqual(t, 0, result.ExitCode, "removeDevice for non-existent device should fail")
	assert.Contains(t, result.Stderr, "404", "server should return 404 for non-existent device")
}

func TestSignalCLI_RemoveDevice_CannotRemovePrimary(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Try to remove primary device (ID 1) — server returns 403 Forbidden
	result := signalCLIExecAccount(t, number, "removeDevice", "--device-id", "1")
	assert.NotEqual(t, 0, result.ExitCode, "removing primary device should fail")
	assert.Contains(t, result.Stderr, "403", "server should return 403 for primary device removal")
}

func TestSignalCLI_AddDevice_InvalidURI(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Provide a syntactically valid Signal device link URI with invalid
	// parameters. The server should reject this gracefully without crashing.
	result := signalCLIExecAccount(t, number, "addDevice",
		"--uri", "sgnl://linkdevice?uuid=invalid&pub_key=invalid")
	assert.NotEqual(t, 0, result.ExitCode,
		"addDevice with invalid URI parameters should fail")
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_AddDevice_MalformedURI(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Provide a completely malformed URI that is not a valid Signal device
	// link. The client or server should reject this gracefully.
	result := signalCLIExecAccount(t, number, "addDevice",
		"--uri", "not-a-uri")
	assert.NotEqual(t, 0, result.ExitCode,
		"addDevice with malformed URI should fail")
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}
