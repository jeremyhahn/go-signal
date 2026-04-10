//go:build integration

package api

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Profiles (signal-cli: updateProfile, getUserStatus)
// =============================================================================

func TestSignalCLI_UpdateProfile_Name(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateProfile",
		"--given-name", "Alice",
		"--family-name", "Smith")
	assert.Equal(t, 0, result.ExitCode, "updateProfile name should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateProfile_About(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateProfile",
		"--given-name", "Bob",
		"--about", "Hello world",
		"--about-emoji", "👋")
	assert.Equal(t, 0, result.ExitCode, "updateProfile about should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateProfile_Avatar(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	tmpFile := t.TempDir() + "/avatar.png"
	require.NoError(t, writeTestFile(tmpFile, "fake-png-data"))

	// Avatar upload goes through the profile endpoint (PUT /v1/profile with
	// avatar:true) which returns S3 POST policy upload attributes. signal-cli
	// then uploads the avatar to the CDN endpoint.
	result := signalCLIExecAccount(t, number, "updateProfile",
		"--given-name", "Charlie",
		"--avatar", tmpFile)
	assert.Equal(t, 0, result.ExitCode, "updateProfile avatar should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateProfile_RemoveAvatar(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateProfile",
		"--given-name", "Dave",
		"--remove-avatar")
	assert.Equal(t, 0, result.ExitCode, "updateProfile --remove-avatar should succeed: %s", result.Stderr)
}

func TestSignalCLI_GetUserStatus_RegisteredUser(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// getUserStatus uses the CDSI (Contact Discovery Service Interface) Noise
	// protocol with SGX enclave attestation. This protocol is not implemented
	// in the Go server. signal-cli exits with code 3 and reports
	// "Unable to check if users are registered: NetworkProtocolException".
	result := signalCLIExecAccount(t, numberA, "getUserStatus", numberB)
	assert.Equal(t, 3, result.ExitCode, "getUserStatus should fail with CDSI not implemented: %s", result.Stderr)
	assert.Contains(t, result.Stderr, "Unable to check if users are registered",
		"getUserStatus error should mention CDSI failure")
}

func TestSignalCLI_GetUserStatus_UnregisteredUser(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	unregistered := "+15559999999"
	// CDSI is not implemented; signal-cli exits with code 3.
	result := signalCLIExecAccount(t, number, "getUserStatus", unregistered)
	assert.Equal(t, 3, result.ExitCode, "getUserStatus should fail with CDSI not implemented: %s", result.Stderr)
	assert.Contains(t, result.Stderr, "Unable to check if users are registered",
		"getUserStatus error should mention CDSI failure")
}

func TestSignalCLI_UpdateProfile_MobileCoinAddress(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	mobileCoinAddr := base64.StdEncoding.EncodeToString([]byte("test-mobilecoin-address"))

	result := signalCLIExecAccount(t, number, "updateProfile",
		"--given-name", "Test",
		"--mobile-coin-address", mobileCoinAddr)
	assert.Equal(t, 0, result.ExitCode,
		"updateProfile with --mobile-coin-address should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateProfile_AllFields(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateProfile",
		"--given-name", "Integration",
		"--family-name", "Tester",
		"--about", "Running all-fields profile update test",
		"--about-emoji", "🧪")
	assert.Equal(t, 0, result.ExitCode,
		"updateProfile with all fields should succeed: %s", result.Stderr)
}

func TestSignalCLI_GetUserStatus_MultipleNumbers(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	unregistered := "+15558880000"

	// Query status for both a registered and an unregistered number.
	// CDSI is not implemented; signal-cli exits with code 3.
	result := signalCLIExecAccount(t, numberA, "getUserStatus", numberB, unregistered)
	assert.Equal(t, 3, result.ExitCode,
		"getUserStatus with multiple numbers should fail with CDSI not implemented: %s", result.Stderr)
	assert.Contains(t, result.Stderr, "Unable to check if users are registered",
		"getUserStatus error should mention CDSI failure")
}
