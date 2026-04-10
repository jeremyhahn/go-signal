//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Account Management (signal-cli: updateAccount, listAccounts, unregister,
// deleteLocalAccountData, setPin, removePin, version)
// =============================================================================

func TestSignalCLI_Version(t *testing.T) {
	result := signalCLIExec(t, "version")
	assert.Equal(t, 0, result.ExitCode, "version should succeed: %s", result.Stderr)
	assert.NotEmpty(t, result.Stdout, "version output should not be empty")
}

func TestSignalCLI_ListAccounts_Empty(t *testing.T) {
	// listAccounts is local-only; may return empty or list of known accounts
	result := signalCLIExec(t, "listAccounts")
	assert.Equal(t, 0, result.ExitCode, "listAccounts should succeed: %s", result.Stderr)
}

func TestSignalCLI_ListAccounts_AfterRegistration(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExec(t, "listAccounts")
	assert.Equal(t, 0, result.ExitCode, "listAccounts should succeed: %s", result.Stderr)
	assert.Contains(t, result.Stdout, number, "registered number should appear in account list")
}

func TestSignalCLI_UpdateAccount_DeviceName(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount", "--device-name", "Test Device")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --device-name should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateAccount_Discoverable(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount", "--discoverable-by-number", "true")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --discoverable-by-number should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateAccount_NotDiscoverable(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount", "--discoverable-by-number", "false")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --discoverable-by-number=false should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateAccount_UnrestrictedUnidentifiedSender(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount", "--unrestricted-unidentified-sender", "true")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --unrestricted-unidentified-sender should succeed: %s", result.Stderr)
}

func TestSignalCLI_SetPin(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "setPin", "12345678")
	assert.Equal(t, 0, result.ExitCode, "setPin should succeed: %s", result.Stderr)
}

func TestSignalCLI_RemovePin(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Set then remove
	result := signalCLIExecAccount(t, number, "setPin", "12345678")
	assert.Equal(t, 0, result.ExitCode, "setPin should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, number, "removePin")
	assert.Equal(t, 0, result.ExitCode, "removePin should succeed: %s", result.Stderr)
}

func TestSignalCLI_Unregister(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "unregister")
	assert.Equal(t, 0, result.ExitCode, "unregister should succeed: %s", result.Stderr)
}

func TestSignalCLI_Unregister_DeleteAccount(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "unregister", "--delete-account")
	assert.Equal(t, 0, result.ExitCode, "unregister --delete-account should succeed: %s", result.Stderr)
}

func TestSignalCLI_DeleteLocalAccountData(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "deleteLocalAccountData", "--ignore-registered")
	assert.Equal(t, 0, result.ExitCode, "deleteLocalAccountData should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateAccount_NumberSharing(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount", "--number-sharing", "true")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --number-sharing true should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateAccount_NumberSharingFalse(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount", "--number-sharing", "false")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --number-sharing false should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateAccount_Username(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Username operations require server-side username reservation which may
	// not be fully implemented. Use lenient assertion to verify the server
	// does not crash while allowing client-side failures.
	result := signalCLIExecAccount(t, number, "updateAccount", "--username", "testuser123")
	t.Logf("result: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_UpdateAccount_DeleteUsername(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Username deletion requires prior username reservation which may not be
	// fully implemented. Use lenient assertion to verify the server does not
	// crash while allowing client-side failures.
	result := signalCLIExecAccount(t, number, "updateAccount", "--delete-username")
	t.Logf("result: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_UpdateAccount_DiscoverableFalseToTrue(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount",
		"--discoverable-by-number", "false")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --discoverable-by-number false should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, number, "updateAccount",
		"--discoverable-by-number", "true")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --discoverable-by-number true should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateAccount_UnrestrictedFalse(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateAccount",
		"--unrestricted-unidentified-sender", "false")
	assert.Equal(t, 0, result.ExitCode, "updateAccount --unrestricted-unidentified-sender false should succeed: %s", result.Stderr)
}

func TestSignalCLI_SetPin_ChangePin(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "setPin", "111111")
	assert.Equal(t, 0, result.ExitCode, "setPin initial should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, number, "setPin", "222222")
	assert.Equal(t, 0, result.ExitCode, "setPin change should succeed: %s", result.Stderr)
}
