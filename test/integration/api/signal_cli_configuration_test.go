//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Configuration (signal-cli: updateConfiguration)
// =============================================================================

func TestSignalCLI_UpdateConfiguration_ReadReceipts(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--read-receipts", "true")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --read-receipts should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_TypingIndicators(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--typing-indicators", "true")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --typing-indicators should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_LinkPreviews(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--link-previews", "true")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --link-previews should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_All(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--read-receipts", "true",
		"--typing-indicators", "false",
		"--link-previews", "true",
		"--unidentified-delivery-indicators", "true")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration all flags should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_ReadReceiptsFalse(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--read-receipts", "false")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --read-receipts false should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_TypingIndicatorsFalse(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--typing-indicators", "false")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --typing-indicators false should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_LinkPreviewsFalse(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--link-previews", "false")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --link-previews false should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_UnidentifiedDeliveryOnly(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--unidentified-delivery-indicators", "false")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --unidentified-delivery-indicators false should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_ToggleReadReceipts(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--read-receipts", "true")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --read-receipts true should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, number, "updateConfiguration",
		"--read-receipts", "false")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --read-receipts false should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateConfiguration_UnidentifiedDeliveryTrue(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "updateConfiguration",
		"--unidentified-delivery-indicators", "true")
	assert.Equal(t, 0, result.ExitCode, "updateConfiguration --unidentified-delivery-indicators true should succeed: %s", result.Stderr)
}
