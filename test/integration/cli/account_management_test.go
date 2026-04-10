//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Account Management (expanded)
// Commands: setPin, removePin, updateConfiguration,
//           startChangeNumber, finishChangeNumber,
//           submitRateLimitChallenge
// =============================================================================

func TestCLI_SetPin(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "setPin", "12345678")
			t.Logf("setPin exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}

func TestCLI_RemovePin(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "removePin")
			t.Logf("removePin exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}

func TestCLI_UpdateConfiguration_ReadReceipts(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number,
				"updateConfiguration", "--read-receipts", "true")
			assert.Equal(t, 0, result.ExitCode, "updateConfiguration should succeed")
		})
	}
}

func TestCLI_StartChangeNumber(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			newNumber := uniqueNumber()
			result := execCLIAccount(t, bin, number, "startChangeNumber", newNumber)
			t.Logf("startChangeNumber exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_FinishChangeNumber(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			newNumber := uniqueNumber()
			result := execCLIAccount(t, bin, number,
				"finishChangeNumber", newNumber,
				"--verification-code", "123456")
			t.Logf("finishChangeNumber exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_SubmitRateLimitChallenge(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number,
				"submitRateLimitChallenge",
				"--challenge", "test-token",
				"--captcha", "test-solution")
			t.Logf("submitRateLimitChallenge exit=%d", result.ExitCode)
		})
	}
}
