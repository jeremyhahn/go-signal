//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Devices
// Commands: listDevices, addDevice, removeDevice
// =============================================================================

func TestCLI_ListDevices(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "listDevices")
			t.Logf("listDevices exit=%d stdout=%s", result.ExitCode, result.Stdout)
		})
	}
}

func TestCLI_AddDevice(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			// addDevice requires a provisioning URI — exercise the help path
			result := execCLIAccount(t, bin, number, "addDevice")
			t.Logf("addDevice exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_RemoveDevice(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			// Try to remove a non-existent device — should fail gracefully
			result := execCLIAccount(t, bin, number, "removeDevice", "99")
			t.Logf("removeDevice exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}

// =============================================================================
// Configuration
// Commands: updateConfiguration
// =============================================================================

func TestCLI_UpdateConfiguration(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			result := execCLIAccount(t, bin, func() string {
				n := uniqueNumber()
				registerAndVerify(t, bin, n)
				return n
			}(), "updateConfiguration",
				"--read-receipts", "true",
				"--typing-indicators", "true",
			)
			assert.Equal(t, 0, result.ExitCode, "updateConfiguration should succeed")
		} else {
			// Our CLI doesn't have updateConfiguration yet — log only
			t.Log("updateConfiguration: not yet implemented in signal-go")
		}
	}
}
