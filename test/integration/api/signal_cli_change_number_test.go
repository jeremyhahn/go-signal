//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Number Change (signal-cli: startChangeNumber, finishChangeNumber)
// =============================================================================

func TestSignalCLI_StartChangeNumber(t *testing.T) {
	oldNumber := signalCLIUniqueNumber()
	newNumber := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, oldNumber)

	result := signalCLIExecAccount(t, oldNumber, "startChangeNumber", newNumber)
	assert.Equal(t, 0, result.ExitCode, "startChangeNumber should succeed: %s", result.Stderr)
}

func TestSignalCLI_StartChangeNumber_Voice(t *testing.T) {
	oldNumber := signalCLIUniqueNumber()
	newNumber := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, oldNumber)

	result := signalCLIExecAccount(t, oldNumber, "startChangeNumber", "--voice", newNumber)
	assert.Equal(t, 0, result.ExitCode, "startChangeNumber --voice should succeed: %s", result.Stderr)
}

func TestSignalCLI_FinishChangeNumber(t *testing.T) {
	oldNumber := signalCLIUniqueNumber()
	newNumber := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, oldNumber)

	result := signalCLIExecAccount(t, oldNumber, "startChangeNumber", newNumber)
	require.Equal(t, 0, result.ExitCode, "startChangeNumber should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, oldNumber, "finishChangeNumber",
		"--verification-code", "123456",
		newNumber)
	assert.Equal(t, 0, result.ExitCode, "finishChangeNumber should succeed: %s", result.Stderr)
}
