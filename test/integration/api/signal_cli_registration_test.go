//go:build integration

package api

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Account Registration & Verification (signal-cli: register, verify)
// =============================================================================

func TestSignalCLI_Register_SMS(t *testing.T) {
	number := signalCLIUniqueNumber()
	result := signalCLIExecAccount(t, number, "register")
	assert.Equal(t, 0, result.ExitCode, "register should succeed: %s", result.Stderr)
}

func TestSignalCLI_Register_Voice(t *testing.T) {
	number := signalCLIUniqueNumber()
	result := signalCLIExecAccount(t, number, "register", "--voice")
	assert.Equal(t, 0, result.ExitCode, "register --voice should succeed: %s", result.Stderr)
}

func TestSignalCLI_Register_WithCaptcha(t *testing.T) {
	number := signalCLIUniqueNumber()
	result := signalCLIExecAccount(t, number, "register", "--captcha", "test-captcha-token")
	assert.Equal(t, 0, result.ExitCode, "register --captcha should succeed: %s", result.Stderr)
}

func TestSignalCLI_Verify_ValidCode(t *testing.T) {
	number := signalCLIUniqueNumber()
	// Register first
	result := signalCLIExecAccount(t, number, "register")
	combined := result.Stdout + result.Stderr
	alreadyRegistered := strings.Contains(combined, "Account is already registered") ||
		strings.Contains(combined, "verify is not necessary") ||
		strings.Contains(combined, "Reregistered existing account")
	if !alreadyRegistered {
		require.Equal(t, 0, result.ExitCode, "register should succeed: %s", result.Stderr)
	}

	// Verify with code
	result = signalCLIExecAccount(t, number, "verify", "123456")
	// If already registered, verify may fail — that's OK.
	if !alreadyRegistered {
		assert.Equal(t, 0, result.ExitCode, "verify should succeed: %s", result.Stderr)
	} else {
		// Account already usable — verify is not needed but we still exercise the path.
		t.Logf("account already registered, verify exit=%d", result.ExitCode)
	}
}

func TestSignalCLI_Verify_WithPIN(t *testing.T) {
	number := signalCLIUniqueNumber()
	result := signalCLIExecAccount(t, number, "register")
	combined := result.Stdout + result.Stderr
	alreadyRegistered := strings.Contains(combined, "Account is already registered") ||
		strings.Contains(combined, "verify is not necessary") ||
		strings.Contains(combined, "Reregistered existing account")
	if !alreadyRegistered {
		require.Equal(t, 0, result.ExitCode, "register should succeed: %s", result.Stderr)
	}

	result = signalCLIExecAccount(t, number, "verify", "123456", "--pin", "12345678")
	if !alreadyRegistered {
		assert.Equal(t, 0, result.ExitCode, "verify --pin should succeed: %s", result.Stderr)
	} else {
		t.Logf("account already registered, verify exit=%d", result.ExitCode)
	}
}

func TestSignalCLI_Verify_InvalidCode(t *testing.T) {
	number := signalCLIUniqueNumber()
	result := signalCLIExecAccount(t, number, "register")
	combined := result.Stdout + result.Stderr
	alreadyRegistered := strings.Contains(combined, "Account is already registered") ||
		strings.Contains(combined, "verify is not necessary") ||
		strings.Contains(combined, "Reregistered existing account")
	if !alreadyRegistered {
		require.Equal(t, 0, result.ExitCode, "register should succeed: %s", result.Stderr)
	}

	// The server uses FixedCode "123456" in test mode. An incorrect code
	// (000000) must be rejected, confirming verification is actually enforced.
	result = signalCLIExecAccount(t, number, "verify", "000000")
	if !alreadyRegistered {
		assert.NotEqual(t, 0, result.ExitCode, "verify with wrong code should fail")
		assert.Contains(t, result.Stderr, "403",
			"verify with wrong code should return 403 Authorization failed")
	} else {
		t.Logf("account already registered, verify exit=%d", result.ExitCode)
	}
}

func TestSignalCLI_Register_Reregister(t *testing.T) {
	number := signalCLIUniqueNumber()
	// Register and verify first time
	signalCLIRegisterAndVerify(t, number)

	// Re-register same number
	result := signalCLIExecAccount(t, number, "register", "--reregister")
	assert.Equal(t, 0, result.ExitCode, "re-register should succeed: %s", result.Stderr)
}
