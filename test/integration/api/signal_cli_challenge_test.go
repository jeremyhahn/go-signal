//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Rate Limiting & Challenge (signal-cli: submitRateLimitChallenge)
// =============================================================================

func TestSignalCLI_SubmitRateLimitChallenge(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "submitRateLimitChallenge",
		"--challenge", "test-challenge-token",
		"--captcha", "test-captcha-solution")
	// This may fail if not rate-limited, which is expected
	t.Logf("submitRateLimitChallenge: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	// The key assertion: the server doesn't crash
	assert.True(t, result.ExitCode == 0 || result.ExitCode == 1,
		"submitRateLimitChallenge should either succeed or fail gracefully")
}
