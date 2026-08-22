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

	// testCaptchaSolution carries the dotted provider.sitekey.action.token
	// layout the server's Checker requires. A bare string is rejected as
	// malformed, which exercises the error path rather than the real one.
	result := signalCLIExecAccount(t, number, "submitRateLimitChallenge",
		"--challenge", "test-challenge-token",
		"--captcha", testCaptchaSolution)
	t.Logf("submitRateLimitChallenge: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.Equal(t, 0, result.ExitCode,
		"submitRateLimitChallenge with a valid captcha should succeed: %s", result.Stderr)
}
