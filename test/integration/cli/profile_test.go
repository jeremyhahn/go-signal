//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Profiles
// Commands: updateProfile, getUserStatus
// =============================================================================

func TestCLI_UpdateProfile(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number,
				"updateProfile",
				"--given-name", "Test",
				"--family-name", "User",
				"--about", "Integration test",
			)
			t.Logf("updateProfile exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}

// TestCLI_GetUserStatus asserts what each CLI ACTUALLY does today, which is
// not the same thing for the two of them.
//
// It previously asserted ExitCode == 0 for BOTH binaries. That is right for the
// Go CLI and impossible for Java signal-cli, which reaches getUserStatus
// through CDSI — and this server has no /cdsi route (#23, task:blocked, an
// owner decision outstanding). So the signal-cli subtest could not pass, and it
// had been failing on main since 2026-08-22, taking the whole Integration suite
// red with it (#64). A week of red trunk was one subtest asserting an unbuilt
// feature.
//
// The sibling test in test/integration/api already asserted the documented
// behaviour for the same gap; the two suites simply disagreed about the same
// known state.
func TestCLI_GetUserStatus(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			other := uniqueNumber()
			registerAndVerify(t, withName(bin, "other"), other)

			result := execCLIAccount(t, bin, number, "getUserStatus", other)

			// The two binaries reach this command by different routes and are
			// asserted separately. Collapsing them into one expectation is
			// what made this test wrong in both directions: it asserted
			// success for the Java client, which cannot have it, and would
			// have asserted failure for the Go client, which already passes.
			switch bin.Kind {
			case KindSignalGo:
				// The Go CLI does not use CDSI at all: getUserStatus resolves
				// each number through GetProfile (cmd/signal/cmd/profile.go),
				// which this server implements. Recorded behaviour is exit 0
				// with {"registered":true}.
				assert.Equal(t, 0, result.ExitCode,
					"the Go CLI resolves getUserStatus through GetProfile and should succeed: %s",
					result.Stderr)

			case KindSignalCLI:
				// Java signal-cli goes through CDSI, and this server has no
				// /cdsi route from the client to the CDSI service — a known
				// architectural gap with an owner decision outstanding (#23,
				// task:blocked), not something this suite can fix.
				//
				// WHEN #23 LANDS THIS FAILS, deliberately: a working route
				// makes the command exit 0. Pinning current behaviour is only
				// safe if the pin breaks when the behaviour is fixed, or it
				// outlives the bug it documents and starts defending it.
				assert.Equal(t, 3, result.ExitCode,
					"signal-cli getUserStatus should fail with CDSI not implemented (#23); "+
						"exit 0 means /cdsi now works and this test needs updating: %s", result.Stderr)
				// Both of the next two are needed. signal-cli wraps ANY
				// IOException from the lookup in the same sentence, so on its
				// own that substring would also be satisfied by a dead server
				// or a TLS failure. The 404 is what identifies the cause as a
				// route that is not there.
				assert.Contains(t, result.Stderr, "Unable to check if users are registered",
					"expected the user-status lookup to fail, got something else: %s", result.Stderr)
				assert.Contains(t, result.Stderr, "404",
					"expected a 404 from the missing /cdsi route; a different I/O failure "+
						"satisfies the message above but is not what this test pins: %s", result.Stderr)
			}
		})
	}
}
