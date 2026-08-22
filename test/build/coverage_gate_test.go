// Package build holds tests for the build system itself — targets whose
// failure modes are invisible to Go tests because they live in the Makefile.
//
// The coverage gate is here because it once passed when it could not measure
// coverage: `bc` handed an empty percentage emitted a syntax error, `|| echo
// 0` substituted 0, and the comparison was false. CI ran that target on every
// push and reported success while enforcing nothing. Manual verification does
// not stop that returning, which is why these cases are executable.
package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is two levels up from test/build.
const repoRoot = "../.."

// runGate invokes the coverage-gate target and reports whether it passed.
func runGate(t *testing.T, profile, coverMin string) (bool, string) {
	t.Helper()
	cmd := exec.Command("make", "--no-print-directory", "coverage-gate",
		"COVERAGE_PROFILE="+profile, "COVER_MIN="+coverMin)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

// writeProfile writes a fixture profile and returns its path.
func writeProfile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// realProfile generates a genuine profile by covering one small package, so
// the passing and below-threshold cases exercise the same extraction path
// production uses rather than a hand-written approximation.
func realProfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "real.out")
	cmd := exec.Command("go", "test", "-count=1",
		"-coverprofile="+path, "-covermode=atomic", "./pkg/captcha/...")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate coverage profile: %v\n%s", err, out)
	}
	return path
}

func TestCoverageGate_FailsClosedOnUnmeasurableCoverage(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.out")

	cases := map[string]string{
		"missing profile":   missing,
		"empty profile":     writeProfile(t, "empty.out", ""),
		"malformed profile": writeProfile(t, "bad.out", "this is not a coverage profile\n"),
	}
	for name, profile := range cases {
		t.Run(name, func(t *testing.T) {
			passed, out := runGate(t, profile, "90")
			if passed {
				t.Errorf("the gate PASSED with no measurable coverage — this is the fail-open:\n%s", out)
			}
		})
	}
}

// A header-only profile is measurable and reports 0.0%. It must fail on the
// threshold, not on extraction: "no coverage" and "no measurement" are
// different facts and the messages should say so.
func TestCoverageGate_HeaderOnlyProfileIsZeroNotUnmeasurable(t *testing.T) {
	profile := writeProfile(t, "hdr.out", "mode: atomic\n")

	passed, out := runGate(t, profile, "90")
	if passed {
		t.Fatalf("0.0%% coverage passed a 90%% gate:\n%s", out)
	}
	if !strings.Contains(out, "is below minimum") {
		t.Errorf("expected a threshold failure, got:\n%s", out)
	}
}

func TestCoverageGate_RealProfile(t *testing.T) {
	profile := realProfile(t)

	t.Run("above minimum passes", func(t *testing.T) {
		if passed, out := runGate(t, profile, "1"); !passed {
			t.Errorf("a real profile failed a 1%% gate:\n%s", out)
		}
	})
	t.Run("below minimum fails", func(t *testing.T) {
		if passed, out := runGate(t, profile, "100"); passed {
			t.Errorf("a real profile passed a 100%% gate:\n%s", out)
		}
	})
}

// COVER_MIN is command-line overridable, and awk coerces a non-numeric
// threshold to 0 — which passes everything. Validating only the measured
// percentage leaves the same fail-open reachable from the other operand.
func TestCoverageGate_FailsClosedOnMalformedThreshold(t *testing.T) {
	profile := realProfile(t)

	// "." is the case a character-class check misses: every character is
	// legal, so it passes validation and then coerces to 0, waving every run
	// through. The others cover empty, non-numeric, trailing-garbage,
	// out-of-range and malformed-decimal input.
	for _, coverMin := range []string{"", "garbage", "90junk", "-1", "101", "9.0.1", ".", "..", ".5", "90."} {
		t.Run("COVER_MIN="+coverMin, func(t *testing.T) {
			passed, out := runGate(t, profile, coverMin)
			if passed {
				t.Errorf("the gate PASSED with threshold %q — a malformed threshold disables enforcement:\n%s",
					coverMin, out)
			}
		})
	}
}
