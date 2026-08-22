package build

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The security gate is here for the same reason the coverage gate is: it once
// passed while measuring less than it claimed. `make lint` and `make gosec`
// ran without build tags, so eight packages — every pkg/desktop/... package and
// the whole of pkg/fido2, the WebAuthn implementation — were analysed by
// neither, and both commands exited 0. A successful invocation says nothing
// about WHICH packages were analysed, which is exactly how the defect survived.
//
// These tests capture the argument vector each tool actually receives and then
// resolve it back to a package list, so a change to BUILD_TAGS, to the
// comma conversion, or to either tool's flag spelling fails here instead of
// silently re-opening the hole.

// shimTool writes a fake tool onto PATH-independent disk that records the
// arguments it was called with and exits 0. Passing it through the Makefile's
// own GOLINT/GOSEC variables means the recipe under test is the real one — only
// the binary at the end of it is replaced.
func shimTool(t *testing.T) (bin, argsFile string) {
	t.Helper()

	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "shim")

	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test fixture must be executable.
		t.Fatalf("write shim: %v", err)
	}
	return bin, argsFile
}

// runTarget runs a Make target with the given overrides and returns the
// arguments the shimmed tool received.
func runTarget(t *testing.T, target, toolVar string, extra ...string) []string {
	t.Helper()

	bin, argsFile := shimTool(t)
	args := append([]string{"--no-print-directory", target, toolVar + "=" + bin}, extra...)

	cmd := exec.Command("make", args...)
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make %s: %v\n%s", target, err, out)
	}

	raw, err := os.ReadFile(argsFile) //nolint:gosec // path is this test's own TempDir.
	if err != nil {
		t.Fatalf("the target never invoked the tool: %v", err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

// flagValue returns the value following flag in argv, or "" when absent.
// gosec and golangci-lint both take "-flag value" rather than "-flag=value"
// for the tag list, so the value is the next element.
func flagValue(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// packagesUnderTags asks the go tool which packages the given tag set selects,
// which is the property the whole gate depends on: a tag string that looks
// right but selects nothing is the original defect.
func packagesUnderTags(t *testing.T, tags string) string {
	t.Helper()

	cmd := exec.Command("go", "list", "-tags", tags, "./...")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -tags %q: %v\n%s", tags, err, out)
	}
	return string(out)
}

// TestLintTarget_AnalysesTheTaggedPackages is the regression test for the lint
// half. The assertion is not that a flag is present but that the flag's value
// selects the packages that were being skipped.
func TestLintTarget_AnalysesTheTaggedPackages(t *testing.T) {
	argv := runTarget(t, "lint", "GOLINT")

	tags := flagValue(argv, "--build-tags")
	if tags == "" {
		t.Fatalf("lint ran without --build-tags: %v", argv)
	}

	pkgs := packagesUnderTags(t, tags)
	for _, want := range []string{
		"github.com/jeremyhahn/go-signal/pkg/fido2",
		"github.com/jeremyhahn/go-signal/pkg/desktop/ws",
	} {
		if !strings.Contains(pkgs, want+"\n") {
			t.Errorf("lint's tag set %q does not select %s — the gate is back to skipping it", tags, want)
		}
	}
}

// TestGosecTarget_AnalysesTheTaggedPackages is the same for gosec, plus the
// separator. gosec wants COMMAS where the go tool wants spaces and does not
// reject the space form — it reads it as one undeclared tag and matches
// nothing, which looks identical to a clean run. Measured: the space form
// scanned the same 414 files as an untagged run, the comma form 445.
func TestGosecTarget_AnalysesTheTaggedPackages(t *testing.T) {
	argv := runTarget(t, "gosec", "GOSEC")

	tags := flagValue(argv, "-tags")
	if tags == "" {
		t.Fatalf("gosec ran without -tags: %v", argv)
	}
	if strings.Contains(tags, " ") {
		t.Fatalf("gosec's tag list %q is space-separated; gosec accepts it and matches nothing", tags)
	}
	if !strings.Contains(tags, ",") {
		t.Fatalf("gosec's tag list %q is not comma-separated: %v", tags, argv)
	}

	pkgs := packagesUnderTags(t, strings.ReplaceAll(tags, ",", " "))
	for _, want := range []string{
		"github.com/jeremyhahn/go-signal/pkg/fido2",
		"github.com/jeremyhahn/go-signal/pkg/desktop/ws",
	} {
		if !strings.Contains(pkgs, want+"\n") {
			t.Errorf("gosec's tag set %q does not select %s — the scan is back to skipping it", tags, want)
		}
	}
}

// The exclude list and the generated-code flag are part of what the gate means.
// CI used to restate them in YAML; they belong to the target now, so they are
// asserted here rather than trusted.
func TestGosecTarget_KeepsItsExclusionsAndSarifOptions(t *testing.T) {
	argv := runTarget(t, "gosec", "GOSEC")
	joined := strings.Join(argv, " ")

	for _, want := range []string{"-exclude=G103,G104,G115,G304,G118", "-exclude-generated"} {
		if !strings.Contains(joined, want) {
			t.Errorf("gosec lost %s: %v", want, argv)
		}
	}
	// Default form writes no file, so it must not ask for one.
	if strings.Contains(joined, "-out=") {
		t.Errorf("the default gosec invocation should not write a report: %v", argv)
	}

	// The SARIF form is what CI runs. -stdout and -verbose=text ride along with
	// it deliberately: the SARIF upload only happens on github.com, so without
	// them a Gitea failure exits 1 with its findings buried in a file nobody
	// reads.
	sarif := runTarget(t, "gosec", "GOSEC", "GOSEC_FMT=sarif", "GOSEC_OUT=gosec.sarif")
	joined = strings.Join(sarif, " ")
	for _, want := range []string{"-fmt=sarif", "-out=gosec.sarif", "-stdout", "-verbose=text"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the SARIF invocation lost %s: %v", want, sarif)
		}
	}
}

// TestGateTags_FollowTheFeatureFlags pins the tag set to its source. BUILD_TAGS
// is assembled from WITH_* switches, and both gates read it, so a switch that
// stops reaching them would narrow the gate without changing either recipe.
func TestGateTags_FollowTheFeatureFlags(t *testing.T) {
	cases := []struct {
		name   string
		flag   string
		absent string
	}{
		{"fido2 disabled", "WITH_FIDO2=0", "fido2"},
		{"desktop disabled", "WITH_DESKTOP=0", "desktop"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lint := flagValue(runTarget(t, "lint", "GOLINT", tc.flag), "--build-tags")
			if slices := strings.Fields(lint); contains(slices, tc.absent) {
				t.Errorf("lint tags %q still carry %q with %s", lint, tc.absent, tc.flag)
			}

			gosec := flagValue(runTarget(t, "gosec", "GOSEC", tc.flag), "-tags")
			if contains(strings.Split(gosec, ","), tc.absent) {
				t.Errorf("gosec tags %q still carry %q with %s", gosec, tc.absent, tc.flag)
			}
		})
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
