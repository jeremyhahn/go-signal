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

// runBoundary separates one invocation's arguments from the next in the shim's
// log. It cannot be "--": golangci-lint's own flags are --timeout and
// --build-tags, so splitting on that would tear an argument list in half and
// then report the pieces as extra invocations. Measured — it did.
const runBoundary = "===end-of-invocation==="

// shimTool writes a fake tool onto PATH-independent disk that records the
// arguments it was called with and exits 0. Passing it through the Makefile's
// own GOLINT/GOSEC variables means the recipe under test is the real one — only
// the binary at the end of it is replaced.
func shimTool(t *testing.T) (bin, argsFile string) {
	t.Helper()

	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "shim")

	// Appends, with a separator, because a target may invoke its tool more
	// than once: `lint` runs a second pass for the integration tag. Overwriting
	// would silently report only the last invocation and let the first go
	// unchecked — the same masked measurement these tests exist to prevent.
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + argsFile + "\necho '" + runBoundary + "' >> " + argsFile + "\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // an executable test fixture must be executable.
		t.Fatalf("write shim: %v", err)
	}
	return bin, argsFile
}

// runTarget runs a Make target with the given overrides and returns the
// arguments of EVERY invocation the shimmed tool received, in order.
func runTarget(t *testing.T, target, toolVar string, extra ...string) [][]string {
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

	var runs [][]string
	for _, block := range strings.Split(strings.TrimRight(string(raw), "\n"), runBoundary) {
		if argv := strings.Split(strings.Trim(block, "\n"), "\n"); len(argv) > 0 && argv[0] != "" {
			runs = append(runs, argv)
		}
	}
	if len(runs) == 0 {
		t.Fatalf("the target never invoked the tool")
	}
	return runs
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
	runs := runTarget(t, "lint", "GOLINT")
	if len(runs) != 2 {
		t.Fatalf("lint made %d invocations, want 2 (repo tags, then integration): %v", len(runs), runs)
	}

	// EVERY pass has to carry tags. Checking only the last would let the first
	// silently go back to analysing nothing.
	sawIntegration := false
	for i, argv := range runs {
		tags := flagValue(argv, "--build-tags")
		if tags == "" {
			t.Fatalf("lint pass %d ran without --build-tags: %v", i+1, argv)
		}
		if contains(strings.Fields(tags), "integration") {
			sawIntegration = true
		}

		pkgs := packagesUnderTags(t, tags)
		for _, want := range []string{
			"github.com/jeremyhahn/go-signal/pkg/fido2",
			"github.com/jeremyhahn/go-signal/pkg/desktop/ws",
		} {
			if !strings.Contains(pkgs, want+"\n") {
				t.Errorf("lint pass %d tag set %q does not select %s — the gate is back to skipping it", i+1, tags, want)
			}
		}
	}
	if !sawIntegration {
		t.Error("no lint pass carries the integration tag: test/integration is unlinted again")
	}
}

// TestGosecTarget_AnalysesTheTaggedPackages is the same for gosec, plus the
// separator. gosec wants COMMAS where the go tool wants spaces and does not
// reject the space form — it reads it as one undeclared tag and matches
// nothing, which looks identical to a clean run. Measured: the space form
// scanned the same 414 files as an untagged run, the comma form 445.
func TestGosecTarget_AnalysesTheTaggedPackages(t *testing.T) {
	runs := runTarget(t, "gosec", "GOSEC")
	if len(runs) != 2 {
		t.Fatalf("gosec made %d invocations, want 2 (repo tags, then integration): %v", len(runs), runs)
	}

	sawIntegration := false
	for i, argv := range runs {
		tags := flagValue(argv, "-tags")
		if tags == "" {
			t.Fatalf("gosec pass %d ran without -tags: %v", i+1, argv)
		}
		// gosec wants COMMAS where the go tool wants spaces, and it does not
		// reject the space form — it reads it as one undeclared tag and matches
		// nothing, which looks identical to a clean run.
		if strings.Contains(tags, " ") {
			t.Fatalf("gosec pass %d tag list %q is space-separated; gosec accepts it and matches nothing", i+1, tags)
		}
		if !strings.Contains(tags, ",") {
			t.Fatalf("gosec pass %d tag list %q is not comma-separated: %v", i+1, tags, argv)
		}
		if contains(strings.Split(tags, ","), "integration") {
			sawIntegration = true
		}

		pkgs := packagesUnderTags(t, strings.ReplaceAll(tags, ",", " "))
		for _, want := range []string{
			"github.com/jeremyhahn/go-signal/pkg/fido2",
			"github.com/jeremyhahn/go-signal/pkg/desktop/ws",
		} {
			if !strings.Contains(pkgs, want+"\n") {
				t.Errorf("gosec pass %d tag set %q does not select %s — the scan is back to skipping it", i+1, tags, want)
			}
		}
	}
	if !sawIntegration {
		t.Error("no gosec pass carries the integration tag: test/integration is unscanned again")
	}
}

// The exclude list and the generated-code flag are part of what the gate means.
// CI used to restate them in YAML; they belong to the target now, so they are
// asserted here rather than trusted.
func TestGosecTarget_KeepsItsExclusionsAndSarifOptions(t *testing.T) {
	runs := runTarget(t, "gosec", "GOSEC")

	// Every pass carries the exclusions, or one of them gates on a different
	// rule set than the other and the difference is invisible.
	for i, argv := range runs {
		joined := strings.Join(argv, " ")
		for _, want := range []string{"-exclude=G103,G104,G115,G304,G118", "-exclude-generated"} {
			if !strings.Contains(joined, want) {
				t.Errorf("gosec pass %d lost %s: %v", i+1, want, argv)
			}
		}
		if strings.Contains(joined, "-out=") {
			t.Errorf("the default gosec invocation should not write a report: %v", argv)
		}
	}

	// The SARIF form is what CI runs. -stdout and -verbose=text ride along with
	// it deliberately: the SARIF upload only happens on github.com, so without
	// them a Gitea failure exits 1 with its findings buried in a file nobody
	// reads.
	sarif := runTarget(t, "gosec", "GOSEC", "GOSEC_FMT=sarif", "GOSEC_OUT=gosec.sarif")
	joined := strings.Join(sarif[0], " ")
	for _, want := range []string{"-fmt=sarif", "-out=gosec.sarif", "-stdout", "-verbose=text"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the SARIF invocation lost %s: %v", want, sarif[0])
		}
	}

	// And ONLY the first pass writes it. gosec truncates its output file, so a
	// second pass writing the same path would overwrite the first pass's
	// findings — the upload would carry half the scan and still report success.
	for i, argv := range sarif[1:] {
		if strings.Contains(strings.Join(argv, " "), "-out=") {
			t.Errorf("gosec pass %d also writes the report; it would overwrite the first pass's findings: %v", i+2, argv)
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
			for i, argv := range runTarget(t, "lint", "GOLINT", tc.flag) {
				lint := flagValue(argv, "--build-tags")
				if contains(strings.Fields(lint), tc.absent) {
					t.Errorf("lint pass %d tags %q still carry %q with %s", i+1, lint, tc.absent, tc.flag)
				}
			}

			for i, argv := range runTarget(t, "gosec", "GOSEC", tc.flag) {
				gosec := flagValue(argv, "-tags")
				if contains(strings.Split(gosec, ","), tc.absent) {
					t.Errorf("gosec pass %d tags %q still carry %q with %s", i+1, gosec, tc.absent, tc.flag)
				}
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
