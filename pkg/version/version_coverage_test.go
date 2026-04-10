package version

import "testing"

// --------------------------------------------------------------------------
// parse – uncovered branches: negative minor, negative patch
// --------------------------------------------------------------------------

// TestParse_NegativeMinorReturnsFalse verifies that a version string with a
// negative minor component is rejected. This exercises the "minor < 0" guard
// inside parse that was not previously reached.
func TestParse_NegativeMinorReturnsFalse(t *testing.T) {
	cases := []string{
		"1.-1.0",
		"2.-5.3",
	}
	for _, v := range cases {
		if IsValid(v) {
			t.Errorf("IsValid(%q) = true; expected false for negative minor", v)
		}
	}
}

// TestParse_NegativePatchReturnsFalse verifies that a version string with a
// negative patch component is rejected, exercising the "patch < 0" guard.
func TestParse_NegativePatchReturnsFalse(t *testing.T) {
	cases := []string{
		"1.0.-1",
		"3.2.-99",
	}
	for _, v := range cases {
		if IsValid(v) {
			t.Errorf("IsValid(%q) = true; expected false for negative patch", v)
		}
	}
}

// --------------------------------------------------------------------------
// Compare – minor and patch comparison branches
// --------------------------------------------------------------------------

// TestCompare_MinorLessThan covers the branch where major components are equal
// and va.minor < vb.minor returns -1.
func TestCompare_MinorLessThan(t *testing.T) {
	got := Compare("1.0.0", "1.1.0")
	if got != -1 {
		t.Errorf("Compare(\"1.0.0\", \"1.1.0\") = %d, want -1", got)
	}
}

// TestCompare_MinorGreaterThan covers the branch where major is equal and
// va.minor > vb.minor returns +1.
func TestCompare_MinorGreaterThan(t *testing.T) {
	got := Compare("1.2.0", "1.1.0")
	if got != 1 {
		t.Errorf("Compare(\"1.2.0\", \"1.1.0\") = %d, want 1", got)
	}
}

// TestCompare_PatchLessThan covers the branch where major and minor are equal
// and va.patch < vb.patch returns -1.
func TestCompare_PatchLessThan(t *testing.T) {
	got := Compare("1.1.0", "1.1.1")
	if got != -1 {
		t.Errorf("Compare(\"1.1.0\", \"1.1.1\") = %d, want -1", got)
	}
}

// TestCompare_PatchGreaterThan covers the branch where major and minor are
// equal and va.patch > vb.patch returns +1.
func TestCompare_PatchGreaterThan(t *testing.T) {
	got := Compare("1.1.2", "1.1.1")
	if got != 1 {
		t.Errorf("Compare(\"1.1.2\", \"1.1.1\") = %d, want 1", got)
	}
}

// TestCompare_AllComponentsEqual covers the final return 0 in Compare when
// major, minor, and patch are all identical.
func TestCompare_AllComponentsEqual(t *testing.T) {
	got := Compare("2.3.4", "2.3.4")
	if got != 0 {
		t.Errorf("Compare(\"2.3.4\", \"2.3.4\") = %d, want 0", got)
	}
}

// TestCompare_MajorGreaterThan covers the va.major > vb.major → +1 branch
// inside the Compare major-comparison block.
func TestCompare_MajorGreaterThan(t *testing.T) {
	got := Compare("3.0.0", "2.0.0")
	if got != 1 {
		t.Errorf("Compare(\"3.0.0\", \"2.0.0\") = %d, want 1", got)
	}
}

// TestCompare_PreReleaseSuffix verifies that pre-release suffixes in the patch
// field are stripped before comparison, exercising the patch suffix strip path
// inside parse when called from Compare.
func TestCompare_PreReleaseSuffix(t *testing.T) {
	// "5.0.0-beta" strips to 5.0.0, which equals "5.0.0".
	got := Compare("5.0.0-beta", "5.0.0")
	if got != 0 {
		t.Errorf("Compare(\"5.0.0-beta\", \"5.0.0\") = %d, want 0", got)
	}
}

// TestCompare_BuildMetadataSuffix verifies that build-metadata suffixes (+) are
// also stripped, exercising the '+' branch of the IndexAny check in parse.
func TestCompare_BuildMetadataSuffix(t *testing.T) {
	got := Compare("1.2.3+build.1", "1.2.3")
	if got != 0 {
		t.Errorf("Compare(\"1.2.3+build.1\", \"1.2.3\") = %d, want 0", got)
	}
}

// --------------------------------------------------------------------------
// IsValid – additional edge cases for parse coverage
// --------------------------------------------------------------------------

// TestIsValid_FourPartVersionIsValid verifies that a four-part version string
// is accepted (extra components are ignored by SplitN with n=4).
func TestIsValid_FourPartVersionIsValid(t *testing.T) {
	if !IsValid("1.2.3.4") {
		t.Error("IsValid(\"1.2.3.4\") should return true (extra component ignored)")
	}
}

// TestIsValid_NegativeMajorReturnsFalse exercises the "major < 0" guard in
// parse, which is distinct from the Atoi error path.
func TestIsValid_NegativeMajorReturnsFalse(t *testing.T) {
	if IsValid("-1.0.0") {
		t.Error("IsValid(\"-1.0.0\") should return false")
	}
}
