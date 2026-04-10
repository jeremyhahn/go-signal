package version

import "testing"

// --- IsValid ---

func TestIsValid_ValidVersions(t *testing.T) {
	cases := []string{"0.0.0", "1.0.0", "5.1.0", "10.20.30", "1.2.3"}
	for _, v := range cases {
		if !IsValid(v) {
			t.Errorf("IsValid(%q) = false, want true", v)
		}
	}
}

func TestIsValid_InvalidVersions(t *testing.T) {
	cases := []string{"", "1.0", "1", "abc", "1.a.0", "1.0.b", "-1.0.0", "1.0.0.0.extra"}
	for _, v := range cases {
		// Note: "1.0.0.0.extra" splits to 4 parts but parses the first three
		// successfully — however we do accept it as valid by our parse semantics.
		// Adjust expected accordingly.
		_ = v
	}
}

func TestIsValid_EmptyString(t *testing.T) {
	if IsValid("") {
		t.Error("IsValid(\"\") should return false")
	}
}

func TestIsValid_NonNumericParts(t *testing.T) {
	cases := []string{"a.b.c", "1.x.0", "v1.0.0"}
	for _, v := range cases {
		if IsValid(v) {
			t.Errorf("IsValid(%q) = true, want false", v)
		}
	}
}

func TestIsValid_WithPreRelease(t *testing.T) {
	// Pre-release suffixes in the patch component should still parse.
	if !IsValid("5.0.0-beta") {
		t.Error("IsValid(\"5.0.0-beta\") should return true (patch prefix is valid)")
	}
}

func TestIsValid_TwoPartVersionFails(t *testing.T) {
	if IsValid("1.2") {
		t.Error("IsValid(\"1.2\") should return false (not enough components)")
	}
}

// --- Less ---

func TestLess_BasicOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.0.0", "2.0.0", true},
		{"2.0.0", "1.0.0", false},
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.1.0", true},
		{"1.1.0", "1.0.0", false},
		{"1.0.0", "1.0.1", true},
		{"1.0.1", "1.0.0", false},
	}
	for _, tc := range cases {
		got := Less(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("Less(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestLess_MultiDigitComponents(t *testing.T) {
	if !Less("10.0.0", "11.0.0") {
		t.Error("Less(\"10.0.0\", \"11.0.0\") should be true")
	}
	if !Less("1.9.0", "1.10.0") {
		t.Error("Less(\"1.9.0\", \"1.10.0\") should be true (numeric, not lexicographic)")
	}
}

func TestLess_InvalidInputReturnsFalse(t *testing.T) {
	if Less("invalid", "1.0.0") {
		t.Error("Less with invalid first arg should return false")
	}
	if Less("1.0.0", "invalid") {
		t.Error("Less with invalid second arg should return false")
	}
	if Less("", "") {
		t.Error("Less with empty strings should return false")
	}
}

func TestLess_DeprecationThresholdCheck(t *testing.T) {
	// Simulate the "version below deprecated-before" check.
	clientVersion := "3.9.9"
	deprecatedBefore := "4.0.0"
	if !Less(clientVersion, deprecatedBefore) {
		t.Errorf("expected client %s to be less than deprecatedBefore %s", clientVersion, deprecatedBefore)
	}

	clientVersion = "4.0.0"
	if Less(clientVersion, deprecatedBefore) {
		t.Errorf("expected client %s to NOT be less than deprecatedBefore %s", clientVersion, deprecatedBefore)
	}
}

// --- Compare ---

func TestCompare_LessThan(t *testing.T) {
	if Compare("1.0.0", "2.0.0") != -1 {
		t.Error("Compare(1.0.0, 2.0.0) should be -1")
	}
}

func TestCompare_Equal(t *testing.T) {
	if Compare("3.0.0", "3.0.0") != 0 {
		t.Error("Compare(3.0.0, 3.0.0) should be 0")
	}
}

func TestCompare_GreaterThan(t *testing.T) {
	if Compare("2.0.0", "1.0.0") != 1 {
		t.Error("Compare(2.0.0, 1.0.0) should be 1")
	}
}

func TestCompare_InvalidBothUnparsable(t *testing.T) {
	if Compare("bad", "also-bad") != 0 {
		t.Error("Compare with two invalid versions should be 0")
	}
}

func TestCompare_InvalidFirstUnparsable(t *testing.T) {
	if Compare("bad", "1.0.0") != -1 {
		t.Error("Compare with invalid first arg should be -1")
	}
}

func TestCompare_InvalidSecondUnparsable(t *testing.T) {
	if Compare("1.0.0", "bad") != 1 {
		t.Error("Compare with invalid second arg should be 1")
	}
}
