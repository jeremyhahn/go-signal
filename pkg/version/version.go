// Package version provides utilities for parsing and comparing semantic
// version strings in the form MAJOR.MINOR.PATCH (e.g. "5.1.0"). Each
// component must be a non-negative decimal integer.
package version

import (
	"strconv"
	"strings"
)

// semver holds the three numeric components of a semantic version string.
type semver struct {
	major, minor, patch int
}

// parse parses a "MAJOR.MINOR.PATCH" string into a semver. Additional
// dot-separated fields are ignored. Returns false when the string does not
// contain at least three dot-separated non-negative integer fields.
func parse(s string) (semver, bool) {
	parts := strings.SplitN(s, ".", 4)
	if len(parts) < 3 {
		return semver{}, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 0 {
		return semver{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil || minor < 0 {
		return semver{}, false
	}
	// Strip any pre-release or build suffix from the patch component.
	patchStr := parts[2]
	if idx := strings.IndexAny(patchStr, "-+"); idx >= 0 {
		patchStr = patchStr[:idx]
	}
	patch, err := strconv.Atoi(patchStr)
	if err != nil || patch < 0 {
		return semver{}, false
	}
	return semver{major, minor, patch}, true
}

// IsValid reports whether s is a parsable MAJOR.MINOR.PATCH version string.
func IsValid(s string) bool {
	_, ok := parse(s)
	return ok
}

// Less reports whether version a is strictly less than version b.
// Both strings must be valid MAJOR.MINOR.PATCH versions; if either is
// unparsable Less returns false.
func Less(a, b string) bool {
	va, ok := parse(a)
	if !ok {
		return false
	}
	vb, ok := parse(b)
	if !ok {
		return false
	}
	if va.major != vb.major {
		return va.major < vb.major
	}
	if va.minor != vb.minor {
		return va.minor < vb.minor
	}
	return va.patch < vb.patch
}

// Compare returns an integer comparing two version strings:
//
//	-1 if a < b
//	 0 if a == b
//	+1 if a > b
//
// Unparsable version strings are treated as less than any valid version.
func Compare(a, b string) int {
	va, aOK := parse(a)
	vb, bOK := parse(b)

	switch {
	case !aOK && !bOK:
		return 0
	case !aOK:
		return -1
	case !bOK:
		return 1
	}

	if va.major != vb.major {
		if va.major < vb.major {
			return -1
		}
		return 1
	}
	if va.minor != vb.minor {
		if va.minor < vb.minor {
			return -1
		}
		return 1
	}
	if va.patch != vb.patch {
		if va.patch < vb.patch {
			return -1
		}
		return 1
	}
	return 0
}
