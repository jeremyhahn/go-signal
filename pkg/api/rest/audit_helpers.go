package rest

// prefixOrEmpty returns the first n bytes of s. Used by the audit
// emission path to log number prefixes (e.g. "+1555") without leaking
// the full E.164 into structured-log records — Java's audit policy
// applies the same truncation.
func prefixOrEmpty(s string, n int) string {
	if n <= 0 || len(s) == 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n]
}
