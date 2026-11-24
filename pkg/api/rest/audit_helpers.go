package rest

// prefixOrEmpty returns the first n bytes of s, so audit logs carry a number prefix, not the full E.164.
func prefixOrEmpty(s string, n int) string {
	if n <= 0 || len(s) == 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	return s[:n]
}
