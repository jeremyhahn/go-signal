package tracing

import (
	"net/http"
)

// HTTPMiddleware attaches the inbound traceparent, or a fresh one, to the request context and echoes it on the response.
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, err := Parse(r.Header.Get(HeaderName))
		if err != nil {
			fresh, mintErr := New()
			if mintErr != nil {
				// Best-effort — if entropy is broken, fall through
				// with a zero-valued TC. Handlers can still run; we
				// only lose correlation.
				next.ServeHTTP(w, r)
				return
			}
			tc = fresh
		}
		w.Header().Set(HeaderName, tc.Header())
		next.ServeHTTP(w, r.WithContext(WithContext(r.Context(), tc)))
	})
}
