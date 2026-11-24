package tracing

import (
	"net/http"
)

// HTTPMiddleware threads a TraceContext through the request lifecycle:
//
//  1. Parse the inbound traceparent header. If valid, attach to ctx.
//  2. If absent or invalid, mint a fresh TraceContext.
//  3. Set the same traceparent on the response so the client can
//     correlate against their own traces.
//  4. Pass the context-extended *http.Request to next.
//
// Pair with the slog handler from pkg/tracing/slog.go to emit the
// trace + span IDs as structured-log fields automatically.
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
