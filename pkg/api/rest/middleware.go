package rest

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/auth"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/service"
)

const (
	// DefaultBodyLimit is the maximum request body size for standard JSON API endpoints.
	DefaultBodyLimit int64 = 256 * 1024 // 256 KB

	// UploadBodyLimit is the maximum request body size for attachment and upload endpoints.
	UploadBodyLimit int64 = 10 * 1024 * 1024 // 10 MB
)

type contextKey int

const (
	accountContextKey contextKey = iota
	unidentifiedSenderContextKey
	deviceContextKey
)

// contextWithAccount stores the authenticated account in the context.
func contextWithAccount(ctx context.Context, acct *accounts.Account) context.Context {
	return context.WithValue(ctx, accountContextKey, acct)
}

// accountFromContext retrieves the authenticated account from the context.
// Returns nil if no account is present.
func accountFromContext(ctx context.Context) *accounts.Account {
	acct, _ := ctx.Value(accountContextKey).(*accounts.Account)
	return acct
}

// contextWithDevice stores the authenticated device ID in the context. It is
// set by authMiddleware once the per-device credential has been verified.
func contextWithDevice(ctx context.Context, deviceID uint64) context.Context {
	return context.WithValue(ctx, deviceContextKey, deviceID)
}

// deviceIDFromContext returns the authenticated device ID for the request. It
// returns accounts.PrimaryDeviceID when no device principal is present (for
// example on sealed-sender or unauthenticated paths) so that callers always
// observe a valid device ID.
func deviceIDFromContext(ctx context.Context) uint64 {
	if id, ok := ctx.Value(deviceContextKey).(uint64); ok {
		return id
	}
	return accounts.PrimaryDeviceID
}

// contextWithUnidentifiedSender marks the request context as carrying a
// sealed-sender (unidentified) message, authenticated via the
// Unidentified-Access-Key header rather than Basic auth.
func contextWithUnidentifiedSender(ctx context.Context) context.Context {
	return context.WithValue(ctx, unidentifiedSenderContextKey, true)
}

// isUnidentifiedSender reports whether the request was authenticated via the
// Unidentified-Access-Key header (sealed-sender path).
func isUnidentifiedSender(ctx context.Context) bool {
	v, _ := ctx.Value(unidentifiedSenderContextKey).(bool)
	return v
}

// jsonMiddleware sets the Content-Type header to application/json for all
// responses passing through this middleware.
func jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the HTTP status code written by a handler so that
// the logging middleware can report it. It also implements http.Hijacker so
// that WebSocket upgrades work through the middleware chain.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.statusCode = code
	sr.ResponseWriter.WriteHeader(code)
}

// Hijack implements http.Hijacker, delegating to the underlying ResponseWriter.
// This is required for WebSocket upgrades to work through the middleware chain.
func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := sr.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, &HijackError{}
}

// HijackError indicates that the underlying ResponseWriter does not support
// connection hijacking.
type HijackError struct{}

func (e *HijackError) Error() string {
	return "websocket: response writer does not support hijacking"
}

// loggingMiddleware logs each request with its method, path, status code, and
// duration. Sensitive query parameters (login, password) are redacted to
// prevent credential exposure in log output.
func loggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(recorder, r)

		// Redact credentials from the logged path — both the query string
		// and the path segments. Query-only redaction was the original and
		// left the larger hole: the credentials this API carries are mostly
		// PATH segments.
		logPath := redactPathSegments(r.URL.Path)
		if r.URL.RawQuery != "" {
			logPath += "?" + redactQueryParams(r.URL.RawQuery)
		}

		logger.Info("request",
			slog.String("method", r.Method),
			slog.String("path", logPath),
			slog.Int("status", recorder.statusCode),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

// credentialPathPrefixes lists route prefixes whose NEXT path segment is a
// credential or a resolvable handle rather than an ordinary identifier.
//
//   - /v1/verification/session/{id} — the id is what POST /v1/registration
//     accepts as proof of verification (enforceVerifiedSession). Anyone who
//     can read it can register that phone number until the session expires,
//     so logging it turns log access into account takeover.
//   - /v1/accounts/username_link/{handle} — resolving the handle returns the
//     account's encrypted username blob.
//   - /v1/fido2/session/{id} and /v1/fido2/enroll/{id}/complete — the id is
//     the handle to an in-flight WebAuthn ceremony, and completing that
//     ceremony is what binds a new authenticator to the account. These routes
//     only exist under the fido2 build tag; a prefix that matches nothing
//     costs nothing, and keeping one policy for the whole access log is
//     safer than a policy that changes shape with the build.
//
// Account UUIDs (/v1/profile/{identifier}, /v2/keys/{identifier}/…) and FIDO2
// credential ids (/v1/fido2/credentials/{id}) are deliberately NOT redacted:
// they are the keys an operator correlates by, they are not bearer
// credentials — a WebAuthn credential id is a public handle the server itself
// hands out in allowCredentials — and blanking them would leave the access log
// unable to answer "what happened to this account". That is a judgement worth
// revisiting deliberately, not by reflex.
var credentialPathPrefixes = []string{
	"/v1/verification/session/",
	"/v1/accounts/username_link/",
	"/v1/fido2/session/",
	"/v1/fido2/enroll/",
}

// redactedSegment replaces a credential-bearing path segment in log output.
const redactedSegment = "[REDACTED]"

// redactPathSegments replaces the segment following a credential-bearing
// route prefix, preserving the rest of the path so the route is still
// identifiable:
//
//	/v1/verification/session/<id>/code -> /v1/verification/session/[REDACTED]/code
//
// The result is for log output only.
func redactPathSegments(path string) string {
	for _, prefix := range credentialPathPrefixes {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := path[len(prefix):]
		if rest == "" {
			// The collection endpoint itself carries no credential.
			return path
		}
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			return prefix + redactedSegment + rest[i:]
		}
		return prefix + redactedSegment
	}
	return path
}

// redactQueryParams replaces the values of sensitive query parameters
// (login, password) with [REDACTED] to prevent credential exposure in logs.
// The resulting string is suitable for use in log output only — it is not
// a valid URL-encoded query string because the redaction marker contains
// unencoded bracket characters.
func redactQueryParams(rawQuery string) string {
	params, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "[REDACTED]"
	}
	sensitiveKeys := map[string]bool{"login": true, "password": true}
	var buf strings.Builder
	first := true
	for key, vals := range params {
		for _, val := range vals {
			if !first {
				buf.WriteByte('&')
			}
			first = false
			buf.WriteString(url.QueryEscape(key))
			buf.WriteByte('=')
			if sensitiveKeys[key] {
				buf.WriteString("[REDACTED]")
			} else {
				buf.WriteString(url.QueryEscape(val))
			}
		}
	}
	return buf.String()
}

// authMiddleware extracts Basic Auth credentials from the request, validates
// them against the accounts manager, and stores the authenticated account in
// the request context. The expected credential format after base64 decoding is
// "uuid.deviceId:password" or "uuid:password".
//
// Security properties:
//   - Auth token comparison uses HKDF-SHA256 via auth.SaltedTokenHash.Verify to
//     prevent timing attacks that could leak valid tokens.
//   - When the UUID is not found a pre-computed dummy SaltedTokenHash.Verify
//     call is performed so that the response time is indistinguishable from a
//     real verification, preventing UUID existence oracle attacks via timing.
func authMiddleware(am service.AccountService, next http.HandlerFunc) http.HandlerFunc {
	// Pre-compute a dummy hash at middleware initialisation. On account-not-found
	// paths we call dummyHash.Verify to perform the same HKDF derivation as a
	// real auth check, equalising response timing regardless of UUID existence.
	dummyHash, _ := auth.NewSaltedTokenHash("dummy-timing-equalization-token")

	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="signal"`)
			writeError(w, http.StatusUnauthorized, "missing credentials")
			return
		}

		// The username may be "uuid.deviceId" or just "uuid". When the
		// device suffix is absent the credential targets the primary device.
		acctUUID := username
		deviceID := accounts.PrimaryDeviceID
		if idx := strings.IndexByte(username, '.'); idx >= 0 {
			acctUUID = username[:idx]
			parsed, perr := strconv.ParseUint(username[idx+1:], 10, 64)
			if perr != nil || parsed == 0 {
				// Equalise timing so an invalid device suffix is
				// indistinguishable from a wrong password.
				dummyHash.Verify(password)
				w.Header().Set("WWW-Authenticate", `Basic realm="signal"`)
				writeError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			deviceID = parsed
		}

		acct, err := am.Get(r.Context(), acctUUID)
		if err != nil {
			// Perform a real hash verification to equalise timing so that
			// response latency does not reveal whether the UUID exists.
			dummyHash.Verify(password)
			w.Header().Set("WWW-Authenticate", `Basic realm="signal"`)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// Verify the password against the *authenticated device's* stored
		// token hash — not the primary device's — so that linked devices
		// authenticate as themselves and device-scoped authorization is
		// enforceable downstream. The constant-time comparison is
		// encapsulated inside AuthTokenHash.Verify (crypto/subtle).
		device := acct.GetDevice(deviceID)
		if device == nil || device.AuthTokenHash == nil {
			// Equalise timing for a missing/credential-less device.
			dummyHash.Verify(password)
			w.Header().Set("WWW-Authenticate", `Basic realm="signal"`)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if !device.AuthTokenHash.Verify(password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="signal"`)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		ctx := contextWithAccount(r.Context(), acct)
		ctx = contextWithDevice(ctx, deviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// optionalAuthMiddleware allows a request to proceed via one of two
// authentication mechanisms:
//
//  1. HTTP Basic auth (existing flow) — behaves identically to authMiddleware.
//  2. Unidentified-Access-Key header — the header value is base64-decoded and
//     compared constant-time against the DESTINATION account's stored
//     UnidentifiedAccessKey. On success the request context is marked with
//     contextWithUnidentifiedSender so that downstream handlers can set the
//     correct EnvelopeTypeUnidentifiedSender envelope type.
//
// The destination UUID must be supplied by the caller via the destUUID
// parameter (typically extracted from the URL path before the middleware
// wraps the handler).
//
// The destination account is located via resolveDest, which must understand
// the same identifier shapes the handler does (ACI:<uuid>, PNI:<uuid>, bare
// UUID, or E.164) so that sealed-sender lookups succeed for every identifier
// form, not just a bare ACI UUID.
//
// Security properties:
//   - UAK comparison always uses crypto/subtle.ConstantTimeCompare to prevent
//     timing oracle attacks.
//   - When the destination does not exist a constant-time dummy comparison is
//     still performed so that account existence cannot be inferred from
//     response timing.
//   - Accounts with a nil or zero-length UnidentifiedAccessKey reject UAK
//     authentication unconditionally; the account must opt in by having a
//     non-empty key. A caller cannot authenticate by supplying an all-zero
//     key against a UAK-less account.
func optionalAuthMiddleware(am service.AccountService, resolveDest func(*http.Request) (*accounts.Account, error), next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Fast path: Basic auth present — delegate entirely to the existing
		// constant-time auth middleware.
		if _, _, ok := r.BasicAuth(); ok {
			authMiddleware(am, next).ServeHTTP(w, r)
			return
		}

		// Sealed-sender path: Unidentified-Access-Key header.
		uakHeader := r.Header.Get("Unidentified-Access-Key")
		if uakHeader == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="signal"`)
			writeError(w, http.StatusUnauthorized, "missing credentials")
			return
		}

		providedKey, err := base64.StdEncoding.DecodeString(uakHeader)
		if err != nil {
			// Fall back to raw (unpadded) base64 used by some clients.
			providedKey, err = base64.RawStdEncoding.DecodeString(uakHeader)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid unidentified access key encoding")
				return
			}
		}

		destAcct, lookupErr := resolveDest(r)

		// hasUAK is true only when the destination account exists AND has a
		// non-empty UnidentifiedAccessKey. A constant-time comparison is always
		// performed (against a fixed 16-byte zero buffer when there is no real
		// key) so the accept/reject branch — and thus account/key existence —
		// is not revealed by control flow; the request is accepted only when a
		// real key was present and matched.
		hasUAK := lookupErr == nil && destAcct != nil && len(destAcct.UnidentifiedAccessKey) > 0
		storedKey := make([]byte, 16)
		if hasUAK {
			storedKey = destAcct.UnidentifiedAccessKey
		}
		matched := subtle.ConstantTimeCompare(providedKey, storedKey) == 1
		if !hasUAK || !matched {
			writeError(w, http.StatusUnauthorized, "invalid unidentified access key")
			return
		}

		// UAK matched and account exists: mark as unidentified sender. We do
		// NOT place the destination account into the context as the "sender"
		// account — the sender is anonymous by design. Downstream handlers
		// check isUnidentifiedSender to select the correct envelope type.
		ctx := contextWithUnidentifiedSender(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// writeJSON marshals v as JSON and writes it to the response with the given
// status code. If marshaling fails, a 500 Internal Server Error is written.
func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		slog.Default().Error("failed to write JSON response", slog.String("error", err.Error()))
	}
}

// writeError writes a JSON error response with the given status code and
// message.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		slog.Default().Error("failed to encode error response", slog.String("error", err.Error()))
	}
}

// limitedBody wraps an io.ReadCloser (produced by http.MaxBytesReader) and
// records whether a MaxBytesError was encountered so that the companion
// limitWriter can intercept the response and return 413.
type limitedBody struct {
	rc interface {
		Read(p []byte) (n int, err error)
		Close() error
	}
	overflowErr *http.MaxBytesError
}

func (lb *limitedBody) Read(p []byte) (int, error) {
	n, err := lb.rc.Read(p)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			lb.overflowErr = mbe
		}
	}
	return n, err
}

func (lb *limitedBody) Close() error {
	return lb.rc.Close()
}

// limitWriter is a ResponseWriter coupled to a limitedBody. Before writing
// headers it checks whether the body reader encountered a MaxBytesError, in
// which case it forces a 413 response regardless of what the inner handler
// intended to write.
type limitWriter struct {
	http.ResponseWriter
	body        *limitedBody
	wroteHeader bool
}

func (lw *limitWriter) WriteHeader(code int) {
	if lw.wroteHeader {
		return
	}
	lw.wroteHeader = true
	if lw.body.overflowErr != nil {
		lw.ResponseWriter.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	lw.ResponseWriter.WriteHeader(code)
}

func (lw *limitWriter) Write(b []byte) (int, error) {
	if !lw.wroteHeader {
		lw.WriteHeader(http.StatusOK)
	}
	// If body overflow was detected, swallow the inner handler's body.
	if lw.body.overflowErr != nil {
		return len(b), nil
	}
	return lw.ResponseWriter.Write(b)
}

// Hijack delegates to the underlying ResponseWriter for WebSocket upgrades.
func (lw *limitWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := lw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, &HijackError{}
}

// bodyLimitMiddleware wraps each request body with http.MaxBytesReader to
// enforce a maximum body size. If the body exceeds the configured limit,
// a 413 Request Entity Too Large response is returned regardless of what the
// inner handler writes. Upload and CDN paths receive UploadBodyLimit; all
// other paths receive DefaultBodyLimit.
func bodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := DefaultBodyLimit
		if isUploadPath(r.URL.Path) {
			limit = UploadBodyLimit
		}

		lb := &limitedBody{rc: http.MaxBytesReader(w, r.Body, limit)}
		lw := &limitWriter{ResponseWriter: w, body: lb}
		r.Body = lb
		next.ServeHTTP(lw, r)

		// If the handler returned without calling WriteHeader (e.g. it read
		// the body, got a MaxBytesError, and simply returned), we must still
		// send 413. This is the fallback path.
		if !lw.wroteHeader && lb.overflowErr != nil {
			lw.ResponseWriter.WriteHeader(http.StatusRequestEntityTooLarge)
		}
	})
}

// isUploadPath reports whether the given URL path is an upload or CDN path
// that requires the larger UploadBodyLimit.
func isUploadPath(path string) bool {
	uploadPrefixes := []string{
		"/cdn/",
		"/cdn2/",
		"/cdn3/",
		"/v4/attachments/",
		"/v1/archives/upload/",
	}
	for _, prefix := range uploadPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// securityHeadersMiddleware adds standard HTTP security headers to every
// response. These headers are required for all Signal API responses regardless
// of content type.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'")
		h.Set("X-XSS-Protection", "0")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware applies rate limiting using the provided RateLimiter. The
// key used for limiting is determined by keyFn, which receives the request and
// the account stored in the context (nil for unauthenticated requests). When
// the limiter returns a *signalerrors.RateLimitedError, the middleware writes a
// 429 response with a Retry-After header and halts the chain.
func rateLimitMiddleware(rl limits.RateLimiter, keyFn func(r *http.Request, acct *accounts.Account) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acct := accountFromContext(r.Context())
		key := keyFn(r, acct)
		if err := rl.Allow(r.Context(), key); err != nil {
			var rle *signalerrors.RateLimitedError
			if errors.As(err, &rle) {
				w.Header().Set("Retry-After", strconv.FormatInt(rle.RetryAfterSeconds, 10))
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ipKey is a keyFn for rateLimitMiddleware that extracts the remote IP
// address from the request. When trustedProxies is non-empty, the
// X-Forwarded-For header is only trusted if the immediate RemoteAddr falls
// within one of the trusted CIDR ranges; when trusted, the rightmost
// untrusted hop is extracted instead of the leftmost (which is trivially
// spoofable). When trustedProxies is empty, XFF is ignored entirely and
// RemoteAddr is used to prevent header spoofing.
func ipKey(r *http.Request, _ *accounts.Account) string {
	return ipKeyWithProxies(r, nil)
}

// ipKeyWithProxies extracts the client IP with trusted proxy awareness.
func ipKeyWithProxies(r *http.Request, trusted []*net.IPNet) string {
	remoteHost := remoteIP(r)

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" || len(trusted) == 0 {
		// No XFF header, or no trusted proxies configured — use RemoteAddr.
		// Trusting XFF unconditionally when no proxies are configured is
		// trivially spoofable by any client.
		return remoteHost
	}

	// Only trust XFF if RemoteAddr is from a trusted proxy.
	remoteIPAddr := net.ParseIP(remoteHost)
	if remoteIPAddr == nil {
		return remoteHost
	}

	isTrusted := false
	for _, cidr := range trusted {
		if cidr.Contains(remoteIPAddr) {
			isTrusted = true
			break
		}
	}
	if !isTrusted {
		return remoteHost
	}

	// Extract the rightmost untrusted hop from XFF.
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(parts[i])
		hopIP := net.ParseIP(hop)
		if hopIP == nil {
			continue
		}
		hopTrusted := false
		for _, cidr := range trusted {
			if cidr.Contains(hopIP) {
				hopTrusted = true
				break
			}
		}
		if !hopTrusted {
			return hop
		}
	}

	// All hops are trusted proxies; use the leftmost as the client.
	return strings.TrimSpace(parts[0])
}

// remoteIP extracts the IP address from RemoteAddr, stripping the port.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// uuidKey is a keyFn for rateLimitMiddleware that returns the authenticated
// account UUID. For unauthenticated requests (acct == nil) it falls back to
// the remote IP so that the limiter always has a valid key.
func uuidKey(r *http.Request, acct *accounts.Account) string {
	if acct != nil {
		return acct.UUID
	}
	return ipKey(r, nil)
}

// redactNumber returns a partially redacted phone number suitable for logging.
// It preserves the first 4 characters and replaces the rest with asterisks.
// Numbers shorter than 5 characters are fully redacted.
func redactNumber(number string) string {
	if len(number) < 5 {
		return "****"
	}
	return number[:4] + "****"
}

// parseUUID validates that raw is a well-formed UUID. On success it returns
// raw unchanged. On failure it writes a 400 Bad Request response and returns
// an empty string; callers must return immediately when the return value is "".
func parseUUID(w http.ResponseWriter, raw string, paramName string) string {
	if _, err := uuid.Parse(raw); err != nil {
		writeError(w, http.StatusBadRequest, "invalid "+paramName)
		return ""
	}
	return raw
}

// isValidE164 reports whether number conforms to E.164 format: a leading '+'
// followed by 1–15 ASCII digits, for a total length of 2–16 characters.
func isValidE164(number string) bool {
	if len(number) < 2 || len(number) > 16 || number[0] != '+' {
		return false
	}
	for i := 1; i < len(number); i++ {
		if number[i] < '0' || number[i] > '9' {
			return false
		}
	}
	return true
}

// requireNotAuthenticated rejects requests that include valid Basic Auth
// credentials. This prevents authenticated users from using endpoints
// intended for anonymous access, matching the Java Signal-Server pattern.
// It returns true when the request carries no Basic Auth credentials and the
// handler should continue; false when Basic Auth was detected and a 400
// response has already been written.
func requireNotAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	if _, _, ok := r.BasicAuth(); ok {
		writeError(w, http.StatusBadRequest, "authentication not permitted on this endpoint")
		return false
	}
	return true
}

// decodeBase64 decodes a base64-encoded string, accepting both standard and
// URL-safe alphabets, with or without padding. This matches the behavior of
// the Java Signal-Server, which uses Jackson's lenient base64 deserializer.
func decodeBase64(s string) ([]byte, error) {
	// Try standard with padding first (most common).
	if data, err := base64.StdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	// Try standard without padding (common in Signal Protocol).
	if data, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	// Try URL-safe with padding.
	if data, err := base64.URLEncoding.DecodeString(s); err == nil {
		return data, nil
	}
	// Try URL-safe without padding.
	return base64.RawURLEncoding.DecodeString(s)
}
