package ses

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// sigV4 signs SES requests with AWS Signature Version 4: buffered bodies only, optional SessionToken.
type sigV4 struct {
	accessKeyID     string
	secretAccessKey *secrets.SecureString
	sessionToken    string
	region          string
	service         string
	now             func() time.Time
}

// Sign adds the SigV4 Authorization, X-Amz-Date and optional X-Amz-Security-Token headers; body must be the exact bytes sent.
func (s *sigV4) Sign(req *http.Request, body []byte) error {
	if s.accessKeyID == "" || s.secretAccessKey.IsEmpty() {
		return errors.New("ses sigv4: missing credentials")
	}
	if s.region == "" {
		return errors.New("ses sigv4: missing region")
	}
	if s.service == "" {
		s.service = "ses"
	}
	nowFn := s.now
	if nowFn == nil {
		nowFn = time.Now
	}
	t := nowFn().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")

	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.Header.Set("Host", req.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}

	payloadHashHex := hexSHA256(body)
	req.Header.Set("X-Amz-Content-Sha256", payloadHashHex)

	canonicalHeaders, signedHeaders := canonicalHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHashHex,
	}, "\n")

	credentialScope := strings.Join([]string{dateStamp, s.region, s.service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	// The secret is revealed only for the key derivation and never becomes a
	// Go string.
	var signingKey []byte
	if !s.secretAccessKey.WithBytes(func(secret []byte) {
		signingKey = deriveSigningKey(secret, dateStamp, s.region, s.service)
	}) {
		return errors.New("ses sigv4: credentials unavailable")
	}
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	auth := "AWS4-HMAC-SHA256 " +
		"Credential=" + s.accessKeyID + "/" + credentialScope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature
	req.Header.Set("Authorization", auth)
	return nil
}

// hexSHA256 returns the lower-case hex SHA-256 digest of data.
func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hmacSHA256 returns HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// deriveSigningKey is HMAC chained over "AWS4"+secret, date, region, service, "aws4_request".
func deriveSigningKey(secret []byte, date, region, service string) []byte {
	kSecret := append([]byte("AWS4"), secret...)
	defer clear(kSecret)
	k := hmacSHA256(kSecret, []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte("aws4_request"))
}

// canonicalURI returns the canonicalized resource path per SigV4. For SES
// requests we hit "/v2/email/outbound-emails" and "/" — no path-traversal
// elements to clean up — so an empty path becomes "/".
func canonicalURI(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.EscapedPath()
}

// canonicalQuery sorts and re-encodes the query string. SES SendEmail uses
// no query parameters today; we still build a canonical form so the helper
// stays correct for future GET-style endpoints.
func canonicalQuery(u *url.URL) string {
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(q))
	for _, k := range keys {
		values := q[k]
		sort.Strings(values)
		for _, v := range values {
			pairs = append(pairs, awsURIEncode(k, true)+"="+awsURIEncode(v, true))
		}
	}
	return strings.Join(pairs, "&")
}

// canonicalHeaders builds the sorted, lower-cased "header:value" block and
// the semicolon-joined SignedHeaders string. SES requires the host and
// x-amz-* headers at minimum.
func canonicalHeaders(req *http.Request) (string, string) {
	names := make([]string, 0, len(req.Header)+1)
	for k := range req.Header {
		names = append(names, strings.ToLower(k))
	}
	if _, ok := req.Header["Host"]; !ok {
		names = append(names, "host")
	}
	sort.Strings(names)
	// Deduplicate (Host may appear twice via header + req.Host).
	uniq := names[:0]
	for i, n := range names {
		if i > 0 && n == names[i-1] {
			continue
		}
		uniq = append(uniq, n)
	}
	var sb strings.Builder
	for _, n := range uniq {
		sb.WriteString(n)
		sb.WriteString(":")
		switch n {
		case "host":
			sb.WriteString(req.Host)
		default:
			values := req.Header.Values(http.CanonicalHeaderKey(n))
			if len(values) == 0 {
				values = req.Header.Values(n)
			}
			sb.WriteString(strings.Join(trimAll(values), ","))
		}
		sb.WriteString("\n")
	}
	return sb.String(), strings.Join(uniq, ";")
}

// awsURIEncode percent-encodes every non-unreserved byte; encodeSlash controls '/'.
func awsURIEncode(s string, encodeSlash bool) string {
	var sb strings.Builder
	for _, b := range []byte(s) {
		if unreservedByte(b) || (!encodeSlash && b == '/') {
			sb.WriteByte(b)
			continue
		}
		// Capital hex letters per AWS spec.
		sb.WriteByte('%')
		sb.WriteString(strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	return sb.String()
}

// unreservedByte matches the AWS-flavored RFC 3986 unreserved character set.
func unreservedByte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '-', b == '_', b == '.', b == '~':
		return true
	}
	return false
}

// trimAll strips leading/trailing whitespace from every entry — SigV4
// requires header values to be trimmed before they're hashed.
func trimAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.TrimSpace(s)
	}
	return out
}
