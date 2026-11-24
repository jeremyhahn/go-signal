package secrets

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"unicode/utf8"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// JSONAppender is implemented by values that append their JSON to a caller buffer, so the plaintext has one owner who can wipe it.
type JSONAppender interface {
	// AppendJSON appends the JSON encoding to dst; the caller wipes it. Implementations must escape <, > and & as encoding/json does.
	AppendJSON(dst []byte) ([]byte, error)
}

// AppendJSONString appends the value to dst as a JSON string, byte-identical to encoding/json, without making a Go string; errors and appends nothing when unreadable.
func (s *SecureString) AppendJSONString(dst []byte) ([]byte, error) {
	var out []byte
	ran := s.WithBytes(func(b []byte) {
		out = appendJSONStringFromBytes(dst, b)
	})
	if !ran {
		return dst, &UnavailableSecretError{}
	}
	return out, nil
}

// Grow returns b with room for n more bytes, wiping the old array if it reallocated.
func Grow(b []byte, n int) []byte {
	if cap(b)-len(b) >= n {
		return b
	}
	grown := make([]byte, len(b), len(b)+n)
	copy(grown, b)
	secure.Wipe(b[:cap(b)])
	return grown
}

// hexDigits is used for the \u00XX form. encoding/json emits lowercase.
const hexDigits = "0123456789abcdef"

// appendJSONStringFromBytes appends src as a quoted JSON string exactly as encoding/json writes it, HTML escaping included.
func appendJSONStringFromBytes(dst, src []byte) []byte {
	// Grow once to the worst case (every byte as \u00XX plus quotes) so append never abandons plaintext.
	dst = Grow(dst, 6*len(src)+2)
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(src); {
		if c := src[i]; c < utf8.RuneSelf {
			if safeJSONByte(c) {
				i++
				continue
			}
			dst = append(dst, src[start:i]...)
			switch c {
			case '\\', '"':
				dst = append(dst, '\\', c)
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			default:
				// Everything else below 0x20, plus <, > and & which
				// encoding/json escapes so a response cannot be reinterpreted
				// when embedded in HTML.
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8: emit U+FFFD's three raw bytes, as encoding/json does.
			dst = append(dst, src[start:i]...)
			dst = utf8.AppendRune(dst, utf8.RuneError)
			i += size
			start = i
			continue
		}
		// U+2028 and U+2029 are valid JSON but are line terminators to a
		// JavaScript parser; encoding/json escapes them.
		if r == '\u2028' || r == '\u2029' {
			dst = append(dst, src[start:i]...)
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[r&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	dst = append(dst, src[start:]...)
	return append(dst, '"')
}

// safeJSONByte reports whether an ASCII byte may be emitted literally.
func safeJSONByte(c byte) bool {
	return c >= 0x20 && c != '"' && c != '\\' && c != '<' && c != '>' && c != '&'
}

// ErrMalformedJSONString reports a value that is not a JSON string literal.
var ErrMalformedJSONString = errors.New("secrets: malformed JSON string")

// AppendUnquotedJSONString decodes a quoted JSON string from src into dst; the caller wipes dst.
func AppendUnquotedJSONString(dst, src []byte) ([]byte, error) {
	if len(src) < 2 || src[0] != '"' || src[len(src)-1] != '"' {
		return dst, ErrMalformedJSONString
	}
	body := src[1 : len(src)-1]
	// Grow once for the worst case: an invalid byte decodes to three bytes of U+FFFD.
	dst = Grow(dst, 3*len(body))
	for i := 0; i < len(body); {
		c := body[i]
		if c != '\\' {
			// Reject a raw quote or control byte, exactly as encoding/json does.
			if c == '"' || c < 0x20 {
				return dst, ErrMalformedJSONString
			}
			if c < utf8.RuneSelf {
				dst = append(dst, c)
				i++
				continue
			}
			// Coerce invalid UTF-8 to U+FFFD per byte, as encoding/json's unquoteBytes does.
			r, size := utf8.DecodeRune(body[i:])
			dst = utf8.AppendRune(dst, r)
			i += size
			continue
		}
		i++
		if i >= len(body) {
			return dst, ErrMalformedJSONString
		}
		switch body[i] {
		case '"', '\\', '/':
			dst = append(dst, body[i])
			i++
		case 'b':
			dst = append(dst, '\b')
			i++
		case 'f':
			dst = append(dst, '\f')
			i++
		case 'n':
			dst = append(dst, '\n')
			i++
		case 'r':
			dst = append(dst, '\r')
			i++
		case 't':
			dst = append(dst, '\t')
			i++
		case 'u':
			r, n, err := decodeUnicodeEscape(body[i:])
			if err != nil {
				return dst, err
			}
			dst = utf8.AppendRune(dst, r)
			i += n
		default:
			return dst, ErrMalformedJSONString
		}
	}
	return dst, nil
}

// jsonNull is the literal encoding/json hands an Unmarshaler for a null value.
var jsonNull = []byte("null")

// jsonLiteralKinds names a non-string JSON value by its first byte, in the
// words encoding/json's own UnmarshalTypeError uses. Anything absent is a
// number: every other value a successful scan can start with is one.
var jsonLiteralKinds = map[byte]string{
	'{': "object",
	'[': "array",
	't': "bool",
	'f': "bool",
}

// JSONStringBytes decodes a JSON string field into a wipeable buffer, rejecting wrong-typed duplicates as a string field would; null leaves it unchanged. Call Wipe when done.
type JSONStringBytes struct {
	b []byte
}

// UnmarshalJSON decodes one JSON string literal into owned bytes, wiping the
// bytes of any earlier occurrence it replaces. data is the decoder's own
// input, not a copy, so no second buffer holding the quoted credential exists.
func (j *JSONStringBytes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, jsonNull) {
		return nil
	}
	if len(data) == 0 || data[0] != '"' {
		kind, ok := jsonLiteralKinds[firstByte(data)]
		if !ok {
			kind = "number"
		}
		return &json.UnmarshalTypeError{Value: kind, Type: reflect.TypeFor[string]()}
	}
	b, err := AppendUnquotedJSONString(nil, data)
	if err != nil {
		secure.Wipe(b)
		return err
	}
	secure.Wipe(j.b)
	j.b = b
	return nil
}

// Bytes returns the decoded plaintext, nil when no string was decoded. The
// slice aliases the value's buffer: Wipe clears it.
func (j *JSONStringBytes) Bytes() []byte {
	return j.b
}

// Wipe zeroes and releases the decoded plaintext. It is idempotent.
func (j *JSONStringBytes) Wipe() {
	secure.Wipe(j.b)
	j.b = nil
}

// firstByte returns data's first byte, or 0 for an empty slice.
func firstByte(data []byte) byte {
	if len(data) == 0 {
		return 0
	}
	return data[0]
}

// decodeUnicodeEscape reads a \uXXXX escape (with surrogate pair) at s[0] == 'u' and returns the rune and bytes consumed; an unpaired surrogate is U+FFFD.
func decodeUnicodeEscape(s []byte) (rune, int, error) {
	hi, err := hex4(s)
	if err != nil {
		return 0, 0, err
	}
	n := 5
	if hi >= 0xD800 && hi < 0xDC00 {
		if len(s) >= 11 && s[5] == '\\' && s[6] == 'u' {
			if lo, err2 := hex4(s[6:]); err2 == nil && lo >= 0xDC00 && lo < 0xE000 {
				return rune(0x10000 + (hi-0xD800)<<10 + (lo - 0xDC00)), 11, nil
			}
		}
		return utf8.RuneError, n, nil
	}
	if hi >= 0xDC00 && hi < 0xE000 {
		return utf8.RuneError, n, nil
	}
	return rune(hi), n, nil
}

// hex4 decodes the four hex digits following s[0] == 'u'.
func hex4(s []byte) (rune, error) {
	if len(s) < 5 {
		return 0, ErrMalformedJSONString
	}
	var buf [2]byte
	if _, err := hex.Decode(buf[:], s[1:5]); err != nil {
		return 0, ErrMalformedJSONString
	}
	return rune(buf[0])<<8 | rune(buf[1]), nil
}
