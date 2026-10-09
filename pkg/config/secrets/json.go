package secrets

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"unicode/utf8"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// JSONAppender is implemented by values that build their own JSON into a
// buffer supplied by the caller, so that the caller — not encoding/json —
// owns the only allocation the plaintext ever lands in and can wipe it.
//
// It exists because encoding/json.Marshaler cannot be made safe for secret
// material. MarshalJSON's contract is to RETURN a fresh buffer; encoding/json
// copies that buffer into its own and drops the original, and the marshaller
// has no hook that runs afterwards. So a credential marshalled through
// json.Marshal always abandons one unwiped heap buffer holding the plaintext,
// no matter how carefully MarshalJSON is written. Handing the destination
// buffer in is the only shape that keeps a single owner.
type JSONAppender interface {
	// AppendJSON appends the value's JSON encoding to dst and returns the
	// extended buffer. The caller owns the result and must wipe it.
	//
	// Implementations MUST escape `<`, `>` and `&` as encoding/json does by
	// default. The output is written to HTTP responses, and an implementation
	// that stopped escaping would reintroduce the cross-site-scripting surface
	// that encoding/json's default removes.
	AppendJSON(ctx context.Context, dst []byte) ([]byte, error)
}

// AppendJSONString appends the protected value to dst as a JSON string
// literal — quotes and escaping included — without the plaintext ever existing
// as a Go string.
//
// This is the serialization counterpart to WithBytes, and it exists because
// the obvious spelling is unsafe in a way that cannot be repaired afterwards.
// Marshalling a credential normally means Reveal() into a Go string and handing
// that to encoding/json, which puts the plaintext in memory that CANNOT be
// wiped: strings are immutable by contract, the compiler places literals in a
// read-only section, and the runtime is free to copy and share them. Writing
// through a string's backing array to "clear it afterwards" faults outright on
// a literal and corrupts runtime internals on a heap string — jeremyhahn/go-frost#15,
// where exactly that helper killed a process with a SIGSEGV no recover can catch.
//
// So there is no cleanup to add: the material has to never become a string.
// The escaping below is byte-for-byte what encoding/json produces, which is a
// property the tests assert against encoding/json itself rather than a claim
// made here — a hand-rolled encoder that merely looks right would be a silent
// protocol change wearing a security fix's clothes.
//
// dst is the caller's buffer and still holds the plaintext afterwards; the
// caller owns wiping it. Reports an error, and appends nothing, when the secret
// is nil, unset, destroyed or unopenable — a credential that cannot be read must
// fail the response rather than emit an empty one a client would treat as valid.
func (s *SecureString) AppendJSONString(ctx context.Context, dst []byte) ([]byte, error) {
	var out []byte
	ran := s.WithBytes(ctx, func(b []byte) {
		out = appendJSONStringFromBytes(dst, b)
	})
	if !ran {
		return dst, &UnavailableSecretError{}
	}
	return out, nil
}

// Grow returns b with room for n more bytes, wiping the old backing array if a
// reallocation was needed.
//
// This exists because plain append() is unsafe for secret material in a way
// that is easy to miss: when it reallocates it copies the contents into a new
// array and ABANDONS the old one, which still holds the plaintext and which
// nothing holds a reference to any more, so nothing can ever wipe it. Growing
// once, deliberately, is the only way to keep every copy accounted for.
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

// appendJSONStringFromBytes appends src to dst as a quoted JSON string,
// matching encoding/json's encoder exactly, including its HTML escaping of
// <, > and & (on by default) and its  /  escaping.
//
// Matching that default matters: those escapes are why the wire form is
// unchanged. Producing "prettier" output here would alter every credential
// response containing one of those bytes.
func appendJSONStringFromBytes(dst, src []byte) []byte {
	// Grow once, up front, to the worst case: every byte escaping to \u00XX,
	// plus the two quotes. Without this, append() reallocates partway through
	// writing the escaped plaintext and abandons an array containing part of
	// it — unreachable, and therefore unwipeable, which is the whole failure
	// this file exists to avoid.
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
			// Invalid UTF-8. encoding/json (Go 1.27) emits the replacement
			// rune's three raw bytes, not the six-character backslash-u escape
			// earlier releases produced. Emitting the escape instead is a
			// different byte string for the same input — caught by the
			// byte-identity test rather than in production.
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

// AppendUnquotedJSONString decodes a JSON string literal from src — quotes
// included — appending the decoded bytes to dst.
//
// It is the parsing counterpart, and it exists for the same reason: the normal
// path is json.Unmarshal into a string field, which lands the credential in
// memory that cannot be wiped before it is ever sealed. Decoding to bytes keeps
// the material in a buffer the caller owns from the first moment it exists.
//
// Callers own wiping dst, and src still holds the encoded credential.
func AppendUnquotedJSONString(dst, src []byte) ([]byte, error) {
	if len(src) < 2 || src[0] != '"' || src[len(src)-1] != '"' {
		return dst, ErrMalformedJSONString
	}
	body := src[1 : len(src)-1]
	// Grow once for the worst case, for the same reason the encoder does: a
	// reallocation partway through would abandon an array already holding
	// decoded credential bytes, and nothing could reach it to wipe it.
	//
	// Three bytes out per byte in is a true upper bound. Decoding usually
	// SHRINKS — every escape is at least two bytes in — but an invalid UTF-8
	// byte expands to the three bytes of U+FFFD, so the output can exceed the
	// input and a capacity sized to len(src) would reallocate on exactly the
	// malformed input this function was just taught to accept.
	dst = Grow(dst, 3*len(body))
	for i := 0; i < len(body); {
		c := body[i]
		if c != '\\' {
			// encoding/json REJECTS both of these raw, and this decoder must
			// reject exactly what it rejects: a raw quote terminates the
			// literal, so anything following it is trailing garbage, and the
			// grammar requires every byte below 0x20 to be escaped.
			//
			// Unreachable from the credential path, where the input is always a
			// literal a successful json.Unmarshal already validated — but this
			// is an exported decoder whose stated contract is equivalence, and
			// accepting what the standard decoder refuses is a divergence in
			// the permissive direction, which is the worse one.
			if c == '"' || c < 0x20 {
				return dst, ErrMalformedJSONString
			}
			if c < utf8.RuneSelf {
				dst = append(dst, c)
				i++
				continue
			}
			// Coerce to well-formed UTF-8, byte for byte as encoding/json's
			// unquoteBytes does. DecodeRune returns (RuneError, 1) for an
			// invalid sequence, so each bad byte becomes one U+FFFD and a
			// valid multi-byte rune is copied through unchanged.
			//
			// Copying the raw bytes instead would be a DECODER DIVERGENCE, not
			// just a residency detail: a payload carrying invalid UTF-8 would
			// seal different credential bytes than the encoding/json path
			// sealed before this change, while still parsing successfully. The
			// acceptance criterion is that parsing is unchanged, and a
			// silently different credential is the worst way to break it.
			//
			// The encoder above does the same: both emit the replacement
			// rune's three raw bytes, as encoding/json does.
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

// JSONStringBytes is the decode target for a credential carried as a JSON
// string: a struct field of this type decodes like a string field, but lands
// the plaintext in a buffer the caller owns and wipes instead of an immutable
// Go string.
//
// It replaces json.RawMessage for that job because RawMessage accepts a value
// of any type and keeps only the last occurrence of a duplicated key, so
// {"password":123,"password":"ok"} decoded — where the string field it stands
// in for rejected it. encoding/json calls UnmarshalJSON once per occurrence,
// so validating here checks every occurrence of the key, and a wrong-typed one
// fails with the same *json.UnmarshalTypeError a string field reported.
//
// null leaves the value unchanged, as it does for a string field. The zero
// value is ready to use; call Wipe when done, on success and failure alike.
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

// decodeUnicodeEscape reads a \uXXXX escape at the start of s (s[0] == 'u'),
// combining a surrogate pair when one is present. Returns the rune and how
// many bytes of s were consumed.
//
// An unpaired surrogate becomes U+FFFD rather than an error: encoding/json
// accepts such input and substitutes the replacement character, and this decoder
// must accept exactly what encoding/json accepts or a payload that used to parse
// would start failing.
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
