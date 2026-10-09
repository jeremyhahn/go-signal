package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// jsonCorpus covers every branch of the encoder, chosen so a missing case is a
// failing test rather than a rare production surprise: the short escapes, the
// \u00XX range, the HTML characters encoding/json escapes by default, the two
// JavaScript line terminators, multi-byte UTF-8, invalid UTF-8, and the
// boundaries around them.
var jsonCorpus = []string{
	"", "hunter2", "a b c",
	`"`, `\`, `/`, `both " and \`,
	"\n", "\r", "\t", "\b", "\f",
	"\x00", "\x01", "\x1f", "\x20", "\x7f",
	"<", ">", "&", "a<b>c&d", "<script>alert(1)</script>",
	"é", "☃", "𝄞", "日本語",
	"\u2028", "\u2029", "before\u2028after\u2029end",
	string([]byte{0xff}), string([]byte{0xc3, 0x28}), string([]byte{0xed, 0xa0, 0x80}),
	"ts:0123456789abcdef", "user:1724371200:9f8e7d",
	strings.Repeat("x", 1024),
}

// The whole point of hand-rolling an encoder is that the wire form does not
// change. That is not a claim to make in a comment — it is asserted against
// encoding/json for every input, because a "prettier" escaping choice here
// would silently alter every credential response containing one of these bytes.
func TestAppendJSONStringFromBytes_ByteIdenticalToEncodingJSON(t *testing.T) {
	for _, s := range jsonCorpus {
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			want, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			got := appendJSONStringFromBytes(nil, []byte(s))
			if !bytes.Equal(got, want) {
				t.Errorf("encoding differs from encoding/json:\n  got  %s\n  want %s", got, want)
			}
		})
	}
}

// Randomised, because a fixed corpus only covers the cases someone thought of.
// Bytes are drawn from the full 0..255 range so invalid UTF-8 appears often.
func TestAppendJSONStringFromBytes_ByteIdenticalOnRandomInput(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 4000; i++ {
		b := make([]byte, rng.Intn(24))
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		want, err := json.Marshal(string(b))
		if err != nil {
			t.Fatalf("json.Marshal(%q): %v", b, err)
		}
		if got := appendJSONStringFromBytes(nil, b); !bytes.Equal(got, want) {
			t.Fatalf("input %q:\n  got  %s\n  want %s", b, got, want)
		}
	}
}

// Exhaustive over every one- and two-byte input, so no combination of control
// characters, HTML characters, UTF-8 lead and continuation bytes, or the
// start of U+2028/U+2029 can diverge from encoding/json unnoticed. The
// reference is the toolchain's own encoder, so a release that changes how it
// writes invalid UTF-8 fails here instead of silently changing the wire form.
func TestAppendJSONStringFromBytes_ByteIdenticalOnEveryShortInput(t *testing.T) {
	check := func(b []byte) {
		t.Helper()
		want, err := json.Marshal(string(b))
		if err != nil {
			t.Fatalf("json.Marshal(%q): %v", b, err)
		}
		if got := appendJSONStringFromBytes(nil, b); !bytes.Equal(got, want) {
			t.Fatalf("input % x:\n  got  %s\n  want %s", b, got, want)
		}
	}
	for i := 0; i < 256; i++ {
		check([]byte{byte(i)})
		for j := 0; j < 256; j++ {
			check([]byte{byte(i), byte(j)})
		}
	}
	// The three-byte sequences around the line separators and surrogates.
	for _, b := range [][]byte{
		{0xe2, 0x80, 0xa7}, {0xe2, 0x80, 0xa8}, {0xe2, 0x80, 0xa9}, {0xe2, 0x80, 0xaa},
		{0xed, 0x9f, 0xbf}, {0xed, 0xa0, 0x80}, {0xed, 0xbf, 0xbf}, {0xee, 0x80, 0x80},
		{0xef, 0xbf, 0xbd}, {0xf4, 0x8f, 0xbf, 0xbf}, {0xf4, 0x90, 0x80, 0x80},
	} {
		check(b)
	}
}

// Appending must respect an existing prefix — the credential marshallers build
// one buffer for the whole object.
func TestAppendJSONStringFromBytes_AppendsToExistingBuffer(t *testing.T) {
	dst := []byte(`{"password":`)
	got := appendJSONStringFromBytes(dst, []byte("secret"))
	if want := `{"password":"secret"`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// Round trip: whatever encoding/json produces, the byte decoder must recover
// the original bytes exactly — including for input encoding/json itself alters
// (invalid UTF-8 becomes U+FFFD before it is ever encoded).
func TestAppendUnquotedJSONString_RoundTripsEncodingJSON(t *testing.T) {
	for _, s := range jsonCorpus {
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			encoded, err := json.Marshal(s)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			got, err := AppendUnquotedJSONString(nil, encoded)
			if err != nil {
				t.Fatalf("AppendUnquotedJSONString: %v", err)
			}
			// encoding/json replaces invalid UTF-8 on the way out, so the
			// fixed point is what encoding/json ITSELF decodes back, not the
			// original bytes.
			var want string
			if err := json.Unmarshal(encoded, &want); err != nil {
				t.Fatalf("json.Unmarshal: %v", err)
			}
			if string(got) != want {
				t.Errorf("round trip lost data:\n  got  %q\n  want %q", got, want)
			}
		})
	}
}

// Escapes encoding/json accepts but never emits must still decode, or a payload
// that used to parse would start failing.
func TestAppendUnquotedJSONString_AcceptsWhatEncodingJSONAccepts(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`"\u0041"`, "A"},
		{`"\/"`, "/"},
		{`"\b\f"`, "\b\f"},
		{`"\ud83d\ude00"`, "\U0001F600"}, // surrogate pair
		{`"\ud800"`, string(utf8.RuneError)},
		{`"\udc00"`, string(utf8.RuneError)},
		{`"\u00e9"`, "é"},
	} {
		got, err := AppendUnquotedJSONString(nil, []byte(tc.in))
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		var viaStdlib string
		if err := json.Unmarshal([]byte(tc.in), &viaStdlib); err != nil {
			t.Fatalf("%s: stdlib rejected it: %v", tc.in, err)
		}
		if string(got) != tc.want || viaStdlib != tc.want {
			t.Errorf("%s: got %q, stdlib %q, want %q", tc.in, got, viaStdlib, tc.want)
		}
	}
}

func TestAppendUnquotedJSONString_RejectsMalformed(t *testing.T) {
	for _, in := range []string{``, `"`, `x"`, `"x`, `"\`, `"\q"`, `"\u12"`, `"\uZZZZ"`,
		// Raw bytes the JSON grammar requires to be escaped. A decoder that
		// waves these through accepts documents encoding/json refuses.
		`"a"b"`, "\"raw\nnewline\"", "\"raw\ttab\"", "\"nul\x00byte\"", "\"\x1f\"",
	} {
		if _, err := AppendUnquotedJSONString(nil, []byte(in)); err == nil {
			t.Errorf("%q: expected an error, got none", in)
		}
	}
}

// The secret serialises itself without the plaintext becoming a Go string.
func TestSecureString_AppendJSONString(t *testing.T) {
	s := MustNewSecureString(`p@ss"w<o>rd`)
	defer s.Destroy()

	got, err := s.AppendJSONString([]byte(`{"password":`))
	if err != nil {
		t.Fatalf("AppendJSONString: %v", err)
	}
	want, _ := json.Marshal(`p@ss"w<o>rd`)
	if string(got) != `{"password":`+string(want) {
		t.Errorf("got %s, want %s", got, `{"password":`+string(want))
	}
}

// An unreadable secret must fail the caller rather than emit an empty
// credential a client would treat as valid — and must append nothing.
func TestSecureString_AppendJSONString_UnreadableFailsClosed(t *testing.T) {
	destroyed := MustNewSecureString("x")
	destroyed.Destroy()
	absent, err := NewOptionalSecureString("")
	if err != nil {
		t.Fatalf("NewOptionalSecureString: %v", err)
	}
	var nilSecret *SecureString

	for name, s := range map[string]*SecureString{"nil": nilSecret, "destroyed": destroyed, "absent": absent} {
		t.Run(name, func(t *testing.T) {
			prefix := []byte(`{"password":`)
			got, err := s.AppendJSONString(prefix)
			if err == nil {
				t.Fatal("expected an error for an unreadable secret")
			}
			if string(got) != string(prefix) {
				t.Errorf("appended %q on failure; nothing should be written", got[len(prefix):])
			}
		})
	}
}

// TestAppendJSONStringFromBytes_GrowsOnceSoNoPlaintextIsAbandoned measures the
// property that has no behavioural signature: the output bytes are identical
// whether or not the buffer is grown up front, so every test above passes
// either way. What differs is how many times append() reallocates — and each
// reallocation abandons an array holding part of the escaped plaintext that
// nothing holds a reference to any more, so nothing can wipe it.
//
// One allocation is the single deliberate Grow. The input is chosen so every
// byte escapes to \u00XX, which is maximum growth pressure and therefore the
// case where an ungrown append reallocates most.
func TestAppendJSONStringFromBytes_GrowsOnceSoNoPlaintextIsAbandoned(t *testing.T) {
	src := bytes.Repeat([]byte{0x01}, 512)
	allocs := testing.AllocsPerRun(50, func() {
		_ = appendJSONStringFromBytes(nil, src)
	})
	if allocs > 1 {
		t.Errorf("appendJSONStringFromBytes made %.0f allocations for a %d-byte all-escaping input; "+
			"more than one means append() reallocated mid-write and abandoned an array "+
			"holding part of the plaintext, which nothing can wipe", allocs, len(src))
	}
}

// The round-trip test above can never reach this: it feeds the decoder
// encoding/json's OWN output, and encoding/json escapes invalid UTF-8 to
// `�` on the way out, so the decoder only ever sees clean ASCII. A
// payload that did not come from encoding/json — a hand-written body, another
// language's serializer — can carry raw invalid UTF-8 inside a string literal,
// and encoding/json accepts it, coercing each bad byte to U+FFFD.
//
// A decoder that copied those bytes through verbatim would seal DIFFERENT
// credential bytes than the encoding/json path sealed before this change,
// while still parsing successfully. That is a silent protocol divergence, and
// the acceptance criterion for this work is that parsing is unchanged.
func TestAppendUnquotedJSONString_CoercesRawInvalidUTF8LikeEncodingJSON(t *testing.T) {
	for _, in := range []string{
		"\"a\xffb\"",           // lone invalid byte
		"\"\xff\"",             // nothing but an invalid byte
		"\"\xc3\"",             // truncated two-byte sequence
		"\"\xe2\x82\"",         // truncated three-byte sequence
		"\"\xf0\x9f\x98\"",     // truncated four-byte sequence
		"\"\xff\xfe\xfd\"",     // a run of them, each its own replacement
		"\"caf\xc3\xa9\"",      // VALID multi-byte must pass through intact
		"\"pw\xffs\xc3\xa9t\"", // mixed valid and invalid
	} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			var viaStdlib string
			if err := json.Unmarshal([]byte(in), &viaStdlib); err != nil {
				t.Fatalf("stdlib rejected input this decoder must match: %v", err)
			}
			got, err := AppendUnquotedJSONString(nil, []byte(in))
			if err != nil {
				t.Fatalf("AppendUnquotedJSONString: %v", err)
			}
			if string(got) != viaStdlib {
				t.Errorf("decoder diverges from encoding/json:\n  got     % x\n  stdlib  % x", got, []byte(viaStdlib))
			}
		})
	}
}

// Randomised over the full byte range, because the fixed cases above only
// cover the malformed sequences someone thought of. Bytes that cannot appear
// unescaped in a JSON string literal are excluded; everything else, valid
// UTF-8 or not, must decode to exactly what encoding/json decodes.
func TestAppendUnquotedJSONString_MatchesEncodingJSONOnRandomRawBytes(t *testing.T) {
	rng := rand.New(rand.NewSource(20260828))
	for i := 0; i < 4000; i++ {
		body := make([]byte, rng.Intn(12))
		for j := range body {
			// The full byte range, INCLUDING raw quotes, raw control bytes and
			// backslashes. Excluding them — as this generator did originally —
			// meant the only inputs ever produced were ones both decoders
			// accept, so the parity check above had nothing to bite on.
			body[j] = byte(rng.Intn(256))
		}
		in := append(append([]byte{'"'}, body...), '"')
		var viaStdlib string
		stdlibErr := json.Unmarshal(in, &viaStdlib)
		got, err := AppendUnquotedJSONString(nil, in)

		// Parity in BOTH directions. Skipping the inputs stdlib rejects — which
		// this test did originally — makes it blind to OVER-acceptance, and
		// over-acceptance is the worse divergence: it seals credential bytes
		// from a payload the standard decoder would have refused outright.
		if stdlibErr != nil {
			if err == nil {
				t.Fatalf("input %q: stdlib rejected it (%v) but this decoder accepted it as % x",
					in, stdlibErr, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("input %q: stdlib accepted but this decoder rejected: %v", in, err)
		}
		if string(got) != viaStdlib {
			t.Fatalf("input %q diverges:\n  got     % x\n  stdlib  % x", in, got, []byte(viaStdlib))
		}
	}
}

// The decoder must grow its destination ONCE, for the same reason the encoder
// must: a reallocation partway abandons an array already holding decoded
// credential bytes, and nothing can reach it to wipe it.
//
// This is not hypothetical for the decoder. Decoding usually shrinks, so a
// capacity of len(src) looks sufficient — but an invalid UTF-8 byte expands to
// the three bytes of U+FFFD, so the output can exceed the input on exactly the
// malformed payload the coercion above was added to accept.
func TestAppendUnquotedJSONString_GrowsOnceSoNoPlaintextIsAbandoned(t *testing.T) {
	in := []byte("\"" + strings.Repeat("\xff", 64) + "\"")
	allocs := testing.AllocsPerRun(100, func() {
		out, err := AppendUnquotedJSONString(nil, in)
		if err != nil {
			t.Fatalf("AppendUnquotedJSONString: %v", err)
		}
		secure.Wipe(out)
	})
	if allocs > 1 {
		t.Errorf("decoder allocated %.0f times; every allocation past the first "+
			"abandons an array holding decoded credential bytes", allocs)
	}
}
