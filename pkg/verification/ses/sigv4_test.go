package ses

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// fixedNow returns a static UTC instant the SigV4 reference vectors use:
//
//	2015-08-30T12:36:00Z. AWS publishes signing example outputs for this
//	timestamp so we can validate our implementation byte-for-byte.
func fixedNow() time.Time {
	return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
}

// TestDeriveSigningKey checks the kSigning derivation against the AWS
// reference example in:
//
//	https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
//
// The expected key for us-east-1/iam at 2015-08-30 is the hex digest below.
func TestDeriveSigningKey_AWSReference(t *testing.T) {
	got := deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam")
	wantHex := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	gotHex := toHex(got)
	if gotHex != wantHex {
		t.Errorf("kSigning = %s, want %s", gotHex, wantHex)
	}
}

// toHex is a tiny helper that returns a lower-case hex string of b. The
// name avoids colliding with the stdlib encoding/hex package import.
func toHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(hexChars[x>>4])
		sb.WriteByte(hexChars[x&0x0f])
	}
	return sb.String()
}

func TestHexSHA256(t *testing.T) {
	// SHA-256("hello world") published constant.
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got := hexSHA256([]byte("hello world")); got != want {
		t.Errorf("hexSHA256 = %s, want %s", got, want)
	}
}

func TestCanonicalURI(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/v2/email/outbound-emails", "/v2/email/outbound-emails"},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(http.MethodPost, "https://example.com"+c.path, nil)
		if got := canonicalURI(req.URL); got != c.want {
			t.Errorf("canonicalURI(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

func TestCanonicalQuery_SortsAndEncodes(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/?b=2&a=1&b=3", nil)
	got := canonicalQuery(req.URL)
	want := "a=1&b=2&b=3"
	if got != want {
		t.Errorf("canonicalQuery = %q, want %q", got, want)
	}
}

func TestCanonicalQuery_EmptyReturnsEmpty(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.com/", nil)
	if got := canonicalQuery(req.URL); got != "" {
		t.Errorf("empty query produced %q", got)
	}
}

func TestAwsURIEncode_RespectsSlashFlag(t *testing.T) {
	if got := awsURIEncode("a/b", false); got != "a/b" {
		t.Errorf("encodeSlash=false: got %q", got)
	}
	if got := awsURIEncode("a/b", true); got != "a%2Fb" {
		t.Errorf("encodeSlash=true: got %q", got)
	}
}

func TestSign_AddsAllExpectedHeaders(t *testing.T) {
	signer := &sigV4{
		accessKeyID:     "AKIDEXAMPLE",
		secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		region:          "us-east-1",
		service:         sesService,
		now:             fixedNow,
	}
	body := []byte(`{"hello":"world"}`)
	req, _ := http.NewRequest(http.MethodPost, "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails",
		strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if err := signer.Sign(req, body); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20150830T123600Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("Authorization does not start with AWS4-HMAC-SHA256: %s", auth)
	}
	if !strings.Contains(auth, "Credential=AKIDEXAMPLE/20150830/us-east-1/ses/aws4_request") {
		t.Errorf("Credential scope incorrect: %s", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=") {
		t.Errorf("SignedHeaders missing: %s", auth)
	}
	if !strings.Contains(auth, "Signature=") {
		t.Errorf("Signature missing: %s", auth)
	}
	// Determinism guard: signing the same request twice must produce the
	// same signature. Detects accidental non-deterministic state inside
	// canonicalHeaders / awsURIEncode.
	req2, _ := http.NewRequest(http.MethodPost, "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails",
		strings.NewReader(string(body)))
	req2.Header.Set("Content-Type", "application/json")
	if err := signer.Sign(req2, body); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if req.Header.Get("Authorization") != req2.Header.Get("Authorization") {
		t.Errorf("Sign not deterministic:\n  first=%s\n  second=%s", req.Header.Get("Authorization"), req2.Header.Get("Authorization"))
	}
}

func TestSign_PropagatesSessionToken(t *testing.T) {
	signer := &sigV4{
		accessKeyID:     "AKID",
		secretAccessKey: "secret",
		sessionToken:    "stoken",
		region:          "us-east-1",
		service:         sesService,
		now:             fixedNow,
	}
	req, _ := http.NewRequest(http.MethodPost, "https://email.us-east-1.amazonaws.com/v2/email/outbound-emails",
		strings.NewReader("{}"))
	if err := signer.Sign(req, []byte("{}")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got := req.Header.Get("X-Amz-Security-Token"); got != "stoken" {
		t.Errorf("X-Amz-Security-Token = %q, want stoken", got)
	}
}

func TestSign_RejectsMissingCredentials(t *testing.T) {
	signer := &sigV4{region: "us-east-1"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("{}"))
	if err := signer.Sign(req, []byte("{}")); err == nil {
		t.Fatal("expected error for missing creds")
	}
}

func TestSign_RejectsMissingRegion(t *testing.T) {
	signer := &sigV4{accessKeyID: "k", secretAccessKey: "s"}
	req, _ := http.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("{}"))
	if err := signer.Sign(req, []byte("{}")); err == nil {
		t.Fatal("expected error for missing region")
	}
}
