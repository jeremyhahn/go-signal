package s3

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// fixedTime returns a deterministic UTC instant used by signature tests so
// the AWS-published HMAC vectors line up with our derivation.
func fixedTime() time.Time {
	return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
}

func TestDeriveSigningKey_S3ProducesStableKeyLength(t *testing.T) {
	// HMAC-SHA256 always returns 32 bytes; guard against an accidental
	// switch to a different hash that would silently break SigV4.
	got := deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3")
	if len(got) != 32 {
		t.Errorf("kSigning length = %d, want 32 (SHA-256)", len(got))
	}
	// The same inputs produce the same key — catch any accidental
	// non-deterministic state inside hmacSHA256.
	again := deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3")
	if hexOf(got) != hexOf(again) {
		t.Errorf("deriveSigningKey not deterministic: %s vs %s", hexOf(got), hexOf(again))
	}
	// Changing any input changes the output (sanity test of the chain).
	other := deriveSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20130525", "us-east-1", "s3")
	if hexOf(got) == hexOf(other) {
		t.Error("kSigning unchanged when date changed")
	}
}

// hexOf returns a lowercase hex string of b.
func hexOf(b []byte) string {
	const hexChars = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(hexChars[x>>4])
		sb.WriteByte(hexChars[x&0x0f])
	}
	return sb.String()
}

func TestPolicyGenerator_Generate_HappyPath(t *testing.T) {
	g := &PolicyGenerator{Region: "us-east-1", Bucket: "signal-stickers", AccessKeyID: "AKID"}
	policy, credential, err := g.Generate(fixedTime(), "stickers/abc/manifest.proto", 10_000)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(policy, `"bucket": "signal-stickers"`) {
		t.Errorf("bucket missing: %s", policy)
	}
	if !strings.Contains(policy, `"key": "stickers/abc/manifest.proto"`) {
		t.Errorf("key missing: %s", policy)
	}
	if !strings.Contains(policy, `"content-length-range", 1, 10000`) {
		t.Errorf("content-length-range missing: %s", policy)
	}
	wantCred := "AKID/20150830/us-east-1/s3/aws4_request"
	if credential != wantCred {
		t.Errorf("credential = %q, want %q", credential, wantCred)
	}
	// Expiration is 30 minutes after now.
	if !strings.Contains(policy, "2015-08-30T13:06:00Z") {
		t.Errorf("expiration window wrong: %s", policy)
	}
}

func TestPolicyGenerator_Generate_RequiresAllFields(t *testing.T) {
	cases := []struct {
		name string
		g    PolicyGenerator
		key  string
		size int64
	}{
		{"no region", PolicyGenerator{Bucket: "b", AccessKeyID: "k"}, "k", 1},
		{"no bucket", PolicyGenerator{Region: "r", AccessKeyID: "k"}, "k", 1},
		{"no access key", PolicyGenerator{Region: "r", Bucket: "b"}, "k", 1},
		{"empty object key", PolicyGenerator{Region: "r", Bucket: "b", AccessKeyID: "k"}, "", 1},
		{"zero size", PolicyGenerator{Region: "r", Bucket: "b", AccessKeyID: "k"}, "k", 0},
		{"negative size", PolicyGenerator{Region: "r", Bucket: "b", AccessKeyID: "k"}, "k", -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := c.g.Generate(fixedTime(), c.key, c.size); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestPolicySigner_Sign_HappyPathDeterministic(t *testing.T) {
	policy := "test-policy-bytes"
	encoded := base64.StdEncoding.EncodeToString([]byte(policy))

	s := &PolicySigner{SecretAccessKey: secrets.MustNewSecureString(t.Context(), "secret"), Region: "us-east-1"}
	sig1, err := s.Sign(t.Context(), fixedTime(), encoded)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig2, err := s.Sign(t.Context(), fixedTime(), encoded)
	if err != nil {
		t.Fatalf("Sign 2: %v", err)
	}
	if sig1 != sig2 {
		t.Errorf("Sign not deterministic for the same inputs")
	}
	if len(sig1) != 64 {
		t.Errorf("signature length = %d, want 64 (hex SHA-256)", len(sig1))
	}
}

func TestPolicySigner_Sign_DifferentDatesDifferentSignatures(t *testing.T) {
	s := &PolicySigner{SecretAccessKey: secrets.MustNewSecureString(t.Context(), "secret"), Region: "us-east-1"}
	day1, _ := s.Sign(t.Context(), fixedTime(), "policy")
	day2, _ := s.Sign(t.Context(), fixedTime().Add(48*time.Hour), "policy")
	if day1 == day2 {
		t.Error("different dates must produce different signatures")
	}
}

func TestPolicySigner_Sign_RequiresFields(t *testing.T) {
	if _, err := (&PolicySigner{Region: "r"}).Sign(t.Context(), fixedTime(), "policy"); err == nil {
		t.Error("expected error for missing secret")
	}
	if _, err := (&PolicySigner{SecretAccessKey: secrets.MustNewSecureString(t.Context(), "s")}).Sign(t.Context(), fixedTime(), "policy"); err == nil {
		t.Error("expected error for missing region")
	}
}

func TestFormatForm_HappyPath(t *testing.T) {
	form, err := FormatForm(
		t.Context(),
		&PolicyGenerator{Region: "us-east-1", Bucket: "b", AccessKeyID: "AKID"},
		&PolicySigner{SecretAccessKey: secrets.MustNewSecureString(t.Context(), "secret"), Region: "us-east-1"},
		fixedTime(),
		"stickers/x/manifest.proto",
		10_000,
	)
	if err != nil {
		t.Fatalf("FormatForm: %v", err)
	}
	if form.Algorithm != "AWS4-HMAC-SHA256" {
		t.Errorf("algorithm = %q", form.Algorithm)
	}
	if form.Acl != "private" {
		t.Errorf("acl = %q", form.Acl)
	}
	if form.Date != "20150830T123600Z" {
		t.Errorf("date = %q", form.Date)
	}
	if form.Credential != "AKID/20150830/us-east-1/s3/aws4_request" {
		t.Errorf("credential = %q", form.Credential)
	}
	// Decode the policy and confirm round-trip.
	decoded, err := base64.StdEncoding.DecodeString(form.Policy)
	if err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if !strings.Contains(string(decoded), `"key": "stickers/x/manifest.proto"`) {
		t.Errorf("decoded policy missing object key: %s", decoded)
	}
}

func TestFormatForm_GeneratorErrorPropagates(t *testing.T) {
	_, err := FormatForm(
		t.Context(),
		&PolicyGenerator{}, // missing fields
		&PolicySigner{SecretAccessKey: secrets.MustNewSecureString(t.Context(), "s"), Region: "r"},
		fixedTime(), "k", 1,
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFormatForm_SignerErrorPropagates(t *testing.T) {
	_, err := FormatForm(
		t.Context(),
		&PolicyGenerator{Region: "r", Bucket: "b", AccessKeyID: "k"},
		&PolicySigner{}, // missing fields
		fixedTime(), "k", 1,
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestEncodePolicy_RoundTrip(t *testing.T) {
	in := `{"hello":"world"}`
	got := EncodePolicy(in)
	dec, err := base64.StdEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(dec) != in {
		t.Errorf("round-trip failed: %q vs %q", dec, in)
	}
}
