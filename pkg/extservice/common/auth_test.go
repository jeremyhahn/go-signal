package common

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestBasicAuthHeader_RoundTripsThroughValidate(t *testing.T) {
	const secret = "test-secret"
	hdr := BasicAuthHeader("alice", []byte(secret))
	user, ok := ValidateBasicAuth(hdr, []byte(secret))
	if !ok {
		t.Fatal("ValidateBasicAuth should accept matching credentials")
	}
	if user != "alice" {
		t.Errorf("user = %q", user)
	}
}

func TestBasicAuthHeader_HMACFormatIsHexEncodedHMACSHA256(t *testing.T) {
	const secret = "k"
	hdr := BasicAuthHeader("alice", []byte(secret))
	// Format: Basic base64("alice:" + hex(hmac-sha256(secret, "alice")))
	raw, err := base64.StdEncoding.DecodeString(hdr[len("Basic "):])
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("alice"))
	want := "alice:" + hex.EncodeToString(mac.Sum(nil))
	if string(raw) != want {
		t.Errorf("decoded = %q, want %q", raw, want)
	}
}

func TestValidateBasicAuth_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
	}{
		{"no prefix", base64.StdEncoding.EncodeToString([]byte("a:b"))},
		{"non-base64", "Basic !!!"},
		{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))},
		{"wrong password", "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := ValidateBasicAuth(c.hdr, []byte("secret")); ok {
				t.Error("expected rejection")
			}
		})
	}
}

func TestValidateBasicAuth_ConstantTimeAccept(t *testing.T) {
	const secret = "abc"
	hdr := BasicAuthHeader("alice", []byte(secret))
	// Sanity: a flipped bit must NOT validate.
	raw, _ := base64.StdEncoding.DecodeString(hdr[len("Basic "):])
	raw[len(raw)-1] ^= 0x01
	tampered := "Basic " + base64.StdEncoding.EncodeToString(raw)
	if _, ok := ValidateBasicAuth(tampered, []byte(secret)); ok {
		t.Error("tampered credential must not validate")
	}
}
