package auth

import (
	"encoding/hex"
	"testing"
)

// TestSigV4SigningKey_AWSVector validates the SigV4 signing-key derivation (the
// HMAC chain underlying SignS3PostPolicy) against the canonical vector AWS
// publishes in its "Calculate the signature" documentation:
//
//	secret  = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
//	date    = "20150830", region = "us-east-1", service = "iam"
//	=> signing key c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9
func TestSigV4SigningKey_AWSVector(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte("20150830"))
	kRegion := hmacSHA256(kDate, []byte("us-east-1"))
	kService := hmacSHA256(kRegion, []byte("iam"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	got := hex.EncodeToString(kSigning)
	want := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got != want {
		t.Fatalf("signing key mismatch:\n got  %s\n want %s", got, want)
	}
}

// TestSignS3PostPolicy_WiringAndDeterminism verifies SignS3PostPolicy derives
// the s3 signing key and HMACs the policy, and that it is deterministic.
func TestSignS3PostPolicy_WiringAndDeterminism(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	policy := "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMVQwMDowMDowMFoifQ==" // arbitrary base64

	// Independently derive the expected signature via the documented chain.
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	want := hex.EncodeToString(hmacSHA256(kSigning, []byte(policy)))

	got := SignS3PostPolicy(secret, date, region, policy)
	if got != want {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", got, want)
	}

	// Determinism: identical inputs yield identical output.
	if again := SignS3PostPolicy(secret, date, region, policy); again != got {
		t.Fatalf("non-deterministic signature: %s != %s", again, got)
	}

	// A different policy must change the signature.
	if SignS3PostPolicy(secret, date, region, policy+"x") == got {
		t.Fatal("signature did not change for a different policy")
	}
}
