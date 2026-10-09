// Package common holds client-side helpers shared by every
// pkg/extservice/* binary client (registration-service, svr2, cdsi,
// storage-service, key-transparency). Pulling these into one place
// keeps the credential-derivation and transport-policy code
// byte-identical across services — a divergence between them would
// silently break the HMAC contract or the mTLS pinning.
package common

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// BasicAuthHeader builds the HTTP Basic auth header value Signal's
// external services expect. The password is the hex-encoded
// HMAC-SHA256 of identity under sharedSecret. Mirrors Java's
// ExternalServiceCredentialsGenerator.
//
// Use this on the chat-server side when constructing requests to
// svr2 / storage-service. Use ValidateBasicAuth on the service-side
// to verify inbound credentials.
func BasicAuthHeader(identity string, sharedSecret []byte) string {
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(identity))
	password := hex.EncodeToString(mac.Sum(nil))
	creds := identity + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// ValidateBasicAuth parses a "Basic <base64>" Authorization header,
// verifies the password matches HMAC-SHA256(sharedSecret, username)
// hex-encoded, and returns the username on success.
//
// Comparison is constant-time. Returns ("", false) on any failure.
func ValidateBasicAuth(authHeader string, sharedSecret []byte) (string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return "", false
	}
	sep := strings.IndexByte(string(raw), ':')
	if sep < 0 {
		return "", false
	}
	username := string(raw[:sep])
	password := string(raw[sep+1:])
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(username))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(password), []byte(want)) != 1 {
		return "", false
	}
	return username, true
}

// BasicAuthHeaderSecret is BasicAuthHeader with the shared secret drawn from
// protected memory. The key is revealed only for the length of the HMAC and
// wiped again before this returns, so a long-lived credential-signing secret
// never has to sit on the heap as a plain []byte.
//
// Returns "" when the secret is unset or destroyed — the caller must treat
// that as a failure to authenticate rather than sending an unsigned header.
func BasicAuthHeaderSecret(ctx context.Context, identity string, sharedSecret *secrets.SecureString) string {
	var header string
	sharedSecret.WithBytes(ctx, func(key []byte) {
		header = BasicAuthHeader(identity, key)
	})
	return header
}

// ValidateBasicAuthSecret is ValidateBasicAuth with the shared secret drawn
// from protected memory, with the same reveal-and-wipe discipline as
// BasicAuthHeaderSecret.
//
// Returns ("", false) when the secret is unset or destroyed, so a wiped
// secret fails closed instead of authenticating anything.
func ValidateBasicAuthSecret(ctx context.Context, authHeader string, sharedSecret *secrets.SecureString) (string, bool) {
	var (
		username string
		ok       bool
	)
	sharedSecret.WithBytes(ctx, func(key []byte) {
		username, ok = ValidateBasicAuth(authHeader, key)
	})
	return username, ok
}
