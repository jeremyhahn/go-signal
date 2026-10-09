// Package common holds client-side helpers shared by every
// pkg/extservice/* binary client (registration-service, svr2, cdsi,
// storage-service, key-transparency). Pulling these into one place
// keeps the credential-derivation and transport-policy code
// byte-identical across services — a divergence between them would
// silently break the HMAC contract or the mTLS pinning.
package common

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"

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
	// Assembled in wipeable buffers. `identity + ":" + password` put the
	// finished credential in a Go string that cannot be wiped and that the
	// runtime is free to copy — and so did hex.EncodeToString before it.
	//
	// The returned header still contains the credential, unavoidably: it is
	// the value the caller has to send. What this removes is the two extra
	// copies that outlived the call with nothing able to clear them.
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(identity))
	sum := mac.Sum(nil)
	defer secure.Wipe(sum)

	creds := make([]byte, 0, len(identity)+1+hex.EncodedLen(len(sum)))
	creds = append(creds, identity...)
	creds = append(creds, ':')
	creds = hex.AppendEncode(creds, sum)
	defer secure.Wipe(creds)

	enc := make([]byte, base64.StdEncoding.EncodedLen(len(creds)))
	defer secure.Wipe(enc)
	base64.StdEncoding.Encode(enc, creds)
	return "Basic " + string(enc)
}

// BasicAuthHeaderCredential builds a Basic auth header value from a credential
// that has ALREADY been issued, keeping the assembly in wipeable buffers.
//
// BasicAuthHeader derives the password from a shared secret by HMAC; this one
// is for callers that hold a generated username/password pair instead and must
// not re-derive it. The two are otherwise the same discipline, which is why
// they live together rather than being open-coded at the call site.
//
// Returns "" when the password is unset or destroyed, so a wiped credential
// fails closed instead of producing a header with an empty password that the
// far side would simply reject.
func BasicAuthHeaderCredential(identity string, password *secrets.SecureString) string {
	var header string
	password.WithBytes(func(pw []byte) {
		// `identity + ":" + password` put the finished credential in a Go
		// string that cannot be wiped and that the runtime is free to copy,
		// and base64.StdEncoding.EncodeToString added a second one.
		creds := make([]byte, 0, len(identity)+1+len(pw))
		creds = append(creds, identity...)
		creds = append(creds, ':')
		creds = append(creds, pw...)
		defer secure.Wipe(creds)

		enc := make([]byte, base64.StdEncoding.EncodedLen(len(creds)))
		defer secure.Wipe(enc)
		base64.StdEncoding.Encode(enc, creds)
		// The returned header still contains the credential, unavoidably: it
		// is the value the caller has to send. What this removes are the
		// copies that outlived the call with nothing able to clear them.
		header = "Basic " + string(enc)
	})
	return header
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
	// The decoded buffer holds `username:password`; wipe it on every path.
	// It used to be left resident, and `string(raw)` copied the credential
	// into memory that cannot be wiped merely to find the separator.
	defer secure.Wipe(raw)

	sep := bytes.IndexByte(raw, ':')
	if sep < 0 {
		return "", false
	}
	username := raw[:sep]
	password := raw[sep+1:]

	// The EXPECTED credential is as sensitive as the presented one — it is
	// the value an attacker needs — so it is derived into bytes and wiped
	// too, where hex.EncodeToString left it in an unwipeable string.
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(username)
	sum := mac.Sum(nil)
	defer secure.Wipe(sum)
	want := make([]byte, 0, hex.EncodedLen(len(sum)))
	want = hex.AppendEncode(want, sum)
	defer secure.Wipe(want)

	if subtle.ConstantTimeCompare(password, want) != 1 {
		return "", false
	}
	// The username is an account identity, not credential material, and is
	// this function's whole return value. The caller's authHeader string still
	// holds the encoded credential — it belongs to net/http and cannot be
	// wiped from here, which is a limit of this fix rather than an oversight.
	return string(username), true
}

// BasicAuthHeaderSecret is BasicAuthHeader with the shared secret drawn from
// protected memory. The key is revealed only for the length of the HMAC and
// wiped again before this returns, so a long-lived credential-signing secret
// never has to sit on the heap as a plain []byte.
//
// Returns "" when the secret is unset or destroyed — the caller must treat
// that as a failure to authenticate rather than sending an unsigned header.
func BasicAuthHeaderSecret(identity string, sharedSecret *secrets.SecureString) string {
	var header string
	sharedSecret.WithBytes(func(key []byte) {
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
func ValidateBasicAuthSecret(authHeader string, sharedSecret *secrets.SecureString) (string, bool) {
	var (
		username string
		ok       bool
	)
	sharedSecret.WithBytes(func(key []byte) {
		username, ok = ValidateBasicAuth(authHeader, key)
	})
	return username, ok
}
