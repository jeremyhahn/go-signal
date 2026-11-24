// Package common holds the credential and transport helpers every pkg/extservice client shares.
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

// BasicAuthHeader returns the Basic auth value with password hex(HMAC-SHA256(sharedSecret, identity)); services verify with ValidateBasicAuth.
func BasicAuthHeader(identity string, sharedSecret []byte) string {
	// Assembled in wipeable buffers; only the returned header holds the credential.
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

// BasicAuthHeaderCredential returns a Basic auth value for an issued credential, built in wipeable buffers; "" when the password is unset or destroyed.
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

// ValidateBasicAuth verifies a Basic header's password is hex HMAC-SHA256(sharedSecret, username) in constant time and returns the username.
func ValidateBasicAuth(authHeader string, sharedSecret []byte) (string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(authHeader[len(prefix):])
	if err != nil {
		return "", false
	}
	// The decoded username:password buffer is wiped on every path.
	defer secure.Wipe(raw)

	sep := bytes.IndexByte(raw, ':')
	if sep < 0 {
		return "", false
	}
	username := raw[:sep]
	password := raw[sep+1:]

	// The expected credential is derived into bytes and wiped too.
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
	// The username is an identity, not credential material; the caller's header string is outside this function's reach.
	return string(username), true
}

// BasicAuthHeaderSecret is BasicAuthHeader with the secret revealed from protected memory only for the HMAC; "" when unset or destroyed.
func BasicAuthHeaderSecret(identity string, sharedSecret *secrets.SecureString) string {
	var header string
	sharedSecret.WithBytes(func(key []byte) {
		header = BasicAuthHeader(identity, key)
	})
	return header
}

// ValidateBasicAuthSecret is ValidateBasicAuth with the secret from protected memory; ("", false) when unset or destroyed.
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
