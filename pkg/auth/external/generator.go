// Package external implements Signal-Server's ExternalServiceCredentialsGenerator
// pattern — an HMAC-signed credential that proves the bearer presented
// `identity` to the Signal server within a short window. Mirrors Java's
// org.whispersystems.textsecuregcm.auth.ExternalServiceCredentialsGenerator.
//
// The generated token shape is `timestamp:signature` (or
// `identity:timestamp:signature` when prependUsername is true). The
// external service (TUS, Storage, SVR, …) validates by re-running the
// HMAC over `identity:timestamp` and comparing.
//
// We only implement the production-relevant configurations: full-length
// signatures, no derived usernames, no timestamp-as-username. Java
// supports those modes via builder flags; if a future endpoint needs them
// they can be added without breaking the existing surface.
package external

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// Credentials is the token pair returned by Generator.Generate. Username
// and Password follow Java's two-tuple naming so HTTP basic-auth wiring is
// 1:1.
//
// Password is a bearer credential for an external service, so it is held in
// protected memory between issuance and the point where a handler puts it on
// the wire. Callers read it with Password.Reveal() at that boundary — an
// unavailable credential must fail the request rather than travel as an empty
// password — and Destroy the credential once the response is written.
type Credentials struct {
	Username string
	Password *secrets.SecureString
}

// Destroy wipes the protected password. Safe on nil and idempotent.
func (c *Credentials) Destroy() {
	if c == nil {
		return
	}
	c.Password.Destroy()
}

// GeneratorConfig configures a Generator. The Key field is the HMAC
// secret shared with the external service. Clock is the wall-clock
// source; nil defaults to time.Now.
type GeneratorConfig struct {
	// Key is the HMAC-SHA256 shared secret. Required.
	Key []byte
	// PrependUsername controls whether the password includes the
	// identity as the first field (`identity:ts:sig`) or just
	// `ts:sig`. Mirrors Java's builder flag.
	PrependUsername bool
	// Clock overrides time.Now for tests.
	Clock func() time.Time
}

// Generator issues HMAC-signed credentials.
type Generator struct {
	cfg GeneratorConfig
}

// NewGenerator returns a Generator with cfg.
func NewGenerator(cfg GeneratorConfig) (*Generator, error) {
	if len(cfg.Key) == 0 {
		return nil, errors.New("external: Key is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Generator{cfg: cfg}, nil
}

// Generate returns a fresh credential for identity. The username matches
// identity verbatim; the password embeds the current timestamp (Unix
// seconds) so the external service can window the credential.
//
// Java parity: produces the same `username` / `password` layout as
// ExternalServiceCredentialsGenerator.generate when configured with
// prependUsername=cfg.PrependUsername, truncateSignature=false,
// shouldDeriveUsername=false, usernameIsTimestamp=false.
func (g *Generator) Generate(identity string) (*Credentials, error) {
	if identity == "" {
		return nil, errors.New("external: identity is required")
	}
	ts := strconv.FormatInt(g.cfg.Clock().Unix(), 10)
	dataToSign := identity + ":" + ts
	sig := g.hmac(dataToSign)
	var password string
	if g.cfg.PrependUsername {
		password = dataToSign + ":" + sig
	} else {
		password = ts + ":" + sig
	}
	sealed, err := secrets.NewSecureString(password)
	if err != nil {
		return nil, err
	}
	return &Credentials{Username: identity, Password: sealed}, nil
}

// Validate verifies that creds was issued by this Generator and is not
// older than maxAge. Returns the embedded timestamp on success so the
// caller can apply additional age policy. The HMAC comparison is constant-
// time. Mirrors Java validateAndGetTimestamp + isCredentialExpired.
func (g *Generator) Validate(creds *Credentials, maxAge time.Duration) (time.Time, error) {
	if creds == nil {
		return time.Time{}, errors.New("external: nil credentials")
	}
	parts := strings.Split(creds.Password.Plaintext(), ":")
	var tsStr, sig string
	switch {
	case len(parts) == 3 && g.cfg.PrependUsername:
		if parts[0] != creds.Username {
			return time.Time{}, errors.New("external: identity mismatch")
		}
		tsStr = parts[1]
		sig = parts[2]
	case len(parts) == 2 && !g.cfg.PrependUsername:
		tsStr = parts[0]
		sig = parts[1]
	default:
		return time.Time{}, errors.New("external: malformed password")
	}
	expected := g.hmac(creds.Username + ":" + tsStr)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return time.Time{}, errors.New("external: signature mismatch")
	}
	tsInt, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return time.Time{}, errors.New("external: malformed timestamp")
	}
	issued := time.Unix(tsInt, 0)
	if maxAge > 0 && g.cfg.Clock().Sub(issued) > maxAge {
		return issued, errors.New("external: credentials expired")
	}
	return issued, nil
}

// hmac returns the hex-encoded HMAC-SHA256 of data under the generator
// key.
func (g *Generator) hmac(data string) string {
	mac := hmac.New(sha256.New, g.cfg.Key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
