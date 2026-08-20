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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
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
	// Key is the HMAC-SHA256 shared secret. Required. It is held in
	// protected memory and revealed only for the length of a single HMAC.
	// NewGenerator clones it, so the caller keeps ownership of the value it
	// passes in and may destroy that copy independently of the Generator.
	Key *secrets.SecureString
	// PrependUsername controls whether the password includes the
	// identity as the first field (`identity:ts:sig`) or just
	// `ts:sig`. Mirrors Java's builder flag.
	PrependUsername bool
	// Clock overrides time.Now for tests.
	Clock func() time.Time
}

// Generator issues HMAC-signed credentials. The shared secret lives in
// protected memory for the Generator's lifetime and is revealed only for the
// duration of a single HMAC computation. Call Destroy at shutdown to wipe it.
type Generator struct {
	cfg GeneratorConfig
}

// NewGenerator returns a Generator with cfg. The key is cloned into an
// allocation the Generator owns; cfg.Key is left untouched.
//
// The clone is taken first and the clone is what gets validated. Checking
// cfg.Key and then cloning it would be two separate reveals of a secret the
// caller still owns and may destroy in between, so a shutdown overlapping a
// startup could return a Generator that reported success and can never sign.
// Validating the key this Generator actually kept makes the constructor's
// verdict true of that key.
func NewGenerator(cfg GeneratorConfig) (*Generator, error) {
	// A clone that failed to allocate is NOT "no key configured": reporting it
	// as the latter would let memory pressure turn a configured generator into
	// a missing one. The two outcomes get different errors.
	key, err := cfg.Key.Clone()
	if err != nil {
		return nil, err
	}
	if key.IsDestroyed() {
		// An unset clone holds nothing to wipe today. Destroying it anyway
		// keeps the ownership contract total: whatever this constructor took
		// ownership of, it releases on the error path.
		key.Destroy()
		return nil, errors.New("external: Key is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	cfg.Key = key
	return &Generator{cfg: cfg}, nil
}

// Destroy wipes the generator's copy of the shared secret. Generate and
// Validate fail closed afterwards. Safe to call more than once.
func (g *Generator) Destroy() {
	if g == nil {
		return
	}
	g.cfg.Key.Destroy()
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
	// The credential is assembled in wipeable byte buffers and sealed from
	// them. Building it as a Go string first — `dataToSign + ":" + sig` — put
	// the finished bearer password in memory that cannot be wiped and that the
	// runtime is free to copy, so destroying the resulting SecureString left
	// the credential resident until the collector happened to run.
	ts := strconv.AppendInt(nil, g.cfg.Clock().Unix(), 10)
	defer wipe(ts)

	dataToSign := make([]byte, 0, len(identity)+1+len(ts))
	dataToSign = append(dataToSign, identity...)
	dataToSign = append(dataToSign, ':')
	dataToSign = append(dataToSign, ts...)
	defer wipe(dataToSign)

	sig, ok := g.hmac(dataToSign)
	if !ok {
		return nil, errors.New("external: generator has been destroyed")
	}
	defer wipe(sig)

	// Wire form is unchanged: `identity:ts:sig` or `ts:sig`, hex signature.
	var password []byte
	if g.cfg.PrependUsername {
		password = make([]byte, 0, len(dataToSign)+1+len(sig))
		password = append(password, dataToSign...)
	} else {
		password = make([]byte, 0, len(ts)+1+len(sig))
		password = append(password, ts...)
	}
	password = append(password, ':')
	password = append(password, sig...)

	// NewSecureStringFromBytes consumes and wipes password.
	sealed, err := secrets.NewSecureStringFromBytes(password)
	if err != nil {
		return nil, err
	}
	return &Credentials{Username: identity, Password: sealed}, nil
}

// wipe zeroes an intermediate buffer that held credential material. The
// finished credential is wiped by NewSecureStringFromBytes, which consumes
// what it seals; this covers the working buffers on the way there.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Validate verifies that creds was issued by this Generator and is not
// older than maxAge. Returns the embedded timestamp on success so the
// caller can apply additional age policy. The HMAC comparison is constant-
// time. Mirrors Java validateAndGetTimestamp + isCredentialExpired.
func (g *Generator) Validate(creds *Credentials, maxAge time.Duration) (time.Time, error) {
	if creds == nil {
		return time.Time{}, errors.New("external: nil credentials")
	}
	// Parse and compare inside the borrow: Plaintext() would copy the whole
	// credential into a Go string that cannot be wiped, which is the same
	// exposure Generate now avoids. Only the timestamp — not secret — leaves
	// this scope.
	var (
		tsDigits []byte
		verr     error
	)
	revealed := creds.Password.WithBytes(func(password []byte) {
		parts := bytes.Split(password, []byte{':'})
		var tsBytes, sig []byte
		switch {
		case len(parts) == 3 && g.cfg.PrependUsername:
			if !bytes.Equal(parts[0], []byte(creds.Username)) {
				verr = errors.New("external: identity mismatch")
				return
			}
			tsBytes, sig = parts[1], parts[2]
		case len(parts) == 2 && !g.cfg.PrependUsername:
			tsBytes, sig = parts[0], parts[1]
		default:
			verr = errors.New("external: malformed password")
			return
		}

		signed := make([]byte, 0, len(creds.Username)+1+len(tsBytes))
		signed = append(signed, creds.Username...)
		signed = append(signed, ':')
		signed = append(signed, tsBytes...)
		defer wipe(signed)

		expected, ok := g.hmac(signed)
		if !ok {
			verr = errors.New("external: generator has been destroyed")
			return
		}
		defer wipe(expected)

		if !hmac.Equal(expected, sig) {
			verr = errors.New("external: signature mismatch")
			return
		}
		// The timestamp is not secret; copy it out so parsing happens after
		// the protected pages are released.
		tsDigits = append(tsDigits, tsBytes...)
	})
	if !revealed {
		return time.Time{}, errors.New("external: credentials have no password")
	}
	if verr != nil {
		return time.Time{}, verr
	}
	tsInt, err := strconv.ParseInt(string(tsDigits), 10, 64)
	if err != nil {
		return time.Time{}, errors.New("external: malformed timestamp")
	}
	issued := time.Unix(tsInt, 0)
	if maxAge > 0 && g.cfg.Clock().Sub(issued) > maxAge {
		return issued, errors.New("external: credentials expired")
	}
	return issued, nil
}

// hmac returns the hex-encoded HMAC-SHA256 of data under the generator key,
// revealing the key from protected memory only for the length of the
// computation.
//
// Reports whether the key was available. False means the Generator has been
// destroyed, and both callers turn that into an error: signing with — or
// comparing against — an empty key would produce a credential an attacker can
// forge, so this fails closed rather than degrading.
func (g *Generator) hmac(data []byte) ([]byte, bool) {
	var sum []byte
	ok := g.cfg.Key.WithBytes(func(key []byte) {
		mac := hmac.New(sha256.New, key)
		mac.Write(data)
		raw := mac.Sum(nil)
		sum = make([]byte, hex.EncodedLen(len(raw)))
		hex.Encode(sum, raw)
		wipe(raw)
	})
	return sum, ok
}
