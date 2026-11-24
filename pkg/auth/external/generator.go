// Package external implements Signal's ExternalServiceCredentialsGenerator: HMAC-signed `[identity:]timestamp:signature` credentials for external services.
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

// Credentials is the username and password pair; Password stays in protected memory, read with Reveal() and destroyed after the response.
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
	// Key is the required HMAC-SHA256 secret; NewGenerator clones it into protected memory.
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

// NewGenerator returns a Generator owning a clone of cfg.Key, and validates the clone.
func NewGenerator(cfg GeneratorConfig) (*Generator, error) {
	// Presence and copy come from one snapshot; an allocation failure is an error, not a missing key.
	key, configured, err := cfg.Key.CloneWithPresence()
	if err != nil {
		return nil, err
	}
	if !configured {
		// An unset clone holds nothing to wipe today. Destroying it anyway
		// keeps the ownership contract total: whatever this constructor took
		// ownership of, it releases on the error path.
		key.Destroy()
		return nil, &MissingKeyError{}
	}
	// Prove the clone opens; configured but unreadable is UnusableKeyError.
	if err := key.TryWithBytes(func([]byte) {}); err != nil {
		key.Destroy()
		return nil, &UnusableKeyError{Cause: err}
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

// Generate returns a credential for identity whose password embeds the Unix time, in Java's layout.
func (g *Generator) Generate(identity string) (*Credentials, error) {
	if identity == "" {
		return nil, errors.New("external: identity is required")
	}
	// Build the credential in wipeable buffers, never a Go string.
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

// Validate checks creds was issued here and is within maxAge, returning its timestamp; the HMAC comparison is constant-time.
func (g *Generator) Validate(creds *Credentials, maxAge time.Duration) (time.Time, error) {
	if creds == nil {
		return time.Time{}, errors.New("external: nil credentials")
	}
	// Parse inside the borrow; only the timestamp leaves this scope.
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

// hmac returns hex HMAC-SHA256 of data and whether the key was available; callers fail closed without it.
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
