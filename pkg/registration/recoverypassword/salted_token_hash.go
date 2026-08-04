package recoverypassword

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	libsignalkdf "github.com/jeremyhahn/go-libsignal/pkg/kdf"
)

// SaltedTokenHash mirrors Java Signal-Server's
// org.whispersystems.textsecuregcm.auth.SaltedTokenHash record. The Hash field
// always carries the V2 prefix "2." followed by 64 lowercase hex characters
// (32 derived bytes); the Salt is 32 lowercase hex characters (16 random bytes).
//
// V1 was a single SHA1 of (salt || token); we reject it on read for parity
// with current Java which still verifies V1 but never produces it. See
// `Verify` for the V1-acceptance behavior.
type SaltedTokenHash struct {
	Hash string
	Salt string
}

const (
	// v2Prefix is the leading marker on a V2 SaltedTokenHash. Must match
	// Java's V2_PREFIX exactly so cross-implementation reads succeed.
	v2Prefix = "2."

	// authTokenHKDFInfo is the HKDF info parameter used by the V2 derivation.
	// It MUST be the literal UTF-8 bytes of "authtoken" — Java's
	// SaltedTokenHash hard-codes this string.
	authTokenHKDFInfo = "authtoken"

	// hashByteLen is the number of HKDF-derived bytes in a V2 hash (32 bytes
	// = 64 hex characters).
	hashByteLen = 32

	// saltByteLen is the number of random salt bytes (16 bytes = 32 hex
	// characters).
	saltByteLen = 16
)

// GenerateSaltedTokenHash returns a fresh V2 SaltedTokenHash for the given
// token. The token is supplied as a string mirroring Java's API (callers
// typically pass `hex.EncodeToString(passwordBytes)`); use TokenFromBytes to
// build that hex string with byte-equivalent semantics.
//
// Returns an error only if the system random source fails.
func GenerateSaltedTokenHash(token string) (*SaltedTokenHash, error) {
	saltBytes := make([]byte, saltByteLen)
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "recoverypassword: read random salt", err)
	}
	salt := hex.EncodeToString(saltBytes)
	hash, err := computeV2Hash(salt, token)
	if err != nil {
		return nil, err
	}
	return &SaltedTokenHash{Hash: hash, Salt: salt}, nil
}

// TokenFromBytes converts a raw byte slice (the recovery password) into the
// canonical Java token representation: lowercase hex, no separators. Mirrors
// Java's `HexFormat.of().formatHex(bytes)` call inside
// RegistrationRecoveryPasswordsManager.
func TokenFromBytes(b []byte) string {
	return hex.EncodeToString(b)
}

// Verify reports whether the supplied token reproduces this hash. Both V1
// (SHA-1 of salt||token) and V2 (HKDF-SHA256) are accepted on read, matching
// Java's verify() switch on the hash version. New hashes are always V2.
func (s *SaltedTokenHash) Verify(token string) bool {
	if s == nil {
		return false
	}
	var theirs string
	var err error
	if strings.HasPrefix(s.Hash, v2Prefix) {
		theirs, err = computeV2Hash(s.Salt, token)
	} else {
		theirs = computeV1Hash(s.Salt, token)
	}
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(theirs), []byte(s.Hash)) == 1
}

// IsV2 reports whether this hash uses the current V2 derivation. Persisted V1
// rows are still accepted on read, but new writes always store V2.
func (s *SaltedTokenHash) IsV2() bool {
	return s != nil && strings.HasPrefix(s.Hash, v2Prefix)
}

// computeV2Hash returns "2." + lower-hex(HKDF-SHA256(token, salt, "authtoken", 32)).
// The HKDF inputs are the UTF-8 byte representations of the hex-encoded salt
// and token strings, exactly matching Java.
func computeV2Hash(salt, token string) (string, error) {
	derived, err := libsignalkdf.DeriveSecrets(
		[]byte(token),
		[]byte(salt),
		[]byte(authTokenHKDFInfo),
		hashByteLen,
	)
	if err != nil {
		return "", signalerrors.Wrap(signalerrors.ErrInternal, "recoverypassword: derive HKDF", err)
	}
	return v2Prefix + hex.EncodeToString(derived), nil
}

// computeV1Hash reproduces Java's deprecated V1 hash for parity on read of
// legacy rows. Never used for new writes.
func computeV1Hash(salt, token string) string {
	// V1 is single-pass SHA-1 of (salt || token), hex-encoded. Stand-alone
	// helper avoids dragging in a SHA1 dep at the package level since this
	// path is read-only and only used for legacy compatibility.
	return v1Sha1Hex(salt + token)
}
