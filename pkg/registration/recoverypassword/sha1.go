package recoverypassword

import (
	// #nosec G505 -- SHA-1 is required for V1 SaltedTokenHash compatibility.
	"crypto/sha1"
	"encoding/hex"
)

// v1Sha1Hex returns the lowercase hex of SHA-1(s). SHA-1 is intentional and
// solely used to verify legacy V1 SaltedTokenHash rows produced by older
// Java Signal-Server deployments. New writes always store V2 (HKDF-SHA256).
func v1Sha1Hex(s string) string {
	// #nosec G401 -- legacy V1 hash compatibility; see package doc.
	sum := sha1.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
