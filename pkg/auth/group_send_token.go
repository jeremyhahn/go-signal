package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const (
	// groupSendTokenSize is the total size of a serialized GroupSendToken:
	// 8 bytes expiration + 32 bytes HMAC = 40 bytes.
	groupSendTokenSize = 40

	// DefaultGroupSendTokenTTL is the default validity period for group send tokens.
	DefaultGroupSendTokenTTL = 24 * time.Hour
)

// GroupSendToken authorizes a sender to deliver messages to members of a
// specific group. The token binds the sender UUID and group ID to an
// expiration timestamp using HMAC-SHA256.
type GroupSendToken struct {
	// Expiration is the Unix timestamp (seconds) after which the token is
	// no longer valid.
	Expiration int64
	// HMAC is the 32-byte HMAC-SHA256 signature.
	HMAC []byte
}

// GenerateGroupSendToken creates a new GroupSendToken binding the given sender
// and group ID. The token expires after ttl from the current time. The key
// parameter is the server-side HMAC secret.
//
// Key zeroing: the caller is responsible for zeroing key after all calls that
// use it are complete. This function does not zero key internally because the
// same key slice is typically passed to both GenerateGroupSendToken and
// VerifyGroupSendToken; zeroing here would corrupt subsequent calls in the
// same request scope. Production callers should derive a fresh []byte copy
// from secure storage for each independent operation and zero it afterward.
func GenerateGroupSendToken(key []byte, senderUUID string, groupID string, ttl time.Duration) *GroupSendToken {
	if ttl <= 0 {
		ttl = DefaultGroupSendTokenTTL
	}
	expiration := time.Now().Unix() + int64(ttl.Seconds())

	mac := computeGroupSendMAC(key, senderUUID, groupID, expiration)

	return &GroupSendToken{
		Expiration: expiration,
		HMAC:       mac,
	}
}

// VerifyGroupSendToken validates that the token is well-formed, not expired,
// and has a valid HMAC for the given sender, group, and key.
//
// Key zeroing: see the note on GenerateGroupSendToken. The caller owns the
// key lifecycle and must zero it once no further calls are needed.
func VerifyGroupSendToken(key []byte, token *GroupSendToken, senderUUID string, groupID string) bool {
	if token == nil || len(token.HMAC) != sha256.Size {
		return false
	}

	// Check expiration.
	if time.Now().Unix() > token.Expiration {
		return false
	}

	expected := computeGroupSendMAC(key, senderUUID, groupID, token.Expiration)
	return hmac.Equal(token.HMAC, expected)
}

// SerializeGroupSendToken encodes the token into a 40-byte slice:
// [0:8] big-endian expiration, [8:40] HMAC.
func SerializeGroupSendToken(token *GroupSendToken) []byte {
	if token == nil || len(token.HMAC) != sha256.Size {
		return nil
	}
	buf := make([]byte, groupSendTokenSize)
	binary.BigEndian.PutUint64(buf[0:8], uint64(token.Expiration))
	copy(buf[8:], token.HMAC)
	return buf
}

// DeserializeGroupSendToken decodes a 40-byte slice into a GroupSendToken.
// Returns nil if the input is malformed.
func DeserializeGroupSendToken(data []byte) *GroupSendToken {
	if len(data) != groupSendTokenSize {
		return nil
	}
	expiration := int64(binary.BigEndian.Uint64(data[0:8]))
	mac := make([]byte, sha256.Size)
	copy(mac, data[8:])
	return &GroupSendToken{
		Expiration: expiration,
		HMAC:       mac,
	}
}

// computeGroupSendMAC computes the HMAC-SHA256 over the token's bound fields.
//
// Each variable-length field is length-prefixed (8-byte big-endian length
// before the bytes) so the MAC input is unambiguously framed: distinct
// (senderUUID, groupID) pairs can never produce the same byte stream through
// concatenation aliasing (e.g. "ab"+"c" vs "a"+"bc"). This is a server-internal
// MAC — the same function generates and verifies, and the serialized 40-byte
// token format (8-byte expiration + 32-byte HMAC) is unchanged — so the framing
// is purely an integrity hardening with no external wire impact.
//
// Key zeroing: the caller (GenerateGroupSendToken or VerifyGroupSendToken)
// owns the key slice and is responsible for zeroing it after all usages are
// complete. This internal helper does not zero key to avoid corrupting callers
// that pass the same slice to multiple functions in sequence.
func computeGroupSendMAC(key []byte, senderUUID string, groupID string, expiration int64) []byte {
	h := hmac.New(sha256.New, key)
	writeLengthPrefixed(h, []byte(senderUUID))
	writeLengthPrefixed(h, []byte(groupID))
	var expBuf [8]byte
	binary.BigEndian.PutUint64(expBuf[:], uint64(expiration))
	h.Write(expBuf[:])
	return h.Sum(nil)
}

// writeLengthPrefixed writes an 8-byte big-endian length followed by b, so that
// a sequence of variable-length fields is unambiguously parseable.
func writeLengthPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
	h.Write(lenBuf[:])
	h.Write(b)
}
