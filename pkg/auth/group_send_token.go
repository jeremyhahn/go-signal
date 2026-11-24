package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"hash"
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
	// Expiration is the Unix time (seconds) after which the token is invalid.
	Expiration int64
	// HMAC is the 32-byte HMAC-SHA256 signature.
	HMAC []byte
}

// GenerateGroupSendToken binds sender and group ID with an HMAC under key, valid for ttl; the caller zeroes key.
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

// VerifyGroupSendToken checks form, expiry and HMAC; the caller zeroes key.
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

// computeGroupSendMAC HMACs the length-prefixed bound fields so distinct pairs cannot alias; the caller owns key.
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
func writeLengthPrefixed(h hash.Hash, b []byte) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
	h.Write(lenBuf[:])
	h.Write(b)
}
