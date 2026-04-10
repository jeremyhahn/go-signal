//go:build fido2

package fido2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// --- FIDO2Session.IsExpired tests ---

func TestFIDO2Session_IsExpired_True(t *testing.T) {
	s := &FIDO2Session{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	assert.True(t, s.IsExpired())
}

func TestFIDO2Session_IsExpired_False(t *testing.T) {
	s := &FIDO2Session{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	assert.False(t, s.IsExpired())
}

// --- WebAuthnUser tests ---

func TestWebAuthnUser_WebAuthnID(t *testing.T) {
	u := &WebAuthnUser{
		ID:          []byte{0x01, 0x02, 0x03},
		Name:        "alice",
		DisplayName: "Alice Wonderland",
	}
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, u.WebAuthnID())
}

func TestWebAuthnUser_WebAuthnName(t *testing.T) {
	u := &WebAuthnUser{
		ID:          []byte{0x01},
		Name:        "alice",
		DisplayName: "Alice Wonderland",
	}
	assert.Equal(t, "alice", u.WebAuthnName())
}

func TestWebAuthnUser_WebAuthnDisplayName(t *testing.T) {
	u := &WebAuthnUser{
		ID:          []byte{0x01},
		Name:        "alice",
		DisplayName: "Alice Wonderland",
	}
	assert.Equal(t, "Alice Wonderland", u.WebAuthnDisplayName())
}

// --- FIDO2SessionType constants ---

func TestSessionTypeConstants(t *testing.T) {
	assert.Equal(t, FIDO2SessionType("registration"), SessionTypeRegistration)
	assert.Equal(t, FIDO2SessionType("login"), SessionTypeLogin)
	assert.Equal(t, FIDO2SessionType("enrollment"), SessionTypeEnrollment)
}
