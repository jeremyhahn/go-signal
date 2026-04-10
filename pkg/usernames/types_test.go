package usernames

import (
	"testing"
	"time"
)

func TestUsernameReservation_Fields(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		now := time.Now()
		res := UsernameReservation{
			UUID:             "test-uuid",
			UsernameHashes:   [][]byte{{1, 2, 3}, {4, 5, 6}},
			ReservationToken: "token-abc",
			ExpiresAt:        now,
		}

		if res.UUID != "test-uuid" {
			t.Errorf("UUID = %q, want %q", res.UUID, "test-uuid")
		}
		if len(res.UsernameHashes) != 2 {
			t.Errorf("UsernameHashes length = %d, want 2", len(res.UsernameHashes))
		}
		if res.ReservationToken != "token-abc" {
			t.Errorf("ReservationToken = %q, want %q", res.ReservationToken, "token-abc")
		}
		if !res.ExpiresAt.Equal(now) {
			t.Errorf("ExpiresAt mismatch")
		}
	})

	t.Run("zero value", func(t *testing.T) {
		var res UsernameReservation
		if res.UUID != "" {
			t.Errorf("expected empty UUID, got %q", res.UUID)
		}
		if res.UsernameHashes != nil {
			t.Errorf("expected nil UsernameHashes, got %v", res.UsernameHashes)
		}
		if res.ReservationToken != "" {
			t.Errorf("expected empty ReservationToken, got %q", res.ReservationToken)
		}
		if !res.ExpiresAt.IsZero() {
			t.Errorf("expected zero ExpiresAt, got %v", res.ExpiresAt)
		}
	})
}

func TestUsernameLink_Fields(t *testing.T) {
	t.Run("all fields populated", func(t *testing.T) {
		link := UsernameLink{
			UUID:               "uuid-link",
			UsernameLinkHandle: "handle-123",
			EncryptedUsername:  []byte{10, 20, 30},
		}

		if link.UUID != "uuid-link" {
			t.Errorf("UUID = %q, want %q", link.UUID, "uuid-link")
		}
		if link.UsernameLinkHandle != "handle-123" {
			t.Errorf("UsernameLinkHandle = %q, want %q", link.UsernameLinkHandle, "handle-123")
		}
		if len(link.EncryptedUsername) != 3 {
			t.Errorf("EncryptedUsername length = %d, want 3", len(link.EncryptedUsername))
		}
	})

	t.Run("zero value", func(t *testing.T) {
		var link UsernameLink
		if link.UUID != "" {
			t.Errorf("expected empty UUID, got %q", link.UUID)
		}
		if link.UsernameLinkHandle != "" {
			t.Errorf("expected empty UsernameLinkHandle, got %q", link.UsernameLinkHandle)
		}
		if link.EncryptedUsername != nil {
			t.Errorf("expected nil EncryptedUsername, got %v", link.EncryptedUsername)
		}
	})
}
