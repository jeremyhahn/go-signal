// Package usernames provides username reservation, confirmation, and link
// management for Signal accounts.
package usernames

import "time"

// UsernameReservation represents a pending username hash reservation for an
// account. The reservation expires after a configurable duration.
type UsernameReservation struct {
	UUID             string
	UsernameHashes   [][]byte
	ReservationToken string
	ExpiresAt        time.Time
}

// UsernameLink associates an encrypted username with a UUID-based handle,
// allowing username lookups without revealing the plaintext username.
type UsernameLink struct {
	UUID               string
	UsernameLinkHandle string // UUID handle for the link
	EncryptedUsername  []byte
}
