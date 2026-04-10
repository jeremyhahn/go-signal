package usernames

import "encoding/hex"

// UsernameHashConflictError indicates the requested username hash is already
// claimed by another account.
type UsernameHashConflictError struct {
	Hash []byte
}

func (e *UsernameHashConflictError) Error() string {
	return "username hash already taken: " + hex.EncodeToString(e.Hash)
}

// UsernameNotFoundError indicates no account is associated with the given
// username hash.
type UsernameNotFoundError struct {
	Hash []byte
}

func (e *UsernameNotFoundError) Error() string {
	return "username hash not found: " + hex.EncodeToString(e.Hash)
}

// InvalidReservationTokenError indicates the provided reservation token does
// not match the expected token for the username reservation.
type InvalidReservationTokenError struct {
	UUID string
}

func (e *InvalidReservationTokenError) Error() string {
	return "invalid reservation token for account " + e.UUID
}

// UsernameLinkNotFoundError indicates no username link exists for the given
// handle.
type UsernameLinkNotFoundError struct {
	Handle string
}

func (e *UsernameLinkNotFoundError) Error() string {
	return "username link not found: " + e.Handle
}

// InvalidArgumentError indicates that a required argument was missing or
// invalid.
type InvalidArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidArgumentError) Error() string {
	return "invalid argument: " + e.Field + ": " + e.Message
}
