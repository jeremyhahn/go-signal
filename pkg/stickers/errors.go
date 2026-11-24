package stickers

import (
	"errors"
	"strconv"
)

// ErrInvalidEnvelope is returned by DecryptPackPayload when the
// supplied envelope fails length, padding, or HMAC checks. Surface
// as a 400-class error to the operator — the pack key or payload is
// corrupted.
var ErrInvalidEnvelope = errors.New("stickers: invalid sticker pack envelope")

// InvalidStickerCountError indicates that the requested sticker count is not
// within the allowed range.
type InvalidStickerCountError struct {
	Count int
}

func (e *InvalidStickerCountError) Error() string {
	return "invalid sticker count: " + strconv.Itoa(e.Count)
}

// PackNotFoundError indicates the supplied pack ID was never issued or has
// since been forgotten.
type PackNotFoundError struct {
	PackID string
}

func (e *PackNotFoundError) Error() string {
	return "sticker pack not found: " + e.PackID
}

// InvalidPackError indicates the supplied PackMetadata was missing a
// required field.
type InvalidPackError struct {
	Reason string
}

func (e *InvalidPackError) Error() string {
	return "invalid sticker pack: " + e.Reason
}
