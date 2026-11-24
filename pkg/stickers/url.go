package stickers

import (
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"unicode"
)

// PackURL is a sticker share URL: https://signal.art/addstickers/#pack_id=<16-byte hex>&pack_key=<32-byte hex>.
type PackURL struct {
	PackID  string
	PackKey []byte
}

// ParsePackURL extracts and checks the hex pack_id and pack_key from the fragment, or returns *PackURLError.
func ParsePackURL(raw string) (*PackURL, error) {
	if raw == "" {
		return nil, &PackURLError{Reason: "empty URL"}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, &PackURLError{Reason: "parse: " + err.Error()}
	}
	if u.Fragment == "" {
		return nil, &PackURLError{Reason: "missing fragment with pack_id/pack_key"}
	}
	q, err := url.ParseQuery(u.Fragment)
	if err != nil {
		return nil, &PackURLError{Reason: "parse fragment: " + err.Error()}
	}
	packID := q.Get("pack_id")
	packKeyHex := q.Get("pack_key")
	if packID == "" {
		return nil, &PackURLError{Reason: "pack_id is required"}
	}
	if packKeyHex == "" {
		return nil, &PackURLError{Reason: "pack_key is required"}
	}
	// Reject whitespace in hex fields rather than trimming it.
	if strings.IndexFunc(packID, unicode.IsSpace) >= 0 {
		return nil, &PackURLError{Reason: "pack_id must not contain whitespace"}
	}
	if strings.IndexFunc(packKeyHex, unicode.IsSpace) >= 0 {
		return nil, &PackURLError{Reason: "pack_key must not contain whitespace"}
	}
	if _, err := hex.DecodeString(packID); err != nil {
		return nil, &PackURLError{Reason: "pack_id must be hex"}
	}
	if len(packID) != 32 {
		return nil, &PackURLError{Reason: "pack_id must be 16 hex bytes (32 chars)"}
	}
	packKey, err := hex.DecodeString(packKeyHex)
	if err != nil {
		return nil, &PackURLError{Reason: "pack_key must be hex"}
	}
	if len(packKey) != PackKeyLen {
		return nil, &PackURLError{Reason: "pack_key must be 32 bytes"}
	}
	return &PackURL{PackID: packID, PackKey: packKey}, nil
}

// PackURLError indicates an invalid sticker pack URL.
type PackURLError struct {
	Reason string
}

// Error implements the error interface.
func (e *PackURLError) Error() string { return "stickers: invalid pack URL: " + e.Reason }

// Is reports whether target is a PackURLError. Lets callers branch
// on the typed error via errors.Is.
func (e *PackURLError) Is(target error) bool {
	var t *PackURLError
	return errors.As(target, &t)
}
