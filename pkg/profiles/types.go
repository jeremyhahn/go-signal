// Package profiles provides user profile types and storage interfaces for the Signal server.
package profiles

// Profile represents a versioned user profile with encrypted fields.
type Profile struct {
	UUID           string
	Version        string
	Name           []byte
	About          []byte
	AboutEmoji     []byte
	Avatar         string
	Commitment     []byte
	PaymentAddress []byte
}

// CreateProfileRequest holds the parameters for creating or updating a profile.
type CreateProfileRequest struct {
	Version        string
	Name           []byte
	About          []byte
	AboutEmoji     []byte
	PaymentAddress []byte
	AvatarUpload   bool
	Commitment     []byte
}

// ProfileResponse represents the full profile response returned to clients.
type ProfileResponse struct {
	IdentityKey                    []byte
	UnidentifiedAccess             []byte
	UnrestrictedUnidentifiedAccess bool
	Capabilities                   map[string]bool
	Badges                         []Badge
	UUID                           string
	Profile                        *Profile
}

// Badge represents a profile badge with display metadata.
type Badge struct {
	ID          string
	Category    string
	Name        string
	Description string
	Sprites6    []string
}
