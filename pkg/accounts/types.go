// Package accounts provides account types and storage interfaces for the Signal server.
package accounts

import (
	"time"

	"github.com/jeremyhahn/go-signal/pkg/auth"
)

// PrimaryDeviceID is the device ID assigned to the primary (first) device on
// every account.
const PrimaryDeviceID uint64 = 1

// Account represents a Signal user account.
type Account struct {
	UUID                           string
	Number                         string
	IdentityKey                    []byte
	PhoneNumberIdentityKey         []byte
	Devices                        []Device
	UnidentifiedAccessKey          []byte
	UnrestrictedUnidentifiedAccess bool
	DiscoverableByPhoneNumber      bool
	Username                       string
	UsernameHash                   []byte
	// RegistrationLockHash is the Argon2id-hashed form of the account's
	// registration lock PIN. A nil value means no lock is set.
	RegistrationLockHash *auth.RegistrationLockHash `json:"registrationLockHash,omitempty"`
	CreatedAt            time.Time
	Version              uint64
}

// GetDevice returns the device with the given ID, or nil if not found.
func (a *Account) GetDevice(id uint64) *Device {
	for i := range a.Devices {
		if a.Devices[i].ID == id {
			return &a.Devices[i]
		}
	}
	return nil
}

// PrimaryDevice returns the primary device (ID 1), or nil if not present.
func (a *Account) PrimaryDevice() *Device {
	return a.GetDevice(PrimaryDeviceID)
}

// IsEnabled returns true if the account has at least one enabled device.
func (a *Account) IsEnabled() bool {
	for i := range a.Devices {
		if IsDeviceEnabled(&a.Devices[i]) {
			return true
		}
	}
	return false
}

// IsDeviceEnabled returns true if the device has the minimum required state to
// send and receive messages (a signed pre-key and a persisted auth token hash).
func IsDeviceEnabled(d *Device) bool {
	return d.SignedPreKey != nil && d.AuthTokenHash != nil
}

// DeviceCapabilities describes the feature set supported by a device.
type DeviceCapabilities struct {
	Storage                  bool
	Transfer                 bool
	PaymentActivation        bool
	DeleteSync               bool
	VersionedExpirationTimer bool
}

// Device represents a linked device on an account.
type Device struct {
	ID   uint64
	Name string

	// AuthToken holds the plaintext token transiently during registration and
	// credential validation. It is never persisted (json:"-") — the hashed
	// form is stored in AuthTokenHash.
	AuthToken string `json:"-"`

	// AuthTokenHash is the salted HKDF-SHA256 digest of AuthToken. This is
	// the only token representation written to storage.
	AuthTokenHash *auth.SaltedTokenHash `json:"authTokenHash,omitempty"`

	Salt                              string
	GcmRegistrationID                 string
	ApnRegistrationID                 string
	VoipApnRegistrationID             string
	FetchesMessages                   bool
	RegistrationID                    uint32
	PhoneNumberIdentityRegistrationID uint32
	SignedPreKey                      *SignedPreKey
	KyberPreKey                       *KyberPreKey
	Capabilities                      DeviceCapabilities
	CreatedAt                         time.Time
	LastSeen                          time.Time
}

// SignedPreKey represents a signed EC pre-key stored on a device.
type SignedPreKey struct {
	KeyID     uint64
	PublicKey []byte
	Signature []byte
}

// KyberPreKey represents a post-quantum KEM pre-key stored on a device.
type KyberPreKey struct {
	KeyID     uint64
	PublicKey []byte
	Signature []byte
}

// DataReport contains a summary of account data for regulatory/transparency
// purposes.
type DataReport struct {
	UUID    string   `json:"uuid"`
	Number  string   `json:"e164"`
	Devices []uint64 `json:"deviceIds"`
}

// CreateAccountRequest holds the parameters for creating a new account.
type CreateAccountRequest struct {
	Number                         string
	IdentityKey                    []byte
	PhoneNumberIdentityKey         []byte
	AuthToken                      string
	RegistrationLock               string
	UnidentifiedAccessKey          []byte
	UnrestrictedUnidentifiedAccess bool
	DiscoverableByPhoneNumber      bool
}
