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
//
// Signal distinguishes two identifiers for every account: the ACI
// (stored in UUID) and the PNI (Phone Number Identity). Both are
// 16-byte UUIDs formatted as 8-4-4-4-12 strings, but they live in
// separate key and message namespaces. PNI is bound to the phone number
// — a number change regenerates PNI but preserves ACI. See
// docs/protocol/pni.md for the full model.
type Account struct {
	// UUID is the account's ACI (Account Identity). Stable for the
	// account's lifetime.
	UUID string
	// PNI is the account's Phone Number Identity. Bound to Number;
	// regenerated if the phone number changes.
	PNI                            string
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
	// BackupCredentialRequests holds the blinded backup-id commitments
	// submitted via PUT /v1/archives/backupid. Empty until the client
	// opts into backups. Mirrors Java's Account.backupCredentialRequests.
	BackupCredentialRequests *BackupCredentialRequests `json:"backupCredentialRequests,omitempty"`
	// BackupVoucher records the most recent paid-tier receipt redemption.
	// Nil if the account has only ever held free-tier credentials. The
	// receipt level is opaque to this layer; backups.AuthManager applies
	// the Signal-specific receipt-level → BackupLevel mapping.
	BackupVoucher *BackupVoucher `json:"backupVoucher,omitempty"`
	CreatedAt     time.Time
	Version       uint64
}

// BackupCredentialRequests carries the two serialized
// BackupAuthCredentialRequest blobs (one per credential type) stored on
// the account after PUT /v1/archives/backupid. Either field may be
// nil in a partial commit. Mirrors Java's
// Account.setBackupCredentialRequests(messages, media) split.
type BackupCredentialRequests struct {
	Messages []byte `json:"messages,omitempty"`
	Media    []byte `json:"media,omitempty"`
}

// BackupVoucher is the per-account paid-tier expiration. Receipt
// redemptions are deduplicated against the redeemed-receipts store,
// then the voucher is extended (or replaced if the receipt level
// changes). Mirrors Java's Account.BackupVoucher record.
type BackupVoucher struct {
	ReceiptLevel uint64    `json:"receiptLevel"`
	Expiration   time.Time `json:"expiration"`
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
