// Package devices provides device provisioning and linking operations for the
// Signal server. It manages the lifecycle of provisioning codes and the
// creation of linked devices on existing accounts.
package devices

import "time"

// ProvisioningCode is returned when a primary device requests a code for
// linking a new device.
type ProvisioningCode struct {
	VerificationCode string `json:"verificationCode"`
}

// LinkDeviceRequest contains the parameters submitted by a new device to
// complete the linking process.
type LinkDeviceRequest struct {
	VerificationCode      string                  `json:"verificationCode"`
	AccountAttributes     DeviceAccountAttributes `json:"accountAttributes"`
	AciSignedPreKey       SignedPreKeyEntity      `json:"aciSignedPreKey"`
	PniSignedPreKey       SignedPreKeyEntity      `json:"pniSignedPreKey"`
	AciPqLastResortPreKey KEMSignedPreKeyEntity   `json:"aciPqLastResortPreKey"`
	PniPqLastResortPreKey KEMSignedPreKeyEntity   `json:"pniPqLastResortPreKey"`
}

// DeviceAccountAttributes carries the device-specific attributes submitted
// during the linking process.
type DeviceAccountAttributes struct {
	FetchesMessages   bool            `json:"fetchesMessages"`
	RegistrationId    uint32          `json:"registrationId"`
	PniRegistrationId uint32          `json:"pniRegistrationId"`
	Name              string          `json:"name"`
	Capabilities      map[string]bool `json:"capabilities"`
}

// SignedPreKeyEntity represents a signed EC pre-key in device provisioning
// payloads.
type SignedPreKeyEntity struct {
	KeyId     uint64 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

// KEMSignedPreKeyEntity represents a post-quantum KEM signed pre-key in device
// provisioning payloads.
type KEMSignedPreKeyEntity struct {
	KeyId     uint64 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

// LinkDeviceResponse is returned after a device is successfully linked,
// containing the assigned device ID.
type LinkDeviceResponse struct {
	DeviceId uint64 `json:"deviceId"`
}

// ProvisioningSession tracks an active provisioning request. The session is
// created when the primary device requests a provisioning code and consumed
// when the new device completes linking.
type ProvisioningSession struct {
	Code      string
	UUID      string // account UUID
	ExpiresAt time.Time
}
