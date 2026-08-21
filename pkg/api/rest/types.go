package rest

// RegistrationRequest is the JSON body submitted during account registration.
type RegistrationRequest struct {
	// SessionID is the ID of a completed verification session. Mutually
	// exclusive with RecoveryPassword: exactly one of the two must be
	// supplied. When SessionID is set the session must exist, must not be
	// expired, and must be in the Verified state for the phone number
	// supplied via Basic Auth.
	SessionID string `json:"sessionId,omitempty"`
	// RecoveryPassword is a base64-encoded registration recovery password
	// that re-registers an account without an SMS verification round trip.
	// Mutually exclusive with SessionID. Mirrors Java
	// RegistrationRequest.recoveryPassword.
	RecoveryPassword string `json:"recoveryPassword,omitempty"`
	// Captcha is an optional `provider.sitekey.action.token` string. When
	// supplied, the server verifies it via captcha.RegistrationCaptchaManager
	// before the account is created. Required when the request fails
	// rate-limit/fraud heuristics (see captchaRequired in the verification
	// session response).
	Captcha               string                   `json:"captcha,omitempty"`
	AccountAttributes     AccountAttributesRequest `json:"accountAttributes"`
	IdentityKey           string                   `json:"aciIdentityKey"`
	PniIdentityKey        string                   `json:"pniIdentityKey"`
	AciSignedPreKey       SignedPreKeyEntity       `json:"aciSignedPreKey"`
	PniSignedPreKey       SignedPreKeyEntity       `json:"pniSignedPreKey"`
	AciPqLastResortPreKey KEMSignedPreKeyEntity    `json:"aciPqLastResortPreKey"`
	PniPqLastResortPreKey KEMSignedPreKeyEntity    `json:"pniPqLastResortPreKey"`
}

// AccountAttributesRequest carries the account attribute fields submitted
// during registration or attribute updates.
type AccountAttributesRequest struct {
	FetchesMessages       bool   `json:"fetchesMessages"`
	RegistrationId        uint32 `json:"registrationId"`
	PniRegistrationId     uint32 `json:"pniRegistrationId"`
	Name                  string `json:"name"`
	UnidentifiedAccessKey string `json:"unidentifiedAccessKey"`
	// RegistrationLock is the PIN the client supplies when re-registering a
	// number that has an active registration lock. Omitted when not applicable.
	RegistrationLock string `json:"registrationLock,omitempty"`
	// RecoveryPassword, when present on an attribute update, replaces the
	// stored registration recovery password for the account's PNI. Mirrors
	// Java AccountAttributes.recoveryPassword.
	RecoveryPassword string          `json:"recoveryPassword,omitempty"`
	Capabilities     map[string]bool `json:"capabilities"`
}

// RegistrationLockErrorResponse is returned with HTTP 423 when a registration
// attempt is blocked by an active registration lock on the existing account.
// The timeRemaining field tells the client how long the lock is still active
// (in seconds) so it can present an appropriate message.
type RegistrationLockErrorResponse struct {
	// TimeRemaining is the number of seconds until the registration lock expires.
	TimeRemaining int64 `json:"timeRemaining"`
}

// RegistrationCaptchaField carries the optional captcha solution submitted
// on a registration request. Top-level on RegistrationRequest so the
// account-create handler can verify it before any account state mutates.
// Mirrors Java RegistrationRequest.captcha.
//
// Format: `provider.sitekey.action.token` (the same dotted layout used by
// PATCH /v1/verification/session/{id}). The action slot must be
// "registration" — captcha.RegistrationCaptchaManager enforces that.
type RegistrationCaptchaField = string

// SignedPreKeyEntity represents a signed EC pre-key in API request/response
// payloads.
type SignedPreKeyEntity struct {
	KeyId     uint64 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

// KEMSignedPreKeyEntity represents a post-quantum KEM signed pre-key in API
// request/response payloads.
type KEMSignedPreKeyEntity struct {
	KeyId     uint64 `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
}

// AccountCreationResponse is returned after successful account registration.
type AccountCreationResponse struct {
	UUID           string `json:"uuid"`
	PNI            string `json:"pni"`
	StorageCapable bool   `json:"storageCapable"`
}

// SetKeysRequestEntity is the JSON body for uploading pre-keys.
type SetKeysRequestEntity struct {
	PreKeys            []PreKeyEntity          `json:"preKeys"`
	SignedPreKey       *SignedPreKeyEntity     `json:"signedPreKey"`
	PqPreKeys          []KEMSignedPreKeyEntity `json:"pqPreKeys"`
	PqLastResortPreKey *KEMSignedPreKeyEntity  `json:"pqLastResortPreKey"`
}

// PreKeyEntity represents a one-time pre-key in API payloads.
type PreKeyEntity struct {
	KeyId     uint64 `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

// PreKeyCountResponse reports the number of remaining one-time pre-keys and
// whether a KEM last-resort pre-key is stored.
type PreKeyCountResponse struct {
	Count   int `json:"count"`
	PqCount int `json:"pqCount"`
	// HasLastResort indicates whether a KEM last-resort pre-key is stored for
	// this device. Clients should upload a last-resort key if this is false.
	HasLastResort bool `json:"hasLastResort"`
}

// PreKeyResponseEntity is the API response containing key material for session
// establishment.
type PreKeyResponseEntity struct {
	IdentityKey string                     `json:"identityKey"`
	Devices     []PreKeyResponseItemEntity `json:"devices"`
}

// PreKeyResponseItemEntity contains the pre-key bundle for a single device.
type PreKeyResponseItemEntity struct {
	DeviceId       uint64                 `json:"deviceId"`
	RegistrationId uint32                 `json:"registrationId"`
	SignedPreKey   *SignedPreKeyEntity    `json:"signedPreKey"`
	PreKey         *PreKeyEntity          `json:"preKey,omitempty"`
	PqPreKey       *KEMSignedPreKeyEntity `json:"pqPreKey,omitempty"`
}

// IncomingMessageEntity represents a single incoming message destined for a
// specific device. RegistrationId is the sender's last-known registration ID
// for that device and is used to detect stale key material (Signal protocol
// §4.2, Java MessageController stale-device check).
// IncomingMessageEntity is one per-device message within a send request.
//
// It deliberately carries NO timestamp. Java's IncomingMessage record has none
// either — the timestamp belongs to the batch (IncomingMessageListEntity) and
// is the value the delivered envelope carries. A per-message field existed
// here once and the send handler sourced the envelope timestamp from it;
// clients never populate it, so every delivered envelope carried 0 and
// libsignal rejected it. Do not reintroduce it.
type IncomingMessageEntity struct {
	Type                int32  `json:"type"`
	DestinationDeviceId uint64 `json:"destinationDeviceId"`
	Content             string `json:"content"`
	RegistrationId      uint32 `json:"registrationId,omitempty"`
}

// IncomingMessageListEntity is a batch of messages submitted by a sender.
type IncomingMessageListEntity struct {
	Messages []IncomingMessageEntity `json:"messages"`
	// Timestamp is the client-assigned send time for the whole batch and
	// becomes the delivered envelope's client_timestamp. libsignal compares
	// it against the timestamp sealed inside the message content, so it must
	// reach the envelope unchanged.
	Timestamp uint64 `json:"timestamp"`
	Online    bool   `json:"online"`
	Urgent    bool   `json:"urgent"`
}

// SendMessageResponseEntity is returned after a message send.
type SendMessageResponseEntity struct {
	NeedsSync bool `json:"needsSync"`
}

// OutgoingMessageEntity represents a pending message for delivery.
type OutgoingMessageEntity struct {
	Type            int32  `json:"type"`
	Timestamp       uint64 `json:"timestamp"`
	Source          string `json:"source,omitempty"`
	SourceDevice    uint32 `json:"sourceDevice,omitempty"`
	Content         string `json:"content"`
	ServerTimestamp uint64 `json:"serverTimestamp"`
	GUID            string `json:"guid"`
	Urgent          bool   `json:"urgent"`
}

// OutgoingMessageEntityList is a list of pending messages for a device.
type OutgoingMessageEntityList struct {
	Messages []OutgoingMessageEntity `json:"messages"`
	More     bool                    `json:"more"`
}

// VerificationSessionResponse describes the state of a verification session.
type VerificationSessionResponse struct {
	ID                   string   `json:"id"`
	AllowedToRequestCode bool     `json:"allowedToRequestCode"`
	Verified             bool     `json:"verified"`
	RequestedInformation []string `json:"requestedInformation"`
}

// UpdateVerificationSessionRequest is the JSON body for PATCH on a
// verification session. Today it carries an optional captcha solution
// (provider.sitekey.action.token format). Future fields will follow Java's
// shape (push challenge token, language hints, etc.).
type UpdateVerificationSessionRequest struct {
	Captcha string `json:"captcha,omitempty"`
}

// CreateVerificationSessionRequest is the JSON body for creating a new
// verification session.
type CreateVerificationSessionRequest struct {
	Number    string `json:"number"`
	Transport string `json:"transport"`
}

// SubmitVerificationCodeRequest is the JSON body for submitting a verification
// code.
type SubmitVerificationCodeRequest struct {
	Code string `json:"code"`
}

// WhoAmIResponse is returned by the /v1/accounts/whoami endpoint.
type WhoAmIResponse struct {
	UUID   string `json:"uuid"`
	Number string `json:"number"`
	PNI    string `json:"pni"`
}

// GcmRegistrationIDRequest is the JSON body for GCM token registration.
type GcmRegistrationIDRequest struct {
	GcmRegistrationID string `json:"gcmRegistrationId"`
}

// ApnRegistrationIDRequest is the JSON body for APN token registration.
type ApnRegistrationIDRequest struct {
	ApnRegistrationID  string `json:"apnRegistrationId"`
	VoipRegistrationID string `json:"voipRegistrationId"`
}

// DeviceInfoEntity represents a single device in the devices list response.
type DeviceInfoEntity struct {
	ID       uint64 `json:"id"`
	Name     string `json:"name,omitempty"`
	Created  int64  `json:"created"`
	LastSeen int64  `json:"lastSeen"`
}

// DeviceInfoListEntity is the response for listing an account's devices.
type DeviceInfoListEntity struct {
	Devices []DeviceInfoEntity `json:"devices"`
}

// SetProfileRequest is the JSON body for updating a user profile.
type SetProfileRequest struct {
	Version        string `json:"version"`
	Name           string `json:"name"`
	About          string `json:"about"`
	AboutEmoji     string `json:"aboutEmoji"`
	PaymentAddress string `json:"paymentAddress"`
	AvatarUpload   bool   `json:"avatar"`
	SameAvatar     bool   `json:"sameAvatar"`
	Commitment     string `json:"commitment"`
}

// ProfileAvatarUploadAttributes contains the upload credentials returned when
// a profile update requests a new avatar. Matches the Java
// ProfileAvatarUploadAttributes entity used for S3 POST policy uploads.
type ProfileAvatarUploadAttributes struct {
	Key        string `json:"key"`
	Credential string `json:"credential"`
	ACL        string `json:"acl"`
	Algorithm  string `json:"algorithm"`
	Date       string `json:"date"`
	Policy     string `json:"policy"`
	Signature  string `json:"signature"`
}

// ProfileResponseEntity is the API response for profile retrieval.
type ProfileResponseEntity struct {
	IdentityKey                    string          `json:"identityKey"`
	UnidentifiedAccess             string          `json:"unidentifiedAccess"`
	UnrestrictedUnidentifiedAccess bool            `json:"unrestrictedUnidentifiedAccess"`
	Capabilities                   map[string]bool `json:"capabilities"`
	Badges                         []any           `json:"badges"`
	UUID                           string          `json:"uuid"`
	Name                           string          `json:"name,omitempty"`
	About                          string          `json:"about,omitempty"`
	AboutEmoji                     string          `json:"aboutEmoji,omitempty"`
	Avatar                         string          `json:"avatar,omitempty"`
	PaymentAddress                 string          `json:"paymentAddress,omitempty"`
	Credential                     any             `json:"credential,omitempty"`
}

// AttachmentDescriptorV3 represents the upload form returned to clients for
// uploading message attachments.
type AttachmentDescriptorV3 struct {
	CDN                  int               `json:"cdn"`
	Key                  string            `json:"key"`
	Headers              map[string]string `json:"headers"`
	SignedUploadLocation string            `json:"signedUploadLocation"`
}

// RemoteConfigItem is preserved for the legacy /v1/config response that
// returned a typed-list payload. Production clients are on /v2/config
// (the Java-current shape, RemoteConfigResponse) which carries a
// name→value map instead.
type RemoteConfigItem struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Value   string `json:"value"`
}

// RemoteConfigResponse is the /v2/config response shape. Mirrors Java
// RemoteConfigurationResponse: a single field containing a map of
// fully-qualified config names to their per-account rendered values.
type RemoteConfigResponse struct {
	Config map[string]string `json:"config"`
}

// KeyCheckRequest is the JSON body for the identity key check endpoint.
type KeyCheckRequest struct {
	IdentityKeys []IdentityKeyItem `json:"identityKeys"`
}

// IdentityKeyItem represents a single identity key submitted for comparison.
type IdentityKeyItem struct {
	UUID        string `json:"uuid"`
	IdentityKey string `json:"identityKey"` // base64
}

// KeyCheckResponse is the API response for the identity key check endpoint,
// containing any mismatched identity keys.
type KeyCheckResponse struct {
	IdentityKeyFingerprints []IdentityKeyItem `json:"identityKeyFingerprints"`
}

// ProfileCredentialResponse represents a stub credential returned alongside
// a profile response when a credential request is provided.
type ProfileCredentialResponse struct {
	Credential     string `json:"credential"`
	RedemptionTime int64  `json:"redemptionTime"`
}

// BatchIdentityCheckRequest is the JSON body for the batch identity check
// endpoint.
type BatchIdentityCheckRequest struct {
	Elements []IdentityCheckElement `json:"elements"`
}

// IdentityCheckElement represents a single identity fingerprint submitted for
// comparison in a batch identity check.
type IdentityCheckElement struct {
	UUID        string `json:"uuid"`
	Fingerprint string `json:"fingerprint"` // base64
}

// BatchIdentityCheckResponse is the API response for the batch identity check
// endpoint, containing any mismatched identities.
type BatchIdentityCheckResponse struct {
	Elements []IdentityCheckResponseElement `json:"elements"`
}

// IdentityCheckResponseElement represents a single mismatched identity in the
// batch identity check response.
type IdentityCheckResponseElement struct {
	UUID        string `json:"uuid"`
	IdentityKey string `json:"identityKey"` // base64
}

// MultiRecipientMessageRequest is the JSON body for the multi-recipient
// message send endpoint.
type MultiRecipientMessageRequest struct {
	Recipients    []MultiRecipientTarget `json:"recipients"`
	CommonPayload string                 `json:"commonPayload"` // base64
	Timestamp     uint64                 `json:"timestamp"`
}

// MultiRecipientTarget represents a single recipient in a multi-recipient
// message send.
type MultiRecipientTarget struct {
	UUID            string   `json:"uuid"`
	DeviceIds       []uint64 `json:"deviceIds"`
	RegistrationIds []uint32 `json:"registrationIds"`
}

// MultiRecipientMessageResponse is the API response for the multi-recipient
// message send endpoint.
type MultiRecipientMessageResponse struct {
	UUIDs404 []string `json:"uuids404"`
}

// MismatchedDevicesResponse is the JSON body returned with HTTP 409 when the
// sender addressed the wrong set of devices. It lists the device IDs that the
// sender omitted (missingDevices) and device IDs that do not exist on the
// recipient account (extraDevices). Matches the Java MismatchedDevicesException
// response format used by MessageController.
type MismatchedDevicesResponse struct {
	MissingDevices []uint64 `json:"missingDevices"`
	ExtraDevices   []uint64 `json:"extraDevices"`
}

// StaleDevicesResponse is the JSON body returned with HTTP 410 when the sender
// holds outdated registration IDs for one or more of the recipient's devices.
// Matches the Java StaleDevicesException response format.
type StaleDevicesResponse struct {
	StaleDevices []uint64 `json:"staleDevices"`
}

// SpamReportRequest is the optional JSON body for the spam report endpoint.
type SpamReportRequest struct {
	Token string `json:"token,omitempty"`
}

// SpamChallengeResponse is returned with HTTP 428 Precondition Required when
// the spam checker requires the sender to complete a challenge before the
// message can be delivered. ChallengeType identifies the required challenge
// mechanism ("captcha" or "push"); Token is an optional opaque token that
// the client must echo back when submitting the challenge response.
type SpamChallengeResponse struct {
	Token         string `json:"token,omitempty"`
	ChallengeType string `json:"options"`
}

// DeliveryCertificateResponse is the API response containing a signed delivery
// certificate for sealed-sender messaging.
type DeliveryCertificateResponse struct {
	Certificate       string `json:"certificate"`
	CertificateExpiry int64  `json:"certificateExpiry"`
}

// RegistrationLockRequest is the JSON body for setting a registration lock.
type RegistrationLockRequest struct {
	RegistrationLock string `json:"registrationLock"`
}

// PhoneNumberDiscoverabilityRequest is the JSON body for setting phone number
// discoverability.
type PhoneNumberDiscoverabilityRequest struct {
	DiscoverableByPhoneNumber bool `json:"discoverableByPhoneNumber"`
}

// UsernameHashReserveRequest is the JSON body for reserving a username hash.
type UsernameHashReserveRequest struct {
	UsernameHashes []string `json:"usernameHashes"`
}

// UsernameHashReserveResponse is returned after a successful username hash
// reservation. ReservationToken must be echoed back by the client in the
// subsequent confirm call (UsernameHashConfirmRequest.ReservationToken).
type UsernameHashReserveResponse struct {
	UsernameHash     string `json:"usernameHash"`
	ReservationToken string `json:"reservationToken"`
}

// UsernameHashConfirmRequest is the JSON body for confirming a reserved
// username hash. The client must supply a zero-knowledge proof (ZkProof,
// base64-encoded) that it knows the nickname/discriminator pair behind
// UsernameHash; the server verifies it via go-libsignal/usernames.VerifyProof
// before binding the hash to the account, mirroring Java Signal-Server's
// `usernameHashZkProofVerifier.verifyProof(...)` call site.
type UsernameHashConfirmRequest struct {
	UsernameHash     string `json:"usernameHash"`
	ReservationToken string `json:"reservationToken"`
	ZkProof          string `json:"zkProof"`
}

// UsernameHashConfirmResponse is returned after a username hash is confirmed,
// echoing the now-bound hash. Mirrors Java's UsernameHashResponse.
type UsernameHashConfirmResponse struct {
	UsernameHash string `json:"usernameHash"`
}

// UsernameHashLookupResponse is returned when looking up a username hash.
type UsernameHashLookupResponse struct {
	UUID string `json:"uuid"`
}

// UsernameLinkSetRequest is the JSON body for setting a username link.
type UsernameLinkSetRequest struct {
	UsernameLinkEncryptedValue string `json:"usernameLinkEncryptedValue"`

	// KeepLinkHandle requests that the server re-use the account's
	// existing link handle (if one exists) rather than minting a fresh
	// one. Clients that are only rotating the ciphertext should set
	// this so previously-published share URLs continue to resolve.
	// Matches Java EncryptedUsername.keepLinkHandle().
	KeepLinkHandle bool `json:"keepLinkHandle,omitempty"`
}

// UsernameLinkSetResponse is returned after a successful username link
// creation.
type UsernameLinkSetResponse struct {
	UsernameLinkHandle string `json:"usernameLinkHandle"`
}

// UsernameLinkLookupResponse is returned when looking up a username link.
type UsernameLinkLookupResponse struct {
	UsernameLinkEncryptedValue string `json:"usernameLinkEncryptedValue"`
}

// LinkDeviceRequestEntity is the JSON body for linking a new device.
type LinkDeviceRequestEntity struct {
	VerificationCode      string                        `json:"verificationCode"`
	AccountAttributes     DeviceAccountAttributesEntity `json:"accountAttributes"`
	AciSignedPreKey       SignedPreKeyEntity            `json:"aciSignedPreKey"`
	PniSignedPreKey       SignedPreKeyEntity            `json:"pniSignedPreKey"`
	AciPqLastResortPreKey KEMSignedPreKeyEntity         `json:"aciPqLastResortPreKey"`
	PniPqLastResortPreKey KEMSignedPreKeyEntity         `json:"pniPqLastResortPreKey"`
}

// DeviceAccountAttributesEntity carries the device-specific attributes submitted
// during device linking.
type DeviceAccountAttributesEntity struct {
	FetchesMessages   bool            `json:"fetchesMessages"`
	RegistrationId    uint32          `json:"registrationId"`
	PniRegistrationId uint32          `json:"pniRegistrationId"`
	Name              string          `json:"name"`
	Capabilities      map[string]bool `json:"capabilities"`
}

// SetDeviceCapabilitiesRequest is the JSON body for updating device capabilities.
type SetDeviceCapabilitiesRequest struct {
	Capabilities map[string]bool `json:"capabilities"`
}

// ProvisioningMessageRequest is the JSON body for sending a provisioning message
// to a waiting provisioning WebSocket session.
type ProvisioningMessageRequest struct {
	Body string `json:"body"`
}

// ChangeNumberRequest is the JSON body for PUT /v2/accounts/number. It mirrors
// the Java ChangeNumberRequest entity, carrying the new phone number,
// verification session info, PNI identity key, and per-device pre-keys.
type ChangeNumberRequest struct {
	Number                       string                           `json:"number"`
	SessionID                    string                           `json:"sessionId,omitempty"`
	RecoveryPassword             string                           `json:"recoveryPassword,omitempty"`
	RegistrationLock             string                           `json:"reglock,omitempty"`
	PniIdentityKey               string                           `json:"pniIdentityKey"`
	DeviceMessages               []IncomingMessageEntity          `json:"deviceMessages"`
	DevicePniSignedPrekeys       map[string]SignedPreKeyEntity    `json:"devicePniSignedPrekeys"`
	DevicePniPqLastResortPrekeys map[string]KEMSignedPreKeyEntity `json:"devicePniPqLastResortPrekeys"`
	PniRegistrationIds           map[string]uint32                `json:"pniRegistrationIds"`
}

// AccountIdentityResponse is the JSON response returned after a successful
// phone number change, matching the Java AccountIdentityResponse entity.
type AccountIdentityResponse struct {
	UUID               string `json:"uuid"`
	Number             string `json:"number"`
	PNI                string `json:"pni"`
	UsernameHash       string `json:"usernameHash,omitempty"`
	UsernameLinkHandle string `json:"usernameLinkHandle,omitempty"`
	StorageCapable     bool   `json:"storageCapable"`
}
