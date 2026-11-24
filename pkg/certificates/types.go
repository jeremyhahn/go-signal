// Package certificates provides delivery certificate and group credential
// generation for sealed-sender messaging in the Signal protocol.
package certificates

// DeliveryCertificate represents a sender certificate for sealed-sender
// messaging. The Certificate field contains the serialized certificate bytes
// and CertificateExpiry is the Unix millisecond timestamp at which the
// certificate expires.
type DeliveryCertificate struct {
	Certificate       []byte `json:"certificate"`
	CertificateExpiry int64  `json:"certificateExpiry"`
}

// SenderCertificate contains the sender's identity information embedded
// within a delivery certificate for sealed-sender message delivery.
type SenderCertificate struct {
	SenderUUID     string `json:"senderUuid"`
	SenderE164     string `json:"senderE164,omitempty"`
	SenderDeviceID uint32 `json:"senderDeviceId"`
	Expiration     int64  `json:"expiration"`
	IdentityKey    []byte `json:"identityKey"`
	Signer         []byte `json:"signer"`
}

// GroupCredentials contains time-limited group send authentication credentials
// along with the phone number identity (PNI) of the requesting account.
type GroupCredentials struct {
	Credentials             []GroupCredential        `json:"credentials"`
	CallLinkAuthCredentials []CallLinkAuthCredential `json:"callLinkAuthCredentials"`
	PNI                     string                   `json:"pni"`
}

// CallLinkAuthCredential represents a single time-limited credential for
// call link authorization at the specified redemption time.
type CallLinkAuthCredential struct {
	Credential     []byte `json:"credential"`
	RedemptionTime int64  `json:"redemptionTime"`
}

// GroupCredential represents a single time-limited credential that can be
// redeemed for group send authorization at the specified redemption time.
type GroupCredential struct {
	Credential     []byte `json:"credential"`
	RedemptionTime int64  `json:"redemptionTime"`
}

// ExpiringProfileKeyCredentialResponse is the server's response for a profile
// key credential request. The Credential field contains the serialized
// ExpiringProfileKeyCredentialResponse from the zkgroup library, and
// CredentialExpirationTime is the Unix timestamp at which the credential expires.
type ExpiringProfileKeyCredentialResponse struct {
	Credential               []byte `json:"credential"`
	CredentialExpirationTime int64  `json:"credentialExpirationTime"`
}
