// Package certificates provides delivery certificate and group credential
// generation for sealed-sender messaging in the Signal protocol.
package certificates

// DeliveryCertificate is a sealed-sender certificate and its expiry in Unix milliseconds.
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

// ExpiringProfileKeyCredentialResponse holds the serialized zkgroup response and its Unix expiry.
type ExpiringProfileKeyCredentialResponse struct {
	Credential               []byte `json:"credential"`
	CredentialExpirationTime int64  `json:"credentialExpirationTime"`
}
