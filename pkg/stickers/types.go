package stickers

import "time"

// StickerPackFormUpload is the upload form clients post to the CDN as multipart S3 POST bodies.
type StickerPackFormUpload struct {
	PackId   string             `json:"packId"`
	Manifest StickerFormField   `json:"manifest"`
	Stickers []StickerFormField `json:"stickers"`
}

// StickerFormField is one S3 POST entry; Headers and Location serve the embedded-CDN path.
type StickerFormField struct {
	Id       int               `json:"id"`
	Key      string            `json:"key"`
	Headers  map[string]string `json:"headers,omitempty"`
	Location string            `json:"location,omitempty"`

	// --- Real S3 POST policy fields (Java parity) ---

	// Acl mirrors the policy condition and is always "private".
	Acl string `json:"acl,omitempty"`
	// Algorithm is "AWS4-HMAC-SHA256" when a signed policy is attached.
	Algorithm string `json:"algorithm,omitempty"`
	// Date is the request datetime in AWS form (YYYYMMDDTHHMMSSZ).
	Date string `json:"date,omitempty"`
	// Policy is the base64-encoded S3 POST policy.
	Policy string `json:"policy,omitempty"`
	// Signature is the lowercase hex HMAC-SHA256 of Policy.
	Signature string `json:"signature,omitempty"`
	// Credential is the SigV4 credential scope.
	Credential string `json:"credential,omitempty"`
	// BucketEndpoint is the S3 URL to POST to; empty without S3, when clients use Location.
	BucketEndpoint string `json:"bucketEndpoint,omitempty"`
}

// PackMetadata records which account requested a pack form.
type PackMetadata struct {
	PackID      string
	AccountUUID string
	IssuedAt    time.Time
}
