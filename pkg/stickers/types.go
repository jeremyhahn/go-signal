package stickers

import "time"

// StickerPackFormUpload describes the upload form returned to clients for
// uploading sticker packs to a CDN. The shape matches Java
// StickerPackFormUploadAttributes: clients embed every StickerFormField in
// a multipart S3 POST body.
type StickerPackFormUpload struct {
	PackId   string             `json:"packId"`
	Manifest StickerFormField   `json:"manifest"`
	Stickers []StickerFormField `json:"stickers"`
}

// StickerFormField describes a single S3 POST upload entry. The Acl /
// Algorithm / Date / Policy / Signature fields are passed through verbatim
// to the multipart body so S3 validates the policy + HMAC. Headers /
// Location stay populated for the legacy embedded-CDN code path so existing
// tests and dev deployments keep working.
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
	// BucketEndpoint is the full S3 endpoint URL the client must POST
	// the form to (e.g. https://my-bucket.s3.us-east-1.amazonaws.com).
	// Empty when the server is not configured for S3 — in that case
	// clients fall back to Location for the embedded-CDN path.
	BucketEndpoint string `json:"bucketEndpoint,omitempty"`
}

// PackMetadata records an issued sticker pack form for persistence. The
// server doesn't store sticker pack contents — those live on S3 — but it
// records the pack ID and account that requested it so abuse / audit
// queries can resolve a pack back to its uploader.
type PackMetadata struct {
	PackID      string
	AccountUUID string
	IssuedAt    time.Time
}
