// Package s3 produces AWS S3 POST-policy upload forms and SigV4 signatures
// over the policy bytes. Mirrors Java Signal-Server's
// org.whispersystems.textsecuregcm.s3.PostPolicyGenerator + PolicySigner so
// existing iOS/Android/Desktop clients can upload sticker packs and
// attachment blobs directly to S3 without round-tripping through the
// server.
//
// No third-party AWS SDK dep — the SigV4 key chain
// (AWS4{secret} → date → region → service → "aws4_request") is the same
// derivation we hand-rolled for SES; the service slot is "s3" here.
package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// dateFormat is the YYYYMMDD form used in SigV4 credential scopes.
const dateFormat = "20060102"

// dateTimeFormat is the YYYYMMDDTHHMMSSZ form used in x-amz-date headers
// and the AWS_DATE_TIME constant on the Java side. The trailing 'Z' is the
// literal Zulu marker emitted by Go's time formatting for UTC.
const dateTimeFormat = "20060102T150405Z"

// expirationFormat matches Java DateTimeFormatter.ISO_INSTANT — used in the
// "expiration" field of the POST policy JSON.
const expirationFormat = time.RFC3339Nano

// PolicyGenerator builds S3 POST-policy upload descriptors. One generator
// instance wraps a bucket + region + access key ID combination; the secret
// is held by the companion PolicySigner.
//
// Each Generate call produces a fresh policy that:
//   - locks the upload to a specific object key
//   - requires acl=private
//   - caps the content length between 1 and the supplied maxSize
//   - is valid for 30 minutes from the supplied wall clock
//
// The policy bytes are base64-encoded for transmission to the client; the
// signer's HMAC of those base64 bytes goes in the form as `x-amz-signature`.
type PolicyGenerator struct {
	Region      string
	Bucket      string
	AccessKeyID string
}

// PolicyForm is the structured output of Generate. Clients embed every
// field in the multipart POST body except Policy (which is base64) and
// Signature (which is hex). The names mirror the Java
// StickerPackFormUploadItem fields so on-wire compatibility is one-for-one.
type PolicyForm struct {
	// Credential is `<accessKeyID>/<date>/<region>/s3/aws4_request`.
	Credential string
	// Policy is the base64-encoded JSON policy.
	Policy string
	// Acl is fixed to "private" per Java parity.
	Acl string
	// Algorithm is fixed to "AWS4-HMAC-SHA256".
	Algorithm string
	// Date is the request datetime in AWS form (YYYYMMDDTHHMMSSZ).
	Date string
	// Signature is the hex HMAC-SHA256 of Policy.
	Signature string
}

// Generate builds the policy + credential pair for the given object key.
// now should be a UTC wall-clock; the helper truncates to UTC so callers
// passing a timezone-aware value get deterministic results.
func (g *PolicyGenerator) Generate(now time.Time, objectKey string, maxSizeBytes int64) (policyJSON, credential string, err error) {
	if g.Region == "" {
		return "", "", errors.New("s3: PolicyGenerator.Region is required")
	}
	if g.Bucket == "" {
		return "", "", errors.New("s3: PolicyGenerator.Bucket is required")
	}
	if g.AccessKeyID == "" {
		return "", "", errors.New("s3: PolicyGenerator.AccessKeyID is required")
	}
	if objectKey == "" {
		return "", "", errors.New("s3: object key is required")
	}
	if maxSizeBytes < 1 {
		return "", "", errors.New("s3: maxSizeBytes must be >= 1")
	}
	now = now.UTC()
	expiration := now.Add(30 * time.Minute).Format(expirationFormat)
	credentialDate := now.Format(dateFormat)
	requestDate := now.Format(dateTimeFormat)
	credential = fmt.Sprintf("%s/%s/%s/s3/aws4_request", g.AccessKeyID, credentialDate, g.Region)

	// Hand-build the JSON to match Java byte-for-byte (the client only
	// needs valid JSON, but byte-identical output makes regression
	// debugging easier). The conditions array order matches Java's
	// PostPolicyGenerator.
	policyJSON = fmt.Sprintf(`{
  "expiration": "%s",
  "conditions": [
    {"bucket": "%s"},
    {"key": "%s"},
    {"acl": "private"},
    ["starts-with", "$Content-Type", ""],
    ["content-length-range", 1, %d],

    {"x-amz-credential": "%s"},
    {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
    {"x-amz-date": "%s" }
  ]
}
`, expiration, g.Bucket, objectKey, maxSizeBytes, credential, requestDate)
	return policyJSON, credential, nil
}

// EncodePolicy base64-encodes the policy JSON for transmission.
func EncodePolicy(policy string) string {
	return base64.StdEncoding.EncodeToString([]byte(policy))
}

// PolicySigner produces the SigV4 HMAC of a base64-encoded policy. The
// secret is held in-process; it is never logged or surfaced to clients.
type PolicySigner struct {
	SecretAccessKey string
	Region          string
}

// Sign computes the SigV4 signature of the base64-encoded policy for the
// given date. Returns lowercase hex per AWS spec. Mirrors Java's
// PolicySigner.getSignature.
func (s *PolicySigner) Sign(now time.Time, encodedPolicy string) (string, error) {
	if s.SecretAccessKey == "" {
		return "", errors.New("s3: PolicySigner.SecretAccessKey is required")
	}
	if s.Region == "" {
		return "", errors.New("s3: PolicySigner.Region is required")
	}
	date := now.UTC().Format(dateFormat)
	key := deriveSigningKey(s.SecretAccessKey, date, s.Region, "s3")
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(encodedPolicy))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// deriveSigningKey implements the SigV4 key chain:
//
//	kSecret  = "AWS4" + secret
//	kDate    = HMAC(kSecret, dateStamp)
//	kRegion  = HMAC(kDate, region)
//	kService = HMAC(kRegion, service)
//	kSigning = HMAC(kService, "aws4_request")
//
// Identical to the SES sigv4.go implementation but service="s3".
func deriveSigningKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// FormatForm builds a PolicyForm from a generator + signer in one call.
// Provided as a convenience for the sticker controller which always pairs
// the two; tests can still call Generate + Sign independently.
func FormatForm(gen *PolicyGenerator, signer *PolicySigner, now time.Time, objectKey string, maxSizeBytes int64) (*PolicyForm, error) {
	policy, credential, err := gen.Generate(now, objectKey, maxSizeBytes)
	if err != nil {
		return nil, err
	}
	encoded := EncodePolicy(policy)
	signature, err := signer.Sign(now, encoded)
	if err != nil {
		return nil, err
	}
	return &PolicyForm{
		Credential: credential,
		Policy:     encoded,
		Acl:        "private",
		Algorithm:  "AWS4-HMAC-SHA256",
		Date:       now.UTC().Format(dateTimeFormat),
		Signature:  signature,
	}, nil
}
