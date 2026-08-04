package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SignS3PostPolicy computes the AWS Signature Version 4 signature for an S3
// browser-based POST upload policy. The signature is the hex-encoded
// HMAC-SHA256 of the base64-encoded policy document under the SigV4 signing key
// derived from the secret access key, date, region, and service ("s3").
//
// This is the POST-policy variant of SigV4 (used for direct browser/client
// uploads): unlike request signing, the "string to sign" is simply the
// base64-encoded policy document itself.
//
//	dateStamp  — the UTC date in "YYYYMMDD" form (the credential-scope date).
//	region     — the S3 region (e.g. "us-east-1").
//	policyB64  — the base64-encoded policy document the client will submit.
func SignS3PostPolicy(secretAccessKey, dateStamp, region, policyB64 string) string {
	kDate := hmacSHA256([]byte("AWS4"+secretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return hex.EncodeToString(hmacSHA256(kSigning, []byte(policyB64)))
}

// hmacSHA256 returns HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
