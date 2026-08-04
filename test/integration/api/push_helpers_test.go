//go:build integration

package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

// generateRSAKeyPEM returns a fresh 2048-bit RSA private key encoded as
// PKCS#8 PEM. Used by the push-e2e test's fake service-account JSON
// envelope so the FCM provider's key-parse path runs against real key
// material.
func generateRSAKeyPEM() (string, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
