package signal

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func TestClientConfig_Destroy_NilFields(t *testing.T) {
	cfg := &ClientConfig{}
	// Must not panic.
	cfg.Destroy()
}

func TestClientConfig_Destroy_WithPassword(t *testing.T) {
	cfg := &ClientConfig{
		Password: secrets.MustNewSecureString("hunter2"),
	}
	cfg.Destroy()
	// After Destroy the password buffer should be zeroed/destroyed.
	if cfg.Password != nil && !cfg.Password.IsDestroyed() {
		t.Error("Password should be destroyed after Destroy()")
	}
}

func TestClientConfig_Destroy_WithCACert(t *testing.T) {
	cfg := &ClientConfig{
		CACert: secrets.MustNewSecureString("-----BEGIN CERTIFICATE-----"),
	}
	cfg.Destroy()
	if cfg.CACert != nil && !cfg.CACert.IsDestroyed() {
		t.Error("CACert should be destroyed after Destroy()")
	}
}

func TestClientConfig_Destroy_BothFields(t *testing.T) {
	cfg := &ClientConfig{
		Password: secrets.MustNewSecureString("pass"),
		CACert:   secrets.MustNewSecureString("cert"),
	}
	cfg.Destroy()
	// No panic and both fields destroyed.
}

func TestCredentials_Destroy_Nil(t *testing.T) {
	var c *Credentials
	c.Destroy() // must not panic
}

func TestCredentials_Destroy_WithPassword(t *testing.T) {
	c := &Credentials{
		Number:   "+15550000001",
		Password: secrets.MustNewSecureString("secret"),
	}
	c.Destroy()
	if c.Password != nil && !c.Password.IsDestroyed() {
		t.Error("Password should be destroyed after Destroy()")
	}
}

func TestCredentials_Destroy_NilPassword(t *testing.T) {
	c := &Credentials{Number: "+15550000001"}
	c.Destroy() // must not panic
}
