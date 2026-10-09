package secrets

import (
	"errors"
	"testing"
)

// TestConfigProcessor_UnopenableSecureStringFieldIsAnError: a configured
// *SecureString field that cannot be opened must fail the processing pass. It
// used to read as "", which the processor treats as "nothing to resolve", so a
// configured URI was skipped without a trace.
func TestConfigProcessor_UnopenableSecureStringFieldIsAnError(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(ctxIgnoringResolver{value: "resolved"})
	cfg := &testSecureConfig{Password: MustNewSecureString(t.Context(), "kms://signal/password")}
	defer cfg.Password.Destroy()

	err := NewConfigProcessor(registry).Process(canceledContext(), cfg)

	var procErr *ProcessingError
	if !errors.As(err, &procErr) {
		t.Fatalf("err = %T (%v), want *ProcessingError", err, err)
	}
	var unavailable *UnavailableSecretError
	if !errors.As(err, &unavailable) {
		t.Errorf("err = %v, want it to wrap *UnavailableSecretError", err)
	}
}

// TestConfigProcessor_UnopenableResolvedStringIsAnError: a resolved secret that
// cannot be read back must fail the pass, not overwrite the field with "".
func TestConfigProcessor_UnopenableResolvedStringIsAnError(t *testing.T) {
	registry := NewResolverRegistry()
	registry.Register(ctxIgnoringResolver{value: "resolved"})
	cfg := &testConfig{Password: "kms://signal/password"}

	err := NewConfigProcessor(registry).Process(canceledContext(), cfg)

	var procErr *ProcessingError
	if !errors.As(err, &procErr) {
		t.Fatalf("err = %T (%v), want *ProcessingError", err, err)
	}
	if cfg.Password != "kms://signal/password" {
		t.Errorf("Password = %q, want the field left untouched", cfg.Password)
	}
}
