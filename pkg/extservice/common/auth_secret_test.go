package common

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestBasicAuthHeaderSecret_MatchesThePlainByteHeader pins the header bytes to
// what BasicAuthHeader produces from the same key: the services on the far end
// re-derive the digest, so any divergence is a wire break.
func TestBasicAuthHeaderSecret_MatchesThePlainByteHeader(t *testing.T) {
	const key, identity = "shared-secret", "alice"

	want := BasicAuthHeader(identity, []byte(key))
	got := BasicAuthHeaderSecret(identity, secrets.MustNewSecureString(key))

	if got != want {
		t.Errorf("BasicAuthHeaderSecret = %q, want %q", got, want)
	}
}

func TestBasicAuthHeaderSecret_RoundTripsThroughValidate(t *testing.T) {
	const key = "shared-secret"
	secret := secrets.MustNewSecureString(key)
	defer secret.Destroy()

	user, ok := ValidateBasicAuthSecret(BasicAuthHeaderSecret("alice", secret), secret)
	if !ok {
		t.Fatal("ValidateBasicAuthSecret rejected a header it minted")
	}
	if user != "alice" {
		t.Errorf("user = %q, want %q", user, "alice")
	}
}

func TestBasicAuthHeaderSecret_UnsetAndDestroyedSecretsYieldNoHeader(t *testing.T) {
	destroyed := secrets.MustNewSecureString("k")
	destroyed.Destroy()

	for name, secret := range map[string]*secrets.SecureString{
		"nil":       nil,
		"unset":     secrets.MustNewSecureString(""),
		"destroyed": destroyed,
	} {
		t.Run(name, func(t *testing.T) {
			if got := BasicAuthHeaderSecret("alice", secret); got != "" {
				t.Errorf("header = %q, want empty — an unusable secret must not sign", got)
			}
		})
	}
}

func TestValidateBasicAuthSecret_RejectsAWrongSecret(t *testing.T) {
	right := secrets.MustNewSecureString("right")
	defer right.Destroy()
	wrong := secrets.MustNewSecureString("wrong")
	defer wrong.Destroy()

	if _, ok := ValidateBasicAuthSecret(BasicAuthHeaderSecret("alice", right), wrong); ok {
		t.Error("ValidateBasicAuthSecret accepted a header signed with a different secret")
	}
}

func TestValidateBasicAuthSecret_FailsClosedForUnusableSecrets(t *testing.T) {
	header := BasicAuthHeader("alice", []byte("shared-secret"))

	destroyed := secrets.MustNewSecureString("shared-secret")
	destroyed.Destroy()

	for name, secret := range map[string]*secrets.SecureString{
		"nil":       nil,
		"unset":     secrets.MustNewSecureString(""),
		"destroyed": destroyed,
	} {
		t.Run(name, func(t *testing.T) {
			if user, ok := ValidateBasicAuthSecret(header, secret); ok {
				t.Errorf("authenticated %q against an unusable secret", user)
			}
		})
	}
}
