package messages

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// stubResolver records which lookup was invoked and returns the
// pre-populated account bound to that path.
type stubResolver struct {
	byACI map[string]*accounts.Account
	byPNI map[string]*accounts.Account
	calls []string // "Get:<uuid>" or "GetByPNI:<uuid>"
}

func newStubResolver() *stubResolver {
	return &stubResolver{
		byACI: map[string]*accounts.Account{},
		byPNI: map[string]*accounts.Account{},
	}
}

func (s *stubResolver) Get(_ context.Context, uuid string) (*accounts.Account, error) {
	s.calls = append(s.calls, "Get:"+uuid)
	if a, ok := s.byACI[uuid]; ok {
		return a, nil
	}
	return nil, &accounts.AccountNotFoundError{Identifier: uuid}
}

func (s *stubResolver) GetByPNI(_ context.Context, pni string) (*accounts.Account, error) {
	s.calls = append(s.calls, "GetByPNI:"+pni)
	if a, ok := s.byPNI[pni]; ok {
		return a, nil
	}
	return nil, &accounts.AccountNotFoundError{Identifier: pni}
}

// ---- ResolveDestinationAccount dispatches by identifier type ----

func TestResolveDestinationAccount_ACI_UsesGet(t *testing.T) {
	t.Parallel()
	r := newStubResolver()
	r.byACI["aci-1"] = &accounts.Account{UUID: "aci-1", PNI: "pni-1"}

	got, err := ResolveDestinationAccount(context.Background(), r, accounts.IdentityTypeACI, "aci-1")
	if err != nil {
		t.Fatalf("ResolveDestinationAccount: %v", err)
	}
	if got.UUID != "aci-1" {
		t.Fatalf("wrong account: %+v", got)
	}
	if len(r.calls) != 1 || r.calls[0] != "Get:aci-1" {
		t.Fatalf("wrong lookup path: %v", r.calls)
	}
}

func TestResolveDestinationAccount_PNI_UsesGetByPNI(t *testing.T) {
	t.Parallel()
	r := newStubResolver()
	r.byPNI["pni-1"] = &accounts.Account{UUID: "aci-1", PNI: "pni-1"}

	got, err := ResolveDestinationAccount(context.Background(), r, accounts.IdentityTypePNI, "pni-1")
	if err != nil {
		t.Fatalf("ResolveDestinationAccount: %v", err)
	}
	if got.PNI != "pni-1" {
		t.Fatalf("wrong account: %+v", got)
	}
	if len(r.calls) != 1 || r.calls[0] != "GetByPNI:pni-1" {
		t.Fatalf("wrong lookup path: %v", r.calls)
	}
}

func TestResolveDestinationAccount_ZeroValue_IsACI(t *testing.T) {
	t.Parallel()
	r := newStubResolver()
	r.byACI["aci-zero"] = &accounts.Account{UUID: "aci-zero"}

	// Zero value of IdentityType is IdentityTypeACI; the resolver
	// should hit the ACI path for legacy senders.
	var zero accounts.IdentityType
	got, err := ResolveDestinationAccount(context.Background(), r, zero, "aci-zero")
	if err != nil {
		t.Fatalf("ResolveDestinationAccount (zero value): %v", err)
	}
	if got.UUID != "aci-zero" {
		t.Fatalf("zero value did not route to ACI: %+v", got)
	}
}

func TestResolveDestinationAccount_MissingAccount_PropagatesNotFound(t *testing.T) {
	t.Parallel()
	r := newStubResolver()
	_, err := ResolveDestinationAccount(context.Background(), r, accounts.IdentityTypePNI, "absent")

	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

// ---- Envelope.StorageNamespace ----

func TestEnvelope_StorageNamespace_ReturnsDestinationUUID(t *testing.T) {
	t.Parallel()
	env := &Envelope{DestinationUUID: "whatever", DestinationIdentityType: accounts.IdentityTypePNI}
	if env.StorageNamespace() != "whatever" {
		t.Fatalf("StorageNamespace mismatch: %s", env.StorageNamespace())
	}
}
