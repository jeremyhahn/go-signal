package signal

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

func TestClient_ListIdentities_NonDAOStore(t *testing.T) {
	// With a non-DAOStore, ListIdentities returns nil without error.
	c := newTestClient(t, "http://localhost", &stubStore{})
	identities, err := c.ListIdentities(context.Background())
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if identities != nil {
		t.Errorf("expected nil for non-DAOStore, got %v", identities)
	}
}

func TestClient_ListIdentities_EmptyDAOStore(t *testing.T) {
	dir := t.TempDir()
	daoStore, err := NewDefaultDAOStore(dir)
	if err != nil {
		t.Fatalf("NewDefaultDAOStore: %v", err)
	}
	defer func() { _ = daoStore.Close() }()

	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   dir,
		Store:     daoStore,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	identities, err := c.ListIdentities(context.Background())
	if err != nil {
		t.Fatalf("ListIdentities DAOStore: %v", err)
	}
	// Empty store returns empty slice.
	if len(identities) != 0 {
		t.Errorf("expected 0 identities, got %d", len(identities))
	}
}

func TestClient_TrustIdentity_NonDAOStore(t *testing.T) {
	// With a non-DAOStore, TrustIdentity returns an error.
	c := newTestClient(t, "http://localhost", &stubStore{})
	err := c.TrustIdentity(context.Background(), "+15550000001")
	if err == nil {
		t.Error("expected error for non-DAOStore")
	}
}

func TestClient_ListIdentities_WithUnverifiedIdentity(t *testing.T) {
	dir := t.TempDir()
	daoStore, err := NewDefaultDAOStore(dir)
	if err != nil {
		t.Fatalf("NewDefaultDAOStore: %v", err)
	}
	defer func() { _ = daoStore.Close() }()

	// Seed an identity key via the DAO identity key store.
	localKP, _ := ecc.GenerateKeyPair()
	localPub := identity.NewKey(localKP.PublicKey())
	localIDKP := identity.NewKeyPair(localPub, localKP.PrivateKey())
	idStore := NewDAOIdentityKeyStore(daoStore.Factory(), localIDKP, 1)

	addr := protocol.NewSignalAddress("contact-uuid", 1)
	remoteKP, _ := ecc.GenerateKeyPair()
	_, err = idStore.SaveIdentity(addr, identity.NewKey(remoteKP.PublicKey()))
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	cfg := ClientConfig{ServerURL: "http://localhost", DataDir: dir, Store: daoStore}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	identities, err := c.ListIdentities(context.Background())
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	if len(identities) == 0 {
		t.Fatal("expected at least one identity")
	}
	if identities[0].TrustLevel != "TRUSTED_UNVERIFIED" {
		t.Errorf("TrustLevel = %q, want TRUSTED_UNVERIFIED", identities[0].TrustLevel)
	}
}

func TestClient_ListIdentities_WithVerifiedIdentity(t *testing.T) {
	dir := t.TempDir()
	daoStore, err := NewDefaultDAOStore(dir)
	if err != nil {
		t.Fatalf("NewDefaultDAOStore: %v", err)
	}
	defer func() { _ = daoStore.Close() }()

	localKP, _ := ecc.GenerateKeyPair()
	localPub := identity.NewKey(localKP.PublicKey())
	localIDKP := identity.NewKeyPair(localPub, localKP.PrivateKey())
	idStore := NewDAOIdentityKeyStore(daoStore.Factory(), localIDKP, 1)

	addr := protocol.NewSignalAddress("verified-uuid", 1)
	remoteKP, _ := ecc.GenerateKeyPair()
	_, err = idStore.SaveIdentity(addr, identity.NewKey(remoteKP.PublicKey()))
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	cfg := ClientConfig{ServerURL: "http://localhost", DataDir: dir, Store: daoStore}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Mark identity as trusted (sets VerifiedStatus = 1 in the DAO).
	if err := c.TrustIdentity(context.Background(), "verified-uuid"); err != nil {
		t.Fatalf("TrustIdentity: %v", err)
	}

	identities, err := c.ListIdentities(context.Background())
	if err != nil {
		t.Fatalf("ListIdentities after trust: %v", err)
	}
	if len(identities) == 0 {
		t.Fatal("expected at least one identity after trust")
	}
	if identities[0].TrustLevel != "TRUSTED_VERIFIED" {
		t.Errorf("TrustLevel = %q, want TRUSTED_VERIFIED", identities[0].TrustLevel)
	}
}

func TestClient_TrustIdentity_NotFoundInDAO(t *testing.T) {
	dir := t.TempDir()
	daoStore, err := NewDefaultDAOStore(dir)
	if err != nil {
		t.Fatalf("NewDefaultDAOStore: %v", err)
	}
	defer func() { _ = daoStore.Close() }()

	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   dir,
		Store:     daoStore,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()

	// No identity saved yet → should return error.
	err = c.TrustIdentity(context.Background(), "+15550000001")
	if err == nil {
		t.Error("expected error when identity not found")
	}
}
