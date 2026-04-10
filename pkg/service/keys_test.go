package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// TestNewKeyService_InterfaceSatisfaction verifies the concrete type satisfies
// the KeyService interface at compile time.
func TestNewKeyService_InterfaceSatisfaction(t *testing.T) {
	var _ KeyService = (*keyService)(nil)
}

func newTestKeyService() KeyService {
	store := newMockPreKeyStore()
	mgr := keys.NewKeysManager(store)
	return NewKeyService(mgr)
}

func TestKeyService_StoreKeys_ECPreKeys(t *testing.T) {
	svc := newTestKeyService()
	req := &keys.SetKeysRequest{
		PreKeys: []*keys.PreKey{
			{KeyID: 1, PublicKey: []byte("pk1")},
			{KeyID: 2, PublicKey: []byte("pk2")},
		},
	}

	if err := svc.StoreKeys(context.Background(), "uuid-k01", 1, req); err != nil {
		t.Fatalf("StoreKeys: unexpected error: %v", err)
	}
}

func TestKeyService_StoreKeys_NilRequest(t *testing.T) {
	svc := newTestKeyService()
	err := svc.StoreKeys(context.Background(), "uuid-k01", 1, nil)
	if err == nil {
		t.Fatal("StoreKeys: expected error for nil request")
	}
}

func TestKeyService_StoreKeys_StoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.storeECErr = errors.New("storage failure")
	mgr := keys.NewKeysManager(store)
	svc := NewKeyService(mgr)

	req := &keys.SetKeysRequest{
		PreKeys: []*keys.PreKey{{KeyID: 1, PublicKey: []byte("pk1")}},
	}
	err := svc.StoreKeys(context.Background(), "uuid-k01", 1, req)
	if err == nil {
		t.Fatal("StoreKeys: expected error from store")
	}
}

func TestKeyService_GetPreKeys_Success(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := keys.NewKeysManager(store)
	svc := NewKeyService(mgr)
	ctx := context.Background()

	// Seed a signed pre-key so GetPreKeys succeeds.
	_ = store.StoreSignedPreKey(ctx, "uuid-k02", 1, &keys.SignedPreKey{
		KeyID:     5,
		PublicKey: []byte("spk"),
		Signature: []byte("sig"),
	})
	// Seed an EC pre-key to be consumed.
	_ = store.StoreECPreKeys(ctx, "uuid-k02", 1, []*keys.PreKey{{KeyID: 10, PublicKey: []byte("ecpk")}})

	item, err := svc.GetPreKeys(ctx, "uuid-k02", 1)
	if err != nil {
		t.Fatalf("GetPreKeys: unexpected error: %v", err)
	}
	if item.SignedPreKey == nil {
		t.Error("GetPreKeys: expected SignedPreKey")
	}
	if item.PreKey == nil {
		t.Error("GetPreKeys: expected PreKey to be consumed")
	}
}

func TestKeyService_GetPreKeys_MissingSignedPreKey(t *testing.T) {
	svc := newTestKeyService()
	_, err := svc.GetPreKeys(context.Background(), "uuid-k03", 1)
	if err == nil {
		t.Fatal("GetPreKeys: expected error when signed pre-key is missing")
	}
}

func TestKeyService_GetPreKeyCount_Success(t *testing.T) {
	store := newMockPreKeyStore()
	mgr := keys.NewKeysManager(store)
	svc := NewKeyService(mgr)
	ctx := context.Background()

	_ = store.StoreECPreKeys(ctx, "uuid-k04", 1, []*keys.PreKey{{KeyID: 1}, {KeyID: 2}})
	_ = store.StoreKEMPreKeys(ctx, "uuid-k04", 1, []*keys.KEMSignedPreKey{{KeyID: 10, PublicKey: []byte("kpk"), Signature: []byte("ksig")}})

	state, err := svc.GetPreKeyCount(ctx, "uuid-k04", 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount: unexpected error: %v", err)
	}
	if state.ECCount != 2 {
		t.Errorf("GetPreKeyCount: expected ECCount=2, got %d", state.ECCount)
	}
	if state.KEMCount != 1 {
		t.Errorf("GetPreKeyCount: expected KEMCount=1, got %d", state.KEMCount)
	}
}

func TestKeyService_GetPreKeyCount_Empty(t *testing.T) {
	svc := newTestKeyService()
	state, err := svc.GetPreKeyCount(context.Background(), "uuid-k05", 1)
	if err != nil {
		t.Fatalf("GetPreKeyCount: unexpected error: %v", err)
	}
	if state.ECCount != 0 || state.KEMCount != 0 {
		t.Errorf("GetPreKeyCount: expected 0/0, got %d/%d", state.ECCount, state.KEMCount)
	}
}

func TestKeyService_GetPreKeyCount_StoreError(t *testing.T) {
	store := newMockPreKeyStore()
	store.countErr = errors.New("count failure")
	mgr := keys.NewKeysManager(store)
	svc := NewKeyService(mgr)

	_, err := svc.GetPreKeyCount(context.Background(), "uuid-k06", 1)
	if err == nil {
		t.Fatal("GetPreKeyCount: expected error from store")
	}
}

func TestKeyService_StoreSignedPreKey_Success(t *testing.T) {
	svc := newTestKeyService()
	spk := &keys.SignedPreKey{KeyID: 7, PublicKey: []byte("pk"), Signature: []byte("sig")}

	if err := svc.StoreSignedPreKey(context.Background(), "uuid-k07", 1, spk); err != nil {
		t.Fatalf("StoreSignedPreKey: unexpected error: %v", err)
	}
}

func TestKeyService_StoreSignedPreKey_Nil(t *testing.T) {
	svc := newTestKeyService()
	err := svc.StoreSignedPreKey(context.Background(), "uuid-k07", 1, nil)
	if err == nil {
		t.Fatal("StoreSignedPreKey: expected error for nil key")
	}
}

func TestKeyService_StoreKEMPreKeys_Success(t *testing.T) {
	svc := newTestKeyService()
	pks := []*keys.KEMSignedPreKey{
		{KeyID: 100, PublicKey: []byte("kpk"), Signature: []byte("ksig")},
	}

	if err := svc.StoreKEMPreKeys(context.Background(), "uuid-k08", 1, pks); err != nil {
		t.Fatalf("StoreKEMPreKeys: unexpected error: %v", err)
	}
}

func TestKeyService_StoreKEMPreKeys_Empty(t *testing.T) {
	svc := newTestKeyService()
	err := svc.StoreKEMPreKeys(context.Background(), "uuid-k08", 1, []*keys.KEMSignedPreKey{})
	if err == nil {
		t.Fatal("StoreKEMPreKeys: expected error for empty slice")
	}
}
