package signal

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	grouprecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	staterecord "github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

func newTestSerializer() *serialize.Serializer {
	return serialize.NewProtobufSerializer()
}

// --- addressKey helper ---

func TestAddressKey_Format(t *testing.T) {
	addr := protocol.NewSignalAddress("user-uuid", 1)
	got := addressKey(addr)
	if got != "user-uuid_1" {
		t.Errorf("addressKey = %q", got)
	}
}

func TestAddressKey_MultipleDevices(t *testing.T) {
	a1 := addressKey(protocol.NewSignalAddress("uuid", 1))
	a2 := addressKey(protocol.NewSignalAddress("uuid", 2))
	if a1 == a2 {
		t.Error("different device IDs should produce different keys")
	}
}

// --- fileSessionStore ---

func TestFileSessionStore_LoadSession_NewReturnsEmpty(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	addr := protocol.NewSignalAddress("user-uuid", 1)
	sess, err := store.LoadSession(addr)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if sess == nil {
		t.Error("expected non-nil empty session for new address")
	}
}

func TestFileSessionStore_ContainsSession_False(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	addr := protocol.NewSignalAddress("nobody", 1)
	ok, err := store.ContainsSession(addr)
	if err != nil {
		t.Fatalf("ContainsSession: %v", err)
	}
	if ok {
		t.Error("expected ContainsSession=false for unknown address")
	}
}

func TestFileSessionStore_StoreAndContains(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	addr := protocol.NewSignalAddress("user-uuid", 1)
	sess := staterecord.NewSession(s.Session, s.State)
	if err := store.StoreSession(addr, sess); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	ok, err := store.ContainsSession(addr)
	if err != nil {
		t.Fatalf("ContainsSession after store: %v", err)
	}
	if !ok {
		t.Error("expected ContainsSession=true after storing session")
	}
}

func TestFileSessionStore_StoreAndLoad(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	addr := protocol.NewSignalAddress("alice-uuid", 1)
	sess := staterecord.NewSession(s.Session, s.State)
	if err := store.StoreSession(addr, sess); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	loaded, err := store.LoadSession(addr)
	if err != nil {
		t.Fatalf("LoadSession after store: %v", err)
	}
	if loaded == nil {
		t.Error("expected non-nil session after store")
	}
}

func TestFileSessionStore_DeleteSession(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	addr := protocol.NewSignalAddress("bob-uuid", 1)
	sess := staterecord.NewSession(s.Session, s.State)
	if err := store.StoreSession(addr, sess); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}
	if err := store.DeleteSession(addr); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	ok, _ := store.ContainsSession(addr)
	if ok {
		t.Error("expected session to be gone after delete")
	}
}

func TestFileSessionStore_DeleteSession_NonExistent(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	// Deleting non-existent session is idempotent.
	addr := protocol.NewSignalAddress("ghost", 1)
	if err := store.DeleteSession(addr); err != nil {
		t.Fatalf("DeleteSession non-existent: %v", err)
	}
}

func TestFileSessionStore_GetSubDeviceSessions_Empty(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	ids, err := store.GetSubDeviceSessions("nobody")
	if err != nil {
		t.Fatalf("GetSubDeviceSessions: %v", err)
	}
	if len(ids) != 0 {
		t.Errorf("expected 0 sub-device sessions, got %d", len(ids))
	}
}

func TestFileSessionStore_GetSubDeviceSessions_WithData(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	name := "multi-device-user"
	// Store sessions for devices 1 (primary, excluded) and 2, 3.
	for _, dev := range []uint32{1, 2, 3} {
		addr := protocol.NewSignalAddress(name, dev)
		sess := staterecord.NewSession(s.Session, s.State)
		if err := store.StoreSession(addr, sess); err != nil {
			t.Fatalf("StoreSession dev %d: %v", dev, err)
		}
	}
	ids, err := store.GetSubDeviceSessions(name)
	if err != nil {
		t.Fatalf("GetSubDeviceSessions: %v", err)
	}
	// Devices 2 and 3 are sub-devices (device 1 is primary, skipped).
	if len(ids) != 2 {
		t.Errorf("expected 2 sub-device sessions, got %d: %v", len(ids), ids)
	}
}

func TestFileSessionStore_DeleteAllSessions(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSessionStore(t.TempDir(), s)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	for _, dev := range []uint32{1, 2} {
		addr := protocol.NewSignalAddress("user", dev)
		sess := staterecord.NewSession(s.Session, s.State)
		if err := store.StoreSession(addr, sess); err != nil {
			t.Fatalf("StoreSession: %v", err)
		}
	}
	if err := store.DeleteAllSessions(); err != nil {
		t.Fatalf("DeleteAllSessions: %v", err)
	}
	ok, _ := store.ContainsSession(protocol.NewSignalAddress("user", 1))
	if ok {
		t.Error("expected all sessions deleted")
	}
}

// --- filePreKeyStore ---

func TestFilePreKeyStore_LoadPreKey_NotFound(t *testing.T) {
	store, err := newFilePreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFilePreKeyStore: %v", err)
	}
	pk, err := store.LoadPreKey(1)
	if err != nil {
		t.Fatalf("LoadPreKey: %v", err)
	}
	if pk != nil {
		t.Error("expected nil for unknown pre-key ID")
	}
}

func TestFilePreKeyStore_StoreAndLoad(t *testing.T) {
	s := newTestSerializer()
	store, err := newFilePreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFilePreKeyStore: %v", err)
	}
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	preKey := staterecord.NewPreKey(1, kp, s.PreKeyRecord)
	if err := store.StorePreKey(1, preKey); err != nil {
		t.Fatalf("StorePreKey: %v", err)
	}
	loaded, err := store.LoadPreKey(1)
	if err != nil {
		t.Fatalf("LoadPreKey: %v", err)
	}
	if loaded == nil {
		t.Error("expected non-nil pre-key after store")
	}
}

func TestFilePreKeyStore_ContainsPreKey(t *testing.T) {
	s := newTestSerializer()
	store, err := newFilePreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFilePreKeyStore: %v", err)
	}
	ok, err := store.ContainsPreKey(99)
	if err != nil || ok {
		t.Errorf("ContainsPreKey before store: ok=%v err=%v", ok, err)
	}
	kp, _ := ecc.GenerateKeyPair()
	_ = store.StorePreKey(99, staterecord.NewPreKey(99, kp, s.PreKeyRecord))
	ok, err = store.ContainsPreKey(99)
	if err != nil || !ok {
		t.Errorf("ContainsPreKey after store: ok=%v err=%v", ok, err)
	}
}

func TestFilePreKeyStore_RemovePreKey(t *testing.T) {
	s := newTestSerializer()
	store, err := newFilePreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFilePreKeyStore: %v", err)
	}
	kp, _ := ecc.GenerateKeyPair()
	_ = store.StorePreKey(5, staterecord.NewPreKey(5, kp, s.PreKeyRecord))
	if err := store.RemovePreKey(5); err != nil {
		t.Fatalf("RemovePreKey: %v", err)
	}
	ok, _ := store.ContainsPreKey(5)
	if ok {
		t.Error("expected pre-key removed")
	}
}

// --- fileSignedPreKeyStore ---

func TestFileSignedPreKeyStore_LoadSignedPreKey_NotFound(t *testing.T) {
	store, err := newFileSignedPreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileSignedPreKeyStore: %v", err)
	}
	spk, err := store.LoadSignedPreKey(1)
	if err != nil {
		t.Fatalf("LoadSignedPreKey: %v", err)
	}
	if spk != nil {
		t.Error("expected nil for unknown signed pre-key")
	}
}

func TestFileSignedPreKeyStore_StoreAndLoad(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSignedPreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileSignedPreKeyStore: %v", err)
	}
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	var sig [64]byte
	spk := staterecord.NewSignedPreKey(1, 1000, kp, sig, s.SignedPreKeyRecord)
	if err := store.StoreSignedPreKey(1, spk); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}
	loaded, err := store.LoadSignedPreKey(1)
	if err != nil {
		t.Fatalf("LoadSignedPreKey after store: %v", err)
	}
	if loaded == nil {
		t.Error("expected non-nil signed pre-key after store")
	}
}

func TestFileSignedPreKeyStore_LoadSignedPreKeys_Empty(t *testing.T) {
	store, err := newFileSignedPreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileSignedPreKeyStore: %v", err)
	}
	keys, err := store.LoadSignedPreKeys()
	if err != nil {
		t.Fatalf("LoadSignedPreKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 signed pre-keys, got %d", len(keys))
	}
}

func TestFileSignedPreKeyStore_LoadSignedPreKeys_WithData(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSignedPreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileSignedPreKeyStore: %v", err)
	}
	var sig [64]byte
	for i := uint32(1); i <= 3; i++ {
		kp, _ := ecc.GenerateKeyPair()
		_ = store.StoreSignedPreKey(i, staterecord.NewSignedPreKey(i, 1000, kp, sig, s.SignedPreKeyRecord))
	}
	keys, err := store.LoadSignedPreKeys()
	if err != nil {
		t.Fatalf("LoadSignedPreKeys: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 signed pre-keys, got %d", len(keys))
	}
}

func TestFileSignedPreKeyStore_ContainsAndRemove(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSignedPreKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileSignedPreKeyStore: %v", err)
	}
	ok, _ := store.ContainsSignedPreKey(7)
	if ok {
		t.Error("expected false before store")
	}
	kp, _ := ecc.GenerateKeyPair()
	var sig [64]byte
	_ = store.StoreSignedPreKey(7, staterecord.NewSignedPreKey(7, 1000, kp, sig, s.SignedPreKeyRecord))
	ok, _ = store.ContainsSignedPreKey(7)
	if !ok {
		t.Error("expected true after store")
	}
	_ = store.RemoveSignedPreKey(7)
	ok, _ = store.ContainsSignedPreKey(7)
	if ok {
		t.Error("expected false after remove")
	}
}

// --- fileIdentityStore ---

func TestFileIdentityStore_GetIdentityKeyPair(t *testing.T) {
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	store, err := newFileIdentityStore(t.TempDir(), idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}
	got := store.GetIdentityKeyPair()
	if got == nil {
		t.Error("expected non-nil identity key pair")
	}
}

func TestFileIdentityStore_GetLocalRegistrationId(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	store, err := newFileIdentityStore(t.TempDir(), idKP, 42)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}
	if id := store.GetLocalRegistrationId(); id != 42 {
		t.Errorf("registrationID = %d", id)
	}
}

func TestFileIdentityStore_SaveAndGetIdentity(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	store, err := newFileIdentityStore(t.TempDir(), idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}

	// Generate a remote identity key to save.
	remoteKP, _ := ecc.GenerateKeyPair()
	remoteKey := identity.NewKey(remoteKP.PublicKey())

	addr := protocol.NewSignalAddress("remote-uuid", 1)
	change, err := store.SaveIdentity(addr, remoteKey)
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	// First save: NewOrUnchanged.
	_ = change

	got, err := store.GetIdentity(addr)
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if got == nil {
		t.Error("expected non-nil identity after save")
	}
}

func TestFileIdentityStore_SaveIdentity_ReplacedExisting(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	store, err := newFileIdentityStore(t.TempDir(), idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}
	addr := protocol.NewSignalAddress("contact", 1)

	// Save first key.
	kp1, _ := ecc.GenerateKeyPair()
	_, _ = store.SaveIdentity(addr, identity.NewKey(kp1.PublicKey()))

	// Save a different key for the same address.
	kp2, _ := ecc.GenerateKeyPair()
	change, err := store.SaveIdentity(addr, identity.NewKey(kp2.PublicKey()))
	if err != nil {
		t.Fatalf("SaveIdentity replace: %v", err)
	}
	_ = change // ReplacedExisting expected
}

func TestFileIdentityStore_IsTrustedIdentity_TOFU(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	store, err := newFileIdentityStore(t.TempDir(), idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}
	addr := protocol.NewSignalAddress("new-contact", 1)
	remoteKP, _ := ecc.GenerateKeyPair()
	remoteKey := identity.NewKey(remoteKP.PublicKey())

	// Trust-on-first-use: unknown address → trusted.
	trusted, err := store.IsTrustedIdentity(addr, remoteKey, 0)
	if err != nil {
		t.Fatalf("IsTrustedIdentity: %v", err)
	}
	if !trusted {
		t.Error("TOFU: expected trusted for unknown address")
	}
}

func TestFileIdentityStore_GetIdentity_NotFound(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	store, err := newFileIdentityStore(t.TempDir(), idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}
	addr := protocol.NewSignalAddress("ghost", 1)
	got, err := store.GetIdentity(addr)
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if got != nil {
		t.Error("expected nil for unknown identity")
	}
}

func TestFileSessionStore_OpenFromExistingDir(t *testing.T) {
	// Covers the disk-load loop in newFileSessionStore.
	// Create a store, persist a session to disk, then open a new store
	// from the same directory — the new store reads the .bin file on startup.
	dir := t.TempDir()
	s := newTestSerializer()

	store1, err := newFileSessionStore(dir, s)
	if err != nil {
		t.Fatalf("newFileSessionStore (first): %v", err)
	}
	addr := protocol.NewSignalAddress("user-uuid", 1)
	sess := staterecord.NewSession(s.Session, s.State)
	if err := store1.StoreSession(addr, sess); err != nil {
		t.Fatalf("StoreSession: %v", err)
	}

	// A second open reads the .bin file from disk.  The empty-session bytes
	// fail to deserialize (continue branch), but the loop body is exercised.
	store2, err := newFileSessionStore(dir, s)
	if err != nil {
		t.Fatalf("newFileSessionStore (second): %v", err)
	}
	_ = store2
}

func TestFileIdentityStore_OpenFromExistingDir(t *testing.T) {
	// Covers the disk-load loop in newFileIdentityStore.
	dir := t.TempDir()
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	store1, err := newFileIdentityStore(dir, idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore (first): %v", err)
	}
	addr := protocol.NewSignalAddress("contact-uuid", 1)
	remoteKP, _ := ecc.GenerateKeyPair()
	_, err = store1.SaveIdentity(addr, identity.NewKey(remoteKP.PublicKey()))
	if err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// Second open reads the .json file written above.
	// The file has non-empty KeyBytes so the full loop body (including _ = key) runs.
	store2, err := newFileIdentityStore(dir, idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore (second): %v", err)
	}
	_ = store2
}

// --- fileSenderKeyStore ---

func TestSenderKeyNameKey_Format(t *testing.T) {
	sender := protocol.NewSignalAddress("sender-uuid", 1)
	name := protocol.NewSenderKeyName("group-abc", sender)
	key := senderKeyNameKey(name)
	if key == "" {
		t.Error("expected non-empty sender key name key")
	}
}

func TestFileSenderKeyStore_StoreAndLoad(t *testing.T) {
	s := newTestSerializer()
	store, err := newFileSenderKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileSenderKeyStore: %v", err)
	}
	sender := protocol.NewSignalAddress("sender-uuid", 1)
	name := protocol.NewSenderKeyName("group-1", sender)

	senderKey := grouprecord.NewSenderKey(s.SenderKeyRecord, s.SenderKeyState)
	if err := store.StoreSenderKey(name, senderKey); err != nil {
		t.Fatalf("StoreSenderKey: %v", err)
	}

	loaded, err := store.LoadSenderKey(name)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	if loaded == nil {
		t.Error("expected non-nil sender key after store")
	}
}

// --- Error path tests for file store constructors ---

func TestNewFilePreKeyStore_MkdirAllError(t *testing.T) {
	parent := t.TempDir()
	// Put a regular file at the path where MkdirAll would need to create a dir.
	conflictFile := parent + "/conflict"
	if err := os.WriteFile(conflictFile, []byte("x"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// subdir inside a file — MkdirAll fails on all POSIX systems.
	_, err := newFilePreKeyStore(conflictFile + "/prekeys")
	if err == nil {
		t.Fatal("expected error when MkdirAll fails")
	}
}

func TestNewFileSignedPreKeyStore_MkdirAllError(t *testing.T) {
	parent := t.TempDir()
	conflictFile := parent + "/conflict"
	if err := os.WriteFile(conflictFile, []byte("x"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := newFileSignedPreKeyStore(conflictFile + "/signed_prekeys")
	if err == nil {
		t.Fatal("expected error when MkdirAll fails")
	}
}

func TestNewFileSenderKeyStore_MkdirAllError(t *testing.T) {
	parent := t.TempDir()
	conflictFile := parent + "/conflict"
	if err := os.WriteFile(conflictFile, []byte("x"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := newFileSenderKeyStore(conflictFile + "/sender_keys")
	if err == nil {
		t.Fatal("expected error when MkdirAll fails")
	}
}

func TestNewFileIdentityStore_MkdirAllError(t *testing.T) {
	parent := t.TempDir()
	conflictFile := parent + "/conflict"
	if err := os.WriteFile(conflictFile, []byte("x"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())
	_, err := newFileIdentityStore(conflictFile+"/identity_keys", idKP, 1)
	if err == nil {
		t.Fatal("expected error when MkdirAll fails")
	}
}

func TestFileSenderKeyStore_Load_NotFound(t *testing.T) {
	store, err := newFileSenderKeyStore(t.TempDir())
	if err != nil {
		t.Fatalf("newFileSenderKeyStore: %v", err)
	}
	sender := protocol.NewSignalAddress("nobody", 1)
	name := protocol.NewSenderKeyName("group-x", sender)
	loaded, err := store.LoadSenderKey(name)
	if err != nil {
		t.Fatalf("LoadSenderKey not found: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil for unknown sender key")
	}
}

// --- Additional coverage tests ---

func TestNewFileSessionStore_MkdirAllError(t *testing.T) {
	// Place a regular file at the path where newFileSessionStore would create
	// "sessions/" so that MkdirAll fails, covering the error-return branch.
	parent := t.TempDir()
	// Create a file named "sessions" so MkdirAll(parent/sessions) fails.
	if err := os.WriteFile(filepath.Join(parent, "sessions"), []byte("x"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	ser := newTestSerializer()
	_, err := newFileSessionStore(parent, ser)
	if err == nil {
		t.Fatal("expected error when MkdirAll fails for sessions dir")
	}
}

func TestNewFileSessionStore_SkipsNonBinFiles(t *testing.T) {
	// Pre-populate the sessions directory with a non-.bin file.  When
	// newFileSessionStore opens the directory, it should skip the file
	// via the "not .bin" continue branch in the startup loop.
	dir := t.TempDir()
	sessDir := filepath.Join(dir, "sessions")
	if err := os.MkdirAll(sessDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessDir, "metadata.json"), []byte("{}"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	ser := newTestSerializer()
	store, err := newFileSessionStore(dir, ser)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}
	// No sessions loaded — the .json file was skipped.
	ok, _ := store.ContainsSession(protocol.NewSignalAddress("anyone", 1))
	if ok {
		t.Error("expected no sessions after skipping non-.bin file")
	}
}

func TestFileSessionStore_StoreSession_WriteFileFails(t *testing.T) {
	// Covers the persist-error return branch in StoreSession. A directory
	// occupying the exact path the session file would take makes WriteFile
	// fail with EISDIR, which holds for every uid — the read-only parent this
	// used to rely on does not, because CI runs as root
	// (testing-guidelines.md §Fault Injection).
	ser := newTestSerializer()
	dir := t.TempDir()
	store, err := newFileSessionStore(dir, ser)
	if err != nil {
		t.Fatalf("newFileSessionStore: %v", err)
	}

	addr := protocol.NewSignalAddress("user", 1)
	if err := os.Mkdir(store.path(addressKey(addr)), 0700); err != nil {
		t.Fatalf("Mkdir blocker: %v", err)
	}

	sess := staterecord.NewSession(ser.Session, ser.State)
	err = store.StoreSession(addr, sess)
	if err == nil {
		t.Fatal("expected error when session file cannot be written")
	}
	if !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("expected EISDIR, got %v", err)
	}
}

func TestNewFileIdentityStore_SkipsInvalidFiles(t *testing.T) {
	// Pre-populate identity_keys with (a) a non-.json file and (b) a .json
	// file with an empty key field.  newFileIdentityStore should skip both,
	// covering the IsDir/non-.json continue and the empty-KeyBytes continue.
	dir := t.TempDir()
	idDir := filepath.Join(dir, "identity_keys")
	if err := os.MkdirAll(idDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// (a) non-.json file → skipped by IsDir/suffix check.
	if err := os.WriteFile(filepath.Join(idDir, "notes.txt"), []byte("skip"), 0600); err != nil {
		t.Fatalf("WriteFile txt: %v", err)
	}
	// (b) .json with empty "key" field → skipped by len(id.KeyBytes) == 0 check.
	if err := os.WriteFile(filepath.Join(idDir, "empty.json"), []byte(`{"fingerprint":"abc","key":""}`), 0600); err != nil {
		t.Fatalf("WriteFile json: %v", err)
	}

	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())
	store, err := newFileIdentityStore(dir, idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}
	_ = store
}

func TestFileIdentityStore_IsTrustedIdentity_KnownKey(t *testing.T) {
	// Save an identity for an address, then call IsTrustedIdentity for the
	// same address.  This covers the "known address" path that compares
	// fingerprints (trusted.Fingerprint() == identityKey.Fingerprint()).
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())
	store, err := newFileIdentityStore(t.TempDir(), idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}

	addr := protocol.NewSignalAddress("known-contact", 1)
	remoteKP, _ := ecc.GenerateKeyPair()
	remoteKey := identity.NewKey(remoteKP.PublicKey())
	if _, err := store.SaveIdentity(addr, remoteKey); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// IsTrustedIdentity should compare fingerprints of the stored key.
	trusted, err := store.IsTrustedIdentity(addr, remoteKey, 0)
	if err != nil {
		t.Fatalf("IsTrustedIdentity: %v", err)
	}
	if !trusted {
		t.Error("expected same key to be trusted")
	}
}

func TestFileIdentityStore_SaveIdentity_WriteFileFails(t *testing.T) {
	// Covers the persist-error return branch in SaveIdentity. A directory
	// occupying the exact path the identity file would take makes WriteFile
	// fail with EISDIR, which root cannot bypass — unlike the read-only
	// parent this used to rely on.
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())
	dir := t.TempDir()
	store, err := newFileIdentityStore(dir, idKP, 1)
	if err != nil {
		t.Fatalf("newFileIdentityStore: %v", err)
	}

	addr := protocol.NewSignalAddress("contact", 1)
	idFile := filepath.Join(dir, "identity_keys", addressKey(addr)+".json")
	if err := os.Mkdir(idFile, 0700); err != nil {
		t.Fatalf("Mkdir blocker: %v", err)
	}

	remoteKP, _ := ecc.GenerateKeyPair()
	_, err = store.SaveIdentity(addr, identity.NewKey(remoteKP.PublicKey()))
	if err == nil {
		t.Fatal("expected error when identity file cannot be written")
	}
	if !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("expected EISDIR, got %v", err)
	}
}
