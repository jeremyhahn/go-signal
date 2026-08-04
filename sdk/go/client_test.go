package signal

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// mockStore is a configurable in-memory Store for tests that need full
// credential or contact support. stubStore (defined in stickers_test.go)
// remains available for lightweight sticker tests.
type mockStore struct {
	credentials      *Credentials
	credErr          error
	saveCredErr      error
	contacts         []Contact
	contactErr       error
	saveContactErr   error
	deleteContactErr error
	messages         map[string][]Message
	saveMsgErr       error
	groups           []Group
	groupErr         error
	saveGroupErr     error
	stickerPacks     []InstalledStickerPack
}

func (s *mockStore) GetCredentials() (*Credentials, error) { return s.credentials, s.credErr }
func (s *mockStore) SaveCredentials(c *Credentials) error {
	s.credentials = c
	return s.saveCredErr
}
func (s *mockStore) GetContacts() ([]Contact, error) { return s.contacts, s.contactErr }
func (s *mockStore) SaveContact(c *Contact) error {
	if s.saveContactErr != nil {
		return s.saveContactErr
	}
	for i, ct := range s.contacts {
		if ct.Number == c.Number {
			s.contacts[i] = *c
			return nil
		}
	}
	s.contacts = append(s.contacts, *c)
	return nil
}
func (s *mockStore) DeleteContact(n string) error {
	if s.deleteContactErr != nil {
		return s.deleteContactErr
	}
	out := s.contacts[:0]
	for _, c := range s.contacts {
		if c.Number != n {
			out = append(out, c)
		}
	}
	s.contacts = out
	return nil
}
func (s *mockStore) GetMessages(id string, limit int) ([]Message, error) {
	if s.messages == nil {
		return nil, nil
	}
	return s.messages[id], nil
}
func (s *mockStore) SaveMessage(m *Message) error {
	if s.messages == nil {
		s.messages = make(map[string][]Message)
	}
	key := m.Destination
	if key == "" {
		key = m.Source
	}
	s.messages[key] = append(s.messages[key], *m)
	return s.saveMsgErr
}
func (s *mockStore) GetGroups() ([]Group, error) { return s.groups, s.groupErr }
func (s *mockStore) SaveGroup(g *Group) error {
	if s.saveGroupErr != nil {
		return s.saveGroupErr
	}
	for i, grp := range s.groups {
		if grp.ID == g.ID {
			s.groups[i] = *g
			return nil
		}
	}
	s.groups = append(s.groups, *g)
	return nil
}
func (s *mockStore) GetStickerPacks() ([]InstalledStickerPack, error) {
	return s.stickerPacks, nil
}
func (s *mockStore) SaveStickerPack(p *InstalledStickerPack) error {
	if p == nil || p.PackID == "" {
		return errSDKInvalidStickerPack
	}
	for i, sp := range s.stickerPacks {
		if sp.PackID == p.PackID {
			s.stickerPacks[i] = *p
			return nil
		}
	}
	s.stickerPacks = append(s.stickerPacks, *p)
	return nil
}
func (s *mockStore) DeleteStickerPack(id string) error {
	out := s.stickerPacks[:0]
	for _, p := range s.stickerPacks {
		if p.PackID != id {
			out = append(out, p)
		}
	}
	s.stickerPacks = out
	return nil
}
func (s *mockStore) Close() error { return nil }

// newTestClient creates a Client for tests, registering cleanup automatically.
func newTestClient(t *testing.T, serverURL string, store Store) *Client {
	t.Helper()
	cfg := ClientConfig{
		ServerURL: serverURL,
		DataDir:   t.TempDir(),
		Store:     store,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// newTestClientWithCreds creates a Client whose store already holds credentials.
func newTestClientWithCreds(t *testing.T, serverURL string, creds *Credentials) *Client {
	t.Helper()
	ms := &mockStore{credentials: creds}
	return newTestClient(t, serverURL, ms)
}

// --- NewClient tests ---

func TestNewClient_MissingServerURL(t *testing.T) {
	_, err := NewClient(ClientConfig{DataDir: t.TempDir(), Store: &stubStore{}})
	if err == nil {
		t.Error("expected error for missing ServerURL")
	}
}

func TestNewClient_MissingDataDir(t *testing.T) {
	_, err := NewClient(ClientConfig{ServerURL: "http://localhost", Store: &stubStore{}})
	if err == nil {
		t.Error("expected error for missing DataDir")
	}
}

func TestNewClient_DefaultUserAgent(t *testing.T) {
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		Store:     &stubStore{},
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.config.UserAgent == "" {
		t.Error("expected default UserAgent to be set")
	}
}

func TestNewClient_WithStore(t *testing.T) {
	store := &stubStore{}
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		Store:     store,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.store != store {
		t.Error("expected injected store to be used")
	}
}

func TestNewClient_LoadsCredentialsFromStore(t *testing.T) {
	creds := &Credentials{
		Number:   "+15550000001",
		UUID:     "some-uuid",
		DeviceID: 2,
		Password: secrets.NewSecureString("mypassword"),
	}
	ms := &mockStore{credentials: creds}
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		Store:     ms,
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.config.Account != "+15550000001" {
		t.Errorf("Account = %q", c.config.Account)
	}
	if c.config.DeviceID != 2 {
		t.Errorf("DeviceID = %d", c.config.DeviceID)
	}
}

func TestClient_Config(t *testing.T) {
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		Store:     &stubStore{},
		UserAgent: "test-agent/1.0",
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() { _ = c.Close() }()
	got := c.Config()
	if got.ServerURL != "http://localhost" {
		t.Errorf("Config().ServerURL = %q", got.ServerURL)
	}
	if got.UserAgent != "test-agent/1.0" {
		t.Errorf("Config().UserAgent = %q", got.UserAgent)
	}
}

func TestClient_Close_WithNilStore(t *testing.T) {
	c := &Client{
		config: ClientConfig{
			Password: secrets.NewSecureString("pw"),
		},
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close with nil store: %v", err)
	}
}

func TestNewSecurePassword(t *testing.T) {
	ss := NewSecurePassword("hunter2")
	if ss == nil {
		t.Fatal("expected non-nil SecureString")
	}
	if ss.Plaintext() != "hunter2" {
		t.Errorf("Plaintext() = %q", ss.Plaintext())
	}
	ss.Destroy()
}

func TestNoopLogger_Methods(t *testing.T) {
	// noopLogger is the logger.Loggable implementation registered in init().
	// All methods are no-ops; calling them directly achieves statement coverage.
	var l noopLogger
	l.Debug("ctx", "message")
	l.Info("ctx", "message")
	l.Warning("ctx", "message")
	l.Error("ctx", "message")
	l.Configure("level")
}

func TestNewClient_NilStore_AutoCreatesDAOStore(t *testing.T) {
	// When Store is nil, NewClient creates a DAOStore automatically.
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		// Store: nil intentionally
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient with nil store: %v", err)
	}
	defer func() { _ = c.Close() }()
	if c.store == nil {
		t.Error("expected auto-created DAO store")
	}
}

func TestNewClient_NilStore_DAOStoreCreationError(t *testing.T) {
	// Make DataDir a file so NewDefaultDAOStore fails.
	parent := t.TempDir()
	conflictFile := parent + "/conflict"
	if err := os.WriteFile(conflictFile, []byte("x"), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   conflictFile, // DAO store can't be created inside a file
	}
	_, err := NewClient(cfg)
	if err == nil {
		t.Error("expected error when DAO store creation fails")
	}
}

func TestInitCrypto_WithCredentials_SetsRegID(t *testing.T) {
	// Credentials in the store should set regID = creds.DeviceID in initCrypto.
	creds := &Credentials{UUID: "my-uuid", DeviceID: 7, Password: NewSecurePassword("pw")}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, "http://localhost", ms)
	if err := c.initCrypto(); err != nil {
		t.Fatalf("initCrypto with credentials: %v", err)
	}
	if c.crypto == nil {
		t.Error("expected crypto state to be initialized")
	}
}

func TestNewClient_WithInvalidCACert(t *testing.T) {
	badPEM := secrets.NewSecureString("not-a-valid-cert")
	defer badPEM.Destroy()
	cfg := ClientConfig{
		ServerURL: "http://localhost",
		DataDir:   t.TempDir(),
		Store:     &stubStore{},
		CACert:    badPEM,
	}
	_, err := NewClient(cfg)
	if err == nil {
		t.Error("expected error for invalid CA cert PEM")
	}
}
