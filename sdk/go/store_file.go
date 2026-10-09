package signal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// FileStore is a file-based implementation of Store that persists data
// as JSON files in a directory hierarchy. Sensitive credential material
// is stored in a separate file with restricted permissions and loaded
// into protected memory on read.
type FileStore struct {
	mu      sync.RWMutex
	rootDir string
}

// NewFileStore creates a new file-based store rooted at the given directory.
func NewFileStore(rootDir string) (*FileStore, error) {
	if err := os.MkdirAll(rootDir, 0700); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "create store dir", err)
	}
	return &FileStore{rootDir: rootDir}, nil
}

func (s *FileStore) path(parts ...string) string {
	return filepath.Join(append([]string{s.rootDir}, parts...)...)
}

func (s *FileStore) readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (s *FileStore) writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// credentialsOnDisk is the serialized format for credentials. The password
// is stored in a separate file to limit exposure surface.
type credentialsOnDisk struct {
	Number   string `json:"number"`
	UUID     string `json:"uuid"`
	PNI      string `json:"pni,omitempty"`
	DeviceID uint32 `json:"deviceId"`
}

func (s *FileStore) GetCredentials(ctx context.Context) (*Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var disk credentialsOnDisk
	if err := s.readJSON(s.path("credentials.json"), &disk); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// Load password from separate restricted file into secure memory.
	var password *secrets.SecureString
	pwBytes, err := os.ReadFile(s.path(".auth_token"))
	if err == nil && len(pwBytes) > 0 {
		password, err = secrets.NewSecureString(ctx, string(pwBytes))
		// Wipe the intermediate buffer immediately, whether or not sealing
		// succeeded.
		for i := range pwBytes {
			pwBytes[i] = 0
		}
		if err != nil {
			return nil, err
		}
	}

	return &Credentials{
		Number:   disk.Number,
		UUID:     disk.UUID,
		PNI:      disk.PNI,
		Password: password,
		DeviceID: disk.DeviceID,
	}, nil
}

func (s *FileStore) SaveCredentials(ctx context.Context, creds *Credentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Write non-sensitive fields to credentials.json.
	disk := credentialsOnDisk{
		Number:   creds.Number,
		UUID:     creds.UUID,
		PNI:      creds.PNI,
		DeviceID: creds.DeviceID,
	}
	if err := s.writeJSON(s.path("credentials.json"), disk); err != nil {
		return err
	}

	// Write password to a separate file with strict permissions.
	// The password is extracted from SecureString, written, and the
	// intermediate buffer is zeroed.
	if creds.Password != nil {
		pw := creds.Password.Bytes(ctx)
		if pw != nil {
			if err := os.WriteFile(s.path(".auth_token"), pw, 0600); err != nil {
				for i := range pw {
					pw[i] = 0
				}
				return err
			}
			for i := range pw {
				pw[i] = 0
			}
		}
	}

	return nil
}

func (s *FileStore) GetContacts() ([]Contact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var contacts []Contact
	if err := s.readJSON(s.path("contacts.json"), &contacts); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return contacts, nil
}

func (s *FileStore) SaveContact(contact *Contact) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	contacts, _ := s.getContactsLocked()
	for i, c := range contacts {
		if c.Number == contact.Number {
			contacts[i] = *contact
			return s.writeJSON(s.path("contacts.json"), contacts)
		}
	}
	contacts = append(contacts, *contact)
	return s.writeJSON(s.path("contacts.json"), contacts)
}

func (s *FileStore) DeleteContact(number string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	contacts, _ := s.getContactsLocked()
	filtered := make([]Contact, 0, len(contacts))
	for _, c := range contacts {
		if c.Number != number {
			filtered = append(filtered, c)
		}
	}
	return s.writeJSON(s.path("contacts.json"), filtered)
}

func (s *FileStore) getContactsLocked() ([]Contact, error) {
	var contacts []Contact
	if err := s.readJSON(s.path("contacts.json"), &contacts); err != nil {
		return nil, err
	}
	return contacts, nil
}

func (s *FileStore) GetMessages(conversationID string, limit int) ([]Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var messages []Message
	path := s.path("messages", conversationID+".json")
	if err := s.readJSON(path, &messages); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if limit > 0 && len(messages) > limit {
		messages = messages[len(messages)-limit:]
	}
	return messages, nil
}

func (s *FileStore) SaveMessage(msg *Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	convID := msg.Source
	if convID == "" {
		convID = msg.Destination
	}
	if msg.GroupID != "" {
		convID = msg.GroupID
	}

	path := s.path("messages", convID+".json")
	var messages []Message
	_ = s.readJSON(path, &messages)
	messages = append(messages, *msg)
	return s.writeJSON(path, messages)
}

func (s *FileStore) GetGroups() ([]Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var groups []Group
	if err := s.readJSON(s.path("groups.json"), &groups); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return groups, nil
}

func (s *FileStore) SaveGroup(group *Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	groups, _ := s.getGroupsLocked()
	for i, g := range groups {
		if g.ID == group.ID {
			groups[i] = *group
			return s.writeJSON(s.path("groups.json"), groups)
		}
	}
	groups = append(groups, *group)
	return s.writeJSON(s.path("groups.json"), groups)
}

func (s *FileStore) getGroupsLocked() ([]Group, error) {
	var groups []Group
	if err := s.readJSON(s.path("groups.json"), &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

func (s *FileStore) GetStickerPacks() ([]InstalledStickerPack, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var packs []InstalledStickerPack
	if err := s.readJSON(s.path("sticker_packs.json"), &packs); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return packs, nil
}

func (s *FileStore) SaveStickerPack(pack *InstalledStickerPack) error {
	if pack == nil || pack.PackID == "" {
		return errors.New("sticker pack: PackID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var packs []InstalledStickerPack
	if err := s.readJSON(s.path("sticker_packs.json"), &packs); err != nil && !os.IsNotExist(err) {
		return err
	}
	for i, p := range packs {
		if p.PackID == pack.PackID {
			packs[i] = *pack
			return s.writeJSON(s.path("sticker_packs.json"), packs)
		}
	}
	packs = append(packs, *pack)
	return s.writeJSON(s.path("sticker_packs.json"), packs)
}

func (s *FileStore) DeleteStickerPack(packID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var packs []InstalledStickerPack
	if err := s.readJSON(s.path("sticker_packs.json"), &packs); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	out := packs[:0]
	for _, p := range packs {
		if p.PackID != packID {
			out = append(out, p)
		}
	}
	return s.writeJSON(s.path("sticker_packs.json"), out)
}

func (s *FileStore) Close() error {
	return nil
}
