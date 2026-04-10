package signal

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// DAOStore implements the Store interface using QRDB GenericDAO for
// persistence. This is the default store for both CLI and desktop modes,
// replacing the legacy FileStore with a proper database-backed implementation.
type DAOStore struct {
	factory *daostore.Factory
}

// NewDAOStore creates a Store backed by the given DAO factory.
func NewDAOStore(factory *daostore.Factory) *DAOStore {
	return &DAOStore{factory: factory}
}

// NewDefaultDAOStore creates a Store with an embedded QRDB KVStore
// backed by PebbleDB in the given data directory. This is the default
// store used by both CLI and desktop modes.
func NewDefaultDAOStore(dataDir string) (*DAOStore, error) {
	kvStore, err := daostore.NewEmbeddedKVStore(dataDir)
	if err != nil {
		return nil, fmt.Errorf("create embedded kvstore: %w", err)
	}

	factory, err := daostore.NewFactory(kvStore)
	if err != nil {
		return nil, fmt.Errorf("create dao factory: %w", err)
	}

	return NewDAOStore(factory), nil
}

func (s *DAOStore) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// GetCredentials loads stored credentials.
func (s *DAOStore) GetCredentials() (*Credentials, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	entity, err := s.factory.Settings.QueryOneByIndex(ctx, "Key", "credentials")
	if err != nil {
		return nil, nil // not found — no credentials stored yet
	}

	// Credentials are stored as JSON in the settings entity value.
	var creds Credentials
	if err := unmarshalCredentials(entity.Value, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

// SaveCredentials persists credentials.
func (s *DAOStore) SaveCredentials(creds *Credentials) error {
	ctx, cancel := s.ctx()
	defer cancel()

	value, err := marshalCredentials(creds)
	if err != nil {
		return err
	}

	existing, getErr := s.factory.Settings.QueryOneByIndex(ctx, "Key", "credentials")
	if getErr == nil && existing != nil {
		existing.Value = value
		return s.factory.Settings.Save(ctx, existing)
	}

	entity := &entities.SettingEntity{
		Key:   "credentials",
		Value: value,
	}
	return s.factory.Settings.Save(ctx, entity)
}

// GetContacts returns all stored contacts.
func (s *DAOStore) GetContacts() ([]Contact, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	contactEntities, err := s.factory.Contacts.Find(ctx).Execute()
	if err != nil {
		return nil, err
	}

	contacts := make([]Contact, len(contactEntities))
	for i, e := range contactEntities {
		contacts[i] = Contact{
			Number:     e.E164,
			UUID:       e.UUID,
			Name:       e.ProfileName,
			GivenName:  e.GivenName,
			FamilyName: e.FamilyName,
			Blocked:    e.IsBlocked,
		}
	}
	return contacts, nil
}

// SaveContact persists a contact.
func (s *DAOStore) SaveContact(contact *Contact) error {
	ctx, cancel := s.ctx()
	defer cancel()

	// Upsert by UUID.
	var entity *entities.ContactEntity
	if contact.UUID != "" {
		existing, err := s.factory.Contacts.QueryOneByIndex(ctx, "UUID", contact.UUID)
		if err == nil && existing != nil {
			entity = existing
		}
	}
	if entity == nil {
		entity = &entities.ContactEntity{}
	}

	entity.UUID = contact.UUID
	entity.E164 = contact.Number
	entity.ProfileName = contact.Name
	entity.GivenName = contact.GivenName
	entity.FamilyName = contact.FamilyName
	entity.IsBlocked = contact.Blocked

	return s.factory.Contacts.Save(ctx, entity)
}

// DeleteContact removes a contact.
func (s *DAOStore) DeleteContact(number string) error {
	ctx, cancel := s.ctx()
	defer cancel()

	entity, err := s.factory.Contacts.QueryOneByIndex(ctx, "E164", number)
	if err != nil {
		return nil
	}
	return s.factory.Contacts.Delete(ctx, entity)
}

// GetMessages returns messages for a conversation.
func (s *DAOStore) GetMessages(conversationID string, limit int) ([]Message, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	query := s.factory.Messages.Find(ctx).
		Where("ConversationID = ?", conversationID).
		OrderBy("Timestamp")
	if limit > 0 {
		query = query.Limit(limit)
	}

	msgEntities, err := query.Execute()
	if err != nil {
		return nil, err
	}

	messages := make([]Message, len(msgEntities))
	for i, e := range msgEntities {
		messages[i] = Message{
			Timestamp:   e.Timestamp,
			Source:      e.SourceUUID,
			Destination: e.ConversationID,
			Body:        e.Body,
		}
	}
	return messages, nil
}

// SaveMessage persists a message.
func (s *DAOStore) SaveMessage(msg *Message) error {
	ctx, cancel := s.ctx()
	defer cancel()

	entity := &entities.MessageEntity{
		GUID:           fmt.Sprintf("%d-%s", msg.Timestamp, msg.Destination),
		ConversationID: msg.Destination,
		SourceUUID:     msg.Source,
		Timestamp:      msg.Timestamp,
		Body:           msg.Body,
		Type:           2, // outgoing by default
	}
	if msg.Source != "" {
		entity.Type = 1 // incoming
	}
	return s.factory.Messages.Save(ctx, entity)
}

// GetGroups returns all stored groups.
func (s *DAOStore) GetGroups() ([]Group, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	groupEntities, err := s.factory.Groups.Find(ctx).Execute()
	if err != nil {
		return nil, err
	}

	groups := make([]Group, len(groupEntities))
	for i, e := range groupEntities {
		groups[i] = Group{
			ID:          e.GroupID,
			Name:        e.Title,
			Description: e.Description,
			Revision:    int(e.Revision),
		}
	}
	return groups, nil
}

// SaveGroup persists a group.
func (s *DAOStore) SaveGroup(group *Group) error {
	ctx, cancel := s.ctx()
	defer cancel()

	var entity *entities.GroupEntity
	existing, err := s.factory.Groups.QueryOneByIndex(ctx, "GroupID", group.ID)
	if err == nil && existing != nil {
		entity = existing
	} else {
		entity = &entities.GroupEntity{}
	}

	entity.GroupID = group.ID
	entity.Title = group.Name
	entity.Description = group.Description
	entity.Revision = group.Revision

	return s.factory.Groups.Save(ctx, entity)
}

// Close releases resources.
func (s *DAOStore) Close() error {
	return nil
}

// Factory returns the underlying DAO factory for direct DAO access.
func (s *DAOStore) Factory() *daostore.Factory {
	return s.factory
}

// marshalCredentials serializes credentials to a string for storage.
// The password is stored as plaintext in the DB (protected by OS-level
// file permissions on PebbleDB's data directory).
func marshalCredentials(creds *Credentials) (string, error) {
	pw := ""
	if creds.Password != nil {
		pw = creds.Password.Plaintext()
	}
	return fmt.Sprintf(`{"number":%q,"uuid":%q,"pni":%q,"password":%q,"deviceId":%d}`,
		creds.Number, creds.UUID, creds.PNI, pw, creds.DeviceID), nil
}

// unmarshalCredentials deserializes credentials from storage.
func unmarshalCredentials(value string, creds *Credentials) error {
	type credJSON struct {
		Number   string `json:"number"`
		UUID     string `json:"uuid"`
		PNI      string `json:"pni"`
		Password string `json:"password"`
		DeviceID uint32 `json:"deviceId"`
	}
	var c credJSON
	if err := json.Unmarshal([]byte(value), &c); err != nil {
		return err
	}
	creds.Number = c.Number
	creds.UUID = c.UUID
	creds.PNI = c.PNI
	creds.DeviceID = c.DeviceID
	if c.Password != "" {
		creds.Password = secrets.NewSecureString(c.Password)
	}
	return nil
}
