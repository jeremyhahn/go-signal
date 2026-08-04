package daostore

import (
	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// Factory creates and holds all GenericDAO instances for the Signal client.
// This factory is shared by both CLI and desktop GUI modes.
type Factory struct {
	Messages      dao.GenericDAO[*entities.MessageEntity]
	Conversations dao.GenericDAO[*entities.ConversationEntity]
	Contacts      dao.GenericDAO[*entities.ContactEntity]
	Groups        dao.GenericDAO[*entities.GroupEntity]
	Reactions     dao.GenericDAO[*entities.ReactionEntity]
	Attachments   dao.GenericDAO[*entities.AttachmentEntity]
	Stickers      dao.GenericDAO[*entities.StickerEntity]
	StickerPacks  dao.GenericDAO[*entities.StickerPackEntity]
	Jobs          dao.GenericDAO[*entities.JobEntity]
	Sessions      dao.GenericDAO[*entities.CryptoSessionEntity]
	PreKeys       dao.GenericDAO[*entities.PreKeyEntity]
	SignedPreKeys dao.GenericDAO[*entities.SignedPreKeyEntity]
	IdentityKeys  dao.GenericDAO[*entities.IdentityKeyEntity]
	SenderKeys    dao.GenericDAO[*entities.SenderKeyEntity]
	Settings      dao.GenericDAO[*entities.SettingEntity]
}

// NewFactory creates all DAOs from the given KVStore.
func NewFactory(store kvstore.KVStore) (*Factory, error) {
	messages, err := dao.New(store, "messages", func() *entities.MessageEntity { return &entities.MessageEntity{} })
	if err != nil {
		return nil, err
	}

	conversations, err := dao.New(store, "conversations", func() *entities.ConversationEntity { return &entities.ConversationEntity{} })
	if err != nil {
		return nil, err
	}

	contacts, err := dao.New(store, "contacts", func() *entities.ContactEntity { return &entities.ContactEntity{} })
	if err != nil {
		return nil, err
	}

	groups, err := dao.New(store, "groups", func() *entities.GroupEntity { return &entities.GroupEntity{} })
	if err != nil {
		return nil, err
	}

	reactions, err := dao.New(store, "reactions", func() *entities.ReactionEntity { return &entities.ReactionEntity{} })
	if err != nil {
		return nil, err
	}

	attachments, err := dao.New(store, "attachments", func() *entities.AttachmentEntity { return &entities.AttachmentEntity{} })
	if err != nil {
		return nil, err
	}

	stickers, err := dao.New(store, "stickers", func() *entities.StickerEntity { return &entities.StickerEntity{} })
	if err != nil {
		return nil, err
	}

	stickerPacks, err := dao.New(store, "sticker_packs", func() *entities.StickerPackEntity { return &entities.StickerPackEntity{} })
	if err != nil {
		return nil, err
	}

	jobs, err := dao.New(store, "jobs", func() *entities.JobEntity { return &entities.JobEntity{} })
	if err != nil {
		return nil, err
	}

	sessions, err := dao.New(store, "crypto_sessions", func() *entities.CryptoSessionEntity { return &entities.CryptoSessionEntity{} })
	if err != nil {
		return nil, err
	}

	preKeys, err := dao.New(store, "crypto_prekeys", func() *entities.PreKeyEntity { return &entities.PreKeyEntity{} })
	if err != nil {
		return nil, err
	}

	signedPreKeys, err := dao.New(store, "crypto_signed_prekeys", func() *entities.SignedPreKeyEntity { return &entities.SignedPreKeyEntity{} })
	if err != nil {
		return nil, err
	}

	identityKeys, err := dao.New(store, "crypto_identity_keys", func() *entities.IdentityKeyEntity { return &entities.IdentityKeyEntity{} })
	if err != nil {
		return nil, err
	}

	senderKeys, err := dao.New(store, "crypto_sender_keys", func() *entities.SenderKeyEntity { return &entities.SenderKeyEntity{} })
	if err != nil {
		return nil, err
	}

	settings, err := dao.New(store, "settings", func() *entities.SettingEntity { return &entities.SettingEntity{} })
	if err != nil {
		return nil, err
	}

	return &Factory{
		Messages:      messages,
		Conversations: conversations,
		Contacts:      contacts,
		Groups:        groups,
		Reactions:     reactions,
		Attachments:   attachments,
		Stickers:      stickers,
		StickerPacks:  stickerPacks,
		Jobs:          jobs,
		Sessions:      sessions,
		PreKeys:       preKeys,
		SignedPreKeys: signedPreKeys,
		IdentityKeys:  identityKeys,
		SenderKeys:    senderKeys,
		Settings:      settings,
	}, nil
}
