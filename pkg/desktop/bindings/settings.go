//go:build desktop

package bindings

import (
	"context"
	"time"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
	"github.com/jeremyhahn/go-signal/pkg/daostore"
	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// SettingsBindings provides settings/preferences operations.
type SettingsBindings struct {
	client  *signal.Client
	factory *daostore.Factory
}

// NewSettingsBindings creates settings bindings.
func NewSettingsBindings(client *signal.Client, f *daostore.Factory) *SettingsBindings {
	return &SettingsBindings{client: client, factory: f}
}

// AppSettings holds all user-configurable preferences.
type AppSettings struct {
	Theme              string `json:"theme"`
	NotificationsEnabled bool  `json:"notificationsEnabled"`
	ReadReceipts       bool   `json:"readReceipts"`
	TypingIndicators   bool   `json:"typingIndicators"`
	LinkPreviews       bool   `json:"linkPreviews"`
	Locale             string `json:"locale"`
}

// GetSettings loads all settings from the DAO.
func (b *SettingsBindings) GetSettings() (*AppSettings, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	settings := &AppSettings{
		Theme:              "system",
		NotificationsEnabled: true,
		ReadReceipts:       true,
		TypingIndicators:   true,
		LinkPreviews:       true,
		Locale:             "en",
	}

	// Load each setting by key.
	settingKeys := map[string]*string{
		"theme":  &settings.Theme,
		"locale": &settings.Locale,
	}

	for key, target := range settingKeys {
		entity, err := b.factory.Settings.QueryOneByIndex(ctx, "Key", key)
		if err == nil && entity != nil {
			*target = entity.Value
		}
	}

	return settings, nil
}

// UpdateSettings saves settings to the DAO.
func (b *SettingsBindings) UpdateSettings(key, value string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	existing, err := b.factory.Settings.QueryOneByIndex(ctx, "Key", key)
	if err == nil && existing != nil {
		existing.Value = value
		return b.factory.Settings.Save(ctx, existing)
	}

	entity := &entities.SettingEntity{
		Key:   key,
		Value: value,
	}
	return b.factory.Settings.Save(ctx, entity)
}

// SetPin sets the registration lock PIN on the server.
func (b *SettingsBindings) SetPin(pin string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.SetPin(ctx, pin)
}

// RemovePin removes the registration lock PIN.
func (b *SettingsBindings) RemovePin() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return b.client.RemovePin(ctx)
}
