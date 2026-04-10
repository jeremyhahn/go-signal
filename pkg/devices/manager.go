package devices

import (
	"context"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// provisioningCodeExpiry is how long a provisioning code remains valid.
const provisioningCodeExpiry = 10 * time.Minute

// DevicesManager coordinates device provisioning and linking operations. It
// delegates persistence to a ProvisioningStore and interacts with the accounts
// and keys managers to create new devices.
type DevicesManager struct {
	store    ProvisioningStore
	accounts *accounts.AccountsManager
	keys     *keys.KeysManager
	logger   *slog.Logger
}

// NewDevicesManager creates a new DevicesManager.
func NewDevicesManager(store ProvisioningStore, accts *accounts.AccountsManager, keysMgr *keys.KeysManager, logger *slog.Logger) *DevicesManager {
	return &DevicesManager{
		store:    store,
		accounts: accts,
		keys:     keysMgr,
		logger:   logger.With(slog.String("component", "devices-manager")),
	}
}

// CreateProvisioningCode generates a new provisioning code for the account
// identified by the given UUID. The code is valid for 10 minutes.
func (m *DevicesManager) CreateProvisioningCode(ctx context.Context, accountUUID string) (*ProvisioningCode, error) {
	code := uuid.New().String()

	session := &ProvisioningSession{
		Code:      code,
		UUID:      accountUUID,
		ExpiresAt: time.Now().Add(provisioningCodeExpiry),
	}

	if err := m.store.StoreSession(ctx, session); err != nil {
		m.logger.Error("failed to store provisioning session",
			slog.String("uuid", accountUUID),
			slog.String("error", err.Error()))
		return nil, err
	}

	m.logger.Info("provisioning code created",
		slog.String("uuid", accountUUID))

	return &ProvisioningCode{VerificationCode: code}, nil
}

// LinkDevice validates the provisioning code, creates a new device on the
// associated account, and stores the provided pre-keys.
func (m *DevicesManager) LinkDevice(ctx context.Context, code string, req *LinkDeviceRequest) (*LinkDeviceResponse, error) {
	session, err := m.store.GetSession(ctx, code)
	if err != nil {
		return nil, &InvalidProvisioningCodeError{Code: code}
	}

	if time.Now().After(session.ExpiresAt) {
		deleteErr := m.store.DeleteSession(ctx, code)
		if deleteErr != nil {
			m.logger.Warn("failed to delete expired provisioning session",
				slog.String("code", code),
				slog.String("error", deleteErr.Error()))
		}
		return nil, &ProvisioningCodeExpiredError{Code: code}
	}

	// Build the device with the provided attributes.
	authToken := uuid.New().String()
	signedPreKey, err := decodeSignedPreKey(&req.AciSignedPreKey)
	if err != nil {
		return nil, err
	}

	device := &accounts.Device{
		Name:                              req.AccountAttributes.Name,
		AuthToken:                         authToken,
		FetchesMessages:                   req.AccountAttributes.FetchesMessages,
		RegistrationID:                    req.AccountAttributes.RegistrationId,
		PhoneNumberIdentityRegistrationID: req.AccountAttributes.PniRegistrationId,
		SignedPreKey:                      signedPreKey,
	}

	acct, err := m.accounts.AddDevice(ctx, session.UUID, device)
	if err != nil {
		m.logger.Error("failed to add device",
			slog.String("uuid", session.UUID),
			slog.String("error", err.Error()))
		return nil, err
	}

	// Find the newly added device to get its assigned ID.
	var newDeviceID uint64
	for _, d := range acct.Devices {
		if d.AuthToken == authToken {
			newDeviceID = d.ID
			break
		}
	}

	// Store pre-keys for the new device.
	if err := m.storeDevicePreKeys(ctx, session.UUID, newDeviceID, req); err != nil {
		m.logger.Warn("failed to store pre-keys for new device",
			slog.String("uuid", session.UUID),
			slog.Uint64("deviceId", newDeviceID),
			slog.String("error", err.Error()))
		// The device is created; pre-key storage failure is non-fatal.
	}

	// Clean up the used provisioning session.
	deleteErr := m.store.DeleteSession(ctx, code)
	if deleteErr != nil {
		m.logger.Warn("failed to delete consumed provisioning session",
			slog.String("code", code),
			slog.String("error", deleteErr.Error()))
	}

	m.logger.Info("device linked",
		slog.String("uuid", session.UUID),
		slog.Uint64("deviceId", newDeviceID))

	return &LinkDeviceResponse{DeviceId: newDeviceID}, nil
}

// SetCapabilities updates the capabilities of a specific device on an account.
func (m *DevicesManager) SetCapabilities(ctx context.Context, accountUUID string, deviceID uint64, caps map[string]bool) error {
	devCaps := accounts.DeviceCapabilities{
		Storage:                  caps["storage"],
		Transfer:                 caps["transfer"],
		PaymentActivation:        caps["paymentActivation"],
		DeleteSync:               caps["deleteSync"],
		VersionedExpirationTimer: caps["versionedExpirationTimer"],
	}

	fetchesMessages := true
	attrs := accounts.DeviceAttributes{
		FetchesMessages: &fetchesMessages,
		Capabilities:    &devCaps,
	}

	if _, err := m.accounts.SetDeviceAttributes(ctx, accountUUID, deviceID, attrs); err != nil {
		m.logger.Error("failed to set device capabilities",
			slog.String("uuid", accountUUID),
			slog.Uint64("deviceId", deviceID),
			slog.String("error", err.Error()))
		return err
	}

	return nil
}

// storeDevicePreKeys stores the signed and KEM pre-keys for a newly linked
// device.
func (m *DevicesManager) storeDevicePreKeys(ctx context.Context, accountUUID string, deviceID uint64, req *LinkDeviceRequest) error {
	aciSigned, err := decodeSignedPreKeyForStore(&req.AciSignedPreKey)
	if err != nil {
		return err
	}
	if err := m.keys.StoreSignedPreKey(ctx, accountUUID, deviceID, aciSigned); err != nil {
		return err
	}

	return nil
}

// decodeSignedPreKey converts a SignedPreKeyEntity to an accounts.SignedPreKey.
func decodeSignedPreKey(entity *SignedPreKeyEntity) (*accounts.SignedPreKey, error) {
	pub, err := base64.StdEncoding.DecodeString(entity.PublicKey)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(entity.Signature)
	if err != nil {
		return nil, err
	}
	return &accounts.SignedPreKey{
		KeyID:     entity.KeyId,
		PublicKey: pub,
		Signature: sig,
	}, nil
}

// decodeSignedPreKeyForStore converts a SignedPreKeyEntity to a
// keys.SignedPreKey for storage.
func decodeSignedPreKeyForStore(entity *SignedPreKeyEntity) (*keys.SignedPreKey, error) {
	pub, err := base64.StdEncoding.DecodeString(entity.PublicKey)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(entity.Signature)
	if err != nil {
		return nil, err
	}
	return &keys.SignedPreKey{
		KeyID:     entity.KeyId,
		PublicKey: pub,
		Signature: sig,
	}, nil
}
