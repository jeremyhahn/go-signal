package service

import (
	"log/slog"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/backups"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// SignalService is the top-level aggregate that provides all service
// interfaces required by REST and gRPC protocol handlers. Protocol handlers
// should accept *SignalService (or individual service interfaces) rather than
// coupling directly to manager types.
type SignalService struct {
	Accounts      AccountService
	Messages      MessageService
	Keys          KeyService
	Profiles      ProfileService
	Certificates  CertificateService
	Devices       DeviceService
	Usernames     UsernameService
	CallSignaling CallSignalingService
	// Backups is wired only when the backup subsystem is enabled (i.e.
	// cmd/signald constructs a backups.Service). Handlers that depend on
	// Backups must nil-check and return Unimplemented when it is absent.
	Backups BackupService
}

// ServiceConfig holds the manager dependencies required to construct a
// SignalService. Each field is required; a nil manager panics at construction
// time rather than producing a partially-functional service.
type ServiceConfig struct {
	Accounts     *accounts.AccountsManager
	Messages     *messages.MessagesManager
	Keys         *keys.KeysManager
	Profiles     *profiles.ProfilesManager
	Certificates *certificates.CertificatesManager
	Devices      *devices.DevicesManager
	Usernames    *usernames.UsernamesManager
	Calling      *calling.CallingManager
	WSSessions   *signalws.SessionManager
	Logger       *slog.Logger
	// Backups is optional. When nil, SignalService.Backups stays nil and
	// gRPC backup handlers return Unimplemented.
	Backups *backups.Service
}

// NewSignalService constructs a SignalService, wiring each manager into its
// corresponding service implementation. Accounts, Messages, Keys, Profiles,
// Certificates, Devices, and Usernames are required and must not be nil.
// CallSignaling is wired only when both WSSessions and Calling are non-nil;
// deployments that do not require 1:1 calling may omit those fields.
func NewSignalService(cfg ServiceConfig) *SignalService {
	svc := &SignalService{
		Accounts:     NewAccountService(cfg.Accounts),
		Messages:     NewMessageService(cfg.Messages),
		Keys:         NewKeyService(cfg.Keys),
		Profiles:     NewProfileService(cfg.Profiles),
		Certificates: NewCertificateService(cfg.Certificates),
		Devices:      NewDeviceService(cfg.Devices),
		Usernames:    NewUsernameService(cfg.Usernames),
	}

	if cfg.WSSessions != nil && cfg.Calling != nil {
		logger := cfg.Logger
		if logger == nil {
			logger = slog.Default()
		}
		svc.CallSignaling = NewCallSignalingService(cfg.WSSessions, cfg.Calling, logger)
	}

	if cfg.Backups != nil {
		svc.Backups = NewBackupService(cfg.Backups)
	}

	return svc
}
