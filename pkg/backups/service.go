package backups

import (
	"context"
	"time"
)

// Service is the BackupService implementation, bundling [Manager] (ZK-side
// archive operations) and [AuthManager] (account-side credential issuance)
// behind a single seam that satisfies service.BackupService. Construct via
// [NewService]; pass to service.NewBackupService at startup.
//
// Mirrors the split Java keeps between BackupManager and BackupAuthManager
// while presenting protocol handlers with a single interface.
type Service struct {
	manager *Manager
	auth    *AuthManager
}

// NewService composes a Manager with an AuthManager. Both must be non-nil.
func NewService(manager *Manager, auth *AuthManager) *Service {
	return &Service{manager: manager, auth: auth}
}

// --- Account-authenticated --------------------------------------------------

// SetBackupID delegates to [AuthManager.CommitBackupID].
func (s *Service) SetBackupID(ctx context.Context, accountUUID string, deviceID uint64, req SetBackupIDRequest) error {
	return s.auth.CommitBackupID(ctx, accountUUID, deviceID, req)
}

// GetBackupIDLimits delegates to [AuthManager.GetBackupIDLimits].
func (s *Service) GetBackupIDLimits(ctx context.Context, accountUUID string) (*BackupIDLimits, error) {
	return s.auth.GetBackupIDLimits(ctx, accountUUID)
}

// RedeemReceipt delegates to [AuthManager.RedeemReceipt].
func (s *Service) RedeemReceipt(ctx context.Context, accountUUID string, req RedeemReceiptRequest) error {
	return s.auth.RedeemReceipt(ctx, accountUUID, req)
}

// GetBackupAuthCredentials delegates to [AuthManager.GetBackupAuthCredentials].
func (s *Service) GetBackupAuthCredentials(
	ctx context.Context,
	accountUUID string,
	redemptionStart time.Time,
	redemptionEnd time.Time,
) (*CredentialsResponse, error) {
	return s.auth.GetBackupAuthCredentials(ctx, accountUUID, redemptionStart, redemptionEnd)
}

// --- ZK-authenticated -------------------------------------------------------

// AuthenticateBackupUser delegates to [Manager.AuthenticateBackupUser].
func (s *Service) AuthenticateBackupUser(
	ctx context.Context,
	presentation []byte,
	signature []byte,
	userAgent string,
) (*AuthenticatedUser, error) {
	return s.manager.AuthenticateBackupUser(ctx, presentation, signature, userAgent)
}

// SetPublicKey delegates to [Manager.SetPublicKey].
func (s *Service) SetPublicKey(
	ctx context.Context,
	presentation []byte,
	signature []byte,
	publicKey []byte,
) error {
	return s.manager.SetPublicKey(ctx, presentation, signature, publicKey)
}

// BackupInfo delegates to [Manager.BackupInfo].
func (s *Service) BackupInfo(ctx context.Context, user *AuthenticatedUser) (*Info, error) {
	return s.manager.BackupInfo(ctx, user)
}

// TTLRefresh delegates to [Manager.TTLRefresh].
func (s *Service) TTLRefresh(ctx context.Context, user *AuthenticatedUser) error {
	return s.manager.TTLRefresh(ctx, user)
}

// CreateMessageBackupUploadDescriptor delegates to
// [Manager.CreateMessageBackupUploadDescriptor].
func (s *Service) CreateMessageBackupUploadDescriptor(
	ctx context.Context,
	user *AuthenticatedUser,
) (*UploadDescriptor, error) {
	return s.manager.CreateMessageBackupUploadDescriptor(ctx, user)
}

// CreateTemporaryAttachmentUploadDescriptor delegates to
// [Manager.CreateTemporaryAttachmentUploadDescriptor].
func (s *Service) CreateTemporaryAttachmentUploadDescriptor(
	ctx context.Context,
	user *AuthenticatedUser,
) (*UploadDescriptor, error) {
	return s.manager.CreateTemporaryAttachmentUploadDescriptor(ctx, user)
}

// GenerateReadAuth delegates to [Manager.GenerateReadAuth].
func (s *Service) GenerateReadAuth(
	ctx context.Context,
	user *AuthenticatedUser,
	cdnNumber int,
) (map[string]string, error) {
	return s.manager.GenerateReadAuth(ctx, user, cdnNumber)
}

// GenerateSVRBAuth delegates to [Manager.GenerateSVRBAuth].
func (s *Service) GenerateSVRBAuth(
	ctx context.Context,
	user *AuthenticatedUser,
) (*ExternalServiceCredentials, error) {
	return s.manager.GenerateSVRBAuth(ctx, user)
}

// GetCopyQuota delegates to [Manager.GetCopyQuota].
func (s *Service) GetCopyQuota(
	ctx context.Context,
	user *AuthenticatedUser,
	toCopy []CopyParameters,
) (*CopyQuota, error) {
	return s.manager.GetCopyQuota(ctx, user, toCopy)
}

// CopyToBackup delegates to [Manager.CopyToBackup].
func (s *Service) CopyToBackup(
	ctx context.Context,
	quota CopyQuota,
	fn func(CopyResult) error,
) error {
	return s.manager.CopyToBackup(ctx, quota, fn)
}

// ListMedia delegates to [Manager.ListMedia].
func (s *Service) ListMedia(
	ctx context.Context,
	user *AuthenticatedUser,
	cursor *string,
	limit int,
) (*ListMediaResult, error) {
	return s.manager.ListMedia(ctx, user, cursor, limit)
}

// DeleteMedia delegates to [Manager.DeleteMedia].
func (s *Service) DeleteMedia(
	ctx context.Context,
	user *AuthenticatedUser,
	descriptors []StorageDescriptor,
	fn func(StorageDescriptor) error,
) error {
	return s.manager.DeleteMedia(ctx, user, descriptors, fn)
}

// DeleteEntireBackup delegates to [Manager.DeleteEntireBackup].
func (s *Service) DeleteEntireBackup(ctx context.Context, user *AuthenticatedUser) error {
	return s.manager.DeleteEntireBackup(ctx, user)
}

// --- Worker-facing ----------------------------------------------------------

// ListBackupAttributes delegates to [Manager.ListBackupAttributes].
func (s *Service) ListBackupAttributes(
	ctx context.Context,
	segments int,
	fn func(StoredAttributes) error,
) error {
	return s.manager.ListBackupAttributes(ctx, segments, fn)
}

// GetExpiredBackups delegates to [Manager.GetExpiredBackups].
func (s *Service) GetExpiredBackups(
	ctx context.Context,
	segments int,
	purgeTime time.Time,
	fn func(ExpiredBackup) error,
) error {
	return s.manager.GetExpiredBackups(ctx, segments, purgeTime, fn)
}

// ExpireBackup delegates to [Manager.ExpireBackup].
func (s *Service) ExpireBackup(ctx context.Context, expired ExpiredBackup) error {
	return s.manager.ExpireBackup(ctx, expired)
}

// RecalculateQuota delegates to [Manager.RecalculateQuota].
func (s *Service) RecalculateQuota(
	ctx context.Context,
	attrs StoredAttributes,
) (*RecalculationResult, error) {
	return s.manager.RecalculateQuota(ctx, attrs)
}
