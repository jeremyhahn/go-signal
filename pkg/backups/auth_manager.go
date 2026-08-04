package backups

import (
	"bytes"
	"context"
	"crypto/rand"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/limits"
)

// MaxCredentialWindow is the maximum half-open redemption window a client
// may request via GetBackupAuthCredentials, matching Java's
// MAX_CREDENTIAL_WINDOW (7 days).
const MaxCredentialWindow = 7 * 24 * time.Hour

// AuthManager handles the account-authenticated half of the backup
// subsystem: committing blinded backup-ids, issuing ZK backup-auth
// credentials, enforcing rotation rate limits, and redeeming paid-tier
// receipts. Mirrors Java's BackupAuthManager.
type AuthManager struct {
	accounts                 *accounts.AccountsManager
	setBackupIDLimiter       limits.RateLimiter
	setPaidMediaIDLimiter    limits.RateLimiter
	serverSecretParams       *zkgroup.GenericServerSecretParams
	receiptServerSecretParam *zkgroup.ServerSecretParams
	redeemedReceipts         RedeemedReceiptsStore
	clock                    func() time.Time
}

// AuthManagerOptions configures an [AuthManager].
type AuthManagerOptions struct {
	// Accounts is required and provides per-account persistence for the
	// stored backup credential requests and voucher.
	Accounts *accounts.AccountsManager
	// SetBackupIDLimiter rate-limits PUT /v1/archives/backupid rotations
	// of the messages slot. Keyed by account UUID.
	SetBackupIDLimiter limits.RateLimiter
	// SetPaidMediaBackupIDLimiter rate-limits paid-tier rotations of the
	// media slot. Keyed by account UUID.
	SetPaidMediaBackupIDLimiter limits.RateLimiter
	// ServerSecretParams signs issued backup-auth credentials.
	ServerSecretParams *zkgroup.GenericServerSecretParams
	// ReceiptServerSecretParams verifies receipt-credential presentations
	// submitted to RedeemReceipt.
	ReceiptServerSecretParams *zkgroup.ServerSecretParams
	// RedeemedReceipts deduplicates receipt serials across accounts.
	RedeemedReceipts RedeemedReceiptsStore
	// Clock is the time source; nil defaults to time.Now in UTC.
	Clock func() time.Time
}

// NewAuthManager constructs an [AuthManager]. All non-Clock fields of
// [AuthManagerOptions] are required.
func NewAuthManager(opts AuthManagerOptions) *AuthManager {
	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &AuthManager{
		accounts:                 opts.Accounts,
		setBackupIDLimiter:       opts.SetBackupIDLimiter,
		setPaidMediaIDLimiter:    opts.SetPaidMediaBackupIDLimiter,
		serverSecretParams:       opts.ServerSecretParams,
		receiptServerSecretParam: opts.ReceiptServerSecretParams,
		redeemedReceipts:         opts.RedeemedReceipts,
		clock:                    clock,
	}
}

// CommitBackupID persists the blinded credential request(s) on the account.
// Only the primary device may commit. At least one of req.MessagesBackupAuthCredentialRequest
// / req.MediaBackupAuthCredentialRequest must be non-nil. Re-committing the
// identical request bytes is a silent no-op (no rate-limit token consumed).
// Mirrors Java BackupAuthManager.commitBackupId.
func (m *AuthManager) CommitBackupID(
	ctx context.Context,
	accountUUID string,
	deviceID uint64,
	req SetBackupIDRequest,
) error {
	if accountUUID == "" {
		return &InvalidArgumentError{Field: "accountUUID", Message: "must not be empty"}
	}
	if deviceID != accounts.PrimaryDeviceID {
		return &PermissionError{Required: BackupLevelFree, Got: 0}
	}
	if len(req.MessagesBackupAuthCredentialRequest) == 0 && len(req.MediaBackupAuthCredentialRequest) == 0 {
		return &InvalidArgumentError{
			Field:   "request",
			Message: "must set at least one of messages or media credential requests",
		}
	}

	// Validate that the supplied bytes parse as zkgroup credential requests.
	// Doing this before any state change keeps malformed requests from
	// burning rate-limit tokens.
	if len(req.MessagesBackupAuthCredentialRequest) > 0 {
		if _, err := zkgroup.DeserializeBackupAuthCredentialRequest(req.MessagesBackupAuthCredentialRequest); err != nil {
			return &InvalidArgumentError{Field: "messagesBackupAuthCredentialRequest", Message: err.Error()}
		}
	}
	if len(req.MediaBackupAuthCredentialRequest) > 0 {
		if _, err := zkgroup.DeserializeBackupAuthCredentialRequest(req.MediaBackupAuthCredentialRequest); err != nil {
			return &InvalidArgumentError{Field: "mediaBackupAuthCredentialRequest", Message: err.Error()}
		}
	}

	account, err := m.accounts.Get(ctx, accountUUID)
	if err != nil {
		return err
	}

	// If the provided slot is nil, fall back to the currently stored value
	// so we always write a complete pair.
	var storedMessages, storedMedia []byte
	if account.BackupCredentialRequests != nil {
		storedMessages = account.BackupCredentialRequests.Messages
		storedMedia = account.BackupCredentialRequests.Media
	}
	targetMessages := storedMessages
	if len(req.MessagesBackupAuthCredentialRequest) > 0 {
		targetMessages = req.MessagesBackupAuthCredentialRequest
	}
	targetMedia := storedMedia
	if len(req.MediaBackupAuthCredentialRequest) > 0 {
		targetMedia = req.MediaBackupAuthCredentialRequest
	}

	requiresMessageRotation := !bytes.Equal(targetMessages, storedMessages)
	requiresMediaRotation := !bytes.Equal(targetMedia, storedMedia)

	if !requiresMessageRotation && !requiresMediaRotation {
		return nil
	}

	if requiresMessageRotation {
		if err := m.setBackupIDLimiter.Allow(ctx, accountUUID); err != nil {
			return err
		}
	}
	if requiresMediaRotation && m.hasActiveVoucher(account) {
		if err := m.setPaidMediaIDLimiter.Allow(ctx, accountUUID); err != nil {
			return err
		}
	}

	account.BackupCredentialRequests = &accounts.BackupCredentialRequests{
		Messages: targetMessages,
		Media:    targetMedia,
	}
	return m.accounts.Update(ctx, account)
}

// GetBackupIDLimits reports rotation cooldown for the account's two
// backup-id slots. Returns zero times when rotation is allowed now.
//
// Note: the underlying token-bucket limiter does not expose a non-consuming
// "has-tokens" probe today. Until [limits.RateLimiter] grows one, this
// returns "allowed now" optimistically — callers should treat the response
// as a hint, not a guarantee. Java's BackupAuthManager.checkBackupIdRotationLimit
// uses hasAvailablePermitsAsync, which is the equivalent we should add.
func (m *AuthManager) GetBackupIDLimits(ctx context.Context, accountUUID string) (*BackupIDLimits, error) {
	if accountUUID == "" {
		return nil, &InvalidArgumentError{Field: "accountUUID", Message: "must not be empty"}
	}
	return &BackupIDLimits{}, nil
}

// GetBackupAuthCredentials issues a backup-auth credential per credential
// type per day in [redemptionStart, redemptionEnd). Mirrors
// BackupAuthManager.getBackupAuthCredentials. The window must be day-aligned
// at both ends and not exceed [MaxCredentialWindow]; otherwise returns
// [*InvalidArgumentError].
func (m *AuthManager) GetBackupAuthCredentials(
	ctx context.Context,
	accountUUID string,
	redemptionStart time.Time,
	redemptionEnd time.Time,
) (*CredentialsResponse, error) {
	if accountUUID == "" {
		return nil, &InvalidArgumentError{Field: "accountUUID", Message: "must not be empty"}
	}
	if !isDayAligned(redemptionStart) || !isDayAligned(redemptionEnd) {
		return nil, &InvalidArgumentError{
			Field:   "redemptionRange",
			Message: "start and end must be day-aligned (UTC midnight)",
		}
	}
	if !redemptionEnd.After(redemptionStart) {
		return nil, &InvalidArgumentError{
			Field:   "redemptionRange",
			Message: "end must be strictly after start",
		}
	}
	if redemptionEnd.Sub(redemptionStart) > MaxCredentialWindow {
		return nil, &InvalidArgumentError{
			Field:   "redemptionRange",
			Message: "window exceeds maximum of 7 days",
		}
	}

	account, err := m.accounts.Get(ctx, accountUUID)
	if err != nil {
		return nil, err
	}

	// Clear an expired voucher before issuance so the user transitions
	// back to the free tier cleanly. Matches Java's pre-issuance cleanup.
	if m.hasExpiredVoucher(account) {
		account.BackupVoucher = nil
		if err := m.accounts.Update(ctx, account); err != nil {
			return nil, err
		}
	}

	if account.BackupCredentialRequests == nil {
		return nil, &NotFoundError{}
	}

	out := &CredentialsResponse{}
	for _, credType := range []CredentialType{CredentialTypeMessages, CredentialTypeMedia} {
		var committed []byte
		switch credType {
		case CredentialTypeMessages:
			committed = account.BackupCredentialRequests.Messages
		case CredentialTypeMedia:
			committed = account.BackupCredentialRequests.Media
		}
		if len(committed) == 0 {
			return nil, &NotFoundError{}
		}
		credReq, err := zkgroup.DeserializeBackupAuthCredentialRequest(committed)
		if err != nil {
			return nil, &InvalidArgumentError{
				Field:   "storedCredentialRequest",
				Message: err.Error(),
			}
		}

		for ts := redemptionStart; ts.Before(redemptionEnd); ts = ts.Add(24 * time.Hour) {
			level := m.levelForRedemption(account, ts)
			var randomness zkgroup.RandomnessBytes
			if _, err := rand.Read(randomness[:]); err != nil {
				return nil, err
			}
			resp, err := credReq.Issue(
				zkgroup.TimestampFromTime(ts),
				level,
				credType,
				m.serverSecretParams,
				randomness,
			)
			if err != nil {
				return nil, err
			}
			out.Credentials = append(out.Credentials, IssuedCredential{
				Type:           credType,
				RedemptionTime: ts,
				Credential:     zkgroup.SerializeBackupAuthCredentialResponse(resp),
			})
		}
	}
	return out, nil
}

// RedeemReceipt verifies the receipt presentation and, if valid + not
// already redeemed, extends the account's paid-tier voucher. Mirrors
// BackupAuthManager.redeemReceipt.
func (m *AuthManager) RedeemReceipt(ctx context.Context, accountUUID string, req RedeemReceiptRequest) error {
	if accountUUID == "" {
		return &InvalidArgumentError{Field: "accountUUID", Message: "must not be empty"}
	}
	if len(req.ReceiptCredentialPresentation) == 0 {
		return &InvalidArgumentError{Field: "receiptCredentialPresentation", Message: "must not be empty"}
	}

	presentation, err := zkgroup.DeserializeReceiptCredentialPresentation(req.ReceiptCredentialPresentation)
	if err != nil {
		return &BadReceiptError{Reason: "malformed presentation: " + err.Error()}
	}
	if err := m.receiptServerSecretParam.VerifyReceiptCredentialPresentation(presentation); err != nil {
		return &BadReceiptError{Reason: "presentation verification failed: " + err.Error()}
	}

	expiration := time.Unix(int64(presentation.GetReceiptExpirationTime().EpochSeconds()), 0).UTC()
	if !m.clock().Before(expiration) {
		return &BadReceiptError{Reason: "receipt is expired"}
	}

	receiptLevel := uint64(presentation.GetReceiptLevel())
	mappedLevel, ok := mapReceiptLevelToBackupLevel(receiptLevel)
	if !ok {
		return &InvalidArgumentError{Field: "receiptLevel", Message: "unrecognized receipt level"}
	}
	if mappedLevel != BackupLevelPaid {
		return &InvalidArgumentError{Field: "receiptLevel", Message: "server does not recognize the requested receipt level"}
	}

	account, err := m.accounts.Get(ctx, accountUUID)
	if err != nil {
		return err
	}
	if account.BackupCredentialRequests == nil || len(account.BackupCredentialRequests.Media) == 0 {
		return &MissingIDCommitmentError{}
	}

	serialBytes := presentation.GetReceiptSerialBytes()
	accepted, err := m.redeemedReceipts.Put(ctx, serialBytes[:], expiration, receiptLevel, accountUUID)
	if err != nil {
		return err
	}
	if !accepted {
		return &BadReceiptError{Reason: "receipt serial already redeemed"}
	}

	// Day-align the expiration before merging into the voucher.
	expiration = expiration.Truncate(24 * time.Hour)
	account.BackupVoucher = mergeVoucher(account.BackupVoucher, &accounts.BackupVoucher{
		ReceiptLevel: receiptLevel,
		Expiration:   expiration,
	})
	return m.accounts.Update(ctx, account)
}

// --- helpers ----------------------------------------------------------------

func (m *AuthManager) hasActiveVoucher(account *accounts.Account) bool {
	v := account.BackupVoucher
	return v != nil && m.clock().Before(v.Expiration)
}

func (m *AuthManager) hasExpiredVoucher(account *accounts.Account) bool {
	v := account.BackupVoucher
	return v != nil && !m.clock().Before(v.Expiration)
}

// levelForRedemption picks the BackupLevel for a single day of issuance.
// A valid voucher whose expiration is at or after the day's redemption time
// promotes the credential to PAID; otherwise it stays at FREE.
func (m *AuthManager) levelForRedemption(account *accounts.Account, redemption time.Time) BackupLevel {
	v := account.BackupVoucher
	if v == nil || redemption.After(v.Expiration) {
		return BackupLevelFree
	}
	mapped, ok := mapReceiptLevelToBackupLevel(v.ReceiptLevel)
	if !ok {
		return BackupLevelFree
	}
	return mapped
}

// mergeVoucher applies Java's BackupAuthManager.merge semantics: if the
// existing voucher has the same receipt level as the new one, keep whichever
// expiration is further out; otherwise the new voucher replaces wholesale.
func mergeVoucher(prev, next *accounts.BackupVoucher) *accounts.BackupVoucher {
	if prev == nil {
		return next
	}
	if prev.ReceiptLevel != next.ReceiptLevel {
		return next
	}
	if prev.Expiration.After(next.Expiration) {
		return prev
	}
	return next
}

// mapReceiptLevelToBackupLevel mirrors Java's BackupLevelUtil.fromReceiptLevel:
// the receipt level is a u64 that the client claims; the server narrows it
// to a known BackupLevel. Valid values are 200 (Free) and 201 (Paid).
func mapReceiptLevelToBackupLevel(receiptLevel uint64) (BackupLevel, bool) {
	switch receiptLevel {
	case uint64(BackupLevelFree):
		return BackupLevelFree, true
	case uint64(BackupLevelPaid):
		return BackupLevelPaid, true
	default:
		return 0, false
	}
}

// isDayAligned returns true when t is exactly UTC midnight.
func isDayAligned(t time.Time) bool {
	return t.Equal(t.Truncate(24 * time.Hour))
}
