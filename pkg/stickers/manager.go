package stickers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"strconv"
	"time"

	s3policy "github.com/jeremyhahn/go-signal/pkg/storage/blob/s3"
)

const (
	// maxStickerManifestSizeBytes mirrors Java
	// Constants.MAXIMUM_STICKER_MANIFEST_SIZE_BYTES (10 KiB).
	maxStickerManifestSizeBytes = 10 * 1024
	// maxStickerSizeBytes mirrors Java
	// Constants.MAXIMUM_STICKER_SIZE_BYTES (300 KiB per sticker).
	maxStickerSizeBytes = 300 * 1024
	// minStickerCount and maxStickerCount mirror the Java
	// @Min(1) @Max(201) annotations on StickerController.getStickersForm.
	minStickerCount = 1
	maxStickerCount = 201
)

// S3Config bundles the S3 credentials + bucket needed to sign sticker
// pack upload forms. When unset, the manager falls back to the legacy
// embedded-CDN URL form (no signed POST policy) so dev deployments keep
// working without S3 credentials.
type S3Config struct {
	Region          string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
}

// configured returns true when every required S3 field is populated.
func (c S3Config) configured() bool {
	return c.Region != "" && c.Bucket != "" && c.AccessKeyID != "" && c.SecretAccessKey != ""
}

// StickersManager issues sticker-pack upload forms. When wired with S3
// credentials it produces real signed POST policies clients can upload
// directly to S3; otherwise it produces a legacy URL-only form pointing
// at the embedded CDN.
type StickersManager struct {
	logger    *slog.Logger
	store     PackStore
	generator *s3policy.PolicyGenerator
	signer    *s3policy.PolicySigner
	clock     func() time.Time
}

// ManagerConfig configures a StickersManager.
type ManagerConfig struct {
	// Logger is required. nil falls back to slog.Default.
	Logger *slog.Logger
	// Store persists pack metadata. nil uses an in-memory store (dev only).
	Store PackStore
	// S3 enables real S3 POST policy signing. Optional in dev; required
	// in production (the server cannot serve sticker uploads otherwise).
	S3 S3Config
}

// NewStickersManager constructs a manager with the configured options.
// A nil logger defaults to slog.Default; a nil store defaults to an
// in-memory store.
func NewStickersManager(cfg ManagerConfig) *StickersManager {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	store := cfg.Store
	if store == nil {
		store = NewMemoryPackStore()
	}
	m := &StickersManager{
		logger: logger,
		store:  store,
		clock:  func() time.Time { return time.Now().UTC() },
	}
	if cfg.S3.configured() {
		m.generator = &s3policy.PolicyGenerator{
			Region:      cfg.S3.Region,
			Bucket:      cfg.S3.Bucket,
			AccessKeyID: cfg.S3.AccessKeyID,
		}
		m.signer = &s3policy.PolicySigner{
			SecretAccessKey: cfg.S3.SecretAccessKey,
			Region:          cfg.S3.Region,
		}
	}
	return m
}

// SetClock overrides the wall-clock source. Intended for tests; production
// callers should leave the default in place so signatures use real time.
func (m *StickersManager) SetClock(now func() time.Time) {
	if now != nil {
		m.clock = now
	}
}

// GetUploadForm returns a pack ID + per-sticker S3 POST form entries for
// stickerCount stickers. Records the issuance in the PackStore against
// accountUUID so the server can attribute uploads later. Mirrors Java's
// StickerController.getStickersForm.
//
// stickerCount must be in [1, 201]. accountUUID must be non-empty; the
// REST handler enforces authentication before calling.
func (m *StickersManager) GetUploadForm(ctx context.Context, accountUUID string, stickerCount int) (*StickerPackFormUpload, error) {
	if stickerCount < minStickerCount || stickerCount > maxStickerCount {
		return nil, &InvalidStickerCountError{Count: stickerCount}
	}
	if accountUUID == "" {
		return nil, &InvalidPackError{Reason: "accountUUID is required"}
	}

	now := m.clock()
	packID, err := generatePackID()
	if err != nil {
		return nil, err
	}
	packLocation := "stickers/" + packID
	manifestKey := packLocation + "/manifest.proto"

	manifest, err := m.makeField(now, -1, manifestKey, maxStickerManifestSizeBytes)
	if err != nil {
		return nil, err
	}

	stickers := make([]StickerFormField, 0, stickerCount)
	for i := 0; i < stickerCount; i++ {
		stickerKey := packLocation + "/full/" + strconv.Itoa(i)
		field, err := m.makeField(now, i, stickerKey, maxStickerSizeBytes)
		if err != nil {
			return nil, err
		}
		stickers = append(stickers, field)
	}

	if err := m.store.Put(ctx, &PackMetadata{
		PackID:      packID,
		AccountUUID: accountUUID,
		IssuedAt:    now,
	}); err != nil {
		m.logger.WarnContext(ctx, "sticker pack persist failed",
			slog.String("packId", packID),
			slog.String("uuid", accountUUID),
			slog.String("error", err.Error()))
		return nil, err
	}

	return &StickerPackFormUpload{
		PackId:   packID,
		Manifest: manifest,
		Stickers: stickers,
	}, nil
}

// GetPack returns previously recorded pack metadata or *PackNotFoundError.
func (m *StickersManager) GetPack(ctx context.Context, packID string) (*PackMetadata, error) {
	return m.store.Get(ctx, packID)
}

// makeField builds either an S3-signed POST form entry (when S3 is
// configured) or a fall-back URL-only entry (otherwise). id=-1 is the
// magic value Java uses for the manifest slot; the JSON field is
// serialized as-is so clients see the same number.
func (m *StickersManager) makeField(now time.Time, id int, objectKey string, maxBytes int64) (StickerFormField, error) {
	if m.generator == nil || m.signer == nil {
		// Embedded-CDN dev path — no S3 signature; client uploads to
		// the same Signal server's TUS-style /cdn3 route.
		return StickerFormField{
			Id:       id,
			Key:      objectKey,
			Headers:  map[string]string{},
			Location: "/cdn3/" + objectKey,
		}, nil
	}
	form, err := s3policy.FormatForm(m.generator, m.signer, now, objectKey, maxBytes)
	if err != nil {
		return StickerFormField{}, err
	}
	return StickerFormField{
		Id:             id,
		Key:            objectKey,
		Acl:            form.Acl,
		Algorithm:      form.Algorithm,
		Date:           form.Date,
		Policy:         form.Policy,
		Signature:      form.Signature,
		Credential:     form.Credential,
		BucketEndpoint: s3BucketEndpoint(m.generator.Bucket, m.generator.Region),
	}, nil
}

// s3BucketEndpoint formats the virtual-hosted S3 URL the client POSTs
// to. Matches the host condition embedded in the signed policy.
func s3BucketEndpoint(bucket, region string) string {
	if bucket == "" || region == "" {
		return ""
	}
	return "https://" + bucket + ".s3." + region + ".amazonaws.com"
}

// generatePackID returns a 32-character hex pack ID matching Java's
// HexFormat.of().formatHex(16 random bytes). crypto/rand is used so the
// pack identifier is unguessable.
func generatePackID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes[:]), nil
}
