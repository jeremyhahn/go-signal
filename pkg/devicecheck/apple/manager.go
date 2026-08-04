package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Defaults mirror Java AppleDeviceCheckManager constants.
const (
	// DefaultChallengeTTL is how long an issued challenge remains valid
	// before VerifyAttestation/VerifyAssertion rejects it.
	DefaultChallengeTTL = time.Hour
	// MaxDeviceKeys is the per-account cap on registered device keys.
	MaxDeviceKeys = 100
	// challengeBytes is the random challenge length before url-safe
	// base64 encoding. Matches Java CHALLENGE_LENGTH (16 bytes).
	challengeBytes = 16
)

// ChallengeType disambiguates challenges issued for attestation versus
// each protected assertion flow. Mirrors Java enum.
type ChallengeType string

const (
	// ChallengeAttest gates new device-key attestation.
	ChallengeAttest ChallengeType = "ATTEST"
	// ChallengeAssertBackupRedemption gates backup redemption assertions.
	ChallengeAssertBackupRedemption ChallengeType = "ASSERT_BACKUP_REDEMPTION"
)

// ChallengeStore persists short-lived challenges. Production deployments
// back this with Redis (per Java); tests + dev use the in-memory variant.
type ChallengeStore interface {
	// Put stores challenge under (accountUUID, challengeType) with the
	// supplied TTL. Replacing an existing challenge is OK (used for TTL
	// refresh).
	Put(ctx context.Context, accountUUID string, ct ChallengeType, challenge string, ttl time.Duration) error
	// Get returns the stored challenge or ErrChallengeNotFound when
	// missing or expired.
	Get(ctx context.Context, accountUUID string, ct ChallengeType) (string, error)
	// Delete removes a challenge after it has been consumed. Idempotent.
	Delete(ctx context.Context, accountUUID string, ct ChallengeType) error
}

// DeviceKeyStore persists registered device keys + sign counters. Apple
// device-check rows are keyed by accountUUID + keyID.
type DeviceKeyStore interface {
	// List returns every key registered against accountUUID. Used to
	// enforce MaxDeviceKeys.
	List(ctx context.Context, accountUUID string) ([]Key, error)
	// Lookup returns the stored Key for (accountUUID, keyID) or
	// ErrKeyNotFound.
	Lookup(ctx context.Context, accountUUID string, keyID []byte) (*Key, error)
	// Insert adds a fresh attestation; returns ErrDuplicatePublicKey if
	// the public-key DER is already bound to a different account.
	Insert(ctx context.Context, k *Key) error
	// UpdateCounter advances the sign counter for (accountUUID, keyID).
	UpdateCounter(ctx context.Context, accountUUID string, keyID []byte, counter uint32) error
}

// Key is the persisted device-key record.
type Key struct {
	AccountUUID  string
	KeyID        []byte
	PublicKeyDER []byte // ECDSA P-256 SubjectPublicKeyInfo (x509.MarshalPKIXPublicKey output)
	SignCount    uint32
	CreatedAt    time.Time
}

// PublicKey decodes the stored DER blob into an *ecdsa.PublicKey. Returns
// an error when the stored bytes are malformed or not P-256 ECDSA.
func (k *Key) PublicKey() (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(k.PublicKeyDER)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apple: parse stored public key", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("apple: stored public key is not ECDSA")
	}
	if ec.Curve != elliptic.P256() {
		return nil, errors.New("apple: stored public key is not P-256")
	}
	return ec, nil
}

// Manager orchestrates challenge issuance + attestation + assertion
// flows. Mirrors Java AppleDeviceCheckManager: challenges in Redis
// (here: ChallengeStore), device keys in Postgres-like DDB (here:
// DeviceKeyStore), verification via the Verifier.
type Manager struct {
	verifier     *Verifier
	challenges   ChallengeStore
	keys         DeviceKeyStore
	challengeTTL time.Duration
}

// ManagerConfig configures NewManager.
type ManagerConfig struct {
	// Verifier is required.
	Verifier *Verifier
	// Challenges + Keys are required.
	Challenges ChallengeStore
	Keys       DeviceKeyStore
	// ChallengeTTL overrides DefaultChallengeTTL.
	ChallengeTTL time.Duration
}

// NewManager validates cfg and returns a wired manager.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("apple: Verifier is required")
	}
	if cfg.Challenges == nil {
		return nil, errors.New("apple: ChallengeStore is required")
	}
	if cfg.Keys == nil {
		return nil, errors.New("apple: DeviceKeyStore is required")
	}
	ttl := cfg.ChallengeTTL
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}
	return &Manager{
		verifier:     cfg.Verifier,
		challenges:   cfg.Challenges,
		keys:         cfg.Keys,
		challengeTTL: ttl,
	}, nil
}

// CreateChallenge issues a fresh random url-safe-base64 challenge for the
// given (account, type). If a challenge already exists its TTL is
// refreshed and the same value is returned — mirrors Java's setGet+expire
// behavior so concurrent issuers don't race-create distinct challenges.
func (m *Manager) CreateChallenge(ctx context.Context, accountUUID string, ct ChallengeType) (string, error) {
	if accountUUID == "" {
		return "", errors.New("apple: accountUUID required")
	}
	existing, err := m.challenges.Get(ctx, accountUUID, ct)
	switch {
	case err == nil:
		// Refresh TTL on the existing value and return it.
		if err := m.challenges.Put(ctx, accountUUID, ct, existing, m.challengeTTL); err != nil {
			return "", err
		}
		return existing, nil
	case errors.Is(err, ErrChallengeNotFound):
		// fall through to mint a fresh challenge
	default:
		return "", err
	}
	raw := make([]byte, challengeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", signalerrors.Wrap(signalerrors.ErrInternal, "apple: read random", err)
	}
	challenge := base64.RawURLEncoding.EncodeToString(raw)
	if err := m.challenges.Put(ctx, accountUUID, ct, challenge, m.challengeTTL); err != nil {
		return "", err
	}
	return challenge, nil
}

// RegisterAttestation verifies an attestation blob against the issued
// challenge and stores the resulting device-key record. Idempotent on
// duplicate keyId for the same account (matches Java behavior).
func (m *Manager) RegisterAttestation(ctx context.Context, accountUUID string, keyID, attestation []byte) error {
	if accountUUID == "" {
		return errors.New("apple: accountUUID required")
	}
	existing, err := m.keys.List(ctx, accountUUID)
	if err != nil {
		return err
	}
	for _, k := range existing {
		if bytesEqualConstantTime(k.KeyID, keyID) {
			// Already registered — silent no-op per Java AppleDeviceCheckManager.
			return nil
		}
	}
	if len(existing) >= MaxDeviceKeys {
		return ErrTooManyKeys
	}
	challenge, err := m.challenges.Get(ctx, accountUUID, ChallengeAttest)
	if err != nil {
		return err
	}
	res, err := m.verifier.VerifyAttestation(challenge, keyID, attestation)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(res.PublicKey)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "apple: marshal device public key", err)
	}
	if err := m.keys.Insert(ctx, &Key{
		AccountUUID:  accountUUID,
		KeyID:        keyID,
		PublicKeyDER: pubDER,
		SignCount:    res.SignCount,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		return err
	}
	// Best-effort delete; failure here just falls back to TTL expiry.
	_ = m.challenges.Delete(ctx, accountUUID, ChallengeAttest)
	return nil
}

// ValidateAssertion verifies an assertion against a previously registered
// device key + challenge. On success the sign-counter is updated.
//
// request is the application bytes the client signed (Signal embeds the
// challenge in this); the embedded challenge must match the challenge
// stored under (accountUUID, ct).
func (m *Manager) ValidateAssertion(ctx context.Context, accountUUID string, keyID []byte, ct ChallengeType, challenge string, request, assertion []byte) error {
	if accountUUID == "" {
		return errors.New("apple: accountUUID required")
	}
	stored, err := m.challenges.Get(ctx, accountUUID, ct)
	if err != nil {
		return err
	}
	if !constantTimeStringEqual(stored, challenge) {
		return errInvalid("provided challenge did not match stored challenge")
	}
	key, err := m.keys.Lookup(ctx, accountUUID, keyID)
	if err != nil {
		return err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return err
	}
	newCounter, err := m.verifier.VerifyAssertion(pub, key.SignCount, request, assertion)
	if err != nil {
		return err
	}
	if err := m.keys.UpdateCounter(ctx, accountUUID, keyID, newCounter); err != nil {
		return err
	}
	_ = m.challenges.Delete(ctx, accountUUID, ct)
	return nil
}

// --- Sentinel errors -------------------------------------------------------

// ErrChallengeNotFound is returned by ChallengeStore.Get when no challenge
// is stored (or it has expired). Callers translate this to HTTP 410.
var ErrChallengeNotFound = errors.New("apple: challenge not found")

// ErrKeyNotFound is returned by DeviceKeyStore.Lookup when no device key
// is registered for (accountUUID, keyID).
var ErrKeyNotFound = errors.New("apple: device key not found")

// ErrDuplicatePublicKey is returned by DeviceKeyStore.Insert when the
// public-key DER is already bound to a different account. Mirrors Java
// DuplicatePublicKeyException.
var ErrDuplicatePublicKey = errors.New("apple: duplicate public key")

// ErrTooManyKeys is returned when an account has reached MaxDeviceKeys.
var ErrTooManyKeys = errors.New("apple: too many device keys")

// --- Helpers ---------------------------------------------------------------

// bytesEqualConstantTime returns true when a and b are byte-identical,
// without leaking length-difference timing.
func bytesEqualConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// constantTimeStringEqual is the string-input variant of the above. Used
// for challenge comparison.
func constantTimeStringEqual(a, b string) bool {
	return bytesEqualConstantTime([]byte(a), []byte(b))
}

// --- In-memory stores ------------------------------------------------------

// MemoryChallengeStore is an in-memory ChallengeStore for tests + dev.
// Entries past their expiry are treated as missing on read.
type MemoryChallengeStore struct {
	mu   sync.Mutex
	rows map[string]challengeRow
	now  func() time.Time
}

type challengeRow struct {
	value     string
	expiresAt time.Time
}

// NewMemoryChallengeStore returns a fresh empty store. SetClock overrides
// the wall clock used to check expiry — tests use this to fast-forward
// past the TTL.
func NewMemoryChallengeStore() *MemoryChallengeStore {
	return &MemoryChallengeStore{rows: make(map[string]challengeRow), now: time.Now}
}

// SetClock overrides the clock for tests.
func (s *MemoryChallengeStore) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func challengeStoreKey(accountUUID string, ct ChallengeType) string {
	return accountUUID + "::" + string(ct)
}

// Put implements ChallengeStore.
func (s *MemoryChallengeStore) Put(_ context.Context, accountUUID string, ct ChallengeType, challenge string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[challengeStoreKey(accountUUID, ct)] = challengeRow{
		value:     challenge,
		expiresAt: s.now().Add(ttl),
	}
	return nil
}

// Get implements ChallengeStore.
func (s *MemoryChallengeStore) Get(_ context.Context, accountUUID string, ct ChallengeType) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[challengeStoreKey(accountUUID, ct)]
	if !ok || s.now().After(row.expiresAt) {
		return "", ErrChallengeNotFound
	}
	return row.value, nil
}

// Delete implements ChallengeStore.
func (s *MemoryChallengeStore) Delete(_ context.Context, accountUUID string, ct ChallengeType) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, challengeStoreKey(accountUUID, ct))
	return nil
}

// MemoryDeviceKeyStore is an in-memory DeviceKeyStore for tests + dev.
type MemoryDeviceKeyStore struct {
	mu   sync.Mutex
	rows map[string]Key    // composite key: accountUUID+hex(keyID)
	pub  map[string]string // pubDER hex -> accountUUID (duplicate detection)
}

// NewMemoryDeviceKeyStore returns a fresh empty store.
func NewMemoryDeviceKeyStore() *MemoryDeviceKeyStore {
	return &MemoryDeviceKeyStore{
		rows: make(map[string]Key),
		pub:  make(map[string]string),
	}
}

func keyStoreKey(accountUUID string, keyID []byte) string {
	return accountUUID + "::" + base64.RawStdEncoding.EncodeToString(keyID)
}

// List implements DeviceKeyStore.
func (s *MemoryDeviceKeyStore) List(_ context.Context, accountUUID string) ([]Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prefix := accountUUID + "::"
	out := make([]Key, 0, 4)
	for k, v := range s.rows {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, v)
		}
	}
	return out, nil
}

// Lookup implements DeviceKeyStore.
func (s *MemoryDeviceKeyStore) Lookup(_ context.Context, accountUUID string, keyID []byte) (*Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[keyStoreKey(accountUUID, keyID)]
	if !ok {
		return nil, ErrKeyNotFound
	}
	clone := row
	return &clone, nil
}

// Insert implements DeviceKeyStore. Rejects duplicate public keys across
// accounts. Idempotent for the same (accountUUID, keyID) pair.
func (s *MemoryDeviceKeyStore) Insert(_ context.Context, k *Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pubKey := base64.RawStdEncoding.EncodeToString(k.PublicKeyDER)
	if owner, ok := s.pub[pubKey]; ok && owner != k.AccountUUID {
		return ErrDuplicatePublicKey
	}
	clone := *k
	s.rows[keyStoreKey(k.AccountUUID, k.KeyID)] = clone
	s.pub[pubKey] = k.AccountUUID
	return nil
}

// UpdateCounter implements DeviceKeyStore.
func (s *MemoryDeviceKeyStore) UpdateCounter(_ context.Context, accountUUID string, keyID []byte, counter uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := keyStoreKey(accountUUID, keyID)
	row, ok := s.rows[key]
	if !ok {
		return ErrKeyNotFound
	}
	row.SignCount = counter
	s.rows[key] = row
	return nil
}
