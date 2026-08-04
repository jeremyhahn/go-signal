package svr2

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// qrdbKV is the minimal qrdb-compatible KV surface this backend
// consumes. Decoupling here keeps the svr2 package free of a direct
// pkg/storage/qrdb dependency — cmd/svr2 wires the qrdbstorage.KVStore
// in as a qrdbKV at startup time.
type qrdbKV interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error
}

// QrdbStorage is a qrdb-backed Storage implementation for cmd/svr2's
// SVR4 record state. Each Record persists as a JSON blob under
// `svr2:record:<identity>` — the per-identity granularity makes
// account deletion (admin DELETE) a single Delete call. Java's
// SVR2 reference stores records in the SGX enclave's per-account
// sealed slots; the qrdb pattern is the non-enclave equivalent for
// the software-attestation deployment profile.
//
// Storage is on-disk via the qrdb backend; production deployments
// layer go-quicraft/seal envelope encryption on top of the KV
// layer so the on-disk record stays sealed even if disk is
// exfiltrated — that wrapper lives at the KV layer below this
// Storage adapter.
type QrdbStorage struct {
	kv     qrdbKV
	prefix string
}

// QrdbStorageConfig configures a QrdbStorage.
type QrdbStorageConfig struct {
	// KV is the qrdb-compatible KV surface. Required.
	KV qrdbKV
	// KeyPrefix namespaces the record keys. Defaults to "svr2:record:".
	KeyPrefix string
}

// NewQrdbStorage constructs a QrdbStorage.
func NewQrdbStorage(cfg QrdbStorageConfig) (*QrdbStorage, error) {
	if cfg.KV == nil {
		return nil, errors.New("svr2: KV is required")
	}
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "svr2:record:"
	}
	return &QrdbStorage{kv: cfg.KV, prefix: prefix}, nil
}

// Compile-time interface conformance.
var _ Storage = (*QrdbStorage)(nil)

func (s *QrdbStorage) key(identity string) string {
	return s.prefix + identity
}

// qrdbRecord is the on-disk JSON shape. Mirrors the in-memory Record
// but spells timestamps as time.Time for portable serialization.
type qrdbRecord struct {
	Version               uint32           `json:"version"`
	MaxTries              uint32           `json:"maxTries"`
	TriesRemaining        uint32           `json:"triesRemaining"`
	OPRFSecretShare       []byte           `json:"oprfSecretShare"`
	AuthCommitment        []byte           `json:"authCommitment"`
	EncryptionSecretShare []byte           `json:"encryptionSecretShare"`
	ZeroSecretShare       []byte           `json:"zeroSecretShare"`
	CreatedAt             time.Time        `json:"createdAt"`
	UpdatedAt             time.Time        `json:"updatedAt"`
	PendingRotation       *qrdbPendingRotn `json:"pendingRotation,omitempty"`
}

type qrdbPendingRotn struct {
	NewVersion                 uint32 `json:"newVersion"`
	OPRFSecretShareDelta       []byte `json:"oprfSecretShareDelta"`
	EncryptionSecretShareDelta []byte `json:"encryptionSecretShareDelta"`
}

func toQrdb(r *Record) *qrdbRecord {
	if r == nil {
		return nil
	}
	out := &qrdbRecord{
		Version:               r.Version,
		MaxTries:              r.MaxTries,
		TriesRemaining:        r.TriesRemaining,
		OPRFSecretShare:       cloneBytes(r.OPRFSecretShare),
		AuthCommitment:        cloneBytes(r.AuthCommitment),
		EncryptionSecretShare: cloneBytes(r.EncryptionSecretShare),
		ZeroSecretShare:       cloneBytes(r.ZeroSecretShare),
		CreatedAt:             r.CreatedAt,
		UpdatedAt:             r.UpdatedAt,
	}
	if r.PendingRotation != nil {
		out.PendingRotation = &qrdbPendingRotn{
			NewVersion:                 r.PendingRotation.NewVersion,
			OPRFSecretShareDelta:       cloneBytes(r.PendingRotation.OPRFSecretShareDelta),
			EncryptionSecretShareDelta: cloneBytes(r.PendingRotation.EncryptionSecretShareDelta),
		}
	}
	return out
}

func fromQrdb(r *qrdbRecord) *Record {
	if r == nil {
		return nil
	}
	out := &Record{
		Version:               r.Version,
		MaxTries:              r.MaxTries,
		TriesRemaining:        r.TriesRemaining,
		OPRFSecretShare:       cloneBytes(r.OPRFSecretShare),
		AuthCommitment:        cloneBytes(r.AuthCommitment),
		EncryptionSecretShare: cloneBytes(r.EncryptionSecretShare),
		ZeroSecretShare:       cloneBytes(r.ZeroSecretShare),
		CreatedAt:             r.CreatedAt,
		UpdatedAt:             r.UpdatedAt,
	}
	if r.PendingRotation != nil {
		out.PendingRotation = &PendingRotation{
			NewVersion:                 r.PendingRotation.NewVersion,
			OPRFSecretShareDelta:       cloneBytes(r.PendingRotation.OPRFSecretShareDelta),
			EncryptionSecretShareDelta: cloneBytes(r.PendingRotation.EncryptionSecretShareDelta),
		}
	}
	return out
}

// Get implements Storage.
func (s *QrdbStorage) Get(ctx context.Context, identity string) (*Record, error) {
	raw, err := s.kv.Get(ctx, s.key(identity))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "svr2: qrdb Get", err)
	}
	if raw == nil {
		return nil, ErrRecordNotFound
	}
	var qr qrdbRecord
	if err := json.Unmarshal(raw, &qr); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "svr2: qrdb unmarshal", err)
	}
	return fromQrdb(&qr), nil
}

// Put implements Storage.
func (s *QrdbStorage) Put(ctx context.Context, identity string, record *Record) error {
	raw, err := json.Marshal(toQrdb(record))
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "svr2: qrdb marshal", err)
	}
	if err := s.kv.Put(ctx, s.key(identity), raw); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "svr2: qrdb Put", err)
	}
	return nil
}

// Delete implements Storage.
func (s *QrdbStorage) Delete(ctx context.Context, identity string) error {
	if err := s.kv.Delete(ctx, s.key(identity)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "svr2: qrdb Delete", err)
	}
	return nil
}

// Count implements Storage. Counts via Scan; the SVR2 record set
// is one row per registered account so this scales with the user
// base — production deployments tracking a metric instead should
// wire a separate counter rather than calling Count on the hot
// path.
func (s *QrdbStorage) Count(ctx context.Context) (int, error) {
	n := 0
	err := s.kv.Scan(ctx, s.prefix, func(key string, _ []byte) error {
		if strings.HasPrefix(key, s.prefix) {
			n++
		}
		return nil
	})
	if err != nil {
		return 0, signalerrors.Wrap(signalerrors.ErrInternal, "svr2: qrdb Scan", err)
	}
	return n, nil
}
