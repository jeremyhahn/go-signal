package messages

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

// MRMTTLSeconds is the 7-day TTL of a shared MRM key, a backstop for views never delivered.
const MRMTTLSeconds = 7 * 86400

// mrmDataField is the hash field that holds the shared multi-recipient
// payload bytes. Byte-equivalent with Java's MessagesCache, which writes the
// literal UTF-8 string "data" as the field name.
const mrmDataField = "data"

// ErrMRMKeyExists is returned by MRMCache.Insert when the shared key is
// already populated. Mirrors Java's `ERR key exists` script error.
var ErrMRMKeyExists = errors.New("mrm: key exists")

// ErrMRMDataMissing means the shared data is gone; discard the parent envelope as stale.
var ErrMRMDataMissing = errors.New("mrm: shared data missing")

// MRMCache holds shared multi-recipient data in Redis, byte-compatible with Signal-Server: hash `mrm::{<uuid>}`, field "data" plus one 18-byte field per recipient view; multi-step operations are Lua scripts.
type MRMCache struct {
	client cache.Client
	logger *slog.Logger
}

// NewMRMCache constructs a new MRM cache backed by the given client.
func NewMRMCache(client cache.Client, logger *slog.Logger) *MRMCache {
	return &MRMCache{
		client: client,
		logger: logger.With(slog.String("component", "mrm-cache")),
	}
}

// SharedMRMKey returns `mrm::{<uuid>}`; the braces are a cluster hash tag so the scripts' keys share a shard.
func SharedMRMKey(mrmGuid uuid.UUID) string {
	return "mrm::{" + mrmGuid.String() + "}"
}

// SharedMRMViewKey returns the 18-byte field name for a recipient view: 17-byte ServiceId then the device ID byte.
func SharedMRMViewKey(serviceID protocol.ServiceId, deviceID byte) string {
	fw := serviceID.FixedWidthBinary()
	out := make([]byte, 18)
	copy(out, fw[:])
	out[17] = deviceID
	return string(out)
}

// mrmInsertScript atomically writes the shared payload and recipient views; returns 1, or `ERR key exists`.
const mrmInsertScript = `
local sharedMrmKey = KEYS[1]
local mrmData      = ARGV[1]

if 1 == redis.call("EXISTS", sharedMrmKey) then
    return redis.error_reply("ERR key exists")
end

redis.call("HSET", sharedMrmKey, "data", mrmData)
redis.call("EXPIRE", sharedMrmKey, 604800)

for i = 2, #ARGV, 2 do
    redis.call("HSET", sharedMrmKey, ARGV[i], ARGV[i + 1])
end

return 1
`

// mrmRemoveScript removes one recipient view per key, deletes hashes left with only `data`, and returns how many were deleted.
const mrmRemoveScript = `
local recipientViewToRemove = ARGV[1]
local keysDeleted = 0

for _, sharedMrmKey in ipairs(KEYS) do
    redis.call("HDEL", sharedMrmKey, recipientViewToRemove)
    if redis.call("HLEN", sharedMrmKey) == 1 then
        redis.call("DEL", sharedMrmKey)
        keysDeleted = keysDeleted + 1
    end
end

return keysDeleted
`

// Insert atomically writes the SealedSender v2 data and per-recipient views with a 7-day TTL; ErrMRMKeyExists means pick a new UUID.
func (c *MRMCache) Insert(ctx context.Context, sharedKey string, data []byte, views map[string][]byte) error {
	args := make([]interface{}, 0, 1+len(views)*2)
	args = append(args, data)
	for viewKey, viewBytes := range views {
		args = append(args, viewKey)
		args = append(args, viewBytes)
	}

	_, err := c.client.Eval(ctx, mrmInsertScript, []string{sharedKey}, args...)
	if err != nil {
		// Redis error replies surface as Go errors with the reply text;
		// match on the script's literal error string.
		if strings.Contains(err.Error(), "ERR key exists") {
			return ErrMRMKeyExists
		}
		return &MRMCacheError{Op: "insert", Cause: err}
	}
	return nil
}

// Get returns the shared data and one recipient view; ErrMRMDataMissing means stale, a nil view means already delivered.
func (c *MRMCache) Get(ctx context.Context, sharedKey string, viewKey string) (data, view []byte, err error) {
	data, err = c.client.HGet(ctx, sharedKey, mrmDataField)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return nil, nil, ErrMRMDataMissing
	}
	if err != nil {
		return nil, nil, &MRMCacheError{Op: "get data", Cause: err}
	}

	view, err = c.client.HGet(ctx, sharedKey, viewKey)
	if errors.Is(err, cache.ErrKeyNotFound) {
		return data, nil, nil
	}
	if err != nil {
		return data, nil, &MRMCacheError{Op: "get view", Cause: err}
	}
	return data, view, nil
}

// RemoveRecipientView removes viewKey from each shared key, deleting hashes left with only `data`; returns how many were deleted.
func (c *MRMCache) RemoveRecipientView(ctx context.Context, sharedKeys []string, viewKey string) (int64, error) {
	if len(sharedKeys) == 0 {
		return 0, nil
	}
	res, err := c.client.Eval(ctx, mrmRemoveScript, sharedKeys, viewKey)
	if err != nil {
		return 0, &MRMCacheError{Op: "remove", Cause: err}
	}
	switch n := res.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	default:
		return 0, &MRMUnexpectedResultTypeError{Result: res}
	}
}
