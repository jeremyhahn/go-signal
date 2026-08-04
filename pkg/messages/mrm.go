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

// MRMTTLSeconds is the time-to-live applied to a freshly-inserted shared MRM
// key. Mirrors Java Signal-Server (`MessagesCacheInsertSharedMultiRecipientPayloadAndViewsScript`),
// which expires the key after 7 days as a back-stop garbage collector for
// recipients whose views are never delivered.
const MRMTTLSeconds = 7 * 86400

// mrmDataField is the hash field that holds the shared multi-recipient
// payload bytes. Byte-equivalent with Java's MessagesCache, which writes the
// literal UTF-8 string "data" as the field name.
const mrmDataField = "data"

// ErrMRMKeyExists is returned by MRMCache.Insert when the shared key is
// already populated. Mirrors Java's `ERR key exists` script error.
var ErrMRMKeyExists = errors.New("mrm: key exists")

// ErrMRMDataMissing is returned by MRMCache.Get when the shared `data` field
// has been removed (typical causes: TTL expired, or every recipient view was
// already delivered and the hash was DEL'd). Callers should treat the parent
// envelope as stale and discard it.
var ErrMRMDataMissing = errors.New("mrm: shared data missing")

// MRMCache holds shared multi-recipient message data in a Redis-shaped
// key-value cache. Wire format and key layout are byte-compatible with Java
// Signal-Server's `MessagesCache` MRM operations:
//
//   - Shared key: `mrm::{<uuid>}` (Redis hash). The braces delimit a Redis
//     cluster hash tag so all keys for a given message route to one shard.
//   - Field "data": the full SealedSenderV2 multi-recipient ciphertext.
//   - Field <18-byte view key>: the per-recipient ReceivedMessage bytes
//     produced by SealedSenderV2SentMessage.SerializedRecipientView.
//
// All multi-step operations are implemented as Lua scripts (Eval'd through
// cache.Client) so they execute atomically on the Redis server. The memory
// cache backend stubs Eval; tests that exercise this type should run against
// miniredis.
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

// SharedMRMKey returns the Redis key for an MRM hash identified by the given
// UUID. Format: `mrm::{<uuid-string>}`. The `{...}` delimit a Redis cluster
// hash tag so that all operations on this MRM message route to the same
// shard, which is required because the Lua scripts target multiple keys
// (KEYS[]) in a single call.
func SharedMRMKey(mrmGuid uuid.UUID) string {
	return "mrm::{" + mrmGuid.String() + "}"
}

// SharedMRMViewKey returns the 18-byte hash-field name for a (serviceID,
// deviceID) recipient view, byte-equivalent with Java's
// `MessagesCache.getSharedMrmViewKey`. The 17-byte ServiceId fixed-width
// binary encoding is concatenated with a single deviceID byte. The result
// is returned as a Go string carrying raw bytes; it survives unchanged
// through the cache.Client interface since Go strings are byte sequences.
func SharedMRMViewKey(serviceID protocol.ServiceId, deviceID byte) string {
	fw := serviceID.FixedWidthBinary()
	out := make([]byte, 18)
	copy(out, fw[:])
	out[17] = deviceID
	return string(out)
}

// mrmInsertScript writes the shared payload and a list of (viewKey, viewBytes)
// recipient views, atomically. Mirrors Java's
// `lua/insert_shared_multirecipient_message_data.lua` line for line. Returns
// 1 on success and `ERR key exists` on duplicate insert.
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

// mrmRemoveScript removes a single recipient view from each provided shared
// MRM key. If, after removal, the only field left for a key is the shared
// `data` field, the entire hash is DEL'd. Returns the number of fully-deleted
// keys. Mirrors Java's `lua/remove_recipient_view_from_mrm_data.lua`.
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

// Insert atomically writes the shared MRM data and per-recipient views.
// Returns ErrMRMKeyExists if the key is already populated; the caller is
// expected to choose a fresh UUID and retry in that case (matching Java's
// MessagesCache.insertSharedMrmPayload, which generates a new UUID for every
// MRM insert).
//
// `data` is the full SealedSenderV2 multi-recipient ciphertext.
// `views` maps each recipient view-key (as returned by SharedMRMViewKey) to
// that recipient's serializedRecipientView bytes (as returned by
// SealedSenderV2SentMessage.SerializedRecipientView).
//
// The key receives a 7-day TTL inside the Lua script so it is garbage-
// collected even if some recipients never come online.
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

// Get returns the shared MRM data and the named recipient view for delivery
// to a client. If the shared `data` field is missing, the call returns
// ErrMRMDataMissing and the caller should treat the parent envelope as
// stale (matching Java's `getMessageWithSharedMrmData` semantics). If `data`
// is present but the requested recipient view has already been removed (a
// concurrent delivery completed), the returned view is nil; the caller is
// expected to skip delivering this envelope and remove it from the per-
// device queue.
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

// RemoveRecipientView removes a single recipient view from each of the
// supplied shared MRM keys, atomically per key. If only the shared `data`
// field remains for a key after removal, the entire hash is DEL'd. Returns
// the number of fully-deleted keys.
//
// Mirrors Java's MessagesCache.removeRecipientViewFromMrmData. Callers
// typically batch several sharedKeys for one viewKey when a recipient acks
// a batch of inbound messages that all referenced different MRM payloads.
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
