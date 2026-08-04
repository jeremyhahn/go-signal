package messages

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

// fakeRecipient describes one recipient row when building a synthetic
// SealedSender v2 multi-recipient SentMessage for tests.
type fakeRecipient struct {
	uuidBytes [16]byte
	devices   []uint8 // device IDs; non-empty means non-excluded recipient
	regIDs    []uint16
}

// buildFakeSSv2Ciphertext crafts a wire-format-valid SealedSender v2 SentMessage
// (version 0x22, UUID-addressed) that go-libsignal's parser will accept. The
// crypto bytes are deterministic but not real, so the result decodes structurally
// but cannot be decrypted — exactly what's needed to exercise the server-side
// fan-out path in SendMRMBinary without dragging in the full crypto setup.
//
// Layout:
//
//	[1] version 0x22
//	[varint] recipient count
//	for each recipient:
//	  [16] uuid bytes
//	  for each device:
//	    [1] device id
//	    [2] registration id with has_more bit if more follow
//	  [32] C_i (encrypted M)
//	  [16] AT_i (auth tag)
//	[32] ephemeral public key
//	[N]  encrypted payload
func buildFakeSSv2Ciphertext(t *testing.T, recipients []fakeRecipient, payload []byte) []byte {
	t.Helper()

	out := make([]byte, 0, 256)
	out = append(out, 0x22) // SealedSenderV2VersionUUID

	// recipient count varint
	var varintBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(varintBuf[:], uint64(len(recipients)))
	out = append(out, varintBuf[:n]...)

	const v2EncryptedMKeySize = 32
	const v2AuthTagSize = 16

	for _, r := range recipients {
		out = append(out, r.uuidBytes[:]...)

		if len(r.devices) == 0 {
			// excluded recipient: device 0 sentinel
			out = append(out, 0x00)
			continue
		}
		for i, dev := range r.devices {
			if dev == 0 {
				t.Fatalf("device id 0 reserved for excluded recipients")
			}
			regID := r.regIDs[i] & 0x3FFF
			if i < len(r.devices)-1 {
				regID |= 0x8000 // has_more
			}
			var regBuf [2]byte
			binary.BigEndian.PutUint16(regBuf[:], regID)
			out = append(out, dev)
			out = append(out, regBuf[:]...)
		}
		// Synthetic encrypted M and auth tag — content irrelevant for parse.
		ci := make([]byte, v2EncryptedMKeySize)
		ati := make([]byte, v2AuthTagSize)
		for j := range ci {
			ci[j] = byte(0xC0 + j)
		}
		for j := range ati {
			ati[j] = byte(0xA0 + j)
		}
		out = append(out, ci...)
		out = append(out, ati...)
	}

	// Ephemeral public key (32 bytes) — synthetic.
	ephPub := make([]byte, 32)
	for i := range ephPub {
		ephPub[i] = byte(0xE0 + i)
	}
	out = append(out, ephPub...)

	// Encrypted payload — caller-supplied so tests can recognize it.
	out = append(out, payload...)

	return out
}

// recordingCache wraps an in-memory map and records each Insert call so tests
// can assert key/payload contents. Built atop the shared fakeCache.
type recordingCache struct {
	*fakeCache
	insertCalls int
}

func newRecordingCache() *recordingCache {
	return &recordingCache{fakeCache: newFakeCache()}
}

// Eval intercepts MRM Lua scripts and emulates them against the fake hash
// store. The scripts we recognize:
//   - mrmInsertScript: KEYS[1] is the shared key; ARGV[1] is data; subsequent
//     ARGV alternate (viewKey, viewBytes). Returns 1 on success, error on
//     duplicate.
//   - mrmRemoveScript: KEYS are sharedKeys; ARGV[1] is the recipient view.
//     Returns the count of fully-deleted keys.
func (c *recordingCache) Eval(_ context.Context, script string, keys []string, args ...interface{}) (interface{}, error) {
	if isInsertScript(script) {
		if len(keys) != 1 {
			return nil, errors.New("expected exactly 1 key")
		}
		sharedKey := keys[0]
		if c.hashes[sharedKey] != nil {
			return nil, errors.New("ERR key exists")
		}
		c.insertCalls++
		// args[0] is data (as []byte)
		dataBytes, ok := args[0].([]byte)
		if !ok {
			return nil, errors.New("expected []byte data")
		}
		c.hashes[sharedKey] = map[string][]byte{mrmDataField: dataBytes}
		// Remaining args alternate (viewKey, viewBytes).
		for i := 1; i+1 < len(args); i += 2 {
			vk, ok1 := args[i].(string)
			vb, ok2 := args[i+1].([]byte)
			if !ok1 || !ok2 {
				return nil, errors.New("malformed view arg pair")
			}
			c.hashes[sharedKey][vk] = vb
		}
		return int64(1), nil
	}
	if isRemoveScript(script) {
		if len(args) != 1 {
			return nil, errors.New("expected exactly 1 ARGV")
		}
		viewKey, ok := args[0].(string)
		if !ok {
			return nil, errors.New("expected string view key")
		}
		var deleted int64
		for _, sharedKey := range keys {
			h := c.hashes[sharedKey]
			if h == nil {
				continue
			}
			delete(h, viewKey)
			if len(h) == 1 {
				if _, hasData := h[mrmDataField]; hasData {
					delete(c.hashes, sharedKey)
					deleted++
				}
			}
		}
		return deleted, nil
	}
	return nil, errors.New("recordingCache: unrecognized script")
}

// isInsertScript / isRemoveScript: cheap heuristics matching distinctive
// substrings in each script body.
func isInsertScript(s string) bool {
	for _, needle := range []string{"key exists", "EXPIRE", `HSET`} {
		if !contains(s, needle) {
			return false
		}
	}
	return true
}

func isRemoveScript(s string) bool {
	for _, needle := range []string{"HDEL", "HLEN", "DEL"} {
		if !contains(s, needle) {
			return false
		}
	}
	return true
}

func contains(s, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Ensure recordingCache still satisfies cache.Client.
var _ cache.Client = (*recordingCache)(nil)

func TestSendMRMBinary_SuccessSingleRecipient(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	rc := newRecordingCache()
	mgr.SetMRMCache(NewMRMCache(rc, managerTestLogger()))

	var rid [16]byte
	rid[15] = 0x42
	recipientUUID := uuid.UUID(rid).String()

	body := buildFakeSSv2Ciphertext(t,
		[]fakeRecipient{{uuidBytes: rid, devices: []uint8{1, 2}, regIDs: []uint16{100, 200}}},
		[]byte("payload-bytes"),
	)

	result, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      body,
		Timestamp: 12345,
		Lookup: func(_ context.Context, u string) (*MRMRecipientAccount, error) {
			if u != recipientUUID {
				return nil, errors.New("unexpected lookup uuid")
			}
			return &MRMRecipientAccount{UUID: u}, nil
		},
	})
	if err != nil {
		t.Fatalf("SendMRMBinary: %v", err)
	}
	if len(result.UUIDs404) != 0 {
		t.Errorf("uuids404 = %v, want empty", result.UUIDs404)
	}
	if rc.insertCalls != 1 {
		t.Errorf("MRM cache Insert calls = %d, want 1", rc.insertCalls)
	}

	// One envelope per device should be queued for this recipient.
	for _, dev := range []uint64{1, 2} {
		queue := store.queues[store.qkey(recipientUUID, dev)]
		if len(queue) != 1 {
			t.Fatalf("device %d: queue len = %d, want 1", dev, len(queue))
		}
		env := queue[0]
		if env.Type != EnvelopeTypeUnidentifiedSender {
			t.Errorf("device %d: type = %v, want UnidentifiedSender", dev, env.Type)
		}
		if !env.Urgent {
			t.Errorf("device %d: urgent = false, want true", dev)
		}
		if len(env.SharedMrmKey) == 0 {
			t.Errorf("device %d: SharedMrmKey not set", dev)
		}
		if len(env.SharedMrmRecipientView) != 18 {
			t.Errorf("device %d: SharedMrmRecipientView len = %d, want 18", dev, len(env.SharedMrmRecipientView))
		}
		if env.Timestamp != 12345 {
			t.Errorf("device %d: timestamp = %d, want 12345", dev, env.Timestamp)
		}
		if env.DestinationUUID != recipientUUID {
			t.Errorf("device %d: dest = %q, want %q", dev, env.DestinationUUID, recipientUUID)
		}
	}

	// Cache content: data field equals the original ciphertext, view field
	// equals the 13-byte serialized view header.
	for sharedKey, h := range rc.hashes {
		if string(h[mrmDataField]) != string(body) {
			t.Errorf("cache[%q].data does not match original ciphertext", sharedKey)
		}
		// Two device views should be present (one per device).
		if len(h) != 1+2 {
			t.Errorf("cache[%q] field count = %d, want 3 (data + 2 views)", sharedKey, len(h))
		}
	}
}

func TestSendMRMBinary_RecipientNotFoundSurfacesIn404(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	rc := newRecordingCache()
	mgr.SetMRMCache(NewMRMCache(rc, managerTestLogger()))

	var rid1, rid2 [16]byte
	rid1[15] = 1
	rid2[15] = 2
	missingUUID := uuid.UUID(rid2).String()

	body := buildFakeSSv2Ciphertext(t,
		[]fakeRecipient{
			{uuidBytes: rid1, devices: []uint8{1}, regIDs: []uint16{10}},
			{uuidBytes: rid2, devices: []uint8{1}, regIDs: []uint16{20}},
		},
		[]byte("hi"),
	)

	result, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      body,
		Timestamp: 1,
		Lookup: func(_ context.Context, u string) (*MRMRecipientAccount, error) {
			if u == missingUUID {
				return nil, errors.New("not found")
			}
			return &MRMRecipientAccount{UUID: u}, nil
		},
	})
	if err != nil {
		t.Fatalf("SendMRMBinary: %v", err)
	}
	if len(result.UUIDs404) != 1 || result.UUIDs404[0] != missingUUID {
		t.Errorf("uuids404 = %v, want [%s]", result.UUIDs404, missingUUID)
	}
	if rc.insertCalls != 1 {
		t.Errorf("MRM cache Insert calls = %d, want 1 (one resolvable recipient)", rc.insertCalls)
	}
}

func TestSendMRMBinary_AllRecipientsMissing_NoCacheInsert(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	rc := newRecordingCache()
	mgr.SetMRMCache(NewMRMCache(rc, managerTestLogger()))

	var rid [16]byte
	rid[15] = 9
	missingUUID := uuid.UUID(rid).String()

	body := buildFakeSSv2Ciphertext(t,
		[]fakeRecipient{{uuidBytes: rid, devices: []uint8{1}, regIDs: []uint16{1}}},
		[]byte("x"),
	)

	result, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      body,
		Timestamp: 1,
		Lookup: func(_ context.Context, _ string) (*MRMRecipientAccount, error) {
			return nil, errors.New("not found")
		},
	})
	if err != nil {
		t.Fatalf("SendMRMBinary: %v", err)
	}
	if len(result.UUIDs404) != 1 || result.UUIDs404[0] != missingUUID {
		t.Errorf("uuids404 = %v", result.UUIDs404)
	}
	if rc.insertCalls != 0 {
		t.Errorf("cache should not be inserted when all recipients missing: insertCalls = %d", rc.insertCalls)
	}
	if len(store.queues) != 0 {
		t.Errorf("no envelopes should be queued: %d queues", len(store.queues))
	}
}

func TestSendMRMBinary_LookupReturnsNilAccount_TreatedAs404(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	mgr.SetMRMCache(NewMRMCache(newRecordingCache(), managerTestLogger()))

	var rid [16]byte
	rid[15] = 5

	body := buildFakeSSv2Ciphertext(t,
		[]fakeRecipient{{uuidBytes: rid, devices: []uint8{1}, regIDs: []uint16{1}}},
		[]byte("x"),
	)

	result, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      body,
		Timestamp: 1,
		Lookup: func(_ context.Context, _ string) (*MRMRecipientAccount, error) {
			// nil account, nil error → treated as missing.
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("SendMRMBinary: %v", err)
	}
	if len(result.UUIDs404) != 1 {
		t.Errorf("uuids404 = %v, want exactly one", result.UUIDs404)
	}
}

// Verify the cross-instance integration path: SendMRMBinary stores a payload,
// then GetMessagesForDevice on the same manager rehydrates it for delivery.
func TestSendMRMBinary_RoundTripWithRehydrate(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	mgr.SetMRMCache(NewMRMCache(newRecordingCache(), managerTestLogger()))

	var rid [16]byte
	rid[15] = 7
	recipientUUID := uuid.UUID(rid).String()

	body := buildFakeSSv2Ciphertext(t,
		[]fakeRecipient{{uuidBytes: rid, devices: []uint8{1}, regIDs: []uint16{42}}},
		[]byte("payload-X"),
	)

	if _, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      body,
		Timestamp: 1,
		Lookup: func(_ context.Context, u string) (*MRMRecipientAccount, error) {
			return &MRMRecipientAccount{UUID: u}, nil
		},
	}); err != nil {
		t.Fatalf("SendMRMBinary: %v", err)
	}

	got, err := mgr.GetMessagesForDevice(context.Background(), recipientUUID, 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("envelopes = %d, want 1", len(got))
	}
	out := got[0]
	if out.SharedMrmKey != nil || out.SharedMrmRecipientView != nil {
		t.Error("rehydrated envelope still has SharedMrm* fields set")
	}
	if len(out.Content) == 0 {
		t.Error("rehydrated envelope has empty Content")
	}
	// First byte of the rebuilt ReceivedMessage is always 0x22 (UUID version).
	if out.Content[0] != 0x22 {
		t.Errorf("Content[0] = 0x%02x, want 0x22", out.Content[0])
	}
}

// Sanity: the protocol.ServiceId imported here should still be useful in tests.
var _ = protocol.NewACI([16]byte{1})
