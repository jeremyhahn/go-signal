package cdsi

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"google.golang.org/protobuf/proto"

	cdsipb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/cdsi"
)

// Wire-format sizes mirror go-libsignal/pkg/net/cdsi.go so server
// and client agree on the packed-bytes layout.
const (
	e164SerializedLen = 8                                                         // big-endian uint64
	uuidSerializedLen = 16                                                        // raw UUID bytes
	aciUakPairLen     = uuidSerializedLen + 16                                    // ACI || access_key
	responseEntryLen  = e164SerializedLen + uuidSerializedLen + uuidSerializedLen // e164 || PNI || ACI
)

// Dispatcher routes decoded CDSI ClientRequest payloads onto the
// Directory and returns the corresponding ClientResponse bytes.
//
// One Dispatcher instance is shared by all sessions; the per-session
// state (rate-limit counters, continuation tokens) is the WebSocket
// handler's responsibility — minimal tokens are emitted here to keep
// the proto wire shape stable.
type Dispatcher struct {
	directory Directory
}

// NewDispatcher constructs a Dispatcher backed by directory.
func NewDispatcher(directory Directory) *Dispatcher {
	if directory == nil {
		panic("cdsi: directory is required")
	}
	return &Dispatcher{directory: directory}
}

// Handle decodes a ClientRequest, performs the directory lookups,
// and returns the encoded ClientResponse bytes.
//
// Authorization model: aci_uak_pairs are checked against the
// directory's recorded access_key — only matched pairs unlock ACI
// disclosure in the response. PNI bytes are returned for every
// registered E.164 (PNI is non-secret per Signal's model).
func (d *Dispatcher) Handle(ctx context.Context, frame []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var req cdsipb.ClientRequest
	if err := proto.Unmarshal(frame, &req); err != nil {
		return nil, err
	}

	// Parse incoming E.164 lists.
	newE164s, err := parseE164s(req.E164SBytes)
	if err != nil {
		return nil, err
	}
	prevE164s, err := parseE164s(req.PrevE164SBytes)
	if err != nil {
		return nil, err
	}
	// Parse ACI/access-key pairs.
	uaks, err := parseAciUakPairs(req.AciUakPairs)
	if err != nil {
		return nil, err
	}
	// Index access keys by ACI so the response builder can authorize
	// ACI disclosure per-entry without re-scanning the list.
	uakIndex := make(map[[16]byte][16]byte, len(uaks))
	for _, p := range uaks {
		uakIndex[p.ACI] = p.AccessKey
	}

	all := append(make([]uint64, 0, len(newE164s)+len(prevE164s)), newE164s...)
	all = append(all, prevE164s...)

	// Build response entries. Java/Rust mirror: emit one entry per
	// input number, with all-zero UUID bytes meaning "absent".
	out := make([]byte, 0, len(all)*responseEntryLen)
	for _, e164 := range all {
		entry, found := d.directory.Lookup(e164)
		out = encodeResponseEntry(out, e164, entry, found, uakIndex)
	}

	resp := &cdsipb.ClientResponse{
		E164PniAciTriples: out,
		Token:             []byte{}, // MVP: no continuation token
		DebugPermitsUsed:  int32(len(all)),
	}
	return proto.Marshal(resp)
}

// parseE164s deserialises a packed big-endian E.164 byte slice.
func parseE164s(b []byte) ([]uint64, error) {
	if len(b)%e164SerializedLen != 0 {
		return nil, errors.New("cdsi: e164 bytes length not a multiple of 8")
	}
	out := make([]uint64, 0, len(b)/e164SerializedLen)
	for i := 0; i < len(b); i += e164SerializedLen {
		v := binary.BigEndian.Uint64(b[i : i+e164SerializedLen])
		out = append(out, v)
	}
	return out, nil
}

// AciUak pairs an ACI with its 16-byte access-key bytes.
type aciUak struct {
	ACI       [16]byte
	AccessKey [16]byte
}

func parseAciUakPairs(b []byte) ([]aciUak, error) {
	if len(b)%aciUakPairLen != 0 {
		return nil, errors.New("cdsi: aci_uak_pairs length not a multiple of 32")
	}
	out := make([]aciUak, 0, len(b)/aciUakPairLen)
	for i := 0; i < len(b); i += aciUakPairLen {
		var p aciUak
		copy(p.ACI[:], b[i:i+uuidSerializedLen])
		copy(p.AccessKey[:], b[i+uuidSerializedLen:i+aciUakPairLen])
		out = append(out, p)
	}
	return out, nil
}

// encodeResponseEntry appends one 40-byte response tuple to out for
// (e164, entry). PNI bytes are always emitted when the entry exists;
// ACI bytes are emitted only when the caller's ACI/access-key matches
// the directory's recorded access_key for the entry's ACI.
//
// Absent entries are emitted as zero-bytes per Java/Rust convention so
// the response shape stays constant-length per input.
func encodeResponseEntry(
	out []byte,
	e164 uint64,
	entry Entry,
	found bool,
	uakIndex map[[16]byte][16]byte,
) []byte {
	var buf [responseEntryLen]byte
	binary.BigEndian.PutUint64(buf[:e164SerializedLen], e164)
	if found {
		copy(buf[e164SerializedLen:e164SerializedLen+uuidSerializedLen], entry.PNI[:])
		if shouldDiscloseACI(entry, uakIndex) {
			copy(buf[e164SerializedLen+uuidSerializedLen:], entry.ACI[:])
		}
	}
	return append(out, buf[:]...)
}

// shouldDiscloseACI returns true when the caller has supplied an
// (ACI, access_key) pair that matches the entry's recorded access_key
// for that ACI. Empty access keys never unlock disclosure.
func shouldDiscloseACI(entry Entry, uakIndex map[[16]byte][16]byte) bool {
	var zero [16]byte
	if entry.ACI == zero {
		return false
	}
	uak, ok := uakIndex[entry.ACI]
	if !ok {
		return false
	}
	if entry.AccessKey == zero {
		return false
	}
	return subtle.ConstantTimeCompare(uak[:], entry.AccessKey[:]) == 1
}
