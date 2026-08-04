package cdsi

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"google.golang.org/protobuf/proto"

	cdsipb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/cdsi"
)

func packE164s(nums ...uint64) []byte {
	out := make([]byte, len(nums)*8)
	for i, n := range nums {
		binary.BigEndian.PutUint64(out[i*8:], n)
	}
	return out
}

func packAciUak(pairs [][2][16]byte) []byte {
	out := make([]byte, len(pairs)*32)
	for i, p := range pairs {
		copy(out[i*32:i*32+16], p[0][:])
		copy(out[i*32+16:(i+1)*32], p[1][:])
	}
	return out
}

func newDirWithEntries(entries ...Entry) *MemoryDirectory {
	d := NewMemoryDirectory()
	for _, e := range entries {
		d.Upsert(e)
	}
	return d
}

func TestDispatch_LookupBareE164ReturnsPNIOnly(t *testing.T) {
	var aci, pni, ak [16]byte
	aci[0] = 1
	pni[1] = 2
	ak[2] = 3
	dir := newDirWithEntries(Entry{E164: 15551112222, ACI: aci, PNI: pni, AccessKey: ak})
	d := NewDispatcher(dir)
	req := &cdsipb.ClientRequest{E164SBytes: packE164s(15551112222)}
	frame, _ := proto.Marshal(req)
	out, err := d.Handle(context.Background(), frame)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	var resp cdsipb.ClientResponse
	if err := proto.Unmarshal(out, &resp); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(resp.E164PniAciTriples) != responseEntryLen {
		t.Fatalf("triples len = %d, want %d", len(resp.E164PniAciTriples), responseEntryLen)
	}
	gotE164 := binary.BigEndian.Uint64(resp.E164PniAciTriples[:8])
	if gotE164 != 15551112222 {
		t.Errorf("returned E164 = %d", gotE164)
	}
	if !bytes.Equal(resp.E164PniAciTriples[8:24], pni[:]) {
		t.Errorf("PNI bytes mismatch")
	}
	var zero [16]byte
	if !bytes.Equal(resp.E164PniAciTriples[24:40], zero[:]) {
		t.Errorf("ACI bytes should be zero without matching access key")
	}
}

func TestDispatch_LookupUnlocksACIWithMatchingAccessKey(t *testing.T) {
	var aci, pni, ak [16]byte
	aci[0] = 0xAA
	pni[1] = 0xBB
	ak[2] = 0xCC
	dir := newDirWithEntries(Entry{E164: 15551112222, ACI: aci, PNI: pni, AccessKey: ak})
	d := NewDispatcher(dir)
	req := &cdsipb.ClientRequest{
		E164SBytes:  packE164s(15551112222),
		AciUakPairs: packAciUak([][2][16]byte{{aci, ak}}),
	}
	frame, _ := proto.Marshal(req)
	out, _ := d.Handle(context.Background(), frame)
	var resp cdsipb.ClientResponse
	_ = proto.Unmarshal(out, &resp)
	if !bytes.Equal(resp.E164PniAciTriples[24:40], aci[:]) {
		t.Errorf("expected ACI bytes after valid access-key proof")
	}
}

func TestDispatch_AbsentNumberReturnsZeroBytes(t *testing.T) {
	d := NewDispatcher(NewMemoryDirectory())
	req := &cdsipb.ClientRequest{E164SBytes: packE164s(15550009999)}
	frame, _ := proto.Marshal(req)
	out, _ := d.Handle(context.Background(), frame)
	var resp cdsipb.ClientResponse
	_ = proto.Unmarshal(out, &resp)
	if len(resp.E164PniAciTriples) != responseEntryLen {
		t.Fatalf("triples len = %d", len(resp.E164PniAciTriples))
	}
	gotE164 := binary.BigEndian.Uint64(resp.E164PniAciTriples[:8])
	if gotE164 != 15550009999 {
		t.Errorf("E164 echo = %d", gotE164)
	}
	var zero [16]byte
	if !bytes.Equal(resp.E164PniAciTriples[8:24], zero[:]) || !bytes.Equal(resp.E164PniAciTriples[24:40], zero[:]) {
		t.Errorf("PNI/ACI should be all-zero for absent number")
	}
}

func TestDispatch_BadE164PackedSliceRejected(t *testing.T) {
	d := NewDispatcher(NewMemoryDirectory())
	req := &cdsipb.ClientRequest{E164SBytes: []byte{1, 2, 3}}
	frame, _ := proto.Marshal(req)
	if _, err := d.Handle(context.Background(), frame); err == nil {
		t.Error("expected error on non-multiple-of-8 e164 slice")
	}
}

func TestDispatch_BadAciUakLengthRejected(t *testing.T) {
	d := NewDispatcher(NewMemoryDirectory())
	req := &cdsipb.ClientRequest{AciUakPairs: []byte{1, 2, 3}}
	frame, _ := proto.Marshal(req)
	if _, err := d.Handle(context.Background(), frame); err == nil {
		t.Error("expected error on non-multiple-of-32 aci_uak slice")
	}
}

func TestDispatch_DebugPermitsTracksLookupCount(t *testing.T) {
	d := NewDispatcher(NewMemoryDirectory())
	req := &cdsipb.ClientRequest{
		E164SBytes:     packE164s(1, 2, 3),
		PrevE164SBytes: packE164s(4, 5),
	}
	frame, _ := proto.Marshal(req)
	out, _ := d.Handle(context.Background(), frame)
	var resp cdsipb.ClientResponse
	_ = proto.Unmarshal(out, &resp)
	if resp.DebugPermitsUsed != 5 {
		t.Errorf("DebugPermitsUsed = %d, want 5", resp.DebugPermitsUsed)
	}
}

func TestNewDispatcher_PanicsWithoutDirectory(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	NewDispatcher(nil)
}

func TestMemoryDirectory_UpsertDeleteVersion(t *testing.T) {
	d := NewMemoryDirectory()
	if d.Count() != 0 {
		t.Errorf("initial count = %d", d.Count())
	}
	d.Upsert(Entry{E164: 1})
	d.Upsert(Entry{E164: 2})
	if d.Count() != 2 {
		t.Errorf("count after upsert = %d", d.Count())
	}
	if d.Version() == 0 {
		t.Error("Version should advance on Upsert")
	}
	if _, ok := d.Lookup(2); !ok {
		t.Error("Lookup should find entry 2")
	}
	d.Delete(2)
	if _, ok := d.Lookup(2); ok {
		t.Error("Lookup should miss after Delete")
	}
}

func TestMemoryDirectory_Replace(t *testing.T) {
	d := NewMemoryDirectory()
	d.Upsert(Entry{E164: 1})
	d.Upsert(Entry{E164: 2})
	if err := d.Replace(context.Background(), []Entry{{E164: 3}, {E164: 4}}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if d.Count() != 2 {
		t.Errorf("count after Replace = %d", d.Count())
	}
	if _, ok := d.Lookup(1); ok {
		t.Error("Lookup should miss old entry")
	}
	if _, ok := d.Lookup(3); !ok {
		t.Error("Lookup should find new entry")
	}
}
