package server

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestMemoryLog_AppendAndLatest(t *testing.T) {
	l := NewMemoryLog()
	if l.Size() != 0 {
		t.Errorf("initial size = %d", l.Size())
	}
	e1, err := l.Append([]byte("alice"), []byte("v1"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e1.Index != 0 {
		t.Errorf("first Index = %d", e1.Index)
	}
	if l.Size() != 1 {
		t.Errorf("size after first append = %d", l.Size())
	}
	got, ok := l.Latest([]byte("alice"))
	if !ok || string(got.Value) != "v1" {
		t.Errorf("Latest mismatch: %v", got)
	}
}

func TestMemoryLog_AppendReplacesLatestButKeepsHistory(t *testing.T) {
	l := NewMemoryLog()
	_, _ = l.Append([]byte("alice"), []byte("v1"))
	_, _ = l.Append([]byte("alice"), []byte("v2"))
	if l.Size() != 2 {
		t.Errorf("size = %d, want 2", l.Size())
	}
	got, _ := l.Latest([]byte("alice"))
	if string(got.Value) != "v2" {
		t.Errorf("Latest value = %q", got.Value)
	}
}

func TestMemoryLog_AppendEmptyKeyRejected(t *testing.T) {
	l := NewMemoryLog()
	if _, err := l.Append(nil, []byte("v")); err == nil {
		t.Error("expected error on empty key")
	}
}

func TestMemoryLog_LatestMissingKey(t *testing.T) {
	l := NewMemoryLog()
	if _, ok := l.Latest([]byte("missing")); ok {
		t.Error("expected miss for unknown key")
	}
}

func TestMemoryLog_RootHashDeterministic(t *testing.T) {
	l1 := NewMemoryLog()
	l2 := NewMemoryLog()
	_, _ = l1.Append([]byte("a"), []byte("1"))
	_, _ = l1.Append([]byte("b"), []byte("2"))
	_, _ = l2.Append([]byte("a"), []byte("1"))
	_, _ = l2.Append([]byte("b"), []byte("2"))
	if l1.RootHash() != l2.RootHash() {
		t.Error("identical logs should produce identical root hashes")
	}
}

func TestSignAndVerifyTreeHead(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	var root [32]byte
	root[0] = 0xAB
	ts := time.UnixMilli(1_700_000_000_000)
	sig := SignTreeHead(priv, 42, root, ts)
	if !VerifyTreeHead(pub, 42, root, ts, sig) {
		t.Error("signature must verify against the same payload")
	}
	if VerifyTreeHead(pub, 43, root, ts, sig) {
		t.Error("size mismatch must fail verification")
	}
	root[1] = 0xCD
	if VerifyTreeHead(pub, 42, root, ts, sig) {
		t.Error("root mismatch must fail verification")
	}
}
