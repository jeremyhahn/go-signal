package stickers

import (
	"bytes"
	"crypto/aes"
	"errors"
	"testing"
)

func TestNewPackKey_Length(t *testing.T) {
	k, err := NewPackKey()
	if err != nil {
		t.Fatalf("NewPackKey: %v", err)
	}
	if len(k) != PackKeyLen {
		t.Errorf("pack key = %d bytes, want %d", len(k), PackKeyLen)
	}
}

func TestNewPackKey_Distinct(t *testing.T) {
	a, _ := NewPackKey()
	b, _ := NewPackKey()
	if bytes.Equal(a, b) {
		t.Error("two successive pack keys are identical — RNG broken")
	}
}

func TestEncryptPackPayload_RejectsWrongLengthKey(t *testing.T) {
	if _, err := EncryptPackPayload(make([]byte, 16), []byte("x")); err == nil {
		t.Error("expected error for short pack key")
	}
	if _, err := EncryptPackPayload(make([]byte, 64), []byte("x")); err == nil {
		t.Error("expected error for long pack key")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key, _ := NewPackKey()
	cases := [][]byte{
		nil,
		{},
		[]byte("hi"),
		bytes.Repeat([]byte{0xAA}, aes.BlockSize-1),
		bytes.Repeat([]byte{0xBB}, aes.BlockSize),
		bytes.Repeat([]byte{0xCC}, aes.BlockSize+1),
		bytes.Repeat([]byte{0xDD}, 4096),
	}
	for _, in := range cases {
		env, err := EncryptPackPayload(key, in)
		if err != nil {
			t.Fatalf("EncryptPackPayload: %v", err)
		}
		out, err := DecryptPackPayload(key, env)
		if err != nil {
			t.Fatalf("DecryptPackPayload: %v", err)
		}
		if !bytes.Equal(out, in) {
			t.Errorf("round-trip mismatch: got %x want %x", out, in)
		}
	}
}

func TestEncryptPackPayload_DistinctIVPerCall(t *testing.T) {
	key, _ := NewPackKey()
	plain := []byte("same plaintext")
	a, _ := EncryptPackPayload(key, plain)
	b, _ := EncryptPackPayload(key, plain)
	if bytes.Equal(a[:envelopeIVLen], b[:envelopeIVLen]) {
		t.Error("two encryptions of the same plaintext share an IV")
	}
}

func TestDecryptPackPayload_RejectsTamperedTag(t *testing.T) {
	key, _ := NewPackKey()
	env, _ := EncryptPackPayload(key, []byte("hello"))
	env[len(env)-1] ^= 0xFF
	_, err := DecryptPackPayload(key, env)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("expected ErrInvalidEnvelope, got %v", err)
	}
}

func TestDecryptPackPayload_RejectsTamperedCiphertext(t *testing.T) {
	key, _ := NewPackKey()
	env, _ := EncryptPackPayload(key, []byte("hello"))
	env[envelopeIVLen] ^= 0xFF
	_, err := DecryptPackPayload(key, env)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("expected ErrInvalidEnvelope, got %v", err)
	}
}

func TestDecryptPackPayload_RejectsTamperedIV(t *testing.T) {
	key, _ := NewPackKey()
	env, _ := EncryptPackPayload(key, []byte("hello"))
	env[0] ^= 0xFF
	_, err := DecryptPackPayload(key, env)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("expected ErrInvalidEnvelope, got %v", err)
	}
}

func TestDecryptPackPayload_RejectsShortEnvelope(t *testing.T) {
	key, _ := NewPackKey()
	_, err := DecryptPackPayload(key, []byte("short"))
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("expected ErrInvalidEnvelope, got %v", err)
	}
}

func TestDecryptPackPayload_RejectsMisalignedCiphertext(t *testing.T) {
	key, _ := NewPackKey()
	// Length where (len - IV - MAC) is NOT a multiple of AES block size.
	env := make([]byte, envelopeIVLen+envelopeMACLen+aes.BlockSize+1)
	_, err := DecryptPackPayload(key, env)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("expected ErrInvalidEnvelope, got %v", err)
	}
}

func TestPKCS7_PadUnpadRoundTrip(t *testing.T) {
	for n := 0; n < 64; n++ {
		in := bytes.Repeat([]byte{0x5A}, n)
		padded := pkcs7Pad(in, aes.BlockSize)
		if len(padded)%aes.BlockSize != 0 {
			t.Fatalf("padded length %d not a block multiple", len(padded))
		}
		out, err := pkcs7Unpad(padded, aes.BlockSize)
		if err != nil {
			t.Fatalf("pkcs7Unpad: %v", err)
		}
		if !bytes.Equal(out, in) {
			t.Errorf("len=%d: round-trip drift", n)
		}
	}
}

func TestPKCS7_UnpadRejectsZeroByte(t *testing.T) {
	in := make([]byte, aes.BlockSize)
	in[aes.BlockSize-1] = 0
	if _, err := pkcs7Unpad(in, aes.BlockSize); err == nil {
		t.Error("expected error for zero padding length")
	}
}

func TestPKCS7_UnpadRejectsOversizePadByte(t *testing.T) {
	in := make([]byte, aes.BlockSize)
	in[aes.BlockSize-1] = byte(aes.BlockSize + 1)
	if _, err := pkcs7Unpad(in, aes.BlockSize); err == nil {
		t.Error("expected error for padding > block size")
	}
}

func TestPKCS7_UnpadRejectsInconsistentPadding(t *testing.T) {
	in := make([]byte, aes.BlockSize*2)
	for i := range in {
		in[i] = 0xAA
	}
	in[len(in)-1] = 4
	in[len(in)-2] = 4
	in[len(in)-3] = 4
	in[len(in)-4] = 5 // wrong value
	if _, err := pkcs7Unpad(in, aes.BlockSize); err == nil {
		t.Error("expected error for inconsistent padding")
	}
}

func TestDerivePackKeys_StableOutput(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, PackKeyLen)
	a1, h1, _ := derivePackKeys(key)
	a2, h2, _ := derivePackKeys(key)
	if !bytes.Equal(a1, a2) || !bytes.Equal(h1, h2) {
		t.Error("HKDF output not deterministic for the same input")
	}
	if bytes.Equal(a1, h1) {
		t.Error("aes/hmac sub-keys are identical — HKDF split is broken")
	}
	if len(a1) != 32 || len(h1) != 32 {
		t.Errorf("subkey lengths = %d, %d; want 32, 32", len(a1), len(h1))
	}
}
