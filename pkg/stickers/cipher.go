package stickers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"strconv"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"golang.org/x/crypto/hkdf"
)

// PackKeyLen is the length of a sticker pack key in bytes. Signal uses a
// fixed 32-byte secret embedded in the share URL.
const PackKeyLen = 32

// stickerPackHKDFInfo is the HKDF info string Signal's clients use when
// deriving per-pack AES/HMAC keys from the pack key. This is part of the
// wire format — clients on every platform must use the exact same value
// or decryption fails.
const stickerPackHKDFInfo = "Sticker Pack"

// envelopeIVLen is the AES-CBC IV length. Same as AES block size.
const envelopeIVLen = aes.BlockSize

// envelopeMACLen is the truncated HMAC-SHA256 tag length. Signal uses
// the full 32-byte SHA-256 output.
const envelopeMACLen = 32

// NewPackKey returns a fresh 32-byte pack key drawn from crypto/rand.
// Callers must surface the key to the operator alongside the pack ID
// (the two together form the share URL).
func NewPackKey() ([]byte, error) {
	k := make([]byte, PackKeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// derivePackKeys derives the AES + HMAC subkeys from a sticker pack
// key. Returns (aesKey, hmacKey) each 32 bytes.
func derivePackKeys(packKey []byte) (aesKey, hmacKey []byte, err error) {
	if len(packKey) != PackKeyLen {
		return nil, nil, signalerrors.New(signalerrors.ErrInvalidArgument, "stickers: pack key must be "+strconv.Itoa(PackKeyLen)+" bytes, got "+strconv.Itoa(len(packKey)))
	}
	salt := make([]byte, 32) // RFC 5869 §3.1: empty salt → 32 zero bytes
	reader := hkdf.New(sha256.New, packKey, salt, []byte(stickerPackHKDFInfo))
	out := make([]byte, 64)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, nil, signalerrors.Wrap(signalerrors.ErrInternal, "stickers: hkdf expand", err)
	}
	return out[:32], out[32:], nil
}

// EncryptPackPayload wraps plaintext (the manifest protobuf or a single
// sticker image) in Signal's sticker-pack envelope:
//
//	output = IV(16) || AES-256-CBC(aesKey, IV, PKCS7(plaintext)) || HMAC-SHA256(hmacKey, IV||ciphertext)
//
// where (aesKey, hmacKey) are derived from packKey via HKDF as described
// in derivePackKeys. The returned slice is suitable for upload to the
// sticker CDN without further wrapping.
func EncryptPackPayload(packKey, plaintext []byte) ([]byte, error) {
	aesKey, hmacKey, err := derivePackKeys(packKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "stickers: aes init", err)
	}
	iv := make([]byte, envelopeIVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "stickers: iv", err)
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(iv)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	out := make([]byte, 0, len(iv)+len(ciphertext)+envelopeMACLen)
	out = append(out, iv...)
	out = append(out, ciphertext...)
	out = append(out, tag...)
	return out, nil
}

// DecryptPackPayload reverses EncryptPackPayload. Useful for round-trip
// tests and for the get-sticker download path. Returns
// (plaintext, error). The HMAC is verified in constant time; a tag
// mismatch returns ErrInvalidEnvelope without leaking timing.
func DecryptPackPayload(packKey, envelope []byte) ([]byte, error) {
	if len(envelope) < envelopeIVLen+envelopeMACLen+aes.BlockSize {
		return nil, ErrInvalidEnvelope
	}
	if (len(envelope)-envelopeIVLen-envelopeMACLen)%aes.BlockSize != 0 {
		return nil, ErrInvalidEnvelope
	}
	aesKey, hmacKey, err := derivePackKeys(packKey)
	if err != nil {
		return nil, err
	}
	iv := envelope[:envelopeIVLen]
	ciphertext := envelope[envelopeIVLen : len(envelope)-envelopeMACLen]
	tag := envelope[len(envelope)-envelopeMACLen:]

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(iv)
	mac.Write(ciphertext)
	if subtle.ConstantTimeCompare(tag, mac.Sum(nil)) != 1 {
		return nil, ErrInvalidEnvelope
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "stickers: aes init", err)
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
	return pkcs7Unpad(padded, aes.BlockSize)
}

// pkcs7Pad appends padding bytes per RFC 5652. Always adds at least
// one byte; for input that is already a block multiple, an entire block
// of value blockSize is appended.
func pkcs7Pad(in []byte, blockSize int) []byte {
	n := blockSize - (len(in) % blockSize)
	out := make([]byte, len(in)+n)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// pkcs7Unpad strips RFC 5652 padding. Validates that the trailing byte
// is in [1, blockSize] and that every padding byte has the same value.
func pkcs7Unpad(in []byte, blockSize int) ([]byte, error) {
	if len(in) == 0 || len(in)%blockSize != 0 {
		return nil, ErrInvalidEnvelope
	}
	n := int(in[len(in)-1])
	if n == 0 || n > blockSize {
		return nil, ErrInvalidEnvelope
	}
	// Verify every padding byte before trusting the count.
	bad := byte(0)
	for i := len(in) - n; i < len(in); i++ {
		bad |= in[i] ^ byte(n)
	}
	if bad != 0 {
		return nil, ErrInvalidEnvelope
	}
	return in[:len(in)-n], nil
}
