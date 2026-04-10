//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Stickers (signal-cli: listStickerPacks, uploadStickerPack, addStickerPack,
// getSticker)
// =============================================================================

func TestSignalCLI_ListStickerPacks(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listStickerPacks")
	assert.Equal(t, 0, result.ExitCode, "listStickerPacks should succeed: %s", result.Stderr)
}

func TestSignalCLI_UploadStickerPack(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	tmpDir := t.TempDir()
	manifest := `{"title":"Test Pack","author":"Test","cover":{"id":0,"emoji":"😀"},"stickers":[{"id":0,"emoji":"😀"}]}`
	require.NoError(t, writeTestFile(tmpDir+"/manifest.json", manifest))
	require.NoError(t, writeTestFile(tmpDir+"/0.png", "fake-sticker-data"))

	result := signalCLIExecAccount(t, number, "uploadStickerPack", tmpDir)

	// Sticker operation may fail client-side but must not crash server
	t.Logf("result: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_AddStickerPack(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	stickerURI := "https://signal.art/addstickers/#pack_id=0000000000000000000000000000000000000000000000000000000000000000&pack_key=0000000000000000000000000000000000000000000000000000000000000000"

	result := signalCLIExecAccount(t, number, "addStickerPack", "--uri", stickerURI)

	// Sticker operation may fail client-side but must not crash server
	t.Logf("result: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_GetSticker(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	dummyPackID := "0000000000000000000000000000000000000000000000000000000000000000"

	result := signalCLIExecAccount(t, number, "getSticker",
		"--pack-id", dummyPackID, "--sticker-id", "0")

	// Sticker operation may fail client-side but must not crash server
	t.Logf("result: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_ListStickerPacks_AfterAdd(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// Add a sticker pack first (may fail, but that's ok)
	stickerURI := "https://signal.art/addstickers/#pack_id=0000000000000000000000000000000000000000000000000000000000000000&pack_key=0000000000000000000000000000000000000000000000000000000000000000"
	signalCLIExecAccount(t, number, "addStickerPack", "--uri", stickerURI)

	// List should still work
	result := signalCLIExecAccount(t, number, "listStickerPacks")
	assert.Equal(t, 0, result.ExitCode, "listStickerPacks after add should succeed: %s", result.Stderr)
}
