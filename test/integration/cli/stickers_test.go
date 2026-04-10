//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCLI_ListStickerPacks(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "listStickerPacks")
			assert.Equal(t, 0, result.ExitCode, "listStickerPacks should succeed")
		})
	}
}

func TestCLI_UploadStickerPack(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "uploadStickerPack", t.TempDir())
			t.Logf("uploadStickerPack exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_AddStickerPack(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "addStickerPack",
				"--uri", "https://signal.art/addstickers/#pack_id=0000&pack_key=0000")
			t.Logf("addStickerPack exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_GetSticker(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "getSticker",
				"--pack-id", "0000", "--sticker-id", "0")
			t.Logf("getSticker exit=%d", result.ExitCode)
		})
	}
}
