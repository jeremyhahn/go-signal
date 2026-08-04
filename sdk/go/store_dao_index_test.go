package signal

import (
	"strings"
	"testing"
)

func TestAssertStickerPackIndex_PassesOnCurrentSchema(t *testing.T) {
	if err := assertStickerPackIndex(); err != nil {
		t.Errorf("assertStickerPackIndex failed on current schema: %v", err)
	}
}

func TestAssertStickerPackIndex_ErrorIsActionable(t *testing.T) {
	// The error message must name the field so an operator looking
	// at a panic stack can find what to fix without spelunking.
	err := assertStickerPackIndex()
	if err != nil && !strings.Contains(err.Error(), "PackID") {
		t.Errorf("error message does not name the PackID field: %v", err)
	}
}
