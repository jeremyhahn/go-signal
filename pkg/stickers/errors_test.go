package stickers

import (
	"errors"
	"testing"
)

func TestInvalidStickerCountError_Error(t *testing.T) {
	tests := []struct {
		name  string
		count int
		want  string
	}{
		{"zero", 0, "invalid sticker count: 0"},
		{"negative", -5, "invalid sticker count: -5"},
		{"too_large", 500, "invalid sticker count: 500"},
		{"boundary_202", 202, "invalid sticker count: 202"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &InvalidStickerCountError{Count: tt.count}
			if got := e.Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvalidStickerCountError_TypeAssertion(t *testing.T) {
	var err error = &InvalidStickerCountError{Count: 999}
	var target *InvalidStickerCountError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *InvalidStickerCountError")
	}
	if target.Count != 999 {
		t.Errorf("got count %d, want 999", target.Count)
	}
}

func TestInvalidStickerCountError_ImplementsError(t *testing.T) {
	var _ error = &InvalidStickerCountError{}
}
