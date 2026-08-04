package stickers

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePackURL_HappyPath(t *testing.T) {
	raw := "https://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef" +
		"&pack_key=" + strings.Repeat("ab", 32)
	got, err := ParsePackURL(raw)
	if err != nil {
		t.Fatalf("ParsePackURL: %v", err)
	}
	if got.PackID != "0123456789abcdef0123456789abcdef" {
		t.Errorf("packID = %q", got.PackID)
	}
	if len(got.PackKey) != PackKeyLen {
		t.Errorf("packKey len = %d", len(got.PackKey))
	}
}

func TestParsePackURL_Empty_Rejected(t *testing.T) {
	_, err := ParsePackURL("")
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_MissingFragment_Rejected(t *testing.T) {
	_, err := ParsePackURL("https://signal.art/addstickers/")
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_MissingPackID_Rejected(t *testing.T) {
	_, err := ParsePackURL("https://signal.art/addstickers/#pack_key=" + strings.Repeat("ab", 32))
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_MissingPackKey_Rejected(t *testing.T) {
	_, err := ParsePackURL("https://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef")
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_BadHex_Rejected(t *testing.T) {
	raw := "https://signal.art/addstickers/#pack_id=ZZZZ&pack_key=" + strings.Repeat("ab", 32)
	_, err := ParsePackURL(raw)
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_WrongPackKeyLength_Rejected(t *testing.T) {
	raw := "https://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef" +
		"&pack_key=ab"
	_, err := ParsePackURL(raw)
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_WrongPackIDLength_Rejected(t *testing.T) {
	raw := "https://signal.art/addstickers/#pack_id=ab&pack_key=" + strings.Repeat("ab", 32)
	_, err := ParsePackURL(raw)
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_WhitespaceInPackID_Rejected(t *testing.T) {
	// %20 = space — embedded inside the hex value before percent-decoding.
	raw := "https://signal.art/addstickers/#pack_id=%200123456789abcdef0123456789abcde&pack_key=" + strings.Repeat("ab", 32)
	_, err := ParsePackURL(raw)
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestParsePackURL_WhitespaceInPackKey_Rejected(t *testing.T) {
	raw := "https://signal.art/addstickers/#pack_id=0123456789abcdef0123456789abcdef" +
		"&pack_key=" + strings.Repeat("ab", 31) + "%20a"
	_, err := ParsePackURL(raw)
	var inv *PackURLError
	if !errors.As(err, &inv) {
		t.Errorf("expected PackURLError, got %v", err)
	}
}

func TestPackURLError_ErrorMethod(t *testing.T) {
	e := &PackURLError{Reason: "test reason"}
	got := e.Error()
	if got != "stickers: invalid pack URL: test reason" {
		t.Errorf("Error() = %q", got)
	}
}

func TestPackURLError_Is(t *testing.T) {
	a := &PackURLError{Reason: "a"}
	b := &PackURLError{Reason: "b"}
	if !errors.Is(a, b) {
		t.Error("PackURLError.Is: same type should match")
	}
	if errors.Is(a, errors.New("other")) {
		t.Error("PackURLError.Is: different error should not match")
	}
}
