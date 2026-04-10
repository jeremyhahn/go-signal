package profiles

import (
	"encoding/json"
	"testing"
)

// --- Profile tests ---

func TestProfile_ZeroValue(t *testing.T) {
	var p Profile
	if p.UUID != "" {
		t.Errorf("expected empty UUID, got %q", p.UUID)
	}
	if p.Version != "" {
		t.Errorf("expected empty Version, got %q", p.Version)
	}
	if p.Name != nil {
		t.Errorf("expected nil Name, got %v", p.Name)
	}
	if p.Avatar != "" {
		t.Errorf("expected empty Avatar, got %q", p.Avatar)
	}
}

func TestProfile_AllFields(t *testing.T) {
	p := Profile{
		UUID:           "test-uuid",
		Version:        "v1",
		Name:           []byte("name"),
		About:          []byte("about"),
		AboutEmoji:     []byte("emoji"),
		Avatar:         "avatar.png",
		Commitment:     []byte("commit"),
		PaymentAddress: []byte("pay"),
	}
	if p.UUID != "test-uuid" {
		t.Fatalf("UUID = %q, want %q", p.UUID, "test-uuid")
	}
	if p.Avatar != "avatar.png" {
		t.Fatalf("Avatar = %q, want %q", p.Avatar, "avatar.png")
	}
	if string(p.Name) != "name" {
		t.Fatalf("Name = %q, want %q", string(p.Name), "name")
	}
}

// --- CreateProfileRequest tests ---

func TestCreateProfileRequest_ZeroValue(t *testing.T) {
	var req CreateProfileRequest
	if req.Version != "" {
		t.Errorf("expected empty Version, got %q", req.Version)
	}
	if req.AvatarUpload {
		t.Error("expected AvatarUpload = false")
	}
	if req.Name != nil {
		t.Errorf("expected nil Name, got %v", req.Name)
	}
}

func TestCreateProfileRequest_AllFields(t *testing.T) {
	req := CreateProfileRequest{
		Version:        "v1",
		Name:           []byte("name"),
		About:          []byte("about"),
		AboutEmoji:     []byte("emoji"),
		PaymentAddress: []byte("pay"),
		AvatarUpload:   true,
		Commitment:     []byte("commit"),
	}
	if req.Version != "v1" {
		t.Fatalf("Version = %q, want %q", req.Version, "v1")
	}
	if !req.AvatarUpload {
		t.Fatal("expected AvatarUpload = true")
	}
}

// --- ProfileResponse tests ---

func TestProfileResponse_ZeroValue(t *testing.T) {
	var resp ProfileResponse
	if resp.UUID != "" {
		t.Errorf("expected empty UUID, got %q", resp.UUID)
	}
	if resp.Profile != nil {
		t.Error("expected nil Profile")
	}
	if resp.Badges != nil {
		t.Error("expected nil Badges")
	}
}

func TestProfileResponse_AllFields(t *testing.T) {
	resp := ProfileResponse{
		IdentityKey:                    []byte("id-key"),
		UnidentifiedAccess:             []byte("ua"),
		UnrestrictedUnidentifiedAccess: true,
		Capabilities:                   map[string]bool{"storage": true},
		Badges:                         []Badge{{ID: "badge-1"}},
		UUID:                           "resp-uuid",
		Profile:                        &Profile{UUID: "p-uuid"},
	}
	if resp.UUID != "resp-uuid" {
		t.Fatalf("UUID = %q, want %q", resp.UUID, "resp-uuid")
	}
	if !resp.UnrestrictedUnidentifiedAccess {
		t.Fatal("expected UnrestrictedUnidentifiedAccess = true")
	}
	if len(resp.Badges) != 1 {
		t.Fatalf("expected 1 badge, got %d", len(resp.Badges))
	}
}

// --- Badge tests ---

func TestBadge_ZeroValue(t *testing.T) {
	var b Badge
	if b.ID != "" {
		t.Errorf("expected empty ID, got %q", b.ID)
	}
	if b.Sprites6 != nil {
		t.Errorf("expected nil Sprites6, got %v", b.Sprites6)
	}
}

func TestBadge_AllFields(t *testing.T) {
	b := Badge{
		ID:          "badge-1",
		Category:    "cat",
		Name:        "Test Badge",
		Description: "desc",
		Sprites6:    []string{"s1", "s2", "s3", "s4", "s5", "s6"},
	}
	if b.ID != "badge-1" {
		t.Fatalf("ID = %q, want %q", b.ID, "badge-1")
	}
	if len(b.Sprites6) != 6 {
		t.Fatalf("expected 6 sprites, got %d", len(b.Sprites6))
	}
}

func TestBadge_JSONRoundTrip(t *testing.T) {
	b := Badge{
		ID:          "badge-json",
		Category:    "test",
		Name:        "JSON Badge",
		Description: "json test",
		Sprites6:    []string{"a", "b"},
	}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded Badge
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.ID != "badge-json" {
		t.Fatalf("ID = %q, want %q", decoded.ID, "badge-json")
	}
}
