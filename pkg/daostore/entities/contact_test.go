package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContactEntity_EntityID(t *testing.T) {
	tests := []struct {
		name string
		id   uint64
	}{
		{"zero", 0},
		{"positive", 77},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &ContactEntity{ID: tc.id}
			assert.Equal(t, tc.id, e.EntityID())
		})
	}
}

func TestContactEntity_SetEntityID(t *testing.T) {
	tests := []struct {
		name string
		id   uint64
	}{
		{"set_one", 1},
		{"set_large", 1_000_000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &ContactEntity{}
			e.SetEntityID(tc.id)
			assert.Equal(t, tc.id, e.ID)
		})
	}
}

func TestContactEntity_Fields(t *testing.T) {
	e := &ContactEntity{
		ID:          5,
		UUID:        "uuid-abc",
		PNI:         "pni-abc",
		E164:        "+15550001234",
		GivenName:   "Alice",
		FamilyName:  "Smith",
		ProfileName: "Alice S.",
		AvatarPath:  "/tmp/avatar.jpg",
		IsBlocked:   false,
		IsVerified:  true,
		ProfileKey:  []byte{0x01, 0x02},
	}
	assert.Equal(t, uint64(5), e.EntityID())
	assert.Equal(t, "Alice", e.GivenName)
	assert.True(t, e.IsVerified)
}
