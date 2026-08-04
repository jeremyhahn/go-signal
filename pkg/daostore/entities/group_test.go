package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroupEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {33}} {
		e := &GroupEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestGroupEntity_SetEntityID(t *testing.T) {
	e := &GroupEntity{}
	e.SetEntityID(20)
	assert.Equal(t, uint64(20), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

func TestGroupEntity_Fields(t *testing.T) {
	e := &GroupEntity{
		ID:               3,
		GroupID:          "grp-abc",
		MasterKey:        []byte{0x01},
		Revision:         5,
		Title:            "Team Chat",
		Description:      "Our group",
		AnnouncementOnly: true,
	}
	assert.Equal(t, uint64(3), e.EntityID())
	assert.Equal(t, "grp-abc", e.GroupID)
	assert.True(t, e.AnnouncementOnly)
}
