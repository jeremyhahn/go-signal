package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// -- CryptoSessionEntity --

func TestCryptoSessionEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {7}} {
		e := &CryptoSessionEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestCryptoSessionEntity_SetEntityID(t *testing.T) {
	e := &CryptoSessionEntity{}
	e.SetEntityID(8)
	assert.Equal(t, uint64(8), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

// -- PreKeyEntity --

func TestPreKeyEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {99}} {
		e := &PreKeyEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestPreKeyEntity_SetEntityID(t *testing.T) {
	e := &PreKeyEntity{}
	e.SetEntityID(100)
	assert.Equal(t, uint64(100), e.ID)
	e.SetEntityID(1)
	assert.Equal(t, uint64(1), e.ID)
}

// -- SignedPreKeyEntity --

func TestSignedPreKeyEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{1}, {500}} {
		e := &SignedPreKeyEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestSignedPreKeyEntity_SetEntityID(t *testing.T) {
	e := &SignedPreKeyEntity{}
	e.SetEntityID(42)
	assert.Equal(t, uint64(42), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

// -- IdentityKeyEntity --

func TestIdentityKeyEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{3}, {200}} {
		e := &IdentityKeyEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestIdentityKeyEntity_SetEntityID(t *testing.T) {
	e := &IdentityKeyEntity{}
	e.SetEntityID(50)
	assert.Equal(t, uint64(50), e.ID)
	e.SetEntityID(999)
	assert.Equal(t, uint64(999), e.ID)
}

// -- SenderKeyEntity --

func TestSenderKeyEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {12}} {
		e := &SenderKeyEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestSenderKeyEntity_SetEntityID(t *testing.T) {
	e := &SenderKeyEntity{}
	e.SetEntityID(5)
	assert.Equal(t, uint64(5), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

// -- SettingEntity --

func TestSettingEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{1}, {88}} {
		e := &SettingEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestSettingEntity_SetEntityID(t *testing.T) {
	e := &SettingEntity{}
	e.SetEntityID(77)
	assert.Equal(t, uint64(77), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

func TestSettingEntity_Fields(t *testing.T) {
	e := &SettingEntity{ID: 1, Key: "theme", Value: "dark"}
	assert.Equal(t, "theme", e.Key)
	assert.Equal(t, "dark", e.Value)
}
