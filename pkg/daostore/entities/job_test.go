package entities

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJobEntity_EntityID(t *testing.T) {
	for _, tc := range []struct{ id uint64 }{{0}, {15}} {
		e := &JobEntity{ID: tc.id}
		assert.Equal(t, tc.id, e.EntityID())
	}
}

func TestJobEntity_SetEntityID(t *testing.T) {
	e := &JobEntity{}
	e.SetEntityID(7)
	assert.Equal(t, uint64(7), e.ID)
	e.SetEntityID(0)
	assert.Equal(t, uint64(0), e.ID)
}

func TestJobEntity_Constants(t *testing.T) {
	assert.Equal(t, 0, JobStatusPending)
	assert.Equal(t, 1, JobStatusRunning)
	assert.Equal(t, 2, JobStatusCompleted)
	assert.Equal(t, 3, JobStatusFailed)
}

func TestJobEntity_CompoundIndexes(t *testing.T) {
	e := JobEntity{}
	defs := e.CompoundIndexes()
	require.Len(t, defs, 1)
	assert.Equal(t, []string{"QueueType", "Status", "NextRunAt"}, defs[0].Fields)
}

func TestJobEntity_CompoundIndexes_DifferentInstances(t *testing.T) {
	// CompoundIndexes must return consistent definitions regardless of field values.
	e1 := JobEntity{QueueType: "send", Status: JobStatusPending}
	e2 := JobEntity{QueueType: "retry", Status: JobStatusFailed}
	assert.Equal(t, e1.CompoundIndexes(), e2.CompoundIndexes())
}
