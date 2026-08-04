package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/groups"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestGroup returns a minimal Group for testing.
func newTestGroup() *groups.Group {
	return &groups.Group{
		ID:        uuid.NewString(),
		Title:     []byte("encrypted-title"),
		Avatar:    "groups/avatar-key",
		Revision:  0,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
		Members: []groups.Member{
			{
				UserID:     uuid.NewString(),
				Role:       groups.MemberRoleAdministrator,
				ProfileKey: []byte("profile-key"),
			},
		},
	}
}

// runGroupStoreContract drives every behavioral expectation of
// groups.GroupStore across all backends.
func runGroupStoreContract(t *testing.T, factory func(t *testing.T) groups.GroupStore) {
	t.Helper()

	t.Run("Create_Get_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		g := newTestGroup()

		require.NoError(t, s.Create(ctx, g))

		got, err := s.Get(ctx, g.ID)
		require.NoError(t, err)
		assert.Equal(t, g.ID, got.ID)
		assert.Equal(t, g.Title, got.Title)
		assert.Equal(t, g.Avatar, got.Avatar)
		assert.Equal(t, g.Revision, got.Revision)
	})

	t.Run("Create_DuplicateID_AlreadyExists", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		g := newTestGroup()

		require.NoError(t, s.Create(ctx, g))

		dup := *g
		err := s.Create(ctx, &dup)
		require.Error(t, err)
		var target *groups.GroupAlreadyExistsError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Get_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.Get(ctx, uuid.NewString())
		require.Error(t, err)
		var target *groups.GroupNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Update_RevisionIncrement_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		g := newTestGroup()
		require.NoError(t, s.Create(ctx, g))

		updated := *g
		updated.Revision = 1
		updated.Title = []byte("updated-title")

		require.NoError(t, s.Update(ctx, &updated))

		got, err := s.Get(ctx, g.ID)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), got.Revision)
		assert.Equal(t, []byte("updated-title"), got.Title)
	})

	t.Run("Update_WrongRevision_VersionConflict", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		g := newTestGroup()
		require.NoError(t, s.Create(ctx, g))

		stale := *g
		stale.Revision = 5 // wrong: must be exactly revision+1 = 1

		err := s.Update(ctx, &stale)
		require.Error(t, err)
		var target *groups.GroupVersionConflictError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Update_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		ghost := newTestGroup()
		ghost.Revision = 1

		err := s.Update(ctx, ghost)
		require.Error(t, err)
		var target *groups.GroupNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Delete_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		g := newTestGroup()
		require.NoError(t, s.Create(ctx, g))

		require.NoError(t, s.Delete(ctx, g.ID))

		_, err := s.Get(ctx, g.ID)
		require.Error(t, err)
		var target *groups.GroupNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("Delete_NotFound_Error", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		err := s.Delete(ctx, uuid.NewString())
		require.Error(t, err)
		var target *groups.GroupNotFoundError
		assert.ErrorAs(t, err, &target)
	})

	t.Run("MultipleRevisions_MonotonicUpdate", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		g := newTestGroup()
		require.NoError(t, s.Create(ctx, g))

		for i := uint32(1); i <= 5; i++ {
			upd := *g
			upd.Revision = i
			require.NoError(t, s.Update(ctx, &upd))
			g = &upd
		}

		got, err := s.Get(ctx, g.ID)
		require.NoError(t, err)
		assert.Equal(t, uint32(5), got.Revision)
	})

	t.Run("MembersPreservedRoundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		g := newTestGroup()
		memberUUID := g.Members[0].UserID

		require.NoError(t, s.Create(ctx, g))

		got, err := s.Get(ctx, g.ID)
		require.NoError(t, err)
		require.Len(t, got.Members, 1)
		assert.Equal(t, memberUUID, got.Members[0].UserID)
		assert.Equal(t, groups.MemberRoleAdministrator, got.Members[0].Role)
	})
}

// TestGroupStoreContract_Memory runs the group contract against the
// in-memory backend.
func TestGroupStoreContract_Memory(t *testing.T) {
	runGroupStoreContract(t, func(t *testing.T) groups.GroupStore {
		return memorystorage.NewMemoryGroupStore()
	})
}

// TestGroupStoreContract_QRDB runs the group contract against the qrdb
// (FakeKVStore) backend.
func TestGroupStoreContract_QRDB(t *testing.T) {
	runGroupStoreContract(t, func(t *testing.T) groups.GroupStore {
		return qrdbstorage.NewGroupStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestGroupStoreContract_Postgres runs the group contract against a live
// Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestGroupStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runGroupStoreContract(t, func(t *testing.T) groups.GroupStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewGroupStore(c.Pool())
	})
}
