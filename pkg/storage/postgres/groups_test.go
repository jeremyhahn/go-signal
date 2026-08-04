package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/groups"
)

// newGroup builds a deterministic Group for tests.
func newGroup(id string) *groups.Group {
	return &groups.Group{
		ID:    id,
		Title: []byte("enc-title"),
		Members: []groups.Member{
			{
				UserID:          "user-1",
				Role:            groups.MemberRoleAdministrator,
				ProfileKey:      []byte("pk"),
				JoinedAtVersion: 0,
			},
		},
		AccessControls: groups.GroupAccessControls{
			Attributes:        groups.AccessAdministrator,
			Members:           groups.AccessMember,
			AddFromInviteLink: groups.AccessUnsatisfiable,
		},
		Revision:  0,
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestGroups_Create_Get_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	s := NewGroupStore(c.Pool())

	g := newGroup("group-abc")
	if err := s.Create(ctx, g); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, "group-abc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "group-abc" || string(got.Title) != "enc-title" {
		t.Fatalf("Get returned unexpected group: %+v", got)
	}
}

func TestGroups_Create_Duplicate_ReturnsAlreadyExists(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	s := NewGroupStore(c.Pool())

	g := newGroup("group-dup")
	if err := s.Create(ctx, g); err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	err := s.Create(ctx, g)
	var aee *groups.GroupAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected GroupAlreadyExistsError, got %T: %v", err, err)
	}
	if aee.GroupID != "group-dup" {
		t.Fatalf("GroupAlreadyExistsError.GroupID = %q, want %q", aee.GroupID, "group-dup")
	}
}

func TestGroups_Get_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())

	_, err := s.Get(context.Background(), "no-such-group")
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError, got %T: %v", err, err)
	}
}

func TestGroups_Update_CorrectRevision(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	s := NewGroupStore(c.Pool())

	g := newGroup("group-upd")
	if err := s.Create(ctx, g); err != nil {
		t.Fatalf("Create: %v", err)
	}

	g.Revision = 1
	g.Title = []byte("updated-title")
	if err := s.Update(ctx, g); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, "group-upd")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Revision != 1 || string(got.Title) != "updated-title" {
		t.Fatalf("Update did not persist: %+v", got)
	}
}

func TestGroups_Update_WrongRevision_ReturnsVersionConflict(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	s := NewGroupStore(c.Pool())

	g := newGroup("group-conflict")
	if err := s.Create(ctx, g); err != nil {
		t.Fatalf("Create: %v", err)
	}

	g.Revision = 5 // skip ahead — current is 0, expected next is 1
	err := s.Update(ctx, g)
	var vce *groups.GroupVersionConflictError
	if !errors.As(err, &vce) {
		t.Fatalf("expected GroupVersionConflictError, got %T: %v", err, err)
	}
	if vce.GroupID != "group-conflict" {
		t.Fatalf("GroupVersionConflictError.GroupID = %q, want %q", vce.GroupID, "group-conflict")
	}
}

func TestGroups_Update_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	s := NewGroupStore(c.Pool())

	g := newGroup("group-missing")
	g.Revision = 1
	err := s.Update(ctx, g)
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError, got %T: %v", err, err)
	}
}

func TestGroups_Delete_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	s := NewGroupStore(c.Pool())

	g := newGroup("group-del")
	if err := s.Create(ctx, g); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, "group-del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := s.Get(ctx, "group-del")
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError after Delete, got %T: %v", err, err)
	}
}

func TestGroups_Delete_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())

	err := s.Delete(context.Background(), "no-such-group")
	var nfe *groups.GroupNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected GroupNotFoundError, got %T: %v", err, err)
	}
}

func TestGroups_Create_NilGroup_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())

	err := s.Create(context.Background(), nil)
	var iae *groups.InvalidGroupArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidGroupArgumentError, got %T: %v", err, err)
	}
}

func TestGroups_Create_EmptyID_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())

	g := newGroup("")
	err := s.Create(context.Background(), g)
	var iae *groups.InvalidGroupArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidGroupArgumentError for empty ID, got %T: %v", err, err)
	}
}

func TestGroups_Update_NilGroup_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())

	err := s.Update(context.Background(), nil)
	var iae *groups.InvalidGroupArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidGroupArgumentError for nil group, got %T: %v", err, err)
	}
}

func TestGroups_Create_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())
	c.Close()

	err := s.Create(context.Background(), newGroup("pool-closed-group"))
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestGroups_Delete_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())
	c.Close()

	err := s.Delete(context.Background(), "some-group")
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *groups.GroupNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not GroupNotFoundError")
	}
}

func TestGroups_Get_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())
	c.Close()

	_, err := s.Get(context.Background(), "some-group")
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *groups.GroupNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, got GroupNotFoundError")
	}
}

func TestGroups_Update_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())
	c.Close()

	g := newGroup("pool-closed-update")
	g.Revision = 1
	err := s.Update(context.Background(), g)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

// TestGroups_Get_CorruptedData_UnmarshalError exercises the json.Unmarshal
// error branch in Get (groups.go:77-79). A row is inserted via raw SQL with a
// data value whose "Title" field contains an invalid base64 string (Group.Title
// is []byte, encoded as base64 in JSON), so json.Unmarshal fails even though
// the row is found.
func TestGroups_Get_CorruptedData_UnmarshalError(t *testing.T) {
	c := newTestClient(t)
	s := NewGroupStore(c.Pool())
	ctx := context.Background()

	groupID := uuid.NewString()
	_, err := c.Pool().Exec(ctx,
		`INSERT INTO groups (id, revision, data, created_at, updated_at)
		 VALUES ($1, 0, '{"Title":"!!! not valid base64 !!!"}'::jsonb, NOW(), NOW())`,
		groupID,
	)
	if err != nil {
		t.Fatalf("raw insert corrupted group: %v", err)
	}

	_, err = s.Get(ctx, groupID)
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	var nfe *groups.GroupNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected unmarshal error, not GroupNotFoundError")
	}
}

func TestGroups_Update_MultipleRevisions(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	s := NewGroupStore(c.Pool())

	g := newGroup("group-multi")
	if err := s.Create(ctx, g); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Apply three consecutive revisions.
	for rev := uint32(1); rev <= 3; rev++ {
		g.Revision = rev
		g.Title = []byte("title-v" + string(rune('0'+rev)))
		if err := s.Update(ctx, g); err != nil {
			t.Fatalf("Update rev %d: %v", rev, err)
		}
	}

	got, err := s.Get(ctx, "group-multi")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Revision != 3 {
		t.Fatalf("Revision = %d, want 3", got.Revision)
	}
}
