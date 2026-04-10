package memory

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/groups"
)

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------

func testGroup(id string) *groups.Group {
	return &groups.Group{
		ID:       id,
		Title:    []byte("enc-title"),
		Avatar:   "cdn-key",
		Revision: 1,
		Members: []groups.Member{
			{
				UserID:       "admin-1",
				Role:         groups.MemberRoleAdministrator,
				ProfileKey:   []byte("pk"),
				Presentation: []byte("pres"),
			},
		},
		AccessControls: groups.GroupAccessControls{
			Attributes: groups.AccessAdministrator,
			Members:    groups.AccessMember,
		},
		InviteLinkPassword: []byte("password"),
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
}

// --------------------------------------------------------------------------
// NewMemoryGroupStore
// --------------------------------------------------------------------------

func TestNewMemoryGroupStore_NotNil(t *testing.T) {
	s := NewMemoryGroupStore()
	if s == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestNewMemoryGroupStore_EmptyMap(t *testing.T) {
	s := NewMemoryGroupStore()
	if len(s.byID) != 0 {
		t.Errorf("expected empty byID map, got %d entries", len(s.byID))
	}
}

// --------------------------------------------------------------------------
// Create
// --------------------------------------------------------------------------

func TestMemoryGroupStore_Create_Success(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("g1")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.byID) != 1 {
		t.Errorf("expected 1 stored group, got %d", len(s.byID))
	}
}

func TestMemoryGroupStore_Create_Duplicate_ReturnsError(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("dup")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	err := s.Create(context.Background(), g)
	if err == nil {
		t.Fatal("expected error for duplicate group ID")
	}
	if _, ok := err.(*groups.GroupAlreadyExistsError); !ok {
		t.Errorf("expected *GroupAlreadyExistsError, got %T", err)
	}
}

func TestMemoryGroupStore_Create_IsolatessCallerReference(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("iso-create")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Mutate the caller's copy.
	g.Title = []byte("mutated")
	stored, err := s.Get(context.Background(), "iso-create")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(stored.Title) == "mutated" {
		t.Error("store did not isolate caller's reference on Create")
	}
}

// --------------------------------------------------------------------------
// Get
// --------------------------------------------------------------------------

func TestMemoryGroupStore_Get_Existing(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("get-g1")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	got, err := s.Get(context.Background(), "get-g1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "get-g1" {
		t.Errorf("got %q, want %q", got.ID, "get-g1")
	}
}

func TestMemoryGroupStore_Get_NonExistent_ReturnsError(t *testing.T) {
	s := NewMemoryGroupStore()
	_, err := s.Get(context.Background(), "no-such")
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if _, ok := err.(*groups.GroupNotFoundError); !ok {
		t.Errorf("expected *GroupNotFoundError, got %T", err)
	}
}

func TestMemoryGroupStore_Get_ReturnsDeepCopy(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("deep-copy-g")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	got, err := s.Get(context.Background(), "deep-copy-g")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got.Title = []byte("modified")
	got2, err := s.Get(context.Background(), "deep-copy-g")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(got2.Title, []byte("modified")) {
		t.Error("Get did not return an independent copy")
	}
}

// --------------------------------------------------------------------------
// Update
// --------------------------------------------------------------------------

func TestMemoryGroupStore_Update_Success(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("upd-g")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	g.Revision = 2
	g.Title = []byte("new-title")
	if err := s.Update(context.Background(), g); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	stored, _ := s.Get(context.Background(), "upd-g")
	if string(stored.Title) != "new-title" {
		t.Errorf("got title %q, want %q", stored.Title, "new-title")
	}
}

func TestMemoryGroupStore_Update_VersionConflict_ReturnsError(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("vc-g")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	g.Revision = 5 // wrong: stored is 1, expected next is 2
	err := s.Update(context.Background(), g)
	if err == nil {
		t.Fatal("expected version conflict error")
	}
	if _, ok := err.(*groups.GroupVersionConflictError); !ok {
		t.Errorf("expected *GroupVersionConflictError, got %T", err)
	}
}

func TestMemoryGroupStore_Update_NonExistent_ReturnsError(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("ne-g")
	g.Revision = 2 // simulated next revision
	err := s.Update(context.Background(), g)
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if _, ok := err.(*groups.GroupNotFoundError); !ok {
		t.Errorf("expected *GroupNotFoundError, got %T", err)
	}
}

func TestMemoryGroupStore_Update_IsolatesCallerReference(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("iso-upd")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	g.Revision = 2
	if err := s.Update(context.Background(), g); err != nil {
		t.Fatalf("update failed: %v", err)
	}
	g.Title = []byte("mutated-after-update")
	stored, _ := s.Get(context.Background(), "iso-upd")
	if bytes.Equal(stored.Title, []byte("mutated-after-update")) {
		t.Error("Update did not isolate caller's reference")
	}
}

// --------------------------------------------------------------------------
// Delete
// --------------------------------------------------------------------------

func TestMemoryGroupStore_Delete_Success(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("del-g")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if err := s.Delete(context.Background(), "del-g"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if len(s.byID) != 0 {
		t.Errorf("expected empty store after delete, got %d", len(s.byID))
	}
}

func TestMemoryGroupStore_Delete_NonExistent_ReturnsError(t *testing.T) {
	s := NewMemoryGroupStore()
	err := s.Delete(context.Background(), "no-such")
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if _, ok := err.(*groups.GroupNotFoundError); !ok {
		t.Errorf("expected *GroupNotFoundError, got %T", err)
	}
}

func TestMemoryGroupStore_Delete_ThenGet_ReturnsError(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("del-get-g")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if err := s.Delete(context.Background(), "del-get-g"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	_, err := s.Get(context.Background(), "del-get-g")
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

// --------------------------------------------------------------------------
// Concurrency
// --------------------------------------------------------------------------

func TestMemoryGroupStore_ConcurrentCreateGet(t *testing.T) {
	s := NewMemoryGroupStore()
	const n = 50

	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			id := "concurrent-g-" + itoa(idx)
			g := testGroup(id)
			_ = s.Create(context.Background(), g)
			_, _ = s.Get(context.Background(), id)
		}(i)
	}
	wg.Wait()
}

func TestMemoryGroupStore_ConcurrentUpdateDelete(t *testing.T) {
	s := NewMemoryGroupStore()
	g := testGroup("conc-upd-del")
	if err := s.Create(context.Background(), g); err != nil {
		t.Fatalf("create failed: %v", err)
	}

	// One goroutine updates; another deletes. Race detector validates safety.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		upd := testGroup("conc-upd-del")
		upd.Revision = 2
		_ = s.Update(context.Background(), upd)
	}()

	go func() {
		defer wg.Done()
		_ = s.Delete(context.Background(), "conc-upd-del")
	}()

	wg.Wait()
}

// --------------------------------------------------------------------------
// cloneGroup internals
// --------------------------------------------------------------------------

func TestCloneGroup_NilSlices(t *testing.T) {
	g := &groups.Group{
		ID:                 "nil-slices",
		Members:            nil,
		PendingMembers:     nil,
		RequestingMembers:  nil,
		Title:              nil,
		InviteLinkPassword: nil,
	}
	clone := cloneGroup(g)
	if clone.Members != nil {
		t.Error("expected nil Members in clone")
	}
}

func TestCloneGroup_WithPendingMembers(t *testing.T) {
	g := &groups.Group{
		ID:    "pend-clone",
		Title: []byte("title"),
		PendingMembers: []groups.PendingMember{
			{ServiceID: "svc-1"},
		},
	}
	clone := cloneGroup(g)
	if len(clone.PendingMembers) != 1 {
		t.Fatalf("expected 1 pending member, got %d", len(clone.PendingMembers))
	}
	if clone.PendingMembers[0].ServiceID != "svc-1" {
		t.Errorf("got %q, want %q", clone.PendingMembers[0].ServiceID, "svc-1")
	}
}

func TestCloneGroup_DeepCopiesTitle(t *testing.T) {
	g := &groups.Group{
		ID:      "title-clone",
		Title:   []byte("original"),
		Members: []groups.Member{{UserID: "u", Role: groups.MemberRoleAdministrator}},
	}
	clone := cloneGroup(g)
	clone.Title[0] = 'X'
	if g.Title[0] == 'X' {
		t.Error("cloneGroup did not deep-copy Title")
	}
}

func TestCloneGroupMembers_ProfileKeyIsolation(t *testing.T) {
	ms := []groups.Member{
		{UserID: "u1", ProfileKey: []byte("pk"), Presentation: []byte("pres")},
	}
	cloned := cloneGroupMembers(ms)
	cloned[0].ProfileKey[0] = 'X'
	if ms[0].ProfileKey[0] == 'X' {
		t.Error("cloneGroupMembers did not isolate ProfileKey")
	}
}

func TestCloneGroupPendingMembers_NilInput(t *testing.T) {
	if cloneGroupPendingMembers(nil) != nil {
		t.Error("expected nil for nil input")
	}
}

func TestCloneGroupPendingMembers_DeepCopy(t *testing.T) {
	ms := []groups.PendingMember{
		{ServiceID: "svc-1", AddedByUserID: "admin-1"},
		{ServiceID: "svc-2", AddedByUserID: "admin-2"},
	}
	cloned := cloneGroupPendingMembers(ms)
	if len(cloned) != len(ms) {
		t.Fatalf("got len %d, want %d", len(cloned), len(ms))
	}
	// Mutate the clone and verify the original is unchanged.
	cloned[0].ServiceID = "mutated"
	if ms[0].ServiceID == "mutated" {
		t.Error("cloneGroupPendingMembers did not produce an independent copy")
	}
}

func TestCloneGroupRequestingMembers_ProfileKeyIsolation(t *testing.T) {
	ms := []groups.RequestingMember{
		{UserID: "req-1", ProfileKey: []byte("pk")},
	}
	cloned := cloneGroupRequestingMembers(ms)
	cloned[0].ProfileKey[0] = 'X'
	if ms[0].ProfileKey[0] == 'X' {
		t.Error("cloneGroupRequestingMembers did not isolate ProfileKey")
	}
}

// itoa converts an int to a string without importing strconv here.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
