package groups

import (
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// MemberRole constants
// --------------------------------------------------------------------------

func TestMemberRoleDefault_ZeroValue(t *testing.T) {
	var r MemberRole
	if r != MemberRoleDefault {
		t.Errorf("expected zero value to be MemberRoleDefault, got %d", r)
	}
}

func TestMemberRoleAdministrator_NotDefault(t *testing.T) {
	if MemberRoleAdministrator == MemberRoleDefault {
		t.Error("MemberRoleAdministrator must differ from MemberRoleDefault")
	}
}

// --------------------------------------------------------------------------
// AccessControl constants
// --------------------------------------------------------------------------

func TestAccessUnknown_ZeroValue(t *testing.T) {
	var ac AccessControl
	if ac != AccessUnknown {
		t.Errorf("expected zero value to be AccessUnknown, got %d", ac)
	}
}

func TestAccessControlValues_Distinct(t *testing.T) {
	vals := []AccessControl{AccessUnknown, AccessAny, AccessMember, AccessAdministrator, AccessUnsatisfiable}
	seen := make(map[AccessControl]bool)
	for _, v := range vals {
		if seen[v] {
			t.Errorf("duplicate AccessControl value: %d", v)
		}
		seen[v] = true
	}
}

// --------------------------------------------------------------------------
// Member
// --------------------------------------------------------------------------

func TestMember_ZeroValue(t *testing.T) {
	var m Member
	if m.UserID != "" {
		t.Error("expected empty UserID on zero Member")
	}
	if m.Role != MemberRoleDefault {
		t.Error("expected MemberRoleDefault on zero Member")
	}
}

func TestMember_Fields(t *testing.T) {
	m := Member{
		UserID:          "user-1",
		Role:            MemberRoleAdministrator,
		ProfileKey:      []byte("pk"),
		Presentation:    []byte("pres"),
		JoinedAtVersion: 3,
	}
	if m.UserID != "user-1" {
		t.Errorf("got %q, want %q", m.UserID, "user-1")
	}
	if m.Role != MemberRoleAdministrator {
		t.Errorf("got %d, want %d", m.Role, MemberRoleAdministrator)
	}
	if m.JoinedAtVersion != 3 {
		t.Errorf("got %d, want 3", m.JoinedAtVersion)
	}
}

// --------------------------------------------------------------------------
// PendingMember
// --------------------------------------------------------------------------

func TestPendingMember_ZeroValue(t *testing.T) {
	var pm PendingMember
	if pm.ServiceID != "" {
		t.Error("expected empty ServiceID on zero PendingMember")
	}
}

func TestPendingMember_Fields(t *testing.T) {
	ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pm := PendingMember{
		ServiceID:     "svc-1",
		Role:          MemberRoleDefault,
		Timestamp:     ts,
		AddedByUserID: "admin-uuid",
	}
	if pm.ServiceID != "svc-1" {
		t.Errorf("got %q, want %q", pm.ServiceID, "svc-1")
	}
	if !pm.Timestamp.Equal(ts) {
		t.Errorf("got %v, want %v", pm.Timestamp, ts)
	}
}

// --------------------------------------------------------------------------
// RequestingMember
// --------------------------------------------------------------------------

func TestRequestingMember_ZeroValue(t *testing.T) {
	var rm RequestingMember
	if rm.UserID != "" {
		t.Error("expected empty UserID on zero RequestingMember")
	}
}

func TestRequestingMember_Fields(t *testing.T) {
	ts := time.Now().UTC()
	rm := RequestingMember{
		UserID:     "req-user",
		ProfileKey: []byte("pk"),
		Timestamp:  ts,
	}
	if rm.UserID != "req-user" {
		t.Errorf("got %q, want %q", rm.UserID, "req-user")
	}
}

// --------------------------------------------------------------------------
// GroupAccessControls
// --------------------------------------------------------------------------

func TestGroupAccessControls_ZeroValue(t *testing.T) {
	var gac GroupAccessControls
	if gac.Attributes != AccessUnknown {
		t.Errorf("expected AccessUnknown, got %d", gac.Attributes)
	}
}

func TestGroupAccessControls_Fields(t *testing.T) {
	gac := GroupAccessControls{
		Attributes:        AccessAdministrator,
		Members:           AccessMember,
		AddFromInviteLink: AccessAny,
	}
	if gac.Attributes != AccessAdministrator {
		t.Errorf("got %d, want AccessAdministrator", gac.Attributes)
	}
	if gac.Members != AccessMember {
		t.Errorf("got %d, want AccessMember", gac.Members)
	}
}

// --------------------------------------------------------------------------
// Group
// --------------------------------------------------------------------------

func TestGroup_ZeroValue(t *testing.T) {
	var g Group
	if g.ID != "" {
		t.Error("expected empty ID on zero Group")
	}
	if g.Revision != 0 {
		t.Errorf("expected zero Revision, got %d", g.Revision)
	}
}

func TestGroup_Fields(t *testing.T) {
	now := time.Now().UTC()
	g := Group{
		ID:        "group-id-1",
		Title:     []byte("enc-title"),
		Avatar:    "cdn-key",
		Revision:  5,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if g.ID != "group-id-1" {
		t.Errorf("got %q, want %q", g.ID, "group-id-1")
	}
	if g.Revision != 5 {
		t.Errorf("got %d, want 5", g.Revision)
	}
}

// --------------------------------------------------------------------------
// CreateGroupRequest / UpdateGroupRequest
// --------------------------------------------------------------------------

func TestCreateGroupRequest_ZeroValue(t *testing.T) {
	var req CreateGroupRequest
	if req.ID != "" {
		t.Error("expected empty ID")
	}
	if len(req.Members) != 0 {
		t.Error("expected empty Members")
	}
}

func TestUpdateGroupRequest_NilFieldsMeansNoChange(t *testing.T) {
	req := UpdateGroupRequest{}
	if req.Title != nil {
		t.Error("expected nil Title")
	}
	if req.AccessControls != nil {
		t.Error("expected nil AccessControls")
	}
}
