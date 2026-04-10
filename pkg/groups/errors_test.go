package groups

import (
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// GroupNotFoundError
// --------------------------------------------------------------------------

func TestGroupNotFoundError_ContainsGroupID(t *testing.T) {
	err := &GroupNotFoundError{GroupID: "abc-123"}
	if !strings.Contains(err.Error(), "abc-123") {
		t.Errorf("expected error to contain group ID, got: %s", err.Error())
	}
}

func TestGroupNotFoundError_ContainsNotFound(t *testing.T) {
	err := &GroupNotFoundError{GroupID: "xyz"}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected error to contain 'not found', got: %s", err.Error())
	}
}

// --------------------------------------------------------------------------
// GroupAlreadyExistsError
// --------------------------------------------------------------------------

func TestGroupAlreadyExistsError_ContainsGroupID(t *testing.T) {
	err := &GroupAlreadyExistsError{GroupID: "group-42"}
	if !strings.Contains(err.Error(), "group-42") {
		t.Errorf("expected error to contain group ID, got: %s", err.Error())
	}
}

func TestGroupAlreadyExistsError_ContainsAlreadyExists(t *testing.T) {
	err := &GroupAlreadyExistsError{GroupID: "g"}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected error to contain 'already exists', got: %s", err.Error())
	}
}

// --------------------------------------------------------------------------
// GroupVersionConflictError
// --------------------------------------------------------------------------

func TestGroupVersionConflictError_ContainsGroupID(t *testing.T) {
	err := &GroupVersionConflictError{GroupID: "gid", ExpectedVersion: 2, ActualVersion: 5}
	if !strings.Contains(err.Error(), "gid") {
		t.Errorf("expected error to contain group ID, got: %s", err.Error())
	}
}

func TestGroupVersionConflictError_ContainsVersions(t *testing.T) {
	err := &GroupVersionConflictError{GroupID: "gid", ExpectedVersion: 2, ActualVersion: 5}
	msg := err.Error()
	if !strings.Contains(msg, "2") {
		t.Errorf("expected error to contain expected version 2, got: %s", msg)
	}
	if !strings.Contains(msg, "5") {
		t.Errorf("expected error to contain actual version 5, got: %s", msg)
	}
}

// --------------------------------------------------------------------------
// InvalidGroupArgumentError
// --------------------------------------------------------------------------

func TestInvalidGroupArgumentError_ContainsField(t *testing.T) {
	err := &InvalidGroupArgumentError{Field: "members", Message: "at least one required"}
	if !strings.Contains(err.Error(), "members") {
		t.Errorf("expected error to contain field name, got: %s", err.Error())
	}
}

func TestInvalidGroupArgumentError_ContainsMessage(t *testing.T) {
	err := &InvalidGroupArgumentError{Field: "id", Message: "must not be empty"}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Errorf("expected error to contain message, got: %s", err.Error())
	}
}

// --------------------------------------------------------------------------
// MemberNotFoundError
// --------------------------------------------------------------------------

func TestMemberNotFoundError_ContainsMemberID(t *testing.T) {
	err := &MemberNotFoundError{GroupID: "g1", MemberID: "m1"}
	if !strings.Contains(err.Error(), "m1") {
		t.Errorf("expected error to contain member ID, got: %s", err.Error())
	}
}

func TestMemberNotFoundError_ContainsGroupID(t *testing.T) {
	err := &MemberNotFoundError{GroupID: "g1", MemberID: "m1"}
	if !strings.Contains(err.Error(), "g1") {
		t.Errorf("expected error to contain group ID, got: %s", err.Error())
	}
}

// --------------------------------------------------------------------------
// GroupAccessDeniedError
// --------------------------------------------------------------------------

func TestGroupAccessDeniedError_ContainsUUID(t *testing.T) {
	err := &GroupAccessDeniedError{GroupID: "g1", UUID: "u1"}
	if !strings.Contains(err.Error(), "u1") {
		t.Errorf("expected error to contain UUID, got: %s", err.Error())
	}
}

func TestGroupAccessDeniedError_ContainsGroupID(t *testing.T) {
	err := &GroupAccessDeniedError{GroupID: "g1", UUID: "u1"}
	if !strings.Contains(err.Error(), "g1") {
		t.Errorf("expected error to contain group ID, got: %s", err.Error())
	}
}
