// Package groups provides Groups v2 types, storage interfaces, and the
// GroupsManager service layer for the Signal server.
package groups

import "strconv"

// GroupNotFoundError indicates the requested group does not exist.
type GroupNotFoundError struct {
	GroupID string
}

func (e *GroupNotFoundError) Error() string {
	return "group not found: " + e.GroupID
}

// GroupAlreadyExistsError indicates a group with the same ID already exists.
type GroupAlreadyExistsError struct {
	GroupID string
}

func (e *GroupAlreadyExistsError) Error() string {
	return "group already exists: " + e.GroupID
}

// GroupVersionConflictError indicates an optimistic locking conflict during a
// group update.
type GroupVersionConflictError struct {
	GroupID         string
	ExpectedVersion uint32
	ActualVersion   uint32
}

func (e *GroupVersionConflictError) Error() string {
	return "version conflict for group " + e.GroupID +
		": expected " + strconv.FormatUint(uint64(e.ExpectedVersion), 10) +
		", got " + strconv.FormatUint(uint64(e.ActualVersion), 10)
}

// InvalidGroupArgumentError indicates a required argument was missing or
// invalid.
type InvalidGroupArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidGroupArgumentError) Error() string {
	return "invalid argument: " + e.Field + ": " + e.Message
}

// MemberNotFoundError indicates the requested member is not part of the group.
type MemberNotFoundError struct {
	GroupID  string
	MemberID string
}

func (e *MemberNotFoundError) Error() string {
	return "member " + e.MemberID + " not found in group " + e.GroupID
}

// GroupAccessDeniedError indicates the requesting account lacks permission to
// perform the operation on the group.
type GroupAccessDeniedError struct {
	GroupID string
	UUID    string
}

func (e *GroupAccessDeniedError) Error() string {
	return "access denied for account " + e.UUID + " on group " + e.GroupID
}
