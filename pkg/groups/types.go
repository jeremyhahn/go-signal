package groups

import "time"

// MemberRole defines the role of a group member.
type MemberRole uint8

const (
	// MemberRoleDefault is the standard member role with no elevated
	// privileges.
	MemberRoleDefault MemberRole = iota

	// MemberRoleAdministrator can modify group settings and manage
	// membership.
	MemberRoleAdministrator
)

// AccessControl defines who may perform a group operation.
type AccessControl uint8

const (
	// AccessUnknown is an uninitialised access control value.
	AccessUnknown AccessControl = iota

	// AccessAny allows any member to perform the operation.
	AccessAny

	// AccessMember restricts the operation to existing members.
	AccessMember

	// AccessAdministrator restricts the operation to administrators.
	AccessAdministrator

	// AccessUnsatisfiable means the operation cannot be performed by any
	// member (used to lock invite-link access).
	AccessUnsatisfiable
)

// Member represents a single member of a Signal Groups v2 group.
type Member struct {
	// UserID is the account UUID of the member.
	UserID string

	// Role is the member's role within the group.
	Role MemberRole

	// ProfileKey is the encrypted profile key for this member (opaque bytes
	// supplied by the client).
	ProfileKey []byte

	// Presentation is the zkgroup credential presentation that proves
	// membership without revealing the underlying identity.
	Presentation []byte

	// JoinedAtVersion is the group version at which this member joined.
	JoinedAtVersion uint32
}

// PendingMember represents an invited-but-not-yet-joined member.
type PendingMember struct {
	// ServiceID is the UUID of the invited account.
	ServiceID string

	// Role is the role that will be assigned upon acceptance.
	Role MemberRole

	// Timestamp is the wall-clock time of the invitation.
	Timestamp time.Time

	// AddedByUserID is the UUID of the member who sent the invitation.
	AddedByUserID string
}

// RequestingMember represents an account that has requested to join the group
// but has not yet been approved by an administrator.
type RequestingMember struct {
	// UserID is the account UUID of the requesting member.
	UserID string

	// ProfileKey is the encrypted profile key (opaque bytes from the client).
	ProfileKey []byte

	// Timestamp is when the join request was submitted.
	Timestamp time.Time
}

// GroupAccessControls defines the access control policies for a group.
type GroupAccessControls struct {
	// Attributes controls who may modify group name, avatar, and description.
	Attributes AccessControl

	// Members controls who may add new members to the group.
	Members AccessControl

	// AddFromInviteLink controls who may use the invite link to join.
	AddFromInviteLink AccessControl
}

// Group represents a Signal Groups v2 group state record.
type Group struct {
	// ID is the globally unique group identifier (base64url-encoded master
	// key derived ID as used by the Signal protocol).
	ID string

	// Title is the group's display name (encrypted on the wire; stored here
	// as the raw ciphertext supplied by the client).
	Title []byte

	// Avatar is the CDN key for the group avatar, if set.
	Avatar string

	// Description is the optional group description ciphertext.
	Description []byte

	// Members is the list of current full members.
	Members []Member

	// PendingMembers is the list of invited members awaiting acceptance.
	PendingMembers []PendingMember

	// RequestingMembers is the list of join requests pending admin approval.
	RequestingMembers []RequestingMember

	// AccessControls defines who may perform each group operation.
	AccessControls GroupAccessControls

	// InviteLinkPassword is the invite link password ciphertext. When empty,
	// the invite link is disabled.
	InviteLinkPassword []byte

	// Revision is the group's monotonically increasing version counter.
	Revision uint32

	// CreatedAt is the timestamp when the group was first created.
	CreatedAt time.Time

	// UpdatedAt is the timestamp of the most recent state change.
	UpdatedAt time.Time
}

// CreateGroupRequest contains the parameters required to create a new group.
type CreateGroupRequest struct {
	// ID is the caller-supplied group identifier.
	ID string

	// Title is the initial group title ciphertext.
	Title []byte

	// Avatar is the optional CDN key for the group avatar.
	Avatar string

	// Description is the optional group description ciphertext.
	Description []byte

	// Members is the initial member list. Must contain at least one
	// administrator.
	Members []Member

	// PendingMembers is the optional initial set of invited members.
	PendingMembers []PendingMember

	// AccessControls defines the initial access control policy.
	AccessControls GroupAccessControls

	// InviteLinkPassword is the optional invite link password.
	InviteLinkPassword []byte
}

// UpdateGroupRequest carries the fields that may be modified in a group
// update. Only non-nil / non-zero fields are applied.
type UpdateGroupRequest struct {
	// Title replaces the current title ciphertext when non-nil.
	Title []byte

	// Avatar replaces the current avatar when non-empty.
	Avatar string

	// Description replaces the current description when non-nil.
	Description []byte

	// AccessControls replaces the current access controls when non-nil.
	AccessControls *GroupAccessControls

	// InviteLinkPassword replaces the current invite link password when
	// non-nil.
	InviteLinkPassword []byte

	// AddMembers is a list of new members to add in this revision.
	AddMembers []Member

	// RemoveMemberIDs is a list of member UUIDs to remove in this revision.
	RemoveMemberIDs []string

	// AddPendingMembers is a list of new pending members to add.
	AddPendingMembers []PendingMember

	// RemovePendingMemberIDs is a list of pending member UUIDs to remove.
	RemovePendingMemberIDs []string
}
