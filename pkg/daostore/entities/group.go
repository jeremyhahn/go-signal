package entities

// GroupEntity represents a Signal group stored locally.
type GroupEntity struct {
	ID               uint64 `json:"id"`
	GroupID          string `json:"groupId" index:"unique"`
	MasterKey        []byte `json:"masterKey,omitempty"`
	Revision         int    `json:"revision" index:"true"`
	Title            string `json:"title"`
	Description      string `json:"description,omitempty"`
	AvatarPath       string `json:"avatarPath,omitempty"`
	InviteLink       string `json:"inviteLink,omitempty"`
	AccessControl    string `json:"accessControl,omitempty"`
	Members          string `json:"members,omitempty"`
	Admins           string `json:"admins,omitempty"`
	PendingMembers   string `json:"pendingMembers,omitempty"`
	BannedMembers    string `json:"bannedMembers,omitempty"`
	AnnouncementOnly bool   `json:"announcementOnly"`
}

func (g *GroupEntity) EntityID() uint64      { return g.ID }
func (g *GroupEntity) SetEntityID(id uint64)  { g.ID = id }
