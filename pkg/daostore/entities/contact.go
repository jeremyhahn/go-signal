package entities

// ContactEntity represents a Signal contact stored locally.
type ContactEntity struct {
	ID          uint64 `json:"id"`
	UUID        string `json:"uuid" index:"unique"`
	PNI         string `json:"pni,omitempty"`
	E164        string `json:"e164,omitempty" index:"unique,sparse"`
	GivenName   string `json:"givenName,omitempty"`
	FamilyName  string `json:"familyName,omitempty"`
	ProfileName string `json:"profileName,omitempty"`
	AvatarPath  string `json:"avatarPath,omitempty"`
	IsBlocked   bool   `json:"isBlocked"`
	IsVerified  bool   `json:"isVerified"`
	ProfileKey  []byte `json:"profileKey,omitempty"`
}

func (c *ContactEntity) EntityID() uint64      { return c.ID }
func (c *ContactEntity) SetEntityID(id uint64)  { c.ID = id }
