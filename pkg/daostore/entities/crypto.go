package entities

// CryptoSessionEntity stores a Signal Protocol session record.
type CryptoSessionEntity struct {
	ID      uint64 `json:"id"`
	Address string `json:"address" index:"unique"`
	Record  []byte `json:"record"`
}

func (s *CryptoSessionEntity) EntityID() uint64      { return s.ID }
func (s *CryptoSessionEntity) SetEntityID(id uint64) { s.ID = id }

// PreKeyEntity stores a one-time pre-key.
type PreKeyEntity struct {
	ID     uint64 `json:"id"`
	KeyID  uint32 `json:"keyId" index:"unique"`
	Record []byte `json:"record"`
}

func (p *PreKeyEntity) EntityID() uint64      { return p.ID }
func (p *PreKeyEntity) SetEntityID(id uint64) { p.ID = id }

// SignedPreKeyEntity stores a signed pre-key.
type SignedPreKeyEntity struct {
	ID     uint64 `json:"id"`
	KeyID  uint32 `json:"keyId" index:"unique"`
	Record []byte `json:"record"`
}

func (s *SignedPreKeyEntity) EntityID() uint64      { return s.ID }
func (s *SignedPreKeyEntity) SetEntityID(id uint64) { s.ID = id }

// IdentityKeyEntity stores a remote contact's identity key.
type IdentityKeyEntity struct {
	ID             uint64 `json:"id"`
	Address        string `json:"address" index:"unique"`
	Key            []byte `json:"key"`
	FirstUse       int64  `json:"firstUse"`
	VerifiedStatus int    `json:"verifiedStatus"`
}

func (i *IdentityKeyEntity) EntityID() uint64      { return i.ID }
func (i *IdentityKeyEntity) SetEntityID(id uint64) { i.ID = id }

// SenderKeyEntity stores a group sender key record.
type SenderKeyEntity struct {
	ID     uint64 `json:"id"`
	Name   string `json:"name" index:"unique"`
	Record []byte `json:"record"`
}

func (s *SenderKeyEntity) EntityID() uint64      { return s.ID }
func (s *SenderKeyEntity) SetEntityID(id uint64) { s.ID = id }

// SettingEntity stores a key-value setting/preference.
type SettingEntity struct {
	ID    uint64 `json:"id"`
	Key   string `json:"key" index:"unique"`
	Value string `json:"value"`
}

func (s *SettingEntity) EntityID() uint64      { return s.ID }
func (s *SettingEntity) SetEntityID(id uint64) { s.ID = id }
