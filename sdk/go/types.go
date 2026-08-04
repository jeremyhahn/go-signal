package signal

import "time"

// Account represents a registered Signal account.
type Account struct {
	Number   string `json:"number"`
	UUID     string `json:"uuid"`
	PNI      string `json:"pni,omitempty"`
	DeviceID uint32 `json:"deviceId"`
}

// Message represents a Signal message (sent or received).
type Message struct {
	Timestamp   int64        `json:"timestamp"`
	Source      string       `json:"source,omitempty"`
	Destination string       `json:"destination,omitempty"`
	GroupID     string       `json:"groupId,omitempty"`
	Body        string       `json:"message,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
	Quote       *Quote       `json:"quote,omitempty"`
	Reaction    *Reaction    `json:"reaction,omitempty"`
	ExpiresIn   int          `json:"expiresInSeconds,omitempty"`
}

// Attachment represents a file attachment on a message.
type Attachment struct {
	ContentType string `json:"contentType"`
	Filename    string `json:"filename,omitempty"`
	Size        int64  `json:"size"`
	ID          string `json:"id,omitempty"`
	LocalPath   string `json:"-"` // local file path for uploads
}

// Quote represents a quoted/reply message.
type Quote struct {
	ID      int64  `json:"id"`
	Author  string `json:"author"`
	Message string `json:"text,omitempty"`
}

// Reaction represents an emoji reaction to a message.
type Reaction struct {
	Emoji     string `json:"emoji"`
	Author    string `json:"targetAuthor"`
	Timestamp int64  `json:"targetSentTimestamp"`
	Remove    bool   `json:"isRemove,omitempty"`
}

// Group represents a Signal group conversation.
type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
	Admins      []string `json:"admins,omitempty"`
	InviteLink  string   `json:"inviteLink,omitempty"`
	Revision    int      `json:"revision"`
}

// Contact represents a Signal contact.
type Contact struct {
	Number     string `json:"number"`
	UUID       string `json:"uuid,omitempty"`
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Blocked    bool   `json:"blocked,omitempty"`
}

// Profile represents a user's Signal profile.
type Profile struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	About      string `json:"about,omitempty"`
	AboutEmoji string `json:"aboutEmoji,omitempty"`
	AvatarPath string `json:"avatarPath,omitempty"`
}

// Device represents a linked Signal device.
type Device struct {
	ID       int       `json:"id"`
	Name     string    `json:"name,omitempty"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"lastSeen"`
}

// Identity represents a contact's identity key.
type Identity struct {
	Number       string    `json:"number"`
	UUID         string    `json:"uuid,omitempty"`
	Fingerprint  string    `json:"fingerprint"`
	SafetyNumber string    `json:"safetyNumber"`
	TrustLevel   string    `json:"trustLevel"`
	Added        time.Time `json:"addedDate"`
}

// FIDO2Credential represents a registered security key.
type FIDO2Credential struct {
	CredentialID string   `json:"credentialId"`
	Name         string   `json:"name"`
	Transport    []string `json:"transport"`
	CreatedAt    int64    `json:"createdAt"`
	LastUsedAt   int64    `json:"lastUsedAt"`
}

// SendOptions configures how a message is sent.
type SendOptions struct {
	Attachments    []string // local file paths
	NoteToSelf     bool
	EndSession     bool
	GroupID        string
	QuoteTimestamp int64
	QuoteAuthor    string
	QuoteMessage   string
	PreviewURL     string
	PreviewTitle   string
	EditTimestamp  int64
}

// ReceiveOptions configures message receiving.
type ReceiveOptions struct {
	Timeout           int // seconds
	IgnoreAttachments bool
	IgnoreStories     bool
	SendReadReceipts  bool
}
