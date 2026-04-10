package entities

// AttachmentEntity represents a file attachment on a message.
type AttachmentEntity struct {
	ID            uint64 `json:"id"`
	MessageID     string `json:"messageId" index:"true"`
	ContentType   string `json:"contentType"`
	FileName      string `json:"fileName,omitempty"`
	Size          int64  `json:"size"`
	LocalPath     string `json:"localPath,omitempty"`
	CDNKey        string `json:"cdnKey,omitempty"`
	CDNNumber     int    `json:"cdnNumber,omitempty"`
	Width         int    `json:"width,omitempty"`
	Height        int    `json:"height,omitempty"`
	ThumbnailPath string `json:"thumbnailPath,omitempty"`
	Digest        []byte `json:"digest,omitempty"`
	Status        int    `json:"status"`
}

func (a *AttachmentEntity) EntityID() uint64      { return a.ID }
func (a *AttachmentEntity) SetEntityID(id uint64)  { a.ID = id }
