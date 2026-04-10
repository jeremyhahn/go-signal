package stickers

// StickerPackFormUpload describes the upload form returned to clients for
// uploading sticker packs to a CDN.
type StickerPackFormUpload struct {
	PackId   string             `json:"packId"`
	Manifest StickerFormField   `json:"manifest"`
	Stickers []StickerFormField `json:"stickers"`
}

// StickerFormField describes a single form field for uploading a sticker or
// manifest blob.
type StickerFormField struct {
	Id       int               `json:"id"`
	Key      string            `json:"key"`
	Headers  map[string]string `json:"headers"`
	Location string            `json:"location"`
}
