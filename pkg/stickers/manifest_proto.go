package stickers

import (
	"google.golang.org/protobuf/encoding/protowire"
)

// Pack manifest wire format (Signal's Stickers.proto Pack, via protowire): title=1, author=2, cover=3, repeated stickers=4; Sticker id=1, emoji=2, content_type=3.

// EncodePackManifest serializes the pack as a Pack protobuf for encryption and upload; sticker IDs are positions matching the upload slots.
func EncodePackManifest(p *LoadedPack) []byte {
	var buf []byte
	if p.Manifest.Title != "" {
		buf = protowire.AppendTag(buf, 1, protowire.BytesType)
		buf = protowire.AppendString(buf, p.Manifest.Title)
	}
	if p.Manifest.Author != "" {
		buf = protowire.AppendTag(buf, 2, protowire.BytesType)
		buf = protowire.AppendString(buf, p.Manifest.Author)
	}
	if p.Cover != nil {
		buf = appendStickerSubmessage(buf, 3, 0, *p.Cover)
	}
	for i, s := range p.Stickers {
		buf = appendStickerSubmessage(buf, 4, uint32(i), s)
	}
	return buf
}

// appendStickerSubmessage encodes a Sticker submessage into the
// parent's slot (field number 3 for cover or 4 for repeated stickers).
func appendStickerSubmessage(parent []byte, parentField, id uint32, s StickerFile) []byte {
	sub := encodeStickerSubmessage(id, s)
	parent = protowire.AppendTag(parent, protowire.Number(parentField), protowire.BytesType)
	parent = protowire.AppendVarint(parent, uint64(len(sub)))
	parent = append(parent, sub...)
	return parent
}

func encodeStickerSubmessage(id uint32, s StickerFile) []byte {
	var buf []byte
	buf = protowire.AppendTag(buf, 1, protowire.VarintType)
	buf = protowire.AppendVarint(buf, uint64(id))
	if s.Emoji != "" {
		buf = protowire.AppendTag(buf, 2, protowire.BytesType)
		buf = protowire.AppendString(buf, s.Emoji)
	}
	if s.ContentType != "" {
		buf = protowire.AppendTag(buf, 3, protowire.BytesType)
		buf = protowire.AppendString(buf, s.ContentType)
	}
	return buf
}
