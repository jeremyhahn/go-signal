package stickers

import "strconv"

// InvalidStickerCountError indicates that the requested sticker count is not
// within the allowed range.
type InvalidStickerCountError struct {
	Count int
}

func (e *InvalidStickerCountError) Error() string {
	return "invalid sticker count: " + strconv.Itoa(e.Count)
}
