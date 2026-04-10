package messages

// InvalidArgumentError indicates a required argument was missing or invalid.
type InvalidArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidArgumentError) Error() string {
	return "invalid argument: " + e.Field + ": " + e.Message
}

// MessageNotFoundError indicates the requested message does not exist.
type MessageNotFoundError struct {
	ServerGUID string
}

func (e *MessageNotFoundError) Error() string {
	return "message not found: " + e.ServerGUID
}
