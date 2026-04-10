package profiles

// InvalidArgumentError indicates a required argument was missing or invalid.
type InvalidArgumentError struct {
	Field   string
	Message string
}

func (e *InvalidArgumentError) Error() string {
	return "invalid argument: " + e.Field + ": " + e.Message
}

// ProfileNotFoundError indicates the requested profile does not exist.
type ProfileNotFoundError struct {
	UUID    string
	Version string
}

func (e *ProfileNotFoundError) Error() string {
	if e.Version != "" {
		return "profile not found: " + e.UUID + " version " + e.Version
	}
	return "profile not found: " + e.UUID
}
