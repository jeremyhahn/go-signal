package spam

// SpamBlockedError is returned when a SpamChecker has determined that a
// message should be permanently blocked. The Reason field carries a
// human-readable explanation suitable for structured logging.
type SpamBlockedError struct {
	Reason string
}

// Error implements the error interface.
func (e *SpamBlockedError) Error() string {
	return "spam blocked: " + e.Reason
}

// SpamChallengeRequiredError requires the sender to complete a challenge (ChallengeType "captcha" or "push").
type SpamChallengeRequiredError struct {
	ChallengeType string
}

// Error implements the error interface.
func (e *SpamChallengeRequiredError) Error() string {
	return "spam challenge required: " + e.ChallengeType
}
