// Package spam provides spam detection and rate limiting for the Signal
// messaging server. It defines the core checker interface, result types, and
// typed errors used across all spam-detection implementations.
package spam

import (
	"context"
	"time"
)

// SpamCheckResult is the outcome of a spam check on a message send operation.
type SpamCheckResult int

const (
	// SpamCheckAllow indicates the message should be delivered normally.
	SpamCheckAllow SpamCheckResult = iota

	// SpamCheckChallenge indicates the sender must complete a challenge
	// (captcha or push) before the message can be delivered.
	SpamCheckChallenge

	// SpamCheckBlock indicates the message must be dropped and the sender
	// should receive a 403 Forbidden response.
	SpamCheckBlock
)

// CheckContext carries the contextual information available at message-send
// time that spam checkers may use when making their determination.
type CheckContext struct {
	// SenderUUID is the ACI UUID of the sending account.
	SenderUUID string

	// RecipientUUID is the ACI UUID of the destination account.
	RecipientUUID string

	// SenderIP is the remote address of the sending client, if available.
	SenderIP string

	// UserAgent is the value of the User-Agent header, if present.
	UserAgent string

	// MessageType is the Signal envelope type (e.g. 1 = CIPHERTEXT).
	MessageType int

	// Timestamp is the server-side time at which the check is performed.
	Timestamp time.Time
}

// SpamChecker evaluates a pending message send and returns a SpamCheckResult
// indicating whether the message should be allowed, challenged, or blocked.
// Implementations must be safe for concurrent use by multiple goroutines.
type SpamChecker interface {
	Check(ctx context.Context, checkCtx *CheckContext) (SpamCheckResult, error)
}
