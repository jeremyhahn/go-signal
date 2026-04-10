// Package captcha provides challenge and CAPTCHA verification for rate limit
// mitigation and abuse prevention in the Signal server.
package captcha

// ChallengeType identifies the kind of challenge issued to a client.
type ChallengeType string

const (
	// ChallengeTypeCaptcha indicates a CAPTCHA challenge that requires the
	// client to solve a visual or audio puzzle.
	ChallengeTypeCaptcha ChallengeType = "captcha"

	// ChallengeTypePush indicates a push-based rate limit challenge where
	// the client proves device possession via a push notification round-trip.
	ChallengeTypePush ChallengeType = "rateLimitPushChallenge"
)

// ChallengeResponse is submitted by a client to answer a previously issued
// challenge. The Type field determines which verification path is used.
type ChallengeResponse struct {
	Type    ChallengeType `json:"type"`
	Token   string        `json:"token"`
	Captcha string        `json:"captcha,omitempty"`
}

// PushChallengeRequest is submitted by a client to request a new push-based
// rate limit challenge token.
type PushChallengeRequest struct {
	Token string `json:"token"`
}
