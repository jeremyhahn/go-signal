// Package captcha verifies challenge and captcha responses for rate-limit and abuse mitigation.
package captcha

import "strings"

// normalize lowercases and trims a token-format slot. Matches the
// Java CaptchaChecker behavior of `Locale.ROOT.toLowerCase().strip()` on
// the slot fields so identifiers compare deterministically.
func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ChallengeType identifies the kind of challenge issued to a client.
type ChallengeType string

const (
	// ChallengeTypeCaptcha is a captcha the client must solve.
	ChallengeTypeCaptcha ChallengeType = "captcha"

	// ChallengeTypePush indicates a push-based rate limit challenge where
	// the client proves device possession via a push notification round-trip.
	ChallengeTypePush ChallengeType = "rateLimitPushChallenge"
)

// ChallengeResponse answers an issued challenge; Type selects the verification path.
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

// Action is the purpose embedded in slot 3 of the captcha token, so solutions for another flow are rejected.
type Action string

const (
	// ActionChallenge gates rate-limit challenge responses.
	ActionChallenge Action = "challenge"
	// ActionRegistration gates account registration / verification-session
	// creation.
	ActionRegistration Action = "registration"
)

// ParseAction returns the Action with the given name (case-insensitive,
// whitespace-stripped). Returns ("", false) for unknown values so callers
// can surface a 400 to the client.
func ParseAction(s string) (Action, bool) {
	switch normalize(s) {
	case string(ActionChallenge):
		return ActionChallenge, true
	case string(ActionRegistration):
		return ActionRegistration, true
	}
	return "", false
}

// String returns the canonical lower-case form. Implements fmt.Stringer.
func (a Action) String() string { return string(a) }
