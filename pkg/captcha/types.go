// Package captcha provides challenge and CAPTCHA verification for rate limit
// mitigation and abuse prevention in the Signal server.
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

// Action identifies the purpose of a CAPTCHA submission. The client embeds
// it in the captcha token (slot 3 of the dotted format) so the server can
// reject solutions intended for a different flow. Mirrors Java's
// org.whispersystems.textsecuregcm.captcha.Action enum.
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
