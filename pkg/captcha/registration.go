package captcha

import (
	"context"
)

// RegistrationCaptchaManager pins the action to ActionRegistration so the
// account-create + verification-session-create handlers never accidentally
// accept a challenge-action token. Mirrors Java's RegistrationCaptchaManager.
type RegistrationCaptchaManager struct {
	checker *Checker
}

// NewRegistrationCaptchaManager wraps the supplied checker.
func NewRegistrationCaptchaManager(checker *Checker) *RegistrationCaptchaManager {
	return &RegistrationCaptchaManager{checker: checker}
}

// Assess runs the registration-action captcha pipeline. Returns a populated
// Assessment on success; a typed error on parse / provider / score failure
// so handlers can surface 400 / 422 distinctions.
//
// A nil `token` indicates no captcha was supplied; the result is (nil, nil)
// so callers can decide whether the absence is acceptable (e.g. first-time
// registration may not require a captcha; required-on-failure escalation
// is enforced higher in the flow).
func (m *RegistrationCaptchaManager) Assess(ctx context.Context, token *string, remoteIP string) (*Assessment, error) {
	if token == nil || *token == "" {
		return nil, nil
	}
	return m.checker.Verify(ctx, ActionRegistration, *token, remoteIP)
}
