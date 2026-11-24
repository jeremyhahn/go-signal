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

// Assess runs the registration captcha check and returns a typed error on failure; a nil token returns (nil, nil).
func (m *RegistrationCaptchaManager) Assess(ctx context.Context, token *string, remoteIP string) (*Assessment, error) {
	if token == nil || *token == "" {
		return nil, nil
	}
	return m.checker.Verify(ctx, ActionRegistration, *token, remoteIP)
}
