package captcha

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// testNopLogger returns an slog.Logger whose output is discarded so test
// runs don't pollute terminal output.
func testNopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stubVerifier returns a canned result and records the inputs it saw.
type stubVerifier struct {
	allowed     map[Action][]string
	result      *VerifyResult
	err         error
	gotToken    string
	gotSiteKey  string
	gotRemoteIP string
}

func (s *stubVerifier) Verify(_ context.Context, token, remoteIP, siteKey string) (*VerifyResult, error) {
	s.gotToken = token
	s.gotSiteKey = siteKey
	s.gotRemoteIP = remoteIP
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}

func (s *stubVerifier) ValidSiteKeys(action Action) []string {
	if s.allowed == nil {
		return nil
	}
	return s.allowed[action]
}

func TestParseAction(t *testing.T) {
	cases := []struct {
		in     string
		want   Action
		wantOk bool
	}{
		{"challenge", ActionChallenge, true},
		{"REGISTRATION", ActionRegistration, true},
		{"  registration  ", ActionRegistration, true},
		{"unknown", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, ok := ParseAction(c.in)
			if ok != c.wantOk || got != c.want {
				t.Errorf("ParseAction(%q) = (%q, %v); want (%q, %v)", c.in, got, ok, c.want, c.wantOk)
			}
		})
	}
}

func TestActionString(t *testing.T) {
	if ActionRegistration.String() != "registration" {
		t.Errorf("ActionRegistration.String() = %q", ActionRegistration.String())
	}
}

func TestParseToken_HappyPath(t *testing.T) {
	got, err := parseToken("recaptcha.SITE-KEY.registration.opaque.token.with.dots")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if got.Provider != "recaptcha" {
		t.Errorf("Provider = %q", got.Provider)
	}
	if got.SiteKey != "site-key" {
		t.Errorf("SiteKey = %q (expected lower-cased)", got.SiteKey)
	}
	if got.Action != ActionRegistration {
		t.Errorf("Action = %q", got.Action)
	}
	// Dots inside the token slot are preserved.
	if got.Token.Plaintext() != "opaque.token.with.dots" {
		t.Errorf("Token = %q", got.Token.Plaintext())
	}
	if got.IsShort {
		t.Error("IsShort should be false")
	}
}

func TestParseToken_ShortSuffix(t *testing.T) {
	got, err := parseToken("recaptcha-short.SK.challenge.abcde")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if got.Provider != "recaptcha" || !got.IsShort {
		t.Errorf("expected provider=recaptcha, IsShort=true; got %+v", got)
	}
	if got.Token.Plaintext() != "abcde" {
		t.Errorf("Token = %q", got.Token.Plaintext())
	}
}

func TestParseToken_RejectsTooFewParts(t *testing.T) {
	cases := []string{
		"recaptcha.sk.registration",
		"recaptcha.sk",
		"recaptcha",
		"",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if _, err := parseToken(c); err == nil {
				t.Errorf("expected error for %q", c)
			}
		})
	}
}

func TestParseToken_RejectsEmptySlot(t *testing.T) {
	_, err := parseToken("recaptcha..registration.tok")
	var inv *InvalidTokenFormatError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidTokenFormatError, got %T: %v", err, err)
	}
}

func TestParseToken_RejectsUnknownAction(t *testing.T) {
	_, err := parseToken("recaptcha.sk.nope.tok")
	var inv *InvalidActionError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidActionError, got %T: %v", err, err)
	}
}

func TestChecker_HappyPath(t *testing.T) {
	v := &stubVerifier{
		result:  &VerifyResult{Success: true, Score: 0.9},
		allowed: map[Action][]string{ActionRegistration: {"site-key"}},
	}
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	got, err := c.Verify(context.Background(), ActionRegistration, "recaptcha.SITE-KEY.registration.opaque", "1.2.3.4")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Accepted() {
		t.Error("expected Accepted=true")
	}
	if v.gotSiteKey != "site-key" || v.gotToken != "opaque" || v.gotRemoteIP != "1.2.3.4" {
		t.Errorf("verifier inputs: token=%q site=%q ip=%q", v.gotToken, v.gotSiteKey, v.gotRemoteIP)
	}
}

func TestChecker_RejectsActionMismatch(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true}}
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	_, err := c.Verify(context.Background(), ActionRegistration, "recaptcha.sk.challenge.t", "")
	var inv *InvalidActionError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidActionError, got %T: %v", err, err)
	}
}

func TestChecker_RejectsUnknownProvider(t *testing.T) {
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": &stubVerifier{result: &VerifyResult{}}}}
	_, err := c.Verify(context.Background(), ActionRegistration, "hcaptcha.sk.registration.t", "")
	var up *UnknownProviderError
	if !errors.As(err, &up) {
		t.Fatalf("expected *UnknownProviderError, got %T: %v", err, err)
	}
}

func TestChecker_EnforcesSiteKeyAllowlist(t *testing.T) {
	v := &stubVerifier{
		result:  &VerifyResult{Success: true},
		allowed: map[Action][]string{ActionRegistration: {"good-key"}},
	}
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	_, err := c.Verify(context.Background(), ActionRegistration, "recaptcha.BAD-KEY.registration.t", "")
	var sk *InvalidSiteKeyError
	if !errors.As(err, &sk) {
		t.Fatalf("expected *InvalidSiteKeyError, got %T: %v", err, err)
	}
}

func TestChecker_NilAllowlistMeansAcceptAny(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true}}
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	if _, err := c.Verify(context.Background(), ActionRegistration, "recaptcha.any-key.registration.t", ""); err != nil {
		t.Errorf("nil allowlist should accept: %v", err)
	}
}

type errExpander struct{}

func (errExpander) Expand(_ context.Context, _ string) (string, error) {
	return "", errors.New("expand failure")
}

type okExpander struct{ token string }

func (e okExpander) Expand(_ context.Context, _ string) (string, error) {
	return e.token, nil
}

func TestChecker_ShortCodeExpands(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true}}
	c := &Checker{
		Providers:  map[string]CaptchaVerifier{"recaptcha": v},
		ShortCodes: okExpander{token: "expanded-token"},
	}
	if _, err := c.Verify(context.Background(), ActionRegistration, "recaptcha-short.sk.registration.sc", ""); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.gotToken != "expanded-token" {
		t.Errorf("verifier saw token=%q, want expanded-token", v.gotToken)
	}
}

func TestChecker_ShortCodeWithoutExpanderErrors(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true}}
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	_, err := c.Verify(context.Background(), ActionRegistration, "recaptcha-short.sk.registration.sc", "")
	var su *ShortCodeUnsupportedError
	if !errors.As(err, &su) {
		t.Fatalf("expected *ShortCodeUnsupportedError, got %T: %v", err, err)
	}
}

func TestChecker_ShortCodeExpandPropagatesError(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true}}
	c := &Checker{
		Providers:  map[string]CaptchaVerifier{"recaptcha": v},
		ShortCodes: errExpander{},
	}
	if _, err := c.Verify(context.Background(), ActionRegistration, "recaptcha-short.sk.registration.sc", ""); err == nil {
		t.Fatal("expected expander error to propagate")
	}
}

func TestChecker_PropagatesProviderError(t *testing.T) {
	want := errors.New("provider down")
	v := &stubVerifier{err: want}
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	_, err := c.Verify(context.Background(), ActionRegistration, "recaptcha.sk.registration.t", "")
	if !errors.Is(err, want) {
		t.Errorf("expected provider error, got %v", err)
	}
}

func TestRegistrationCaptchaManager_NilTokenIsNoop(t *testing.T) {
	c := &Checker{}
	mgr := NewRegistrationCaptchaManager(c)
	got, err := mgr.Assess(context.Background(), nil, "1.2.3.4")
	if err != nil || got != nil {
		t.Errorf("nil token: got (%v, %v); want (nil, nil)", got, err)
	}
	empty := ""
	got, err = mgr.Assess(context.Background(), &empty, "1.2.3.4")
	if err != nil || got != nil {
		t.Errorf("empty token: got (%v, %v); want (nil, nil)", got, err)
	}
}

func TestRegistrationCaptchaManager_Assess(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true, Score: 0.9}}
	c := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	mgr := NewRegistrationCaptchaManager(c)
	tok := "recaptcha.sk.registration.opaque"
	got, err := mgr.Assess(context.Background(), &tok, "1.1.1.1")
	if err != nil {
		t.Fatalf("Assess: %v", err)
	}
	if !got.Accepted() {
		t.Error("expected Accepted=true")
	}
}

func TestAssessment_AcceptedFalseOnNil(t *testing.T) {
	var a *Assessment
	if a.Accepted() {
		t.Error("nil Assessment must not be Accepted")
	}
	if (&Assessment{Result: nil}).Accepted() {
		t.Error("nil Result must not be Accepted")
	}
	if (&Assessment{Result: &VerifyResult{Success: false}}).Accepted() {
		t.Error("Success=false must not be Accepted")
	}
}

func TestNormalizeSiteKeys(t *testing.T) {
	if normalizeSiteKeys(nil) != nil {
		t.Error("nil in must produce nil out")
	}
	out := normalizeSiteKeys(map[Action][]string{
		ActionRegistration: {"ABC", "XyZ"},
	})
	got := out[ActionRegistration]
	if len(got) != 2 || got[0] != "abc" || got[1] != "xyz" {
		t.Errorf("unexpected normalization: %+v", got)
	}
}

func TestHCaptchaVerifier_ValidSiteKeys(t *testing.T) {
	v := &HCaptchaVerifier{siteKeysByAction: map[Action][]string{ActionRegistration: {"k1"}}}
	if got := v.ValidSiteKeys(ActionRegistration); len(got) != 1 || got[0] != "k1" {
		t.Errorf("unexpected: %+v", got)
	}
	// Unset action returns nil.
	if got := v.ValidSiteKeys(ActionChallenge); got != nil {
		t.Errorf("expected nil for unconfigured action, got %+v", got)
	}
	// Verifier built without any allowlist returns nil (no enforcement).
	v2 := &HCaptchaVerifier{siteKeysByAction: nil}
	if got := v2.ValidSiteKeys(ActionRegistration); got != nil {
		t.Errorf("expected nil for nil map, got %+v", got)
	}
}

func TestCaptchaManager_UsesCheckerWhenConfigured(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true, Score: 0.9}}
	ck := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	mgr := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Checker: ck,
		Logger:  testNopLogger(),
	})
	resp := &ChallengeResponse{
		Type:    ChallengeTypeCaptcha,
		Token:   "challenge-token",
		Captcha: "recaptcha.sk.challenge.opaque",
	}
	if err := mgr.HandleChallengeResponse(context.Background(), "u1", resp); err != nil {
		t.Fatalf("HandleChallengeResponse: %v", err)
	}
	if v.gotToken != "opaque" {
		t.Errorf("verifier saw token=%q, want opaque", v.gotToken)
	}
}

func TestCaptchaManager_CheckerRejectsMismatchedAction(t *testing.T) {
	v := &stubVerifier{result: &VerifyResult{Success: true}}
	ck := &Checker{Providers: map[string]CaptchaVerifier{"recaptcha": v}}
	mgr := NewCaptchaManagerWithConfig(CaptchaManagerConfig{
		Checker: ck,
		Logger:  testNopLogger(),
	})
	resp := &ChallengeResponse{
		Type:    ChallengeTypeCaptcha,
		Token:   "challenge-token",
		Captcha: "recaptcha.sk.registration.opaque", // wrong action for challenge handler
	}
	err := mgr.HandleChallengeResponse(context.Background(), "u1", resp)
	var inv *InvalidActionError
	if !errors.As(err, &inv) {
		t.Fatalf("expected *InvalidActionError, got %T: %v", err, err)
	}
}

func TestReCAPTCHAVerifier_ValidSiteKeys(t *testing.T) {
	v := &ReCAPTCHAVerifier{siteKeysByAction: map[Action][]string{ActionChallenge: {"k1"}}}
	if got := v.ValidSiteKeys(ActionChallenge); len(got) != 1 || got[0] != "k1" {
		t.Errorf("unexpected: %+v", got)
	}
	if got := v.ValidSiteKeys(ActionRegistration); got != nil {
		t.Errorf("expected nil for unconfigured action, got %+v", got)
	}
	if got := (&ReCAPTCHAVerifier{}).ValidSiteKeys(ActionRegistration); got != nil {
		t.Errorf("expected nil from zero-value verifier, got %+v", got)
	}
}

// The parsed solution is a bearer value: Destroy must wipe it, and Verify
// defers it, so it must be safe to call twice and on nil.
func TestParsedToken_Destroy_WipesToken(t *testing.T) {
	got, err := parseToken("recaptcha.sitekey.challenge.solution")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	if got.Token.Plaintext() != "solution" {
		t.Fatalf("Token = %q, want solution", got.Token.Plaintext())
	}
	got.Destroy()
	if left := got.Token.Plaintext(); left != "" {
		t.Errorf("token survived Destroy: %q", left)
	}
}

func TestParsedToken_Destroy_IdempotentAndNilSafe(t *testing.T) {
	got, err := parseToken("recaptcha.sitekey.challenge.solution")
	if err != nil {
		t.Fatalf("parseToken: %v", err)
	}
	got.Destroy()
	got.Destroy()
	(*parsedToken)(nil).Destroy()
}
