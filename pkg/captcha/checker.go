package captcha

import (
	"context"
	"strings"
)

// tokenSeparator is the dot character between slots in the captcha token
// format. Mirrors Java CaptchaChecker.SEPARATOR.
const tokenSeparator = "."

// shortCodeSuffix is appended to the provider prefix when the client wants
// the server to expand a short code into the full captcha token via the
// ShortCodeExpander. Mirrors Java CaptchaChecker.SHORT_SUFFIX.
const shortCodeSuffix = "-short"

// parsedToken is the decoded captcha-token-format string. Fields are
// already normalized to lower-case where appropriate (provider, site key)
// and unchanged for token bytes.
type parsedToken struct {
	Provider  string // "recaptcha" / "hcaptcha" / etc.
	SiteKey   string // lower-cased
	Action    Action // parsed enum
	Token     string // raw provider-issued solution
	IsShort   bool   // true when input used the "-short" provider suffix
	RawAction string // original action slot (for metrics / error messages)
}

// parseToken splits a captcha submission of the form
// `provider.sitekey.action.token` into its components. `provider` may carry
// a `-short` suffix indicating Token is a short-code that must be expanded
// via a ShortCodeExpander before the provider verify call.
//
// Returns *InvalidTokenFormatError when the input does not have exactly
// four dot-separated slots or the action slot does not parse.
func parseToken(input string) (*parsedToken, error) {
	// SplitN(_, 4) preserves any literal dots inside the token slot.
	parts := strings.SplitN(input, tokenSeparator, 4)
	if len(parts) < 4 {
		return nil, &InvalidTokenFormatError{Reason: "expected provider.sitekey.action.token"}
	}
	provider := normalize(parts[0])
	siteKey := normalize(parts[1])
	rawAction := parts[2]
	token := parts[3]
	isShort := false
	if strings.HasSuffix(provider, shortCodeSuffix) {
		isShort = true
		provider = provider[:len(provider)-len(shortCodeSuffix)]
	}
	action, ok := ParseAction(rawAction)
	if !ok {
		return nil, &InvalidActionError{Action: rawAction}
	}
	if provider == "" || siteKey == "" || token == "" {
		return nil, &InvalidTokenFormatError{Reason: "empty slot in captcha token"}
	}
	return &parsedToken{
		Provider:  provider,
		SiteKey:   siteKey,
		Action:    action,
		Token:     token,
		IsShort:   isShort,
		RawAction: rawAction,
	}, nil
}

// ShortCodeExpander resolves short captcha codes into the full provider
// token. When a deployment does not use short codes, leave Checker.ShortCodes
// nil and any `-short` submission falls through with *ShortCodeUnsupportedError.
type ShortCodeExpander interface {
	Expand(ctx context.Context, code string) (string, error)
}

// Checker parses an incoming captcha submission, dispatches to the right
// provider, and validates the site-key + action allowlist. It is the Go
// analogue of Java CaptchaChecker.
//
// Providers is the lookup table from the leading `provider` slot to the
// CaptchaVerifier responsible for that scheme. Unknown providers produce
// *UnknownProviderError so the REST layer can return HTTP 400.
type Checker struct {
	Providers  map[string]CaptchaVerifier
	ShortCodes ShortCodeExpander
}

// Assessment is the structured outcome of a captcha submission. It
// preserves the parsed slot data so handlers can emit metrics + audit logs
// without re-parsing the token.
type Assessment struct {
	Provider string
	SiteKey  string
	Action   Action
	Result   *VerifyResult
}

// Accepted reports whether the assessment was successful end-to-end.
func (a *Assessment) Accepted() bool {
	return a != nil && a.Result != nil && a.Result.Success
}

// Verify parses input, looks up the provider, runs site-key + action
// validation, and delegates the cryptographic check to the provider's
// CaptchaVerifier. Mirrors Java CaptchaChecker.verify.
//
//   - expectedAction is the action this call site requires. A token whose
//     embedded action differs is rejected even when the provider would have
//     accepted the underlying solution; this prevents replay across flows.
//   - remoteIP is forwarded to the provider for fraud signals.
func (c *Checker) Verify(ctx context.Context, expectedAction Action, input, remoteIP string) (*Assessment, error) {
	parsed, err := parseToken(input)
	if err != nil {
		return nil, err
	}
	if parsed.Action != expectedAction {
		return nil, &InvalidActionError{Action: parsed.RawAction}
	}
	token := parsed.Token
	if parsed.IsShort {
		if c.ShortCodes == nil {
			return nil, &ShortCodeUnsupportedError{}
		}
		expanded, err := c.ShortCodes.Expand(ctx, token)
		if err != nil {
			return nil, err
		}
		token = expanded
	}
	provider, ok := c.Providers[parsed.Provider]
	if !ok {
		return nil, &UnknownProviderError{Provider: parsed.Provider}
	}
	// Per-action site-key allowlist (optional — verifiers that opt out via
	// ValidSiteKeys(action)==nil accept any site key, preserving the legacy
	// "no enforcement" behavior of the standalone HCaptchaVerifier).
	if alw, ok := provider.(siteKeyAllowlist); ok {
		allowed := alw.ValidSiteKeys(parsed.Action)
		if allowed != nil && !containsKey(allowed, parsed.SiteKey) {
			return nil, &InvalidSiteKeyError{SiteKey: parsed.SiteKey, Action: parsed.Action}
		}
	}
	res, err := provider.Verify(ctx, token, remoteIP, parsed.SiteKey)
	if err != nil {
		return nil, err
	}
	return &Assessment{
		Provider: parsed.Provider,
		SiteKey:  parsed.SiteKey,
		Action:   parsed.Action,
		Result:   res,
	}, nil
}

// siteKeyAllowlist is the opt-in interface providers implement to enforce
// per-action site-key allowlists. Implementing it is optional; verifiers
// that don't (e.g. the TestVerifier) accept any site key.
type siteKeyAllowlist interface {
	// ValidSiteKeys returns the set of allowed site keys for the given
	// action. A nil return means "no restriction".
	ValidSiteKeys(action Action) []string
}

// containsKey returns true when `set` contains `key`. Case-insensitive on
// `key`; the provider is expected to lower-case its allowlist entries
// during configuration.
func containsKey(set []string, key string) bool {
	for _, k := range set {
		if k == key {
			return true
		}
	}
	return false
}
