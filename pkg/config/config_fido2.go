//go:build fido2

package config

// FIDO2Config holds WebAuthn/FIDO2 settings. Only compiled when the fido2
// build tag is active.
type FIDO2Config struct {
	Enabled          bool     `yaml:"enabled"`
	RPID             string   `yaml:"rpId"`
	RPName           string   `yaml:"rpName"`
	RPOrigins        []string `yaml:"rpOrigins"`
	Attestation      string   `yaml:"attestation"`      // "none", "indirect", "direct"
	UserVerification string   `yaml:"userVerification"` // "required", "preferred", "discouraged"
	TimeoutSeconds   int      `yaml:"timeoutSeconds"`
	RequireMFA       bool     `yaml:"requireMfa"`
	AllowFIDO2Only   bool     `yaml:"allowFido2Only"`
}

// Validate checks the FIDO2 configuration for required fields and valid values.
func (c *FIDO2Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.RPID == "" {
		return &ConfigValidationError{
			Field:   "fido2.rpId",
			Message: "rpId is required when FIDO2 is enabled",
		}
	}

	if c.RPName == "" {
		return &ConfigValidationError{
			Field:   "fido2.rpName",
			Message: "rpName is required when FIDO2 is enabled",
		}
	}

	if len(c.RPOrigins) == 0 {
		return &ConfigValidationError{
			Field:   "fido2.rpOrigins",
			Message: "at least one origin is required when FIDO2 is enabled",
		}
	}

	validAttestations := map[string]struct{}{
		"":         {},
		"none":     {},
		"indirect": {},
		"direct":   {},
	}
	if _, ok := validAttestations[c.Attestation]; !ok {
		return &ConfigValidationError{
			Field:   "fido2.attestation",
			Message: "must be one of: none, indirect, direct",
		}
	}

	validUV := map[string]struct{}{
		"":            {},
		"required":    {},
		"preferred":   {},
		"discouraged": {},
	}
	if _, ok := validUV[c.UserVerification]; !ok {
		return &ConfigValidationError{
			Field:   "fido2.userVerification",
			Message: "must be one of: required, preferred, discouraged",
		}
	}

	return nil
}

// ApplyDefaults sets default values for unset FIDO2 fields.
func (c *FIDO2Config) ApplyDefaults() {
	if c.Attestation == "" {
		c.Attestation = "none"
	}
	if c.UserVerification == "" {
		c.UserVerification = "preferred"
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 60
	}
}
