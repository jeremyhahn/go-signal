package accounts

// IdentityType is the ACI or PNI namespace that pre-keys, identity keys and sessions are keyed by; see docs/protocol/pni.md.
type IdentityType int

const (
	// IdentityTypeACI is the account-identity namespace.
	IdentityTypeACI IdentityType = iota
	// IdentityTypePNI is the phone-number-identity namespace.
	IdentityTypePNI
)

// String returns "ACI" or "PNI" for logging / diagnostics.
func (t IdentityType) String() string {
	switch t {
	case IdentityTypeACI:
		return "ACI"
	case IdentityTypePNI:
		return "PNI"
	default:
		return "Unknown"
	}
}

// IdentityUUID returns the bare ACI or PNI UUID for the identity, or "" when unset.
func (a *Account) IdentityUUID(t IdentityType) string {
	if a == nil {
		return ""
	}
	switch t {
	case IdentityTypeACI:
		return a.UUID
	case IdentityTypePNI:
		return a.PNI
	default:
		return ""
	}
}

// ServiceIdentifierString returns "PNI:<uuid>" for PNI and "<uuid>" for ACI, for wire output only.
func ServiceIdentifierString(t IdentityType, bareUUID string) string {
	if bareUUID == "" {
		return ""
	}
	if t == IdentityTypePNI {
		return "PNI:" + bareUUID
	}
	return bareUUID
}
