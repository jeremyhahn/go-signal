package accounts

// IdentityType enumerates the two identifier namespaces used across the
// Signal protocol. Every Signal account has an ACI (Account Identity) and
// a PNI (Phone Number Identity). Pre-keys, identity keys, and session
// state are namespaced by IdentityType so an ACI-targeted session never
// mixes with PNI-targeted state.
//
// See docs/protocol/pni.md for the full model.
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

// IdentityUUID returns the account UUID for the requested identity
// namespace: the ACI (Account.UUID) or the PNI (Account.PNI). An empty
// string is returned when the identity is not set on the account —
// callers check for the empty case and return a not-found-style error.
//
// Both UUIDs are stored bare (no "PNI:" prefix). Use ServiceIdentifierString
// when serializing for wire output.
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

// ServiceIdentifierString returns the canonical Signal ServiceIdentifier
// string for a (type, bareUUID) pair: "PNI:<uuid>" for PNI, "<uuid>" for ACI.
// Use this at wire boundaries (REST responses, ServiceIdentifier serialization);
// never persist the prefixed form.
func ServiceIdentifierString(t IdentityType, bareUUID string) string {
	if bareUUID == "" {
		return ""
	}
	if t == IdentityTypePNI {
		return "PNI:" + bareUUID
	}
	return bareUUID
}
